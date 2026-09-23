use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Client;
use serde::Deserialize;
use std::sync::LazyLock;
use tokio::sync::{Notify, RwLock};
use tracing::{debug, info, instrument, warn};

use super::bootstrap::{ip_matches_prefix, parse_asn_range, validate_bootstrap_url};
use super::types::RdapResponse;
use crate::error::{Result, SeerError};
use crate::http::{read_body_capped, BodyReadError, Overflow};
use crate::retry::{NetworkRetryClassifier, RetryClassifier, RetryExecutor, RetryPolicy};
use crate::validation::normalize_domain;

const IANA_BOOTSTRAP_DNS: &str = "https://data.iana.org/rdap/dns.json";
const IANA_BOOTSTRAP_IPV4: &str = "https://data.iana.org/rdap/ipv4.json";
const IANA_BOOTSTRAP_IPV6: &str = "https://data.iana.org/rdap/ipv6.json";
const IANA_BOOTSTRAP_ASN: &str = "https://data.iana.org/rdap/asn.json";

/// Default timeout for RDAP queries (15 seconds).
/// With the 5s connect_timeout, this gives 10s for the server to respond.
/// Most RDAP servers respond within 2-5 seconds; slow ccTLD registries
/// may need the full 15s.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// Connect timeout — fail fast when a host is unreachable rather than
/// waiting the full request timeout on a TCP handshake that will never complete.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// TTL for bootstrap data (24 hours)
const BOOTSTRAP_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Minimum interval between bootstrap refresh attempts when the cache is
/// expired-but-present or empty. Prevents a thundering herd of concurrent
/// callers from all hammering IANA simultaneously during an outage.
const BOOTSTRAP_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// TTL for a *partial* bootstrap load — one where some IANA registry file
/// (say dns.json) failed while the others loaded. The failed section is
/// carried over from the previous dataset (or left empty on a cold start),
/// and the short TTL makes the next caller retry the gap within minutes
/// instead of pinning it for [`BOOTSTRAP_TTL`]. Kept above
/// [`BOOTSTRAP_REFRESH_MIN_INTERVAL`] so the throttle stays meaningful.
const BOOTSTRAP_PARTIAL_TTL: Duration = Duration::from_secs(5 * 60);

/// `Accept` header for RDAP queries. RFC 7480 §4.2 asks for
/// `application/rdap+json`, but a few servers (rdap.nic.sn) answer 406 unless
/// plain JSON is also acceptable, so it is offered at a lower preference.
const RDAP_ACCEPT: &str = "application/rdap+json, application/json;q=0.9";

/// Maximum HTTP redirect hops followed for one RDAP query. RFC 7480 §5.2
/// uses redirects for cross-registry referral (ARIN → RIPE for an IP it
/// doesn't hold, LACNIC → registro.br, a TLD's moved base URL); real chains
/// are one hop, so three is ample while bounding a hostile server.
const MAX_RDAP_REDIRECTS: usize = 3;

/// Shared HTTP client for bootstrap fetches against IANA.
/// The bootstrap targets are hardcoded data.iana.org URLs, so this client
/// does not need DNS-rebinding protection. Per-query RDAP requests use
/// per-host clients that pin validated resolved IPs, cached briefly in
/// [`PINNED_CLIENT_CACHE`].
///
/// Wrapped in `Option` so a reqwest builder failure surfaces as a typed
/// `SeerError::HttpError` via `rdap_http_client()` instead of a process
/// panic at first use (library code must not `.expect()` on shared state).
static RDAP_HTTP_CLIENT: LazyLock<Option<Client>> = LazyLock::new(|| {
    Client::builder()
        .timeout(DEFAULT_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .user_agent("Seer/1.0 (RDAP Client)")
        .pool_max_idle_per_host(10)
        // Bootstrap targets are hardcoded https://data.iana.org URLs that return
        // terminal JSON; disable redirect-following for defense in depth so a
        // compromised/MITM'd hop can't bounce the fetch to an internal address.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()
});

/// Returns a reference to the shared RDAP bootstrap HTTP client, or a typed
/// error if the builder failed at initialization time. Call sites use
/// `rdap_http_client()?` instead of dereferencing the static directly.
fn rdap_http_client() -> Result<&'static Client> {
    RDAP_HTTP_CLIENT
        .as_ref()
        .ok_or_else(|| SeerError::HttpError("failed to initialize HTTP client".into()))
}

/// Bootstrap cache with TTL support
static BOOTSTRAP_CACHE: LazyLock<RwLock<Option<CachedBootstrap>>> =
    LazyLock::new(|| RwLock::new(None));

/// Timestamp of the most recent bootstrap refresh attempt (success or failure).
/// Used together with `BOOTSTRAP_REFRESH_MIN_INTERVAL` to throttle retry
/// storms when IANA is unreachable.
static BOOTSTRAP_LAST_ATTEMPT: LazyLock<RwLock<Option<Instant>>> =
    LazyLock::new(|| RwLock::new(None));

/// Notifies waiters when an in-flight bootstrap load completes (success or
/// failure). Solves the first-boot thundering-herd race where two concurrent
/// cold-cache callers would otherwise see: caller A records its attempt
/// timestamp, then caller B checks the timestamp and finds it "too recent"
/// and returns a spurious `throttled and no cache available` error while A
/// is still actively loading. Losers instead wait on this notify with a
/// bounded timeout, then re-check the cache.
static BOOTSTRAP_LOAD_NOTIFY: LazyLock<Notify> = LazyLock::new(Notify::new);

/// True while some task is running a bootstrap load. Lets a throttled
/// cold-cache caller tell "a load is in flight — wait for its notify" apart
/// from "the last load already finished (and failed) — nobody will notify",
/// so it only blocks in the former case instead of sleeping the full bounded
/// timeout for the rest of the throttle window.
static BOOTSTRAP_LOAD_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Marks a bootstrap load in flight for its lifetime. Dropping it — on
/// completion *or* cancellation of the loading future — clears the flag and
/// wakes every waiter, so a dropped winner can't leave losers hanging.
struct BootstrapLoadGuard;

impl BootstrapLoadGuard {
    fn start() -> Self {
        BOOTSTRAP_LOAD_IN_FLIGHT.store(true, Ordering::SeqCst);
        Self
    }
}

impl Drop for BootstrapLoadGuard {
    fn drop(&mut self) {
        BOOTSTRAP_LOAD_IN_FLIGHT.store(false, Ordering::SeqCst);
        BOOTSTRAP_LOAD_NOTIFY.notify_waiters();
    }
}

/// Cached bootstrap data with timestamp for TTL tracking
struct CachedBootstrap {
    data: BootstrapData,
    loaded_at: Instant,
    /// [`BOOTSTRAP_TTL`] for a complete load; [`BOOTSTRAP_PARTIAL_TTL`] when
    /// some registry section failed to load this time.
    ttl: Duration,
}

impl CachedBootstrap {
    #[cfg(test)]
    fn new(data: BootstrapData) -> Self {
        Self::with_ttl(data, BOOTSTRAP_TTL)
    }

    fn with_ttl(data: BootstrapData, ttl: Duration) -> Self {
        Self {
            data,
            loaded_at: Instant::now(),
            ttl,
        }
    }

    fn is_expired(&self) -> bool {
        self.loaded_at.elapsed() > self.ttl
    }

    fn age(&self) -> Duration {
        self.loaded_at.elapsed()
    }
}

/// Parsed IANA bootstrap data.
/// Each TLD/prefix/ASN range is associated with an ordered list of
/// candidate RDAP base URLs (IANA may list multiple per RFC 9224). Callers
/// try them in order and fall back on failure.
struct BootstrapData {
    dns: HashMap<String, Arc<Vec<url::Url>>>,
    ipv4: Vec<(IpRange, Arc<Vec<url::Url>>)>,
    ipv6: Vec<(IpRange, Arc<Vec<url::Url>>)>,
    asn: Vec<(AsnRange, Arc<Vec<url::Url>>)>,
}

#[derive(Clone)]
struct IpRange {
    prefix: String,
}

#[derive(Clone)]
struct AsnRange {
    start: u32,
    end: u32,
}

#[derive(Deserialize)]
struct BootstrapResponse {
    services: Vec<Vec<serde_json::Value>>,
}

/// One bootstrap fetch. Each registry section is `None` when that IANA file
/// failed to fetch or parse (or parsed to nothing), so a partial failure can
/// be merged over the previous dataset instead of replacing it.
struct BootstrapLoad {
    dns: Option<HashMap<String, Arc<Vec<url::Url>>>>,
    ipv4: Option<Vec<(IpRange, Arc<Vec<url::Url>>)>>,
    ipv6: Option<Vec<(IpRange, Arc<Vec<url::Url>>)>>,
    asn: Option<Vec<(AsnRange, Arc<Vec<url::Url>>)>>,
}

impl BootstrapLoad {
    /// True when every registry section loaded.
    fn is_complete(&self) -> bool {
        self.dns.is_some() && self.ipv4.is_some() && self.ipv6.is_some() && self.asn.is_some()
    }

    /// Cache TTL for this load: the full day when complete, the short
    /// [`BOOTSTRAP_PARTIAL_TTL`] when a section is missing.
    fn ttl(&self) -> Duration {
        if self.is_complete() {
            BOOTSTRAP_TTL
        } else {
            BOOTSTRAP_PARTIAL_TTL
        }
    }

    /// Builds the dataset to cache, keeping `previous`'s section for every
    /// registry that failed this time — a refresh where only dns.json timed
    /// out must not wipe good (if stale) TLD data.
    fn merge_over(self, previous: Option<BootstrapData>) -> BootstrapData {
        let (dns, ipv4, ipv6, asn) = match previous {
            Some(p) => (Some(p.dns), Some(p.ipv4), Some(p.ipv6), Some(p.asn)),
            None => (None, None, None, None),
        };
        BootstrapData {
            dns: self.dns.or(dns).unwrap_or_default(),
            ipv4: self.ipv4.or(ipv4).unwrap_or_default(),
            ipv6: self.ipv6.or(ipv6).unwrap_or_default(),
            asn: self.asn.or(asn).unwrap_or_default(),
        }
    }
}

/// Stores a finished load into `cache` (the contents of [`BOOTSTRAP_CACHE`])
/// by merging it over the previous dataset, unless another task already
/// stored a still-fresh dataset while this load ran.
fn store_bootstrap_load(cache: &mut Option<CachedBootstrap>, load: BootstrapLoad) {
    if cache.as_ref().is_some_and(|c| !c.is_expired()) {
        return;
    }
    let ttl = load.ttl();
    if !load.is_complete() {
        warn!(
            dns = load.dns.is_some(),
            ipv4 = load.ipv4.is_some(),
            ipv6 = load.ipv6.is_some(),
            asn = load.asn.is_some(),
            retry_in_secs = ttl.as_secs(),
            "RDAP bootstrap partially loaded; keeping previous data for failed registries"
        );
    }
    let previous = cache.take().map(|c| c.data);
    *cache = Some(CachedBootstrap::with_ttl(load.merge_over(previous), ttl));
}

/// Waits (bounded) for an in-flight bootstrap load to complete, then
/// re-checks the cache. Used by losers of the throttle race so a concurrent
/// cold-cache caller doesn't spuriously error with "throttled and no cache
/// available" while the winner is still loading.
///
/// The `notified` future must be created BEFORE the caller observes the
/// throttle condition — otherwise `notify_waiters()` could fire in the gap
/// between observing "still throttled, empty cache" and subscribing, and
/// this call would then block until timeout.
async fn wait_for_in_flight_load(
    notified: std::pin::Pin<&mut tokio::sync::futures::Notified<'_>>,
) -> Result<()> {
    // Only block while a load is actually running. Once the last load has
    // finished (a cold load that failed leaves the cache empty), nobody will
    // notify again, and waiting would stall every caller for the full timeout
    // until the throttle window passes. The winner writes the cache before
    // clearing the flag, so observing `false` here means the cache check
    // below already sees its result. Still bounded, in case the winner hangs.
    if BOOTSTRAP_LOAD_IN_FLIGHT.load(Ordering::SeqCst) {
        let _ = tokio::time::timeout(DEFAULT_TIMEOUT, notified).await;
    }
    let cache = BOOTSTRAP_CACHE.read().await;
    if cache.is_some() {
        Ok(())
    } else {
        Err(SeerError::RdapBootstrapError(
            "bootstrap refresh throttled and no cache available".to_string(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct RdapClient {
    retry_policy: RetryPolicy,
    /// Per-request timeout for RDAP queries (default [`DEFAULT_TIMEOUT`]).
    timeout: Duration,
    /// When true, skips the reserved-IP SSRF validation for loopback URLs so
    /// tests can target a 127.0.0.1 wiremock fixture (any other URL, such as
    /// a scripted redirect target, still gets the full guard). Not settable
    /// outside `#[cfg(test)]` builds — production requests always validate
    /// and pin resolved IPs.
    allow_reserved: bool,
}

impl Default for RdapClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RdapClient {
    /// Creates a new RDAP client with default settings.
    pub fn new() -> Self {
        Self {
            // RDAP registries rate-limit hard. Give 429s a few jittered,
            // server-hint-aware retries to clear a *brief* limit, but keep the
            // total bounded (≈10s worst case) so a sticky rate limit falls
            // through to the WHOIS/DNS fallback fast instead of hanging an
            // interactive lookup. The old 2× 100ms never cleared a real limit;
            // a multi-attempt 30s honor was the opposite mistake.
            retry_policy: RetryPolicy::new()
                .with_max_attempts(3)
                .with_initial_delay(Duration::from_millis(500))
                .with_max_delay(Duration::from_secs(5)),
            timeout: DEFAULT_TIMEOUT,
            allow_reserved: false,
        }
    }

    /// Builds a client honoring `~/.seer/config.toml` settings.
    ///
    /// Reads `timeouts.rdap_secs` (already clamped to 1–300s by
    /// [`crate::config::SeerConfig::load`]). Sugar over
    /// [`RdapClient::with_timeout`] — equivalent to
    /// `RdapClient::new().with_timeout(config.rdap_timeout())`.
    pub fn from_config(config: &crate::config::SeerConfig) -> Self {
        Self::new().with_timeout(config.rdap_timeout())
    }

    /// Sets the per-request timeout for RDAP queries.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Test-only: allow requests to loopback/reserved addresses (mock servers).
    #[cfg(test)]
    pub(crate) fn allowing_reserved_for_tests(mut self) -> Self {
        self.allow_reserved = true;
        self
    }

    /// Sets the retry policy for transient network failures.
    ///
    /// The default policy retries up to 2 times with exponential backoff.
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }

    /// Disables retries (single attempt only).
    pub fn without_retries(mut self) -> Self {
        self.retry_policy = RetryPolicy::no_retry();
        self
    }

    /// Ensures bootstrap data is loaded and not expired.
    ///
    /// Uses stale-while-revalidate: if refresh fails, stale data is used.
    /// Performs the actual network load WITHOUT holding the write lock, so
    /// concurrent readers are never blocked by an in-flight HTTP request
    /// (fix for the previous deadlock/await-under-lock hazard).
    ///
    /// Refresh attempts are also throttled to at most one per
    /// `BOOTSTRAP_REFRESH_MIN_INTERVAL` to avoid thundering-herd storms
    /// against IANA when bootstrap is down.
    ///
    /// Concurrent cold-cache callers coordinate via `BOOTSTRAP_LOAD_NOTIFY`:
    /// losers of the throttle race wait (with a bounded timeout) for the
    /// winner's load instead of erroring out immediately.
    async fn ensure_bootstrap(&self) -> Result<()> {
        // Fast path: read-lock and return if fresh.
        {
            let cache = BOOTSTRAP_CACHE.read().await;
            if let Some(cached) = cache.as_ref() {
                if !cached.is_expired() {
                    return Ok(());
                }
            }
        }

        // Register a notify subscription BEFORE we check the throttle gate,
        // so a `notify_waiters()` from the winner can't slip between our
        // "still throttled, empty cache" check and our `.notified().await`.
        // `Notify::notified()` holds the permit slot the moment it's
        // constructed; only `.await` blocks.
        let notified = BOOTSTRAP_LOAD_NOTIFY.notified();
        tokio::pin!(notified);

        // Throttle refresh attempts. If another caller tried very recently,
        // either return stale data we already have, or wait for their load
        // to complete rather than erroring with "throttled and no cache".
        {
            let last = BOOTSTRAP_LAST_ATTEMPT.read().await;
            if let Some(ts) = *last {
                if ts.elapsed() < BOOTSTRAP_REFRESH_MIN_INTERVAL {
                    // Another caller attempted a refresh very recently.
                    let cache = BOOTSTRAP_CACHE.read().await;
                    if cache.is_some() {
                        // We have some data (possibly stale) — accept it.
                        return Ok(());
                    }
                    // Cache is empty AND another task is mid-load (or just
                    // failed). Wait for an in-flight load instead of
                    // returning an error; a load that already failed yields
                    // the throttle error without waiting.
                    drop(cache);
                    drop(last);
                    return wait_for_in_flight_load(notified).await;
                }
            }
        }

        // Record the attempt timestamp before we begin the network load, and
        // mark the load in flight inside the same critical section: a loser
        // that observes the fresh timestamp is then guaranteed to observe the
        // in-flight flag too (see `wait_for_in_flight_load`).
        let load_guard = {
            let mut last = BOOTSTRAP_LAST_ATTEMPT.write().await;
            // Double-check in case another task just updated it.
            if let Some(ts) = *last {
                if ts.elapsed() < BOOTSTRAP_REFRESH_MIN_INTERVAL {
                    drop(last);
                    let cache = BOOTSTRAP_CACHE.read().await;
                    if cache.is_some() {
                        return Ok(());
                    }
                    drop(cache);
                    return wait_for_in_flight_load(notified).await;
                }
            }
            *last = Some(Instant::now());
            BootstrapLoadGuard::start()
        };

        // Perform the actual load WITHOUT holding any cache lock. Whichever
        // branch exits (or if this future is dropped mid-load), dropping
        // `load_guard` clears the in-flight flag and notifies waiters so
        // losers don't hang for the full bounded timeout.
        debug!("Loading/refreshing RDAP bootstrap data");
        let load_result = load_bootstrap_data_with_retry(&self.retry_policy).await;

        let outcome = match load_result {
            Ok(load) => {
                // Merges per registry over any previous (stale) data, and
                // skips the store if another task loaded fresh data while we
                // ran.
                let mut cache = BOOTSTRAP_CACHE.write().await;
                store_bootstrap_load(&mut cache, load);
                Ok(())
            }
            Err(e) => {
                // Stale-while-revalidate: keep using any existing stale cache.
                let cache = BOOTSTRAP_CACHE.read().await;
                if let Some(cached) = cache.as_ref() {
                    debug!(
                        error = %e,
                        age_hours = cached.age().as_secs() / 3600,
                        "Bootstrap refresh failed, using stale data"
                    );
                    Ok(())
                } else {
                    // No stale data available.
                    Err(e)
                }
            }
        };

        // Clear the in-flight flag and wake any losers waiting on our load
        // (after the cache write above, so they observe its result).
        drop(load_guard);
        outcome
    }

    /// Looks up the candidate RDAP base URLs for a domain's TLD.
    fn get_rdap_urls_for_domain(cache: &BootstrapData, domain: &str) -> Option<Arc<Vec<url::Url>>> {
        let tld = domain.rsplit('.').next()?;
        cache.dns.get(&tld.to_lowercase()).cloned()
    }

    /// Looks up the candidate RDAP base URLs for an IP address.
    fn get_rdap_urls_for_ip(cache: &BootstrapData, ip: IpAddr) -> Option<Arc<Vec<url::Url>>> {
        let ranges = match ip {
            IpAddr::V4(_) => &cache.ipv4,
            IpAddr::V6(_) => &cache.ipv6,
        };
        ranges
            .iter()
            .find(|(range, _)| ip_matches_prefix(&range.prefix, ip))
            .map(|(_, urls)| Arc::clone(urls))
    }

    /// Looks up the candidate RDAP base URLs for an ASN.
    fn get_rdap_urls_for_asn(cache: &BootstrapData, asn: u32) -> Option<Arc<Vec<url::Url>>> {
        cache
            .asn
            .iter()
            .find(|(range, _)| (range.start..=range.end).contains(&asn))
            .map(|(_, urls)| Arc::clone(urls))
    }

    /// Resolves the candidate query URLs for one lookup: `pick` selects the
    /// base URLs from the loaded bootstrap (`what` names the query in the
    /// "no RDAP server" error) and each is joined with `path`. The cache lock
    /// is released on return, before any HTTP request.
    async fn candidate_urls(
        pick: impl FnOnce(&BootstrapData) -> Option<Arc<Vec<url::Url>>>,
        what: &str,
        path: &str,
    ) -> Result<Vec<url::Url>> {
        let cache_guard = BOOTSTRAP_CACHE.read().await;
        let cache = cache_guard.as_ref().ok_or_else(|| {
            SeerError::RdapBootstrapError("bootstrap data not loaded".to_string())
        })?;
        let bases = pick(&cache.data)
            .ok_or_else(|| SeerError::RdapBootstrapError(format!("no RDAP server for {}", what)))?;
        Ok(build_rdap_urls(&bases, path))
    }

    /// Looks up RDAP registration data for a domain.
    ///
    /// Uses IANA bootstrap data to find the appropriate RDAP server for the TLD.
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn lookup_domain(&self, domain: &str) -> Result<RdapResponse> {
        self.ensure_bootstrap().await?;

        let domain = normalize_domain(domain)?;
        let urls = Self::candidate_urls(
            |data| Self::get_rdap_urls_for_domain(data, &domain),
            &domain,
            &format!("domain/{}", domain),
        )
        .await?;
        self.query_rdap_urls(&urls).await
    }

    /// Looks up RDAP registration data for an IP address.
    ///
    /// Uses IANA bootstrap data to find the appropriate RIR (Regional Internet Registry).
    #[instrument(skip(self), fields(ip = %ip))]
    pub async fn lookup_ip(&self, ip: &str) -> Result<RdapResponse> {
        self.ensure_bootstrap().await?;

        let ip_addr: IpAddr = ip
            .parse()
            .map_err(|_| SeerError::InvalidIpAddress(ip.to_string()))?;
        let urls = Self::candidate_urls(
            |data| Self::get_rdap_urls_for_ip(data, ip_addr),
            ip,
            &format!("ip/{}", ip),
        )
        .await?;
        self.query_rdap_urls(&urls).await
    }

    /// Looks up RDAP registration data for an Autonomous System Number (ASN).
    ///
    /// Uses IANA bootstrap data to find the appropriate RIR for the ASN range.
    #[instrument(skip(self), fields(asn = %asn))]
    pub async fn lookup_asn(&self, asn: u32) -> Result<RdapResponse> {
        self.ensure_bootstrap().await?;
        let urls = Self::candidate_urls(
            |data| Self::get_rdap_urls_for_asn(data, asn),
            &format!("AS{}", asn),
            &format!("autnum/{}", asn),
        )
        .await?;
        self.query_rdap_urls(&urls).await
    }

    /// Returns the RDAP base URL for a given TLD, if known from bootstrap data.
    ///
    /// Loads bootstrap data if not already cached. Returns `None` if the TLD
    /// has no registered RDAP server in the IANA bootstrap registry. When
    /// IANA lists multiple URLs for a TLD, the first one is returned.
    #[instrument(skip(self), fields(tld = %tld))]
    pub async fn get_rdap_base_url_for_tld(&self, tld: &str) -> Option<String> {
        if self.ensure_bootstrap().await.is_err() {
            return None;
        }

        let cache_guard = BOOTSTRAP_CACHE.read().await;
        let cache = cache_guard.as_ref()?;
        // IANA bootstrap keys are A-labels (punycode); convert a Unicode TLD
        // (e.g. "рф" -> "xn--p1ai") so it matches. ASCII TLDs are unchanged;
        // an un-convertible value falls back to the lowercased input.
        let lower = tld.to_lowercase();
        let key = crate::validation::domain_to_ascii(&lower).unwrap_or(lower);
        cache
            .data
            .dns
            .get(&key)
            .and_then(|urls| urls.first())
            .map(|u| u.to_string())
    }

    /// Queries a list of candidate RDAP URLs in order, returning the first
    /// successful response. Each URL is attempted with the full retry policy.
    /// If all candidates fail, the last error is returned wrapped with context.
    async fn query_rdap_urls(&self, urls: &[url::Url]) -> Result<RdapResponse> {
        if urls.is_empty() {
            return Err(SeerError::RdapError(
                "no candidate RDAP URLs available".to_string(),
            ));
        }

        let mut last_error: Option<SeerError> = None;
        // A definitive 404 from any candidate is the strongest available-ness
        // signal there is. Preserve the first one we see so a later candidate's
        // non-404 failure (timeout/5xx/conn) can't bury it — otherwise
        // `rdap_error_is_404` would return false and a genuinely available
        // domain would be misreported as inconclusive.
        let mut not_found_error: Option<SeerError> = None;
        for (idx, url) in urls.iter().enumerate() {
            let url_str = url.as_str().to_string();
            debug!(url = %url_str, candidate = idx + 1, total = urls.len(), "Querying RDAP");
            match self.query_rdap_with_retry(&url_str).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    if urls.len() > 1 {
                        debug!(
                            url = %url_str,
                            error = %e,
                            candidate = idx + 1,
                            total = urls.len(),
                            "RDAP candidate failed, trying next",
                        );
                    }
                    if not_found_error.is_none() && crate::rdap::rdap_error_is_404(&e) {
                        not_found_error = Some(e);
                    } else {
                        last_error = Some(e);
                    }
                }
            }
        }

        // All candidates failed. Prefer a preserved 404 over a later non-404
        // failure so the authoritative not-found signal reaches the caller.
        Err(wrap_all_candidates_failed(
            not_found_error.or(last_error),
            urls.len(),
        ))
    }

    /// Queries a single RDAP endpoint, retrying transient failures. Unlike the
    /// generic `RetryExecutor`, this honors a `Retry-After` header on HTTP 429
    /// responses — registries rate-limit aggressively, and the server-suggested
    /// delay clears the limit far more reliably than blind exponential backoff.
    async fn query_rdap_with_retry(&self, url: &str) -> Result<RdapResponse> {
        let classifier = NetworkRetryClassifier::new();
        let mut attempt = 0;
        loop {
            match query_rdap_attempt(url, self.timeout, self.allow_reserved).await {
                Ok(resp) => return Ok(resp),
                Err((err, retry_after)) => {
                    let attempts_remaining =
                        self.retry_policy.max_attempts.saturating_sub(attempt + 1);
                    if !classifier.is_retryable(&err) || attempts_remaining == 0 {
                        return Err(if attempt > 0 {
                            SeerError::RetryExhausted {
                                attempts: attempt + 1,
                                last_error: Box::new(err),
                            }
                        } else {
                            err
                        });
                    }
                    let backoff = self.retry_policy.delay_for_attempt(attempt);
                    let delay = effective_retry_delay(backoff, retry_after);
                    debug!(
                        url = %url,
                        attempt = attempt + 1,
                        max_attempts = self.retry_policy.max_attempts,
                        delay_ms = delay.as_millis(),
                        error = %err,
                        "Retrying RDAP after transient error"
                    );
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
            }
        }
    }
}

/// Maximum RDAP response body size (10 MB, matching CT log response limit).
const MAX_RDAP_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

/// Cap on how long we'll honor a server-supplied `Retry-After`. Real RDAP
/// 429s ask for a second or two; anything larger we treat as "give up and
/// fall back to WHOIS/DNS" rather than hang an interactive lookup — and the
/// cap also stops a hostile/misconfigured header from pinning the client.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(5);

/// Parses an RDAP URL and enforces the https-only scheme, returning the
/// (unbracketed) host and effective port.
///
/// Defense-in-depth: RDAP is HTTPS-only. The scheme is enforced here — on
/// every request, pinned-client cache hit or miss — so the guard does not
/// silently depend on the bootstrap's parse-time check. A plaintext `http://`
/// (downgrade) or any non-https URL — including a server-supplied link or
/// redirect target ever fed in — must never be fetched, even when the host
/// resolves to a public address.
fn parse_rdap_url(url: &str) -> Result<(String, u16)> {
    let parsed = url::Url::parse(url)
        .map_err(|e| SeerError::RdapError(format!("invalid URL '{}': {}", url, e)))?;
    if parsed.scheme() != "https" {
        return Err(SeerError::RdapError(format!(
            "RDAP URL '{}' is not https — request blocked (downgrade/SSRF protection)",
            url
        )));
    }
    // Use `host()` (not `host_str()`) so an IPv6 literal comes back
    // unbracketed and hits the shared guard's IP-literal short-circuit.
    let host = match parsed.host() {
        Some(url::Host::Domain(d)) => d.to_string(),
        Some(url::Host::Ipv4(ip)) => ip.to_string(),
        Some(url::Host::Ipv6(ip)) => ip.to_string(),
        None => return Err(SeerError::RdapError(format!("URL '{}' has no host", url))),
    };
    let port = parsed.port_or_known_default().unwrap_or(443);
    Ok((host, port))
}

/// Resolves an RDAP host through the shared SSRF guard
/// ([`crate::net::resolve_public_host`]), mapping failures into the RDAP
/// error domain.
///
/// The shared guard bounds the OS-resolver lookup (`getaddrinfo` has no
/// deadline, so a black-holed hostname could otherwise pin a worker thread)
/// and falls back to hickory when the system resolver is broken — the same
/// envelope as every other outbound leg. The reserved-range policy is
/// unchanged (the previous local check delegated to the same
/// `net::is_reserved_ip`), and the guard's error deliberately omits the
/// resolved IP (internal-DNS-oracle hardening, issue #49).
async fn resolve_rdap_host(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    crate::net::resolve_public_host(host, port)
        .await
        .map_err(|e| SeerError::RdapError(format!("{} — request blocked (SSRF protection)", e)))
}

/// Validates that a URL is https and does not resolve to a reserved/private IP
/// address (SSRF protection). Test-only composition of the two production
/// pieces: [`send_rdap_request`] runs [`parse_rdap_url`] on every request and
/// [`resolve_rdap_host`] on pinned-client cache misses.
#[cfg(test)]
async fn validate_url_not_reserved(url: &str) -> Result<Vec<SocketAddr>> {
    let (host, port) = parse_rdap_url(url)?;
    resolve_rdap_host(&host, port).await
}

/// Parses an HTTP `Retry-After` header value. Supports the common
/// delta-seconds form (`Retry-After: 5`); the HTTP-date form is not used by
/// RDAP rate limiters in practice and yields `None` (caller falls back to
/// exponential backoff).
fn parse_retry_after(value: &str) -> Option<Duration> {
    value.trim().parse::<u64>().ok().map(Duration::from_secs)
}

/// Chooses the delay before the next RDAP attempt: honor the server's
/// `Retry-After` (capped at [`MAX_RETRY_AFTER`]) when present, otherwise use
/// the policy's exponential backoff.
fn effective_retry_delay(backoff: Duration, retry_after: Option<Duration>) -> Duration {
    match retry_after {
        Some(hint) => hint.min(MAX_RETRY_AFTER),
        None => backoff,
    }
}

/// TTL for cached pinned RDAP clients. Short by design: on expiry the next
/// request re-runs the full SSRF validation (fresh DNS + reserved-range
/// check), so pinned addresses are re-checked against rebinding at most a
/// minute apart, while bulk lookups, confusables scans, and per-query retries
/// inside the window reuse one connection pool instead of paying DNS + TCP +
/// TLS handshake per attempt.
const PINNED_CLIENT_TTL: Duration = Duration::from_secs(60);

/// Cache key for pinned RDAP clients: (host, port, request timeout). The
/// timeout is part of the key because it is baked into the built
/// `reqwest::Client` — two `RdapClient`s configured with different timeouts
/// must not share one pinned client.
type PinnedClientKey = (String, u16, Duration);

/// Pinned per-host RDAP clients. `reqwest::Client` is Arc-backed, so cloning
/// out of the cache shares the underlying connection pool. Entries are only
/// ever inserted after full SSRF validation ([`validate_url_not_reserved`]);
/// the loopback requests the `#[cfg(test)]` allow-reserved mode exempts
/// bypass this cache in both directions (never insert, never read).
/// Capacity-bounded: evicting
/// a live entry merely forces a re-validate + rebuild on next use.
static PINNED_CLIENT_CACHE: LazyLock<crate::cache::TtlCache<PinnedClientKey, Client>> =
    LazyLock::new(|| crate::cache::TtlCache::with_max_capacity(PINNED_CLIENT_TTL, 64));

/// Sends one RDAP request: SSRF-validates the URL and pins the resolved IPs on
/// a cached per-host client (DNS-rebinding defense), returning the raw response.
///
/// The pinned client is cached for [`PINNED_CLIENT_TTL`] keyed by
/// (host, port, timeout), so repeated queries — and retry attempts within one
/// query — skip the DNS lookup and client build. The cheap URL-shape checks
/// (parse + https enforcement) still run on every request: keying on host:port
/// alone would otherwise let a cached https entry serve a plaintext `http://`
/// URL aimed at the same port.
///
/// `allow_reserved` (test seam, see [`RdapClient::allow_reserved`]) skips the
/// validation and IP pinning for **loopback** URLs only, so `#[cfg(test)]`
/// mock servers are reachable; any other URL (e.g. a redirect target a test
/// scripts) still runs the full production guard. Always false on
/// production paths.
async fn send_rdap_request(
    url: &str,
    timeout: Duration,
    allow_reserved: bool,
) -> Result<reqwest::Response> {
    // Keep the connect timeout no larger than the overall request timeout so a
    // sub-5s configured timeout stays internally consistent.
    let connect_timeout = CONNECT_TIMEOUT.min(timeout);
    if allow_reserved && is_loopback_url(url) {
        // Test seam: build a one-off unpinned client and never touch the
        // shared pinned-client cache — a test-mode client reaching loopback
        // must not be servable to a production request (nor vice versa).
        let client = Client::builder()
            .timeout(timeout)
            .connect_timeout(connect_timeout)
            .user_agent("Seer/1.0 (RDAP Client)")
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| SeerError::RdapError(format!("failed to build HTTP client: {}", e)))?;
        return client
            .get(url)
            .header(reqwest::header::ACCEPT, RDAP_ACCEPT)
            .send()
            .await
            .map_err(Into::into);
    }

    // Always-on URL-shape checks (parse + https-only enforcement).
    let (host, port) = parse_rdap_url(url)?;

    let key = (host.clone(), port, timeout);
    let client = match PINNED_CLIENT_CACHE.get(&key) {
        Some(client) => client,
        None => {
            // SSRF protection: validate the URL does not resolve to reserved
            // IPs and capture the resolved SocketAddrs so we can pin them on
            // the HTTP client. If the host is an IP literal the resolved vec
            // already holds it, so `resolve_to_addrs` is still correct.
            let resolved = resolve_rdap_host(&host, port).await?;
            let client = Client::builder()
                .timeout(timeout)
                .connect_timeout(connect_timeout)
                .user_agent("Seer/1.0 (RDAP Client)")
                .resolve_to_addrs(&host, &resolved)
                // SSRF defense: `resolve_to_addrs` pins only THIS host's validated IPs.
                // reqwest's own policy would follow redirects re-resolving each new
                // host with its own resolver — so a 3xx to http://169.254.169.254 (or
                // any internal host) would bypass the reserved-IP guard entirely.
                // Redirects are instead followed manually by `query_rdap_attempt`,
                // one hop at a time, each hop re-entering this function and so
                // re-running the https check, SSRF validation, and pinning.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|e| SeerError::RdapError(format!("failed to build HTTP client: {}", e)))?;
            PINNED_CLIENT_CACHE.insert(key.clone(), client.clone());
            client
        }
    };

    match client
        .get(url)
        .header(reqwest::header::ACCEPT, RDAP_ACCEPT)
        .send()
        .await
    {
        Ok(resp) => Ok(resp),
        Err(e) => {
            // A connect-level failure may mean the pinned addresses went
            // stale (host re-IP'd inside the TTL). Evict so the next attempt
            // re-resolves instead of failing on the same dead pin for the
            // rest of the window.
            if e.is_connect() {
                PINNED_CLIENT_CACHE.remove(&key);
            }
            Err(e.into())
        }
    }
}

/// Streams, size-bounds, and parses an RDAP response body. `url` is only used
/// for the timeout error message. `timeout` is the per-request deadline for the
/// body-read phase, so a caller-configured timeout is honored end-to-end (not
/// silently capped at the hardcoded default).
async fn read_and_parse_rdap_body(
    response: reqwest::Response,
    url: &str,
    timeout: Duration,
) -> Result<RdapResponse> {
    // Stream body with incremental size check to prevent memory exhaustion.
    // A server that opens the connection but trickles bytes forever is
    // classified as a timeout (not a generic RdapError) so retries can be
    // driven appropriately.
    let body = read_body_capped(response, MAX_RDAP_RESPONSE_SIZE, timeout, Overflow::Reject)
        .await
        .map_err(|e| match e {
            BodyReadError::Chunk(e) => {
                SeerError::RdapError(format!("failed to read response: {}", e))
            }
            BodyReadError::TooLarge => SeerError::RdapError(format!(
                "RDAP response exceeds {} byte limit",
                MAX_RDAP_RESPONSE_SIZE
            )),
            BodyReadError::TimedOut => SeerError::Timeout(format!(
                "timed out reading RDAP response body from {} after {:?}",
                url, timeout
            )),
        })?;

    let rdap: RdapResponse = serde_json::from_slice(&body)?;
    // Bound attacker-controlled payload post-deserialization. The 10MB
    // body cap prevents unbounded download, but a well-formed response
    // can still pack millions of keys or deeply-nested values into the
    // serde_json::Map, and adversarial `entities` nesting can drive
    // recursive walkers to stack-overflow. See RdapResponse::validate.
    rdap.validate()?;
    Ok(rdap)
}

/// Whether `url` targets a loopback IP literal — the only hosts the
/// `#[cfg(test)]` allow-reserved seam may reach unvalidated.
fn is_loopback_url(url: &str) -> bool {
    match url::Url::parse(url).ok().as_ref().and_then(url::Url::host) {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    }
}

/// Returns the `Location` of a redirect response RDAP clients follow
/// (301/302/303/307/308), or `None` for any other status (including a
/// redirect status without a usable `Location`, which then fails as an
/// ordinary non-success status).
fn redirect_location(response: &reqwest::Response) -> Option<&str> {
    match response.status().as_u16() {
        301 | 302 | 303 | 307 | 308 => response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        _ => None,
    }
}

/// Resolves a redirect `Location` (absolute or relative) against the URL
/// that returned it. The target is NOT trusted here: the next hop goes back
/// through [`send_rdap_request`], which enforces https and runs the SSRF
/// validation + pinning for the new host.
fn resolve_redirect_target(current: &str, location: &str) -> Result<String> {
    url::Url::parse(current)
        .and_then(|base| base.join(location))
        .map(String::from)
        .map_err(|e| SeerError::RdapError(format!("invalid RDAP redirect target: {}", e)))
}

/// One RDAP attempt. On failure, returns the error together with an optional
/// server-suggested retry delay parsed from a 429 `Retry-After` header so the
/// caller's backoff can honor it. Uses a cached per-host HTTP client that pins
/// the validated resolved IPs to prevent DNS rebinding (TOCTOU between
/// validation and connect); see [`send_rdap_request`].
///
/// Redirects (RFC 7480 §5.2 — e.g. ARIN 303 → RIPE for an address it doesn't
/// hold) are followed manually for up to [`MAX_RDAP_REDIRECTS`] hops. Each
/// hop re-enters `send_rdap_request`, so an http:// (downgrade) or
/// reserved/internal target is refused exactly like a bootstrap URL would
/// be; a URL seen twice aborts the chain as a loop.
async fn query_rdap_attempt(
    url: &str,
    timeout: Duration,
    allow_reserved: bool,
) -> std::result::Result<RdapResponse, (SeerError, Option<Duration>)> {
    let mut current = url.to_string();
    let mut visited: HashSet<String> = HashSet::new();
    let response = loop {
        visited.insert(current.clone());
        let response = send_rdap_request(&current, timeout, allow_reserved)
            .await
            .map_err(|e| (e, None))?;
        let Some(location) = redirect_location(&response) else {
            break response;
        };
        if visited.len() > MAX_RDAP_REDIRECTS {
            return Err((
                SeerError::RdapError(format!(
                    "RDAP query exceeded {} redirects",
                    MAX_RDAP_REDIRECTS
                )),
                None,
            ));
        }
        let next = resolve_redirect_target(&current, location).map_err(|e| (e, None))?;
        if visited.contains(&next) {
            return Err((
                SeerError::RdapError("RDAP redirect loop detected".to_string()),
                None,
            ));
        }
        debug!(from = %current, to = %next, "Following RDAP redirect");
        current = next;
    };

    if !response.status().is_success() {
        let status = response.status();
        // A 429 may carry a `Retry-After`; surface it so the retry loop can
        // wait exactly as long as the registry asks instead of guessing.
        let retry_after = if status.as_u16() == 429 {
            response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(parse_retry_after)
        } else {
            None
        };
        return Err((
            SeerError::RdapError(format!("query failed with status {}", status)),
            retry_after,
        ));
    }

    read_and_parse_rdap_body(response, &current, timeout)
        .await
        .map_err(|e| (e, None))
}

/// Loads IANA RDAP bootstrap data from all registries with retry. Only a
/// load where *every* registry failed is an error (and is retryable); a
/// partial load succeeds and is merged by [`store_bootstrap_load`].
async fn load_bootstrap_data_with_retry(policy: &RetryPolicy) -> Result<BootstrapLoad> {
    let executor = RetryExecutor::new(policy.clone());
    executor.execute(load_bootstrap_data).await
}

/// Loads IANA RDAP bootstrap data from all registries. Each section of the
/// returned [`BootstrapLoad`] is `None` when that registry failed.
async fn load_bootstrap_data() -> Result<BootstrapLoad> {
    debug!("Loading RDAP bootstrap data from IANA");

    // SSRF validation is skipped here — these are hardcoded IANA URLs, not user input.
    // User-supplied URLs are still validated in send_rdap_request() via
    // validate_url_not_reserved() (which also enforces the https scheme).

    let http = rdap_http_client()?;

    let dns_future = http.get(IANA_BOOTSTRAP_DNS).send();
    let ipv4_future = http.get(IANA_BOOTSTRAP_IPV4).send();
    let ipv6_future = http.get(IANA_BOOTSTRAP_IPV6).send();
    let asn_future = http.get(IANA_BOOTSTRAP_ASN).send();

    // Use join! instead of try_join! so one slow/failing registry doesn't
    // block the others. We load whatever data is available.
    let (dns_resp, ipv4_resp, ipv6_resp, asn_resp) =
        tokio::join!(dns_future, ipv4_future, ipv6_future, asn_future);

    // Stream body with incremental size check to prevent memory exhaustion
    const MAX_BOOTSTRAP_SIZE: usize = 10 * 1024 * 1024; // 10 MB

    async fn read_bootstrap(resp: reqwest::Response) -> Result<BootstrapResponse> {
        // Bound the streaming read with the same timeout used for RDAP
        // queries. Without this, a slow or stalled IANA response (open TCP
        // but no bytes arriving) could hang all RDAP lookups indefinitely
        // because `ensure_bootstrap` awaits this future.
        let body = read_body_capped(resp, MAX_BOOTSTRAP_SIZE, DEFAULT_TIMEOUT, Overflow::Reject)
            .await
            .map_err(|e| match e {
                BodyReadError::Chunk(e) => {
                    SeerError::RdapBootstrapError(format!("failed to read body: {}", e))
                }
                BodyReadError::TooLarge => SeerError::RdapBootstrapError(format!(
                    "bootstrap response too large (exceeds {} bytes)",
                    MAX_BOOTSTRAP_SIZE
                )),
                BodyReadError::TimedOut => SeerError::Timeout(format!(
                    "RDAP bootstrap body read timed out after {:?}",
                    DEFAULT_TIMEOUT
                )),
            })?;

        serde_json::from_slice(&body).map_err(Into::into)
    }

    // Parse each response independently, logging failures
    let dns_data = match dns_resp {
        Ok(resp) => match read_bootstrap(resp).await {
            Ok(data) => Some(data),
            Err(e) => {
                warn!(error = %e, "Failed to parse DNS bootstrap response");
                None
            }
        },
        Err(e) => {
            warn!(error = %e, "Failed to fetch DNS bootstrap from IANA");
            None
        }
    };
    let ipv4_data = match ipv4_resp {
        Ok(resp) => match read_bootstrap(resp).await {
            Ok(data) => Some(data),
            Err(e) => {
                warn!(error = %e, "Failed to parse IPv4 bootstrap response");
                None
            }
        },
        Err(e) => {
            warn!(error = %e, "Failed to fetch IPv4 bootstrap from IANA");
            None
        }
    };
    let ipv6_data = match ipv6_resp {
        Ok(resp) => match read_bootstrap(resp).await {
            Ok(data) => Some(data),
            Err(e) => {
                warn!(error = %e, "Failed to parse IPv6 bootstrap response");
                None
            }
        },
        Err(e) => {
            warn!(error = %e, "Failed to fetch IPv6 bootstrap from IANA");
            None
        }
    };
    let asn_data = match asn_resp {
        Ok(resp) => match read_bootstrap(resp).await {
            Ok(data) => Some(data),
            Err(e) => {
                warn!(error = %e, "Failed to parse ASN bootstrap response");
                None
            }
        },
        Err(e) => {
            warn!(error = %e, "Failed to fetch ASN bootstrap from IANA");
            None
        }
    };

    // Helper: extract and validate all URLs in order, preserving IANA-listed
    // ordering. Invalid URLs are logged and skipped rather than rejecting the
    // entire service entry. Returns None when no valid URLs remain.
    fn collect_valid_urls(urls: &[serde_json::Value]) -> Option<Arc<Vec<url::Url>>> {
        let mut out = Vec::new();
        for u in urls {
            if let Some(s) = u.as_str() {
                match validate_bootstrap_url(s) {
                    Ok(parsed) => out.push(parsed),
                    Err(e) => {
                        debug!(url = s, error = %e, "Skipping invalid bootstrap URL");
                    }
                }
            }
        }
        if out.is_empty() {
            None
        } else {
            Some(Arc::new(out))
        }
    }

    // Helper: parse an IPv4/IPv6 prefix registry into (prefix, urls) pairs.
    fn parse_prefix_services(data: BootstrapResponse) -> Vec<(IpRange, Arc<Vec<url::Url>>)> {
        let mut out = Vec::new();
        for service in data.services {
            if service.len() >= 2 {
                if let (Some(prefixes), Some(urls)) = (service[0].as_array(), service[1].as_array())
                {
                    if let Some(urls_arc) = collect_valid_urls(urls) {
                        for prefix in prefixes {
                            if let Some(prefix_str) = prefix.as_str() {
                                out.push((
                                    IpRange {
                                        prefix: prefix_str.to_string(),
                                    },
                                    Arc::clone(&urls_arc),
                                ));
                            }
                        }
                    }
                }
            }
        }
        out
    }

    // Each section below is `None` when its registry failed. A section that
    // fetched but parsed to nothing is treated the same way, so a truncated
    // or empty file is retried rather than cached over good data.

    // Parse DNS bootstrap
    let dns = dns_data
        .map(|data| {
            let mut dns = HashMap::new();
            for service in data.services {
                if service.len() >= 2 {
                    if let (Some(tlds), Some(urls)) = (service[0].as_array(), service[1].as_array())
                    {
                        if let Some(urls_arc) = collect_valid_urls(urls) {
                            for tld in tlds {
                                if let Some(tld_str) = tld.as_str() {
                                    dns.insert(tld_str.to_lowercase(), Arc::clone(&urls_arc));
                                }
                            }
                        }
                    }
                }
            }
            dns
        })
        .filter(|dns| !dns.is_empty());

    // Parse IPv4 / IPv6 bootstrap
    let ipv4 = ipv4_data
        .map(parse_prefix_services)
        .filter(|v| !v.is_empty());
    let ipv6 = ipv6_data
        .map(parse_prefix_services)
        .filter(|v| !v.is_empty());

    // Parse ASN bootstrap
    let asn = asn_data
        .map(|data| {
            let mut asn = Vec::new();
            for service in data.services {
                if service.len() >= 2 {
                    if let (Some(ranges), Some(urls)) =
                        (service[0].as_array(), service[1].as_array())
                    {
                        if let Some(urls_arc) = collect_valid_urls(urls) {
                            for range in ranges {
                                if let Some(range_str) = range.as_str() {
                                    if let Some((start, end)) = parse_asn_range(range_str) {
                                        asn.push((AsnRange { start, end }, Arc::clone(&urls_arc)));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            asn
        })
        .filter(|v| !v.is_empty());

    // If ALL four registries failed, that's a real error. The message is
    // matched by `NetworkRetryClassifier` as transient, so the retry policy
    // gets another go at IANA.
    if dns.is_none() && ipv4.is_none() && ipv6.is_none() && asn.is_none() {
        return Err(SeerError::RdapBootstrapError(
            "all IANA bootstrap registries failed".to_string(),
        ));
    }

    info!(
        dns_entries = dns.as_ref().map_or(0, HashMap::len),
        ipv4_ranges = ipv4.as_ref().map_or(0, Vec::len),
        ipv6_ranges = ipv6.as_ref().map_or(0, Vec::len),
        asn_ranges = asn.as_ref().map_or(0, Vec::len),
        "RDAP bootstrap loaded"
    );

    Ok(BootstrapLoad {
        dns,
        ipv4,
        ipv6,
        asn,
    })
}

/// Wraps the "all N candidate URLs failed" case for `query_rdap_urls`.
///
/// Preserves the `SeerError::Timeout` variant when the last failure was a
/// timeout, so upstream callers that branch on `Timeout` for retry-or-not
/// decisions can still do so. Non-timeout failures are wrapped in a generic
/// `RdapError` with the last error's Display in the message. The
/// single-candidate case returns the last error unchanged to avoid
/// double-wrapping.
fn wrap_all_candidates_failed(last_error: Option<SeerError>, candidate_count: usize) -> SeerError {
    let last = last_error.unwrap_or_else(|| SeerError::RdapError("no candidates".to_string()));

    if candidate_count <= 1 {
        return last;
    }

    match last {
        SeerError::Timeout(msg) => SeerError::Timeout(format!(
            "all {} RDAP candidate URLs timed out; last error: {}",
            candidate_count, msg
        )),
        other => SeerError::RdapError(format!(
            "all {} RDAP candidate URLs failed; last error: {}",
            candidate_count, other
        )),
    }
}

/// Builds full RDAP query URLs for each candidate base URL, preserving order.
fn build_rdap_urls(bases: &[url::Url], path: &str) -> Vec<url::Url> {
    bases
        .iter()
        .filter_map(|base| {
            // Ensure the base URL ends with `/` before joining so the path is
            // appended (not replacing the final path segment).
            let base_str = base.as_str();
            let normalized = if base_str.ends_with('/') {
                base_str.to_string()
            } else {
                format!("{}/", base_str)
            };
            url::Url::parse(&normalized).and_then(|u| u.join(path)).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_config_applies_rdap_timeout() {
        let mut config = crate::config::SeerConfig::default();
        config.timeouts.rdap_secs = 33;
        let client = RdapClient::from_config(&config);
        assert_eq!(client.timeout, Duration::from_secs(33));
    }

    #[test]
    fn test_default_client_has_retry_policy() {
        let client = RdapClient::new();
        // Tuned up from 2 so 429 rate limits get a couple of backoff-and-retry
        // chances, but kept small so a sticky limit falls through to the
        // WHOIS/DNS fallback fast instead of hanging.
        assert_eq!(client.retry_policy.max_attempts, 3);
    }

    // --- Retry-After parsing / delay selection (Fix #1) ------------------

    #[test]
    fn parse_retry_after_parses_delta_seconds() {
        assert_eq!(parse_retry_after("5"), Some(Duration::from_secs(5)));
        assert_eq!(parse_retry_after("  10 "), Some(Duration::from_secs(10)));
        assert_eq!(parse_retry_after("0"), Some(Duration::from_secs(0)));
    }

    #[test]
    fn parse_retry_after_rejects_http_date_and_junk() {
        // Only the delta-seconds form is supported; an HTTP-date or garbage
        // value yields None (caller falls back to exponential backoff).
        assert_eq!(parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT"), None);
        assert_eq!(parse_retry_after("soon"), None);
        assert_eq!(parse_retry_after(""), None);
    }

    #[test]
    fn effective_retry_delay_prefers_capped_retry_after() {
        // Honors the server hint when present.
        assert_eq!(
            effective_retry_delay(Duration::from_millis(100), Some(Duration::from_secs(5))),
            Duration::from_secs(5)
        );
        // Caps an excessive hint at MAX_RETRY_AFTER so a bad header can't pin us.
        assert_eq!(
            effective_retry_delay(Duration::from_millis(100), Some(Duration::from_secs(600))),
            MAX_RETRY_AFTER
        );
    }

    #[test]
    fn effective_retry_delay_falls_back_to_backoff() {
        assert_eq!(
            effective_retry_delay(Duration::from_millis(250), None),
            Duration::from_millis(250)
        );
    }

    #[test]
    fn test_client_without_retries() {
        let client = RdapClient::new().without_retries();
        assert_eq!(client.retry_policy.max_attempts, 1);
    }

    #[test]
    fn test_client_custom_retry_policy() {
        let policy = RetryPolicy::new().with_max_attempts(5);
        let client = RdapClient::new().with_retry_policy(policy);
        assert_eq!(client.retry_policy.max_attempts, 5);
    }

    #[test]
    fn test_cached_bootstrap_expiration() {
        let data = BootstrapData {
            dns: HashMap::new(),
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            asn: Vec::new(),
        };
        let cached = CachedBootstrap::new(data);
        // Fresh cache should not be expired
        assert!(!cached.is_expired());
    }

    #[test]
    fn test_rdap_http_client_is_configured() {
        // Force lazy initialization and verify it doesn't panic; the real
        // reqwest builder is expected to succeed in any normal environment.
        let client = rdap_http_client();
        assert!(client.is_ok(), "RDAP HTTP client builder must succeed");
    }

    #[test]
    fn test_parse_bootstrap_empty_services() {
        // Verifies that parsing empty bootstrap data doesn't panic
        let data = BootstrapData {
            dns: HashMap::new(),
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            asn: Vec::new(),
        };
        // Should return None for any lookup on empty data
        assert!(RdapClient::get_rdap_urls_for_domain(&data, "example.com").is_none());
        assert!(RdapClient::get_rdap_urls_for_asn(&data, 12345).is_none());
    }

    // --- validate_url_not_reserved tests (C1 regression) ----------------

    #[tokio::test]
    async fn test_validate_url_not_reserved_rejects_loopback_literal() {
        let err = validate_url_not_reserved("https://127.0.0.1/domain/example.com")
            .await
            .unwrap_err();
        assert!(
            matches!(err, SeerError::RdapError(ref s) if s.contains("reserved")),
            "expected reserved-IP error, got: {:?}",
            err
        );
    }

    #[tokio::test]
    async fn test_validate_url_not_reserved_rejects_private_ipv4_literal() {
        let err = validate_url_not_reserved("https://10.0.0.1/")
            .await
            .unwrap_err();
        assert!(
            matches!(err, SeerError::RdapError(ref s) if s.contains("reserved")),
            "expected reserved-IP error, got: {:?}",
            err
        );
    }

    #[tokio::test]
    async fn test_validate_url_not_reserved_rejects_non_https_scheme() {
        // Defense-in-depth (M3): an http:// URL to an otherwise-public host must
        // be refused at fetch time, independent of bootstrap parse-time
        // validation. Uses an IP literal so the check is hermetic (no DNS).
        let err = validate_url_not_reserved("http://93.184.216.34/domain/example.com")
            .await
            .unwrap_err();
        assert!(
            matches!(err, SeerError::RdapError(ref s) if s.contains("not https")),
            "expected non-https rejection, got: {:?}",
            err
        );
    }

    #[tokio::test]
    async fn test_validate_url_not_reserved_rejects_ipv6_loopback_literal() {
        // Also exercises the `Url::host()` unbracketing: "[::1]" must reach
        // the shared guard as the parseable literal "::1".
        let err = validate_url_not_reserved("https://[::1]/")
            .await
            .unwrap_err();
        assert!(
            matches!(err, SeerError::RdapError(ref s) if s.contains("reserved")),
            "expected reserved-IP error, got: {:?}",
            err
        );
    }

    #[tokio::test]
    async fn test_validate_url_not_reserved_returns_resolved_addrs_for_public_literal() {
        // A public IP literal should return a one-element vector containing
        // exactly that address, ready for `resolve_to_addrs` pinning.
        let addrs = validate_url_not_reserved("https://8.8.8.8/").await.unwrap();
        assert_eq!(addrs.len(), 1);
        assert!(addrs[0].ip().is_ipv4());
        assert_eq!(addrs[0].port(), 443);
    }

    // --- build_rdap_urls tests (M16) ------------------------------------

    #[test]
    fn test_build_rdap_urls_preserves_order_and_appends_path() {
        let bases = vec![
            url::Url::parse("https://rdap.a.example/").unwrap(),
            url::Url::parse("https://rdap.b.example").unwrap(), // no trailing slash
        ];
        let built = build_rdap_urls(&bases, "domain/example.com");
        assert_eq!(built.len(), 2);
        assert_eq!(
            built[0].as_str(),
            "https://rdap.a.example/domain/example.com"
        );
        assert_eq!(
            built[1].as_str(),
            "https://rdap.b.example/domain/example.com"
        );
    }

    #[test]
    fn test_build_rdap_urls_empty_input_returns_empty() {
        let built = build_rdap_urls(&[], "domain/example.com");
        assert!(built.is_empty());
    }

    // --- wrap_all_candidates_failed tests (Issue 2 regression) ----------

    #[test]
    fn test_wrap_all_candidates_failed_preserves_timeout_variant() {
        // When the last failure was a Timeout, the wrapped error must ALSO
        // be a Timeout so upstream retry logic can still branch on it.
        let last = SeerError::Timeout("body read timed out".to_string());
        let wrapped = wrap_all_candidates_failed(Some(last), 3);
        match wrapped {
            SeerError::Timeout(msg) => {
                assert!(
                    msg.contains("all 3 RDAP candidate URLs timed out"),
                    "expected wrapped timeout message, got: {}",
                    msg
                );
                assert!(
                    msg.contains("body read timed out"),
                    "expected original message preserved, got: {}",
                    msg
                );
            }
            other => panic!(
                "expected SeerError::Timeout after wrapping a Timeout, got: {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_wrap_all_candidates_failed_wraps_non_timeout_as_rdap_error() {
        let last = SeerError::RdapError("500 internal error".to_string());
        let wrapped = wrap_all_candidates_failed(Some(last), 2);
        assert!(
            matches!(wrapped, SeerError::RdapError(ref s) if s.contains("all 2 RDAP candidate URLs failed")),
            "expected wrapped RdapError, got: {:?}",
            wrapped
        );
    }

    #[test]
    fn test_wrap_all_candidates_failed_single_candidate_returns_unchanged() {
        // Single-candidate case: return the last error unchanged to avoid
        // misleading "all 1 candidates failed" wrapping.
        let last = SeerError::Timeout("single timeout".to_string());
        let wrapped = wrap_all_candidates_failed(Some(last), 1);
        assert!(
            matches!(wrapped, SeerError::Timeout(ref s) if s == "single timeout"),
            "expected unchanged Timeout, got: {:?}",
            wrapped
        );
    }

    #[test]
    fn test_wrap_all_candidates_failed_no_last_error_returns_placeholder() {
        let wrapped = wrap_all_candidates_failed(None, 0);
        assert!(matches!(wrapped, SeerError::RdapError(_)));
    }

    // --- BOOTSTRAP_LOAD_NOTIFY concurrency test (Issue 1 regression) ----
    //
    // This test spawns two concurrent `ensure_bootstrap` calls on what is
    // effectively a cold/expired cache. The point is to exercise the
    // throttle-race path: before the Notify fix, one of the tasks could
    // observe `last_attempt.elapsed() < BOOTSTRAP_REFRESH_MIN_INTERVAL`
    // with an empty cache and immediately return
    // `RdapBootstrapError("bootstrap refresh throttled and no cache available")`.
    //
    // We cannot easily mock `load_bootstrap_data_with_retry`, but we CAN
    // exercise the coordination primitives directly to verify that a waiter
    // subscribing to BOOTSTRAP_LOAD_NOTIFY before a notify_waiters() call
    // correctly wakes, and that a spurious wake followed by a populated
    // cache is treated as success.

    // Both bootstrap-notify tests mutate the shared BOOTSTRAP_CACHE static,
    // so they must be serialized against each other (cargo test parallelism
    // would otherwise race them).
    static BOOTSTRAP_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn test_bootstrap_load_notify_wakes_waiter_when_cache_populated() {
        let _guard = BOOTSTRAP_TEST_LOCK.lock().await;

        // Start from a known-empty state.
        {
            let mut cache = BOOTSTRAP_CACHE.write().await;
            *cache = None;
        }

        // Construct a notified subscription BEFORE triggering the notify,
        // mirroring the order in ensure_bootstrap.
        let notified = BOOTSTRAP_LOAD_NOTIFY.notified();
        tokio::pin!(notified);

        // Simulate a winning loader populating the cache and signalling.
        {
            let mut cache = BOOTSTRAP_CACHE.write().await;
            *cache = Some(CachedBootstrap::new(BootstrapData {
                dns: HashMap::new(),
                ipv4: Vec::new(),
                ipv6: Vec::new(),
                asn: Vec::new(),
            }));
        }
        BOOTSTRAP_LOAD_NOTIFY.notify_waiters();

        let result = wait_for_in_flight_load(notified).await;
        assert!(
            result.is_ok(),
            "expected waiter to see populated cache, got: {:?}",
            result
        );

        // Clean up so we don't leak state into other tests.
        {
            let mut cache = BOOTSTRAP_CACHE.write().await;
            *cache = None;
        }
    }

    #[tokio::test]
    async fn test_bootstrap_load_notify_empty_cache_after_wake_returns_error() {
        let _guard = BOOTSTRAP_TEST_LOCK.lock().await;

        // Ensure cache is empty.
        {
            let mut cache = BOOTSTRAP_CACHE.write().await;
            *cache = None;
        }

        let notified = BOOTSTRAP_LOAD_NOTIFY.notified();
        tokio::pin!(notified);

        // Winner's load failed — they notify with empty cache.
        BOOTSTRAP_LOAD_NOTIFY.notify_waiters();

        let result = wait_for_in_flight_load(notified).await;
        assert!(
            matches!(
                result,
                Err(SeerError::RdapBootstrapError(ref s))
                    if s.contains("throttled and no cache available")
            ),
            "expected throttled error when cache still empty after notify, got: {:?}",
            result
        );
    }

    // ---- deterministic mock-server tests -----------------------------------
    //
    // wiremock serves scripted RDAP responses on 127.0.0.1. These exercise the
    // single-endpoint query path (`query_rdap_with_retry` / `query_rdap_urls`)
    // directly — no IANA bootstrap involved, so the global bootstrap cache is
    // untouched and tests stay parallel-safe. The SSRF guard deliberately
    // refuses loopback, so the client uses the `#[cfg(test)]`-only
    // `allowing_reserved_for_tests` seam, absent from release builds.

    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn mock_rdap_404_is_nonretryable_typed_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = RdapClient::new()
            .without_retries()
            .allowing_reserved_for_tests();
        let err = client
            .query_rdap_with_retry(&format!("{}/domain/example.com", server.uri()))
            .await
            .unwrap_err();
        assert!(
            matches!(err, SeerError::RdapError(ref m) if m.contains("404")),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn mock_rdap_429_honors_retry_after_and_succeeds() {
        let server = MockServer::start().await;
        // First request: rate-limited with an immediate retry hint. The mock
        // expires after one use, so the retry falls through to the 200 below.
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{"objectClassName":"domain","handle":"MOCK-1"}"#,
                "application/rdap+json",
            ))
            .mount(&server)
            .await;

        let client = RdapClient::new().allowing_reserved_for_tests();
        let resp = client
            .query_rdap_with_retry(&format!("{}/domain/example.com", server.uri()))
            .await
            .unwrap();
        assert_eq!(resp.handle.as_deref(), Some("MOCK-1"));
    }

    #[tokio::test]
    async fn mock_rdap_malformed_body_is_parse_error_not_panic() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("not json", "text/plain"))
            .mount(&server)
            .await;

        let client = RdapClient::new()
            .without_retries()
            .allowing_reserved_for_tests();
        let err = client
            .query_rdap_with_retry(&format!("{}/domain/example.com", server.uri()))
            .await
            .unwrap_err();
        assert!(matches!(err, SeerError::JsonError(_)), "got: {err:?}");
    }

    #[tokio::test]
    async fn mock_rdap_candidate_fallback_uses_second_url() {
        let bad = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&bad)
            .await;
        let good = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{"objectClassName":"domain","handle":"MOCK-2"}"#,
                "application/rdap+json",
            ))
            .mount(&good)
            .await;

        let client = RdapClient::new()
            .without_retries()
            .allowing_reserved_for_tests();
        let urls = vec![
            url::Url::parse(&format!("{}/domain/example.com", bad.uri())).unwrap(),
            url::Url::parse(&format!("{}/domain/example.com", good.uri())).unwrap(),
        ];
        let resp = client.query_rdap_urls(&urls).await.unwrap();
        assert_eq!(resp.handle.as_deref(), Some("MOCK-2"));
    }

    /// When an earlier candidate authoritatively reports 404 (no such object)
    /// but a later candidate fails for a different reason (5xx/timeout/conn),
    /// the definitive 404 — the strongest availability signal — must survive in
    /// the returned error. Otherwise `rdap_error_is_404` returns false and a
    /// genuinely available domain is misreported as inconclusive.
    #[tokio::test]
    async fn mock_rdap_404_on_first_candidate_survives_later_non_404_failure() {
        let not_found = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&not_found)
            .await;
        let broken = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&broken)
            .await;

        let client = RdapClient::new()
            .without_retries()
            .allowing_reserved_for_tests();
        let urls = vec![
            url::Url::parse(&format!("{}/domain/example.com", not_found.uri())).unwrap(),
            url::Url::parse(&format!("{}/domain/example.com", broken.uri())).unwrap(),
        ];
        let err = client.query_rdap_urls(&urls).await.unwrap_err();
        assert!(
            crate::rdap::rdap_error_is_404(&err),
            "404 from candidate 1 must survive candidate 2's non-404 failure, got: {err:?}"
        );
    }

    // ---- pinned-client cache tests ------------------------------------

    /// A cache hit must skip DNS resolution and the SSRF re-validation
    /// entirely. The test seeds the cache under a host that can never
    /// resolve (`.invalid`, RFC 2606): if `send_rdap_request` consults the
    /// cache, the request proceeds to the pinned (dead) loopback address and
    /// fails with a connect-level `ReqwestError`; if the cache were bypassed,
    /// validation would fail first with the DNS-failed `RdapError`.
    /// Hermetic: no DNS happens on the hit path, and the loopback connect is
    /// refused immediately.
    #[tokio::test]
    async fn pinned_client_cache_hit_skips_dns_and_revalidation() {
        let host = "pinned-cache-hit.seer-test.invalid";
        let timeout = Duration::from_secs(2);
        let key = (host.to_string(), 443u16, timeout);

        // Simulate a prior validated build (production inserts only after
        // validate; the pinned address here is loopback purely so the connect
        // fails fast without any network). NOTE: `resolve_to_addrs` ignores
        // the SocketAddr port — traffic goes to the URL's port (443).
        let pinned: Vec<SocketAddr> = vec!["127.0.0.1:443".parse().expect("valid addr")];
        let client = Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .resolve_to_addrs(host, &pinned)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client builds");
        PINNED_CLIENT_CACHE.insert(key.clone(), client);

        let err = send_rdap_request(
            &format!("https://{}/domain/example.com", host),
            timeout,
            false,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, SeerError::ReqwestError { .. }),
            "cache hit must reach the connect stage (ReqwestError), not fail \
             SSRF validation (RdapError) — got: {err:?}"
        );

        // Don't leak the synthetic entry into other tests (the connect-error
        // eviction usually removes it already; this makes it unconditional).
        PINNED_CLIENT_CACHE.remove(&key);
    }

    /// The `#[cfg(test)]` allow-reserved seam must bypass the shared cache in
    /// both directions: a test-mode request (whose client would happily reach
    /// loopback) must never insert an entry a production request could be
    /// served from.
    #[tokio::test]
    async fn test_mode_requests_never_populate_pinned_client_cache() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{"objectClassName":"domain","handle":"MOCK-CACHE"}"#,
                "application/rdap+json",
            ))
            .mount(&server)
            .await;

        let client = RdapClient::new()
            .without_retries()
            .allowing_reserved_for_tests();
        let uri = format!("{}/domain/example.com", server.uri());
        let resp = client.query_rdap_with_retry(&uri).await.unwrap();
        assert_eq!(resp.handle.as_deref(), Some("MOCK-CACHE"));

        // The key the production path would have used for this host must be
        // absent (test-mode requests run with the client's default timeout).
        let parsed = url::Url::parse(&uri).unwrap();
        let host = parsed.host_str().unwrap().to_string();
        let port = parsed.port_or_known_default().unwrap();
        assert!(
            PINNED_CLIENT_CACHE
                .get(&(host, port, DEFAULT_TIMEOUT))
                .is_none(),
            "test-mode request must not populate the shared pinned-client cache"
        );
    }

    // ---- RDAP redirect following (RFC 7480 §5.2) -------------------------

    use wiremock::matchers::path;

    const MOCK_OK_BODY: &str = r#"{"objectClassName":"domain","handle":"MOCK-REDIRECT"}"#;

    #[test]
    fn is_loopback_url_only_matches_loopback_literals() {
        assert!(is_loopback_url("http://127.0.0.1:8080/domain/x"));
        assert!(is_loopback_url("http://[::1]:8080/domain/x"));
        assert!(!is_loopback_url("https://10.0.0.1/domain/x"));
        assert!(!is_loopback_url("https://rdap.example.com/domain/x"));
        assert!(!is_loopback_url("not a url"));
    }

    #[tokio::test]
    async fn mock_rdap_303_redirect_is_followed() {
        // ARIN answers 303 → RIPE for an address it doesn't hold; this used
        // to surface as "query failed with status 303".
        let target = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ip/192.36.148.17"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(MOCK_OK_BODY, "application/rdap+json"),
            )
            .expect(1)
            .mount(&target)
            .await;
        let origin = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(303)
                    .insert_header("Location", format!("{}/ip/192.36.148.17", target.uri())),
            )
            .mount(&origin)
            .await;

        let client = RdapClient::new()
            .without_retries()
            .allowing_reserved_for_tests();
        let resp = client
            .query_rdap_with_retry(&format!("{}/ip/192.36.148.17", origin.uri()))
            .await
            .unwrap();
        assert_eq!(resp.handle.as_deref(), Some("MOCK-REDIRECT"));
    }

    #[tokio::test]
    async fn mock_rdap_relative_redirect_is_resolved_against_current_url() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/old/domain/example.com"))
            .respond_with(
                ResponseTemplate::new(301).insert_header("Location", "/new/domain/example.com"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/new/domain/example.com"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(MOCK_OK_BODY, "application/rdap+json"),
            )
            .mount(&server)
            .await;

        let client = RdapClient::new()
            .without_retries()
            .allowing_reserved_for_tests();
        let resp = client
            .query_rdap_with_retry(&format!("{}/old/domain/example.com", server.uri()))
            .await
            .unwrap();
        assert_eq!(resp.handle.as_deref(), Some("MOCK-REDIRECT"));
    }

    /// Scripts a redirect to `location` and returns the error the client
    /// reports. The test seam only exempts loopback, so the redirect target
    /// runs through the full production guard.
    async fn redirect_error(location: &str) -> SeerError {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(302).insert_header("Location", location))
            .mount(&server)
            .await;
        let client = RdapClient::new()
            .without_retries()
            .allowing_reserved_for_tests();
        client
            .query_rdap_with_retry(&format!("{}/domain/example.com", server.uri()))
            .await
            .unwrap_err()
    }

    #[tokio::test]
    async fn mock_rdap_redirect_to_plain_http_is_refused() {
        // Downgrade: a public IP literal keeps this hermetic (the https check
        // fires before any resolution or connect).
        let err = redirect_error("http://93.184.216.34/domain/example.com").await;
        assert!(
            matches!(err, SeerError::RdapError(ref m) if m.contains("not https")),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn mock_rdap_redirect_to_reserved_address_is_refused() {
        for location in [
            "https://10.0.0.1/domain/example.com",
            "https://169.254.169.254/latest/meta-data/",
        ] {
            let err = redirect_error(location).await;
            assert!(
                matches!(err, SeerError::RdapError(ref m) if m.contains("reserved")),
                "{location}: got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn mock_rdap_redirect_loop_is_detected() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/a"))
            .respond_with(ResponseTemplate::new(307).insert_header("Location", "/b"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/b"))
            .respond_with(ResponseTemplate::new(307).insert_header("Location", "/a"))
            .mount(&server)
            .await;
        let client = RdapClient::new()
            .without_retries()
            .allowing_reserved_for_tests();
        let err = client
            .query_rdap_with_retry(&format!("{}/a", server.uri()))
            .await
            .unwrap_err();
        assert!(
            matches!(err, SeerError::RdapError(ref m) if m.contains("loop")),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn mock_rdap_redirect_chain_is_capped() {
        let server = MockServer::start().await;
        for hop in 0..=MAX_RDAP_REDIRECTS {
            Mock::given(method("GET"))
                .and(path(format!("/hop{hop}")))
                .respond_with(
                    ResponseTemplate::new(308)
                        .insert_header("Location", format!("/hop{}", hop + 1)),
                )
                .mount(&server)
                .await;
        }
        let client = RdapClient::new()
            .without_retries()
            .allowing_reserved_for_tests();
        let err = client
            .query_rdap_with_retry(&format!("{}/hop0", server.uri()))
            .await
            .unwrap_err();
        assert!(
            matches!(err, SeerError::RdapError(ref m) if m.contains("exceeded")),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn mock_rdap_sends_accept_header_with_json_fallback() {
        // rdap.nic.sn answers 406 to `application/rdap+json` alone.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            // Compare the raw header: wiremock's `header` matcher splits on
            // commas, so it could never equal the whole list.
            .and(|req: &wiremock::Request| {
                req.headers.get("accept").and_then(|v| v.to_str().ok()) == Some(RDAP_ACCEPT)
            })
            .respond_with(ResponseTemplate::new(200).set_body_raw(MOCK_OK_BODY, "application/json"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(406))
            .mount(&server)
            .await;
        let client = RdapClient::new()
            .without_retries()
            .allowing_reserved_for_tests();
        let resp = client
            .query_rdap_with_retry(&format!("{}/domain/example.sn", server.uri()))
            .await
            .unwrap();
        assert_eq!(resp.handle.as_deref(), Some("MOCK-REDIRECT"));
        assert!(RDAP_ACCEPT.contains("application/json"));
    }

    // ---- bootstrap partial loads (per-registry merge) --------------------

    fn url_arc(u: &str) -> Arc<Vec<url::Url>> {
        Arc::new(vec![url::Url::parse(u).expect("valid url")])
    }

    fn full_load() -> BootstrapLoad {
        let mut dns = HashMap::new();
        dns.insert("com".to_string(), url_arc("https://rdap.verisign.example/"));
        BootstrapLoad {
            dns: Some(dns),
            ipv4: Some(vec![(
                IpRange {
                    prefix: "8.0.0.0/8".to_string(),
                },
                url_arc("https://rdap.arin.example/"),
            )]),
            ipv6: Some(Vec::new()),
            asn: Some(vec![(
                AsnRange { start: 1, end: 10 },
                url_arc("https://rdap.arin.example/"),
            )]),
        }
    }

    #[test]
    fn complete_bootstrap_load_gets_full_ttl() {
        let load = full_load();
        assert!(load.is_complete());
        assert_eq!(load.ttl(), BOOTSTRAP_TTL);
    }

    #[test]
    fn partial_bootstrap_load_keeps_previous_section_and_short_ttl() {
        // Previous (expired) dataset with good DNS data.
        let mut previous = Some(CachedBootstrap::with_ttl(
            full_load().merge_over(None),
            Duration::ZERO,
        ));
        std::thread::sleep(Duration::from_millis(2));
        assert!(previous.as_ref().is_some_and(CachedBootstrap::is_expired));

        // Refresh where dns.json failed but the others loaded.
        let mut partial = full_load();
        partial.dns = None;
        assert!(!partial.is_complete());
        store_bootstrap_load(&mut previous, partial);

        let cached = previous.expect("cache populated");
        assert_eq!(cached.ttl, BOOTSTRAP_PARTIAL_TTL);
        assert!(
            RdapClient::get_rdap_urls_for_domain(&cached.data, "example.com").is_some(),
            "the failed dns section must be carried over, not wiped"
        );
        assert!(RdapClient::get_rdap_urls_for_asn(&cached.data, 5).is_some());
    }

    #[test]
    fn partial_cold_bootstrap_load_leaves_failed_section_empty() {
        let mut cache = None;
        let mut partial = full_load();
        partial.dns = None;
        store_bootstrap_load(&mut cache, partial);
        let cached = cache.expect("cache populated");
        assert_eq!(cached.ttl, BOOTSTRAP_PARTIAL_TTL);
        assert!(RdapClient::get_rdap_urls_for_domain(&cached.data, "example.com").is_none());
    }

    #[test]
    fn bootstrap_store_does_not_overwrite_fresh_data() {
        let mut fresh = full_load();
        fresh.dns = Some(HashMap::from([(
            "org".to_string(),
            url_arc("https://rdap.pir.example/"),
        )]));
        let mut cache = Some(CachedBootstrap::new(fresh.merge_over(None)));
        store_bootstrap_load(&mut cache, full_load());
        let cached = cache.expect("cache populated");
        assert!(RdapClient::get_rdap_urls_for_domain(&cached.data, "example.org").is_some());
        assert!(RdapClient::get_rdap_urls_for_domain(&cached.data, "example.com").is_none());
    }

    // ---- in-flight tracking for throttled cold-cache callers -------------

    #[tokio::test]
    async fn wait_returns_immediately_when_no_load_is_in_flight() {
        let _guard = BOOTSTRAP_TEST_LOCK.lock().await;
        {
            let mut cache = BOOTSTRAP_CACHE.write().await;
            *cache = None;
        }
        assert!(!BOOTSTRAP_LOAD_IN_FLIGHT.load(Ordering::SeqCst));

        // A failed cold load already finished: nobody will notify. The
        // caller must get the throttle error right away, not after the full
        // DEFAULT_TIMEOUT wait.
        let notified = BOOTSTRAP_LOAD_NOTIFY.notified();
        tokio::pin!(notified);
        let result =
            tokio::time::timeout(Duration::from_secs(2), wait_for_in_flight_load(notified))
                .await
                .expect("must not block when no load is in flight");
        assert!(
            matches!(result, Err(SeerError::RdapBootstrapError(ref s)) if s.contains("throttled")),
            "got: {result:?}"
        );
    }

    #[tokio::test]
    async fn wait_blocks_until_in_flight_load_finishes() {
        let _guard = BOOTSTRAP_TEST_LOCK.lock().await;
        {
            let mut cache = BOOTSTRAP_CACHE.write().await;
            *cache = None;
        }

        let load = BootstrapLoadGuard::start();
        let notified = BOOTSTRAP_LOAD_NOTIFY.notified();
        tokio::pin!(notified);

        let loader = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            {
                let mut cache = BOOTSTRAP_CACHE.write().await;
                *cache = Some(CachedBootstrap::new(full_load().merge_over(None)));
            }
            // Clears the flag and notifies, like the end of ensure_bootstrap.
            drop(load);
        });

        let result =
            tokio::time::timeout(Duration::from_secs(5), wait_for_in_flight_load(notified))
                .await
                .expect("waiter must wake via the loader's notify");
        assert!(result.is_ok(), "got: {result:?}");
        loader.await.expect("loader joined");
        assert!(!BOOTSTRAP_LOAD_IN_FLIGHT.load(Ordering::SeqCst));

        let mut cache = BOOTSTRAP_CACHE.write().await;
        *cache = None;
    }
}
