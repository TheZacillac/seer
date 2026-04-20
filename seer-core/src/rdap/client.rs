use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::{Notify, RwLock};
use tracing::{debug, info, instrument};

use super::types::RdapResponse;
use crate::error::{Result, SeerError};
use crate::retry::{RetryExecutor, RetryPolicy};
use crate::validation::{describe_reserved_ip, normalize_domain};

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

/// Shared HTTP client for bootstrap fetches against IANA.
/// The bootstrap targets are hardcoded data.iana.org URLs, so this client
/// does not need DNS-rebinding protection. Per-query RDAP requests build
/// their own short-lived client that pins resolved IPs.
///
/// Wrapped in `Option` so a reqwest builder failure surfaces as a typed
/// `SeerError::HttpError` via `rdap_http_client()` instead of a process
/// panic at first use (library code must not `.expect()` on shared state).
static RDAP_HTTP_CLIENT: Lazy<Option<Client>> = Lazy::new(|| {
    Client::builder()
        .timeout(DEFAULT_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .user_agent("Seer/1.0 (RDAP Client)")
        .pool_max_idle_per_host(10)
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
static BOOTSTRAP_CACHE: Lazy<RwLock<Option<CachedBootstrap>>> = Lazy::new(|| RwLock::new(None));

/// Timestamp of the most recent bootstrap refresh attempt (success or failure).
/// Used together with `BOOTSTRAP_REFRESH_MIN_INTERVAL` to throttle retry
/// storms when IANA is unreachable.
static BOOTSTRAP_LAST_ATTEMPT: Lazy<RwLock<Option<Instant>>> = Lazy::new(|| RwLock::new(None));

/// Notifies waiters when an in-flight bootstrap load completes (success or
/// failure). Solves the first-boot thundering-herd race where two concurrent
/// cold-cache callers would otherwise see: caller A records its attempt
/// timestamp, then caller B checks the timestamp and finds it "too recent"
/// and returns a spurious `throttled and no cache available` error while A
/// is still actively loading. Losers instead wait on this notify with a
/// bounded timeout, then re-check the cache.
static BOOTSTRAP_LOAD_NOTIFY: Lazy<Notify> = Lazy::new(Notify::new);

/// Cached bootstrap data with timestamp for TTL tracking
struct CachedBootstrap {
    data: BootstrapData,
    loaded_at: Instant,
}

impl CachedBootstrap {
    fn new(data: BootstrapData) -> Self {
        Self {
            data,
            loaded_at: Instant::now(),
        }
    }

    fn is_expired(&self) -> bool {
        self.loaded_at.elapsed() > BOOTSTRAP_TTL
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
    // Bounded wait so we don't block forever if the winner's future was
    // cancelled/dropped before it could notify.
    let _ = tokio::time::timeout(DEFAULT_TIMEOUT, notified).await;
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
            retry_policy: RetryPolicy::default().with_max_attempts(2),
        }
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
                    // failed). Wait for them instead of returning an error.
                    drop(cache);
                    drop(last);
                    return wait_for_in_flight_load(notified).await;
                }
            }
        }

        // Record the attempt timestamp before we begin the network load.
        // Holding this lock is cheap (no await in between read+write here).
        {
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
        }

        // Perform the actual load WITHOUT holding any cache lock. Whichever
        // branch exits, we must notify waiters so losers don't hang for the
        // full bounded timeout.
        debug!("Loading/refreshing RDAP bootstrap data");
        let load_result = load_bootstrap_data_with_retry(&self.retry_policy).await;

        let outcome = match load_result {
            Ok(data) => {
                let mut cache = BOOTSTRAP_CACHE.write().await;
                // Double-check: another task may have loaded while we ran.
                // Only overwrite if the current cache is missing or expired.
                let should_store = cache.as_ref().map(|c| c.is_expired()).unwrap_or(true);
                if should_store {
                    *cache = Some(CachedBootstrap::new(data));
                }
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

        // Wake any losers waiting on our load. Safe to call in both branches.
        BOOTSTRAP_LOAD_NOTIFY.notify_waiters();
        outcome
    }

    /// Looks up the candidate RDAP base URLs for a domain's TLD.
    fn get_rdap_urls_for_domain(cache: &BootstrapData, domain: &str) -> Option<Arc<Vec<url::Url>>> {
        let tld = domain.rsplit('.').next()?;
        cache.dns.get(&tld.to_lowercase()).cloned()
    }

    /// Looks up the candidate RDAP base URLs for an IP address.
    fn get_rdap_urls_for_ip(cache: &BootstrapData, ip: &IpAddr) -> Option<Arc<Vec<url::Url>>> {
        match ip {
            IpAddr::V4(addr) => {
                for (range, urls) in &cache.ipv4 {
                    if ipv4_matches_prefix(&range.prefix, addr) {
                        return Some(Arc::clone(urls));
                    }
                }
            }
            IpAddr::V6(addr) => {
                for (range, urls) in &cache.ipv6 {
                    if ipv6_matches_prefix(&range.prefix, addr) {
                        return Some(Arc::clone(urls));
                    }
                }
            }
        }

        None
    }

    /// Looks up the candidate RDAP base URLs for an ASN.
    fn get_rdap_urls_for_asn(cache: &BootstrapData, asn: u32) -> Option<Arc<Vec<url::Url>>> {
        for (range, urls) in &cache.asn {
            if asn >= range.start && asn <= range.end {
                return Some(Arc::clone(urls));
            }
        }

        None
    }

    /// Looks up RDAP registration data for a domain.
    ///
    /// Uses IANA bootstrap data to find the appropriate RDAP server for the TLD.
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn lookup_domain(&self, domain: &str) -> Result<RdapResponse> {
        self.ensure_bootstrap().await?;

        let domain = normalize_domain(domain)?;

        // Extract candidate URLs while holding the lock, then release before HTTP requests.
        let urls = {
            let cache_guard = BOOTSTRAP_CACHE.read().await;
            let cache = cache_guard.as_ref().ok_or_else(|| {
                SeerError::RdapBootstrapError("bootstrap data not loaded".to_string())
            })?;

            let bases = Self::get_rdap_urls_for_domain(&cache.data, &domain).ok_or_else(|| {
                SeerError::RdapBootstrapError(format!("no RDAP server for {}", domain))
            })?;

            build_rdap_urls(&bases, &format!("domain/{}", domain))
        }; // Lock released here

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

        let urls = {
            let cache_guard = BOOTSTRAP_CACHE.read().await;
            let cache = cache_guard.as_ref().ok_or_else(|| {
                SeerError::RdapBootstrapError("bootstrap data not loaded".to_string())
            })?;

            let bases = Self::get_rdap_urls_for_ip(&cache.data, &ip_addr).ok_or_else(|| {
                SeerError::RdapBootstrapError(format!("no RDAP server for {}", ip))
            })?;

            build_rdap_urls(&bases, &format!("ip/{}", ip))
        };

        self.query_rdap_urls(&urls).await
    }

    /// Looks up RDAP registration data for an Autonomous System Number (ASN).
    ///
    /// Uses IANA bootstrap data to find the appropriate RIR for the ASN range.
    #[instrument(skip(self), fields(asn = %asn))]
    pub async fn lookup_asn(&self, asn: u32) -> Result<RdapResponse> {
        self.ensure_bootstrap().await?;

        let urls = {
            let cache_guard = BOOTSTRAP_CACHE.read().await;
            let cache = cache_guard.as_ref().ok_or_else(|| {
                SeerError::RdapBootstrapError("bootstrap data not loaded".to_string())
            })?;

            let bases = Self::get_rdap_urls_for_asn(&cache.data, asn).ok_or_else(|| {
                SeerError::RdapBootstrapError(format!("no RDAP server for AS{}", asn))
            })?;

            build_rdap_urls(&bases, &format!("autnum/{}", asn))
        };

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
        cache
            .data
            .dns
            .get(&tld.to_lowercase())
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
                    last_error = Some(e);
                }
            }
        }

        // All candidates failed.
        Err(wrap_all_candidates_failed(last_error, urls.len()))
    }

    /// Queries a single RDAP endpoint with retry logic.
    async fn query_rdap_with_retry(&self, url: &str) -> Result<RdapResponse> {
        let executor = RetryExecutor::new(self.retry_policy.clone());
        let url = url.to_string();

        executor
            .execute(|| {
                let url = url.clone();
                async move { query_rdap_internal(&url).await }
            })
            .await
    }
}

/// Maximum RDAP response body size (10 MB, matching CT log response limit).
const MAX_RDAP_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

/// Validates that a URL does not resolve to a reserved/private IP address (SSRF protection).
///
/// Returns the full list of resolved `SocketAddr`s so the caller can pin them on a
/// per-request HTTP client via `resolve_to_addrs`. Pinning prevents a DNS rebinding
/// TOCTOU where the hostname could resolve to a different (private) address between
/// validation here and the actual HTTP connect.
async fn validate_url_not_reserved(url: &str) -> Result<Vec<SocketAddr>> {
    let parsed = url::Url::parse(url)
        .map_err(|e| SeerError::RdapError(format!("invalid URL '{}': {}", url, e)))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| SeerError::RdapError(format!("URL '{}' has no host", url)))?;
    let port = parsed.port_or_known_default().unwrap_or(443);

    // If the host is already an IP literal, check it directly.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if let Some(reason) = describe_reserved_ip(&ip) {
            return Err(SeerError::RdapError(format!(
                "RDAP URL resolves to reserved IP {}: {} — request blocked (SSRF protection)",
                ip, reason
            )));
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let addr = format!("{}:{}", host, port);

    let socket_addrs: Vec<SocketAddr> = tokio::net::lookup_host(&addr)
        .await
        .map_err(|e| SeerError::RdapError(format!("failed to resolve host '{}': {}", host, e)))?
        .collect();

    if socket_addrs.is_empty() {
        return Err(SeerError::RdapError(format!(
            "host '{}' resolved to no addresses",
            host
        )));
    }

    for socket_addr in &socket_addrs {
        if let Some(reason) = describe_reserved_ip(&socket_addr.ip()) {
            return Err(SeerError::RdapError(format!(
                "RDAP URL resolves to reserved IP {}: {} — request blocked (SSRF protection)",
                socket_addr.ip(),
                reason
            )));
        }
    }

    Ok(socket_addrs)
}

/// Validates a bootstrap-extracted URL before caching it.
///
/// Rejects non-https schemes, IP-literal hosts, missing hosts, and hosts
/// containing whitespace or control characters. Returns the parsed URL on
/// success so the caller can cache it in normalized form.
fn validate_bootstrap_url(s: &str) -> Result<url::Url> {
    let parsed = url::Url::parse(s)
        .map_err(|e| SeerError::RdapError(format!("bad bootstrap URL {}: {}", s, e)))?;
    if parsed.scheme() != "https" {
        return Err(SeerError::RdapError(format!(
            "bootstrap URL must be https, got {}",
            parsed.scheme()
        )));
    }
    let host = parsed
        .host()
        .ok_or_else(|| SeerError::RdapError(format!("bootstrap URL has no host: {}", s)))?;
    match host {
        url::Host::Ipv4(_) | url::Host::Ipv6(_) => {
            return Err(SeerError::RdapError(format!(
                "bootstrap URL must not be an IP literal: {}",
                s
            )));
        }
        url::Host::Domain(d) => {
            if d.is_empty() || d.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(SeerError::RdapError(format!(
                    "bootstrap URL has invalid host: {}",
                    s
                )));
            }
        }
    }
    Ok(parsed)
}

/// Internal function to query an RDAP endpoint (used by retry executor).
///
/// Builds a per-request HTTP client that pins the validated resolved IPs to
/// prevent DNS rebinding (TOCTOU between validation and connect).
async fn query_rdap_internal(url: &str) -> Result<RdapResponse> {
    // SSRF protection: validate the URL does not resolve to reserved IPs and
    // capture the resolved SocketAddrs so we can pin them on the HTTP client.
    let resolved = validate_url_not_reserved(url).await?;

    let parsed = url::Url::parse(url)
        .map_err(|e| SeerError::RdapError(format!("invalid URL '{}': {}", url, e)))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| SeerError::RdapError(format!("URL '{}' has no host", url)))?;

    // Build a short-lived client pinning the validated IPs. If the host was
    // an IP literal the resolved vec already holds it, so `resolve_to_addrs`
    // is still correct.
    let client = Client::builder()
        .timeout(DEFAULT_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .user_agent("Seer/1.0 (RDAP Client)")
        .resolve_to_addrs(host, &resolved)
        .build()
        .map_err(|e| SeerError::RdapError(format!("failed to build HTTP client: {}", e)))?;

    let response = client
        .get(url)
        .header("Accept", "application/rdap+json")
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(SeerError::RdapError(format!(
            "query failed with status {}",
            response.status()
        )));
    }

    // Stream body with incremental size check to prevent memory exhaustion.
    // Wrap the chunk loop in a timeout so a server that opens the connection
    // but trickles bytes forever is classified as a timeout (not a generic
    // RdapError) and retries can be driven appropriately.
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    let streamed = tokio::time::timeout(DEFAULT_TIMEOUT, async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk
                .map_err(|e| SeerError::RdapError(format!("failed to read response: {}", e)))?;
            body.extend_from_slice(&chunk);
            if body.len() > MAX_RDAP_RESPONSE_SIZE {
                return Err(SeerError::RdapError(format!(
                    "RDAP response exceeds {} byte limit",
                    MAX_RDAP_RESPONSE_SIZE
                )));
            }
        }
        Ok::<(), SeerError>(())
    })
    .await;

    match streamed {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(SeerError::Timeout(format!(
                "timed out reading RDAP response body from {} after {:?}",
                host, DEFAULT_TIMEOUT
            )));
        }
    }

    let rdap: RdapResponse = serde_json::from_slice(&body)?;
    // Bound attacker-controlled payload post-deserialization. The 10MB
    // body cap prevents unbounded download, but a well-formed response
    // can still pack millions of keys or deeply-nested values into the
    // serde_json::Map, and adversarial `entities` nesting can drive
    // recursive walkers to stack-overflow. See RdapResponse::validate.
    rdap.validate()?;
    Ok(rdap)
}

/// Loads IANA RDAP bootstrap data from all registries with retry.
async fn load_bootstrap_data_with_retry(policy: &RetryPolicy) -> Result<BootstrapData> {
    let executor = RetryExecutor::new(policy.clone());
    executor.execute(load_bootstrap_data).await
}

/// Loads IANA RDAP bootstrap data from all registries.
async fn load_bootstrap_data() -> Result<BootstrapData> {
    debug!("Loading RDAP bootstrap data from IANA");

    // SSRF validation is skipped here — these are hardcoded IANA URLs, not user input.
    // User-supplied URLs are still validated in query_rdap_internal().

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
        // Bound the streaming-read loop with the same timeout used for RDAP
        // queries. Without this, a slow or stalled IANA response (open TCP
        // but no bytes arriving) could hang all RDAP lookups indefinitely
        // because `ensure_bootstrap` awaits this future. Mirrors the pattern
        // in `query_rdap_internal`.
        let mut body = Vec::new();
        let mut stream = resp.bytes_stream();
        let streamed = tokio::time::timeout(DEFAULT_TIMEOUT, async {
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| {
                    SeerError::RdapBootstrapError(format!("failed to read body: {}", e))
                })?;
                body.extend_from_slice(&chunk);
                if body.len() > MAX_BOOTSTRAP_SIZE {
                    return Err(SeerError::RdapBootstrapError(format!(
                        "bootstrap response too large (exceeds {} bytes)",
                        MAX_BOOTSTRAP_SIZE
                    )));
                }
            }
            Ok::<(), SeerError>(())
        })
        .await;

        match streamed {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(SeerError::Timeout(format!(
                    "RDAP bootstrap body read timed out after {:?}",
                    DEFAULT_TIMEOUT
                )));
            }
        }

        serde_json::from_slice(&body).map_err(Into::into)
    }

    // Parse each response independently, logging failures
    let dns_data = match dns_resp {
        Ok(resp) => match read_bootstrap(resp).await {
            Ok(data) => Some(data),
            Err(e) => {
                debug!(error = %e, "Failed to parse DNS bootstrap response");
                None
            }
        },
        Err(e) => {
            debug!(error = %e, "Failed to fetch DNS bootstrap from IANA");
            None
        }
    };
    let ipv4_data = match ipv4_resp {
        Ok(resp) => match read_bootstrap(resp).await {
            Ok(data) => Some(data),
            Err(e) => {
                debug!(error = %e, "Failed to parse IPv4 bootstrap response");
                None
            }
        },
        Err(e) => {
            debug!(error = %e, "Failed to fetch IPv4 bootstrap from IANA");
            None
        }
    };
    let ipv6_data = match ipv6_resp {
        Ok(resp) => match read_bootstrap(resp).await {
            Ok(data) => Some(data),
            Err(e) => {
                debug!(error = %e, "Failed to parse IPv6 bootstrap response");
                None
            }
        },
        Err(e) => {
            debug!(error = %e, "Failed to fetch IPv6 bootstrap from IANA");
            None
        }
    };
    let asn_data = match asn_resp {
        Ok(resp) => match read_bootstrap(resp).await {
            Ok(data) => Some(data),
            Err(e) => {
                debug!(error = %e, "Failed to parse ASN bootstrap response");
                None
            }
        },
        Err(e) => {
            debug!(error = %e, "Failed to fetch ASN bootstrap from IANA");
            None
        }
    };

    // If ALL four registries failed, that's a real error
    if dns_data.is_none() && ipv4_data.is_none() && ipv6_data.is_none() && asn_data.is_none() {
        return Err(SeerError::RdapBootstrapError(
            "all IANA bootstrap registries failed".to_string(),
        ));
    }

    let mut dns = HashMap::new();
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut asn = Vec::new();

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

    // Parse DNS bootstrap
    if let Some(dns_data) = dns_data {
        for service in dns_data.services {
            if service.len() >= 2 {
                if let (Some(tlds), Some(urls)) = (service[0].as_array(), service[1].as_array()) {
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
    }

    // Parse IPv4 bootstrap
    if let Some(ipv4_data) = ipv4_data {
        for service in ipv4_data.services {
            if service.len() >= 2 {
                if let (Some(prefixes), Some(urls)) = (service[0].as_array(), service[1].as_array())
                {
                    if let Some(urls_arc) = collect_valid_urls(urls) {
                        for prefix in prefixes {
                            if let Some(prefix_str) = prefix.as_str() {
                                ipv4.push((
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
    }

    // Parse IPv6 bootstrap
    if let Some(ipv6_data) = ipv6_data {
        for service in ipv6_data.services {
            if service.len() >= 2 {
                if let (Some(prefixes), Some(urls)) = (service[0].as_array(), service[1].as_array())
                {
                    if let Some(urls_arc) = collect_valid_urls(urls) {
                        for prefix in prefixes {
                            if let Some(prefix_str) = prefix.as_str() {
                                ipv6.push((
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
    }

    // Parse ASN bootstrap
    if let Some(asn_data) = asn_data {
        for service in asn_data.services {
            if service.len() >= 2 {
                if let (Some(ranges), Some(urls)) = (service[0].as_array(), service[1].as_array()) {
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
    }

    info!(
        dns_entries = dns.len(),
        ipv4_ranges = ipv4.len(),
        ipv6_ranges = ipv6.len(),
        asn_ranges = asn.len(),
        "RDAP bootstrap loaded"
    );

    Ok(BootstrapData {
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

fn parse_asn_range(range: &str) -> Option<(u32, u32)> {
    if let Some(pos) = range.find('-') {
        let start = range[..pos].parse().ok()?;
        let end = range[pos + 1..].parse().ok()?;
        Some((start, end))
    } else {
        let num = range.parse().ok()?;
        Some((num, num))
    }
}

fn ipv4_matches_prefix(prefix: &str, ip: &Ipv4Addr) -> bool {
    let (addr_part, mask_part) = match prefix.split_once('/') {
        Some((a, m)) => (a, Some(m)),
        None => (prefix, None),
    };

    let prefix_ip: Ipv4Addr = match addr_part.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    let mask_bits: u32 = match mask_part.and_then(|s| s.parse().ok()) {
        Some(bits) if bits <= 32 => bits,
        Some(_) => return false,
        None => 32,
    };

    let mask = if mask_bits == 0 {
        0
    } else {
        u32::MAX << (32 - mask_bits)
    };

    let ip_value = u32::from(*ip);
    let prefix_value = u32::from(prefix_ip);

    (ip_value & mask) == (prefix_value & mask)
}

fn ipv6_matches_prefix(prefix: &str, ip: &Ipv6Addr) -> bool {
    let (addr_part, mask_part) = match prefix.split_once('/') {
        Some((a, m)) => (a, Some(m)),
        None => (prefix, None),
    };

    let prefix_ip: Ipv6Addr = match addr_part.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    let mask_bits: u32 = match mask_part.and_then(|s| s.parse().ok()) {
        Some(bits) if bits <= 128 => bits,
        Some(_) => return false,
        None => 128,
    };

    let mask = if mask_bits == 0 {
        0u128
    } else {
        u128::MAX << (128 - mask_bits)
    };

    let ip_value = ipv6_to_u128(ip);
    let prefix_value = ipv6_to_u128(&prefix_ip);

    (ip_value & mask) == (prefix_value & mask)
}

fn ipv6_to_u128(ip: &Ipv6Addr) -> u128 {
    let segments = ip.segments();
    let mut value = 0u128;
    for segment in segments {
        value = (value << 16) | segment as u128;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_client_has_retry_policy() {
        let client = RdapClient::new();
        assert_eq!(client.retry_policy.max_attempts, 2);
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
    fn test_ipv4_prefix_matching_partial_mask() {
        let ip_in = Ipv4Addr::new(203, 0, 114, 1);
        let ip_out = Ipv4Addr::new(203, 0, 120, 1);
        assert!(ipv4_matches_prefix("203.0.112.0/21", &ip_in));
        assert!(!ipv4_matches_prefix("203.0.112.0/21", &ip_out));
    }

    #[test]
    fn test_ipv6_prefix_matching_partial_mask() {
        let ip_in: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let ip_out: Ipv6Addr = "2001:db9::1".parse().unwrap();
        assert!(ipv6_matches_prefix("2001:db8::/33", &ip_in));
        assert!(!ipv6_matches_prefix("2001:db8::/33", &ip_out));
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

    // --- validate_bootstrap_url tests (H1) ------------------------------

    #[test]
    fn test_validate_bootstrap_url_accepts_https() {
        let url = validate_bootstrap_url("https://rdap.example.com/").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("rdap.example.com"));
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_http() {
        let err = validate_bootstrap_url("http://rdap.example.com/").unwrap_err();
        assert!(
            matches!(err, SeerError::RdapError(ref s) if s.contains("https")),
            "expected https-scheme error, got: {:?}",
            err
        );
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_ftp() {
        let err = validate_bootstrap_url("ftp://rdap.example.com/").unwrap_err();
        assert!(matches!(err, SeerError::RdapError(_)));
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_ip_literal_v4() {
        let err = validate_bootstrap_url("https://192.0.2.1/").unwrap_err();
        assert!(
            matches!(err, SeerError::RdapError(ref s) if s.contains("IP literal")),
            "expected IP-literal error, got: {:?}",
            err
        );
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_ip_literal_v6() {
        let err = validate_bootstrap_url("https://[2001:db8::1]/").unwrap_err();
        assert!(
            matches!(err, SeerError::RdapError(ref s) if s.contains("IP literal")),
            "expected IP-literal error, got: {:?}",
            err
        );
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_garbage() {
        let err = validate_bootstrap_url("not a url").unwrap_err();
        assert!(matches!(err, SeerError::RdapError(_)));
    }

    // --- validate_url_not_reserved tests (C1 regression) ----------------

    #[tokio::test]
    async fn test_validate_url_not_reserved_rejects_loopback_literal() {
        let err = validate_url_not_reserved("https://127.0.0.1/domain/example.com")
            .await
            .unwrap_err();
        assert!(
            matches!(err, SeerError::RdapError(ref s) if s.contains("reserved IP")),
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
            matches!(err, SeerError::RdapError(ref s) if s.contains("reserved IP")),
            "expected reserved-IP error, got: {:?}",
            err
        );
    }

    #[tokio::test]
    async fn test_validate_url_not_reserved_rejects_ipv6_loopback_literal() {
        let err = validate_url_not_reserved("https://[::1]/")
            .await
            .unwrap_err();
        assert!(
            matches!(err, SeerError::RdapError(ref s) if s.contains("reserved IP")),
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
}
