use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tracing::{debug, instrument, warn};

use tokio::time::timeout as tokio_timeout;

use crate::availability::{AvailabilityChecker, AvailabilityResult, PriorRdap, PriorWhois};
use crate::cache::TtlCache;
use crate::dns::{DnsPresence, DnsResolver};
use crate::error::{Result, SeerError};
use crate::rdap::{rdap_error_is_404, RdapClient, RdapResponse};
use crate::whois::{get_registry_url, get_tld, WhoisClient, WhoisResponse};

/// Cache TTL for lookup results (5 minutes).
const LOOKUP_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Grace period for the second protocol after the first one finishes *with
/// usable data*. If RDAP answers and WHOIS hasn't responded within this
/// window (or vice versa), we use the answer in hand rather than waiting the
/// loser's full timeout. A winner that failed — or returned an unusable
/// body — grants no such truncation: the other leg is then the only possible
/// source of registry data and runs to its own bounded completion (see
/// [`race_with_grace`]).
const PROTOCOL_GRACE_PERIOD: Duration = Duration::from_secs(5);

/// Maximum length for public-facing error strings.
const MAX_PUBLIC_ERROR_LEN: usize = 256;

/// Upper bound a coalesced waiter will block on the owner's in-flight lookup
/// before falling through to re-contend for ownership itself. Bounds the wait
/// so a lost notification (e.g. the owner's future was cancelled/dropped before
/// it could notify) can't hang the waiter forever. Sized to comfortably exceed
/// a full concurrent RDAP+WHOIS race (≈15s per protocol plus the grace period
/// and retries) so the common path always wakes via `notify_waiters()`.
const DEFAULT_INFLIGHT_WAIT: Duration = Duration::from_secs(30);

/// Global cache for lookup results to avoid redundant network calls.
static LOOKUP_CACHE: Lazy<TtlCache<String, LookupResult>> =
    Lazy::new(|| TtlCache::new(LOOKUP_CACHE_TTL));

/// In-flight lookup coalescing map: normalized-domain -> Weak<Notify>.
/// Only one network race runs per unique domain at a time; concurrent callers
/// wait on the shared Notify and then read the result from LOOKUP_CACHE.
static LOOKUP_INFLIGHT: Lazy<Mutex<HashMap<String, Weak<Notify>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Regex patterns for stripping IP literals from public error messages.
static IPV4_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("IPV4_RE is a valid regex"));

/// Candidate pattern for IPv6 literals: a hex/colon token containing either
/// a `::` compression or at least three colons. This catches plausible IPv6
/// addresses cheaply; each match is then validated by `Ipv6Addr::from_str`
/// before redaction, so MAC fragments, hex hashes, and similar colon-laden
/// tokens are left alone.
static IPV6_CANDIDATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[0-9a-fA-F:]*(?:::|(?:[0-9a-fA-F]{1,4}:){3,})[0-9a-fA-F:]*\b")
        .expect("IPV6_CANDIDATE_RE is a valid regex")
});

/// Redact substrings that parse as valid IPv6 addresses, leaving non-IPv6
/// tokens (e.g. `af:ba:12`) untouched.
fn strip_ipv6(msg: &str) -> String {
    IPV6_CANDIDATE_RE
        .replace_all(msg, |caps: &regex::Captures| {
            let candidate = &caps[0];
            if Ipv6Addr::from_str(candidate).is_ok() {
                "[ip-redacted]".to_string()
            } else {
                candidate.to_string()
            }
        })
        .into_owned()
}

/// Test-only hook: counts the number of times `lookup_concurrent` is actually
/// invoked (i.e., the underlying network race runs). Used to verify request
/// coalescing. Not exposed outside the crate.
#[cfg(test)]
static LOOKUP_CONCURRENT_CALLS: Lazy<std::sync::atomic::AtomicUsize> =
    Lazy::new(|| std::sync::atomic::AtomicUsize::new(0));

/// Returns true if the parsed WHOIS response lacks all key registration
/// signals: no registrar, no creation date, and no expiration date.
///
/// This is a necessary-but-not-sufficient signal for domain availability;
/// `lookup_concurrent` combines it with an RDAP 404 before routing to the
/// availability path. Nameservers alone don't disqualify thinness — some
/// registries return placeholder nameservers for unregistered domains.
fn whois_response_is_thin(w: &WhoisResponse) -> bool {
    w.registrar.is_none() && w.creation_date.is_none() && w.expiration_date.is_none()
}

/// Returns true if an RDAP response carries enough data to serve as the
/// primary lookup result: the domain name plus at least one other piece of
/// information (dates, entities, nameservers, or status).
fn rdap_response_is_useful(response: &RdapResponse) -> bool {
    let has_name = response.ldh_name.is_some() || response.unicode_name.is_some();
    let has_dates = response
        .events
        .iter()
        .any(|e| e.event_action == "registration" || e.event_action == "expiration");
    let has_entities = !response.entities.is_empty();
    let has_nameservers = !response.nameservers.is_empty();
    let has_status = !response.status.is_empty();

    has_name && (has_dates || has_entities || has_nameservers || has_status)
}

/// Race predicate for the WHOIS leg of [`race_with_grace`]: only a response
/// carrying real registration data counts as "data in hand" for
/// grace-truncation purposes. A thin body — e.g. an Identity-Digital-style
/// "no WHOIS service" sentinel, or a "no match" banner — must not cut a
/// viable in-flight RDAP query down to the grace period: RDAP is then the
/// only possible source of registry data, and for "no match" bodies a late
/// RDAP 200 must remain able to veto the availability claim (v0.26.6 rule).
/// Mirrors the RDAP-side [`rdap_response_is_useful`] gate; thinness is
/// [`whois_response_is_thin`], the same signal the fallback ladders use.
fn whois_leg_has_data(w: &Result<WhoisResponse>) -> bool {
    matches!(w, Ok(data) if !whois_response_is_thin(data))
}

/// Decides whether a WHOIS response + RDAP error combination should route
/// to the availability path. Returns `(confidence, method)` when routing is
/// warranted, `None` to keep the existing `LookupResult::Whois` behavior.
///
/// Case A: WHOIS explicitly indicates no registration (highest priority).
/// Case B: WHOIS returned but lacks registration data AND RDAP returned 404.
fn classify_whois_leg(
    w: &WhoisResponse,
    rdap_err: &SeerError,
) -> Option<(&'static str, &'static str)> {
    if w.is_available() {
        return Some(("high", "whois"));
    }
    if whois_response_is_thin(w) && rdap_error_is_404(rdap_err) {
        // Must stay in lockstep with `availability::decide_fallback`'s
        // RDAP-404 branch: the registry's own 404 is authoritative, so the
        // verdict is high-confidence via RDAP — not a hedged WHOIS signal.
        return Some(("high", "rdap"));
    }
    None
}

/// Wraps `classify_whois_leg` with the "RDAP returned 200" veto: a successful
/// RDAP response (HTTP 200, even if the body is thin) is positive evidence
/// that the domain object exists, so we never let a WHOIS-only signal flip
/// the verdict to "available" in that case. This guards against WHOIS
/// propagation lag against freshly-provisioned domains the registry has
/// already begun serving via RDAP. v0.26.6 regression fix.
fn should_route_to_availability(
    rdap_returned_200: bool,
    rdap_seer_error: Option<&SeerError>,
    whois_data: &WhoisResponse,
) -> Option<(&'static str, &'static str)> {
    if rdap_returned_200 {
        return None;
    }
    // `is_available()` streams the raw response (~1 MB worst case) line by
    // line. Compute it once and reuse — `classify_whois_leg` also calls it,
    // so the original code paid the scan twice on every non-404 RDAP-error
    // path. We pre-check Case A here; if it doesn't fire we drop into the
    // 404+thin Case B branch via `classify_whois_leg`.
    if whois_data.is_available() {
        return Some(("high", "whois"));
    }
    rdap_seer_error.and_then(|e| {
        // Case B only: WHOIS is not available, so the only remaining path
        // is "thin WHOIS + RDAP 404". `classify_whois_leg` will re-check
        // `is_available()` for free (it's false now), so this is a single
        // additional thin-check call.
        classify_whois_leg(whois_data, e)
    })
}

/// Verdict for the "thin WHOIS leg + non-200 RDAP failure" fallback block in
/// [`SmartLookup::lookup_concurrent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThinFallback {
    /// The registry refused/throttled the query — no usable registration
    /// signal. Report inconclusive rather than guessing.
    Inconclusive,
    /// Thin WHOIS, RDAP not 200, apex is NXDOMAIN — likely available.
    Available,
    /// Thin/no-service WHOIS, RDAP unavailable, apex IS delegated — registered.
    Registered,
    /// Preconditions not met — keep the existing [`LookupResult::Whois`].
    UseWhois,
}

/// Pure decision for the thin-WHOIS fallback block. Encodes the same issue-#45
/// precedence as [`crate::availability::decide_fallback`] so the smart-lookup
/// hot path and the dedicated availability path cannot diverge: a registry that
/// *refused/throttled* the query (rather than authoritatively answering) is
/// inconclusive and must NOT be inverted into "available" or fail-safed to
/// "registered" on the strength of DNS presence.
///
/// `whois_refuses` is [`crate::whois::WhoisResponse::indicates_registry_refusal`]
/// precomputed by the caller. Routes are only considered when the WHOIS body was
/// thin (no registrar/dates) and RDAP did NOT return an HTTP 200 — a 200, even
/// with a thin body, proves the domain object exists and vetoes every
/// DNS-derived reclassification. [`DnsPresence::Unknown`] (a failed probe) is not
/// positive evidence either way, so it falls through to WHOIS.
fn classify_thin_fallback(
    is_thin: bool,
    rdap_returned_200: bool,
    whois_refuses: bool,
    dns: DnsPresence,
) -> ThinFallback {
    if !is_thin || rdap_returned_200 {
        return ThinFallback::UseWhois;
    }
    if whois_refuses {
        return ThinFallback::Inconclusive;
    }
    match dns {
        DnsPresence::Absent => ThinFallback::Available,
        DnsPresence::Present => ThinFallback::Registered,
        DnsPresence::Unknown => ThinFallback::UseWhois,
    }
}

/// Sanitizes an error message for inclusion in a public-facing response.
///
/// Strips IPv4 and IPv6 literals (to avoid leaking internal addresses when
/// an SSRF guard rejects a resolved URL) and caps the total length to
/// [`MAX_PUBLIC_ERROR_LEN`] characters.
fn sanitize_error_for_public(msg: &str) -> String {
    let s = IPV4_RE.replace_all(msg, "[ip-redacted]");
    let s = strip_ipv6(&s);
    if s.chars().count() > MAX_PUBLIC_ERROR_LEN {
        let mut trunc: String = s.chars().take(MAX_PUBLIC_ERROR_LEN).collect();
        trunc.push('…');
        trunc
    } else {
        s
    }
}

/// RAII guard for the in-flight-lookup slot. On drop, removes the entry
/// from `LOOKUP_INFLIGHT` and notifies any waiters so they can read the
/// freshly-populated cache.
///
/// NOTE on failed-owner retry semantics:
/// When the owning task's lookup fails, `InflightGuard::drop` runs, the
/// `HashMap` entry is removed, and `notify_waiters()` fires. Waiters wake,
/// observe an empty cache, and one of them becomes the new owner — triggering
/// a fresh network race. This means transient failures are automatically
/// retried by any concurrent waiter. Callers that observe a timeout error
/// should not assume no work is in flight; another concurrent caller may
/// already be retrying.
struct InflightGuard {
    key: String,
    notify: Arc<Notify>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        // Always remove the entry before notifying. The earlier `try_lock`
        // design skipped removal under contention, but that left a stale
        // `Weak<Notify>` in the map: a caller arriving in the brief window
        // between `notify_waiters()` firing and the owner's `Arc<Notify>`
        // dropping could upgrade the Weak, register as a waiter on the
        // already-fired Notify, and block forever (notify_waiters only
        // wakes currently-registered waiters; it does not accumulate
        // permits for later registrations).
        //
        // Contention windows on this `std::sync::Mutex<HashMap>` are
        // microseconds — the brief block here is safer than the stale-entry
        // hazard. Poisoned-mutex recovery is preserved.
        let mut inflight = LOOKUP_INFLIGHT.lock().unwrap_or_else(|p| p.into_inner());
        inflight.remove(&self.key);
        drop(inflight);
        self.notify.notify_waiters();
    }
}

/// Outcome of one leg of the concurrent RDAP/WHOIS race.
///
/// Tracks whether the leg completed naturally or was truncated by the grace
/// period, so downstream error messages can distinguish a true timeout from a
/// loser-truncation.
enum LegOutcome<T> {
    /// The leg ran to its own completion (success or error).
    Completed(T),
    /// The leg was abandoned because the other protocol answered first with
    /// usable data and this leg did not finish within
    /// [`PROTOCOL_GRACE_PERIOD`] of that answer.
    GraceTruncated,
}

/// Races the RDAP and WHOIS legs of a smart lookup.
///
/// Whichever leg finishes first is inspected with its `*_has_data` predicate:
///
/// * Winner brought usable data → the still-running leg is merely
///   supplementary, so it gets [`PROTOCOL_GRACE_PERIOD`] to finish before
///   being truncated.
/// * Winner came back empty-handed (an error, or a response the caller's
///   predicate rejects) → the other leg is now the only possible source of
///   registry data, so it runs to its own (already timeout-bounded)
///   completion. This matters for RDAP-less TLDs such as .ru: the bootstrap
///   miss fails in microseconds and must not shave the WHOIS budget down to
///   the grace period. It also avoids pure waste — a truncated leg was
///   re-queried in full by the availability fallback anyway.
async fn race_with_grace<R, W>(
    rdap_fut: impl std::future::Future<Output = R>,
    whois_fut: impl std::future::Future<Output = W>,
    rdap_has_data: impl Fn(&R) -> bool,
    whois_has_data: impl Fn(&W) -> bool,
) -> (LegOutcome<R>, LegOutcome<W>) {
    tokio::pin!(rdap_fut);
    tokio::pin!(whois_fut);

    tokio::select! {
        rdap_res = &mut rdap_fut => {
            let whois_leg = if rdap_has_data(&rdap_res) {
                match tokio_timeout(PROTOCOL_GRACE_PERIOD, whois_fut).await {
                    Ok(res) => LegOutcome::Completed(res),
                    Err(_) => LegOutcome::GraceTruncated,
                }
            } else {
                LegOutcome::Completed(whois_fut.await)
            };
            (LegOutcome::Completed(rdap_res), whois_leg)
        }
        whois_res = &mut whois_fut => {
            let rdap_leg = if whois_has_data(&whois_res) {
                match tokio_timeout(PROTOCOL_GRACE_PERIOD, rdap_fut).await {
                    Ok(res) => LegOutcome::Completed(res),
                    Err(_) => LegOutcome::GraceTruncated,
                }
            } else {
                LegOutcome::Completed(rdap_fut.await)
            };
            (rdap_leg, LegOutcome::Completed(whois_res))
        }
    }
}

/// Public-facing error string for a grace-truncated leg. Truncation only
/// happens when the other protocol answered first with usable data (see
/// [`race_with_grace`]), so the wording says the winner "answered" — the old
/// "after RDAP won" phrasing misled when the winner had merely finished first
/// with an error.
fn grace_truncated_error(truncated: &str, winner: &str) -> String {
    format!(
        "{} did not respond within the {}s grace period after {} answered",
        truncated,
        PROTOCOL_GRACE_PERIOD.as_secs(),
        winner
    )
}

/// Internal classification of the RDAP leg of a concurrent lookup.
///
/// Distinguishing `NoData` (HTTP 200 but response was missing useful fields)
/// from `Error` lets the orchestrator prefer a thin WHOIS result over the
/// availability fallback when RDAP silently returned nothing.
enum RdapOutcome {
    Useful(RdapResponse),
    NoData(RdapResponse),
    Error(SeerError),
    /// RDAP future did not complete within the grace period after WHOIS
    /// answered with a response.
    GraceTimeout,
}

/// Progress callback for smart lookup operations.
/// Called with a message describing the current phase of the lookup.
pub type LookupProgressCallback = Arc<dyn Fn(&str) + Send + Sync>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "lowercase")]
pub enum LookupResult {
    Rdap {
        data: Box<RdapResponse>,
        #[serde(skip_serializing_if = "Option::is_none")]
        whois_fallback: Option<WhoisResponse>,
    },
    Whois {
        data: WhoisResponse,
        rdap_error: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        rdap_fallback: Option<Box<RdapResponse>>,
    },
    Available {
        data: Box<AvailabilityResult>,
        rdap_error: String,
        whois_error: String,
        /// Raw WHOIS response, when one was available at routing time
        /// (Cases A and B in the design spec). `None` preserves the
        /// pre-existing "both protocols errored" semantics.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        whois_data: Option<WhoisResponse>,
    },
}

impl LookupResult {
    /// Returns the domain name from the lookup result.
    pub fn domain_name(&self) -> Option<String> {
        match self {
            LookupResult::Rdap { data, .. } => data.domain_name().map(String::from),
            LookupResult::Whois { data, .. } => Some(data.domain.clone()),
            LookupResult::Available { data, .. } => Some(data.domain.clone()),
        }
    }

    /// Returns the registrar name, preferring RDAP data with WHOIS fallback.
    pub fn registrar(&self) -> Option<String> {
        match self {
            LookupResult::Rdap {
                data,
                whois_fallback,
            } => data
                .get_registrar()
                .or_else(|| whois_fallback.as_ref().and_then(|w| w.registrar.clone())),
            LookupResult::Whois { data, .. } => data.registrar.clone(),
            LookupResult::Available { .. } => None,
        }
    }

    /// Returns the registrant organization, preferring RDAP data with WHOIS fallback.
    pub fn organization(&self) -> Option<String> {
        match self {
            LookupResult::Rdap {
                data,
                whois_fallback,
            } => data
                .get_registrant_organization()
                .or_else(|| whois_fallback.as_ref().and_then(|w| w.organization.clone())),
            LookupResult::Whois { data, .. } => data.organization.clone(),
            LookupResult::Available { .. } => None,
        }
    }

    /// Returns true if the result came from RDAP.
    pub fn is_rdap(&self) -> bool {
        matches!(self, LookupResult::Rdap { .. })
    }

    /// Returns true if the result came from WHOIS.
    pub fn is_whois(&self) -> bool {
        matches!(self, LookupResult::Whois { .. })
    }

    /// Returns true if the result is an availability check fallback.
    pub fn is_available(&self) -> bool {
        matches!(self, LookupResult::Available { .. })
    }

    /// Returns the expiration date and registrar info from the lookup result.
    pub fn expiration_info(&self) -> (Option<DateTime<Utc>>, Option<String>) {
        match self {
            LookupResult::Rdap {
                data,
                whois_fallback,
            } => {
                // Try to get expiration from RDAP events
                let expiration_date = data
                    .events
                    .iter()
                    .find(|e| e.event_action == "expiration")
                    .and_then(|e| e.parsed_date())
                    .or_else(|| {
                        // Fallback to WHOIS if available
                        whois_fallback.as_ref().and_then(|w| w.expiration_date)
                    });

                let registrar = data
                    .get_registrar()
                    .or_else(|| whois_fallback.as_ref().and_then(|w| w.registrar.clone()));

                (expiration_date, registrar)
            }
            LookupResult::Whois { data, .. } => (data.expiration_date, data.registrar.clone()),
            LookupResult::Available { .. } => (None, None),
        }
    }
}

/// Truncates `s` to at most `max` bytes, backing up to the nearest UTF-8 char
/// boundary at or below `max`. `String::truncate` panics if the byte offset is
/// not a char boundary, and WHOIS `raw_response` is server-controlled and may
/// preserve multi-byte UTF-8, so we must not truncate blindly at a fixed byte
/// offset. (`str::floor_char_boundary` would do this, but it is unstable on
/// stable Rust, so we walk backwards manually.)
fn truncate_on_char_boundary(s: &mut String, max: usize) {
    if s.len() > max {
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
}

/// Trims an oversized WHOIS `raw_response` in place (char-boundary safe),
/// appending a truncation marker. A raw body can be up to 1 MB (the WHOIS
/// client's response cap); 32 KB is plenty for the parsed fields while
/// bounding memory wherever responses are retained — the lookup cache here
/// and the bulk executor's buffered results.
pub(crate) fn trim_whois_raw(whois: &mut WhoisResponse) {
    const MAX_RAW: usize = 32 * 1024;
    if whois.raw_response.len() > MAX_RAW {
        truncate_on_char_boundary(&mut whois.raw_response, MAX_RAW);
        whois.raw_response.push_str("\n... [truncated]");
    }
}

/// Trims any retained raw WHOIS body inside a [`LookupResult`] via
/// [`trim_whois_raw`]. Applied before caching lookups and by the bulk
/// executor before buffering results.
pub(crate) fn trim_raw_response(mut result: LookupResult) -> LookupResult {
    match result {
        LookupResult::Whois { ref mut data, .. } => trim_whois_raw(data),
        LookupResult::Rdap {
            ref mut whois_fallback,
            ..
        } => {
            if let Some(w) = whois_fallback {
                trim_whois_raw(w);
            }
        }
        LookupResult::Available {
            ref mut whois_data, ..
        } => {
            if let Some(w) = whois_data {
                trim_whois_raw(w);
            }
        }
    }

    result
}

#[derive(Debug, Clone)]
pub struct SmartLookup {
    rdap_client: RdapClient,
    whois_client: WhoisClient,
    availability_checker: AvailabilityChecker,
    dns_resolver: DnsResolver,
    /// Deprecated: both protocols are now always attempted concurrently.
    prefer_rdap: bool,
    /// Deprecated: WHOIS data is now always attached when available.
    include_fallback: bool,
}

impl Default for SmartLookup {
    fn default() -> Self {
        Self::new()
    }
}

impl SmartLookup {
    /// Creates a new SmartLookup that runs RDAP and WHOIS concurrently,
    /// falling back to an availability check if both fail.
    pub fn new() -> Self {
        Self {
            rdap_client: RdapClient::new(),
            whois_client: WhoisClient::new(),
            availability_checker: AvailabilityChecker::new(),
            dns_resolver: DnsResolver::new(),
            prefer_rdap: true,
            include_fallback: false,
        }
    }

    /// Builds a SmartLookup whose RDAP/WHOIS/DNS sub-clients honor the
    /// per-protocol timeouts in `config`.
    pub fn from_config(config: &crate::config::SeerConfig) -> Self {
        Self {
            rdap_client: RdapClient::new().with_timeout(config.rdap_timeout()),
            whois_client: WhoisClient::new().with_timeout(config.whois_timeout()),
            availability_checker: AvailabilityChecker::from_config(config),
            dns_resolver: DnsResolver::new().with_timeout(config.dns_timeout()),
            prefer_rdap: true,
            include_fallback: false,
        }
    }

    /// Deprecated: both protocols are now always attempted concurrently.
    /// This method is kept for API compatibility but has no effect.
    #[deprecated(note = "This field has no effect. RDAP is always tried concurrently with WHOIS.")]
    pub fn prefer_rdap(mut self, prefer: bool) -> Self {
        self.prefer_rdap = prefer;
        self
    }

    /// Deprecated: WHOIS data is now always attached when available.
    /// This method is kept for API compatibility but has no effect.
    #[deprecated(note = "This field has no effect. RDAP is always tried concurrently with WHOIS.")]
    pub fn include_fallback(mut self, include: bool) -> Self {
        self.include_fallback = include;
        self
    }

    /// Performs a smart lookup for a domain, trying both RDAP and WHOIS concurrently.
    /// Falls back to an availability check if both fail.
    /// Results are cached for 5 minutes to avoid redundant network calls.
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn lookup(&self, domain: &str) -> Result<LookupResult> {
        self.lookup_with_progress(domain, None).await
    }

    /// Performs a lookup with an optional progress callback.
    /// The callback is called with messages describing the current phase.
    /// Results are cached for 5 minutes. Concurrent lookups for the same
    /// domain are coalesced — only one network race runs per domain at a time.
    #[instrument(skip(self, progress), fields(domain = %domain))]
    pub async fn lookup_with_progress(
        &self,
        domain: &str,
        progress: Option<LookupProgressCallback>,
    ) -> Result<LookupResult> {
        let normalized = crate::validation::normalize_domain(domain)?;

        // Check cache first
        if let Some(cached) = LOOKUP_CACHE.get(&normalized) {
            debug!(domain = %normalized, "Returning cached lookup result");
            return Ok(cached);
        }

        // Coalesce in-flight lookups: if another task is already running a
        // race for this domain, wait on its Notify rather than starting a
        // second race. Two branches:
        //   - Waiter: another task owns the slot; await its notify, then
        //     read the cache. If the cache is still empty (owner failed),
        //     loop and re-contend for ownership.
        //   - Owner: no entry exists; insert a Weak handle, hold the Arc
        //     for the duration of the work, then remove and notify on drop.
        //
        // A `loop` with a separate lock-scope per iteration keeps the
        // `MutexGuard` from being held across any `.await`.
        let _guard = loop {
            enum Slot {
                Waiter(Arc<Notify>),
                Owner(InflightGuard),
            }

            let slot = {
                // Recover from poisoning rather than panicking: a prior
                // owner's panic should not permanently wedge the in-flight
                // tracker for every future lookup.
                let mut inflight = LOOKUP_INFLIGHT.lock().unwrap_or_else(|p| p.into_inner());
                match inflight.get(&normalized).and_then(|w| w.upgrade()) {
                    Some(existing) => Slot::Waiter(existing),
                    None => {
                        let n = Arc::new(Notify::new());
                        inflight.insert(normalized.clone(), Arc::downgrade(&n));
                        Slot::Owner(InflightGuard {
                            key: normalized.clone(),
                            notify: n,
                        })
                    }
                }
            };

            match slot {
                Slot::Waiter(n) => {
                    debug!(domain = %normalized, "Waiting for in-flight lookup to complete");
                    // Ordering requirement (mirrors rdap::client::ensure_bootstrap):
                    // construct and pin the `Notified` future BEFORE we re-check
                    // the cache. `Notify::notified()` reserves the wakeup slot the
                    // moment it is constructed (only `.await` blocks), so a
                    // `notify_waiters()` fired by the owner's `InflightGuard::drop`
                    // after this point cannot be missed. Without this, the owner
                    // could drop (removing the map entry and firing
                    // `notify_waiters()`) in the gap between us releasing the lock
                    // above and subscribing here — `notify_waiters` stores no
                    // permit for late subscribers, so the waiter would hang.
                    let notified = n.notified();
                    tokio::pin!(notified);

                    // Re-check the cache now that we're subscribed: the owner may
                    // have populated it and notified in the gap between the lock
                    // release and our subscription.
                    if let Some(cached) = LOOKUP_CACHE.get(&normalized) {
                        return Ok(cached);
                    }

                    // Bounded wait: if the owner's future was cancelled/dropped
                    // without notifying, or the notification was otherwise lost,
                    // fall through and re-contend for ownership rather than
                    // hanging forever. The RDAP timeout is a sensible bound for a
                    // single domain lookup race.
                    let _ = tokio_timeout(DEFAULT_INFLIGHT_WAIT, notified.as_mut()).await;

                    if let Some(cached) = LOOKUP_CACHE.get(&normalized) {
                        return Ok(cached);
                    }
                    // Owner finished without populating the cache (failed or
                    // errored), or the wait timed out. Re-contend for ownership.
                    continue;
                }
                Slot::Owner(guard) => break guard,
            }
        };

        let result = self.lookup_concurrent(&normalized, progress).await?;

        // Cache a trimmed copy to limit memory usage before releasing
        // waiters (via guard drop) so they observe the cached value.
        LOOKUP_CACHE.insert(normalized.clone(), trim_raw_response(result.clone()));

        Ok(result)
    }

    /// Clears the lookup result cache.
    pub fn clear_cache() {
        LOOKUP_CACHE.clear();
    }

    #[instrument(skip(self, progress), fields(domain = %domain))]
    async fn lookup_concurrent(
        &self,
        domain: &str,
        progress: Option<LookupProgressCallback>,
    ) -> Result<LookupResult> {
        #[cfg(test)]
        LOOKUP_CONCURRENT_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        debug!(domain = %domain, "Attempting RDAP and WHOIS concurrently");

        if let Some(ref cb) = progress {
            cb("Querying RDAP and WHOIS concurrently");
        }

        let rdap_fut = self.rdap_client.lookup_domain(domain);
        let whois_fut = self.whois_client.lookup(domain);

        // Race: a winner with usable data grants the loser only a grace
        // period; a winner that failed (or returned an unusable body) leaves
        // the loser as the sole possible data source, so it runs to its own
        // bounded completion. Both predicates gate on usefulness — RDAP via
        // `rdap_response_is_useful`, WHOIS via `whois_leg_has_data`
        // (non-thin) — so neither side's empty answer can truncate the
        // other. See `race_with_grace`.
        let (rdap_leg, whois_leg) = race_with_grace(
            rdap_fut,
            whois_fut,
            |r| matches!(r, Ok(data) if rdap_response_is_useful(data)),
            whois_leg_has_data,
        )
        .await;

        if matches!(whois_leg, LegOutcome::GraceTruncated) {
            debug!("WHOIS did not finish within grace period after RDAP answered, proceeding with RDAP only");
        }
        if matches!(rdap_leg, LegOutcome::GraceTruncated) {
            debug!("RDAP did not finish within grace period after WHOIS answered, proceeding with WHOIS only");
        }

        // Classify the RDAP leg.
        let rdap_outcome = match rdap_leg {
            LegOutcome::Completed(Ok(data)) => {
                if rdap_response_is_useful(&data) {
                    RdapOutcome::Useful(data)
                } else {
                    RdapOutcome::NoData(data)
                }
            }
            LegOutcome::Completed(Err(e)) => RdapOutcome::Error(e),
            LegOutcome::GraceTruncated => RdapOutcome::GraceTimeout,
        };

        // Phase 1: If RDAP returned useful data, use it as primary.
        if let RdapOutcome::Useful(rdap_data) = rdap_outcome {
            debug!("RDAP lookup successful");
            let whois_fallback = match whois_leg {
                LegOutcome::Completed(Ok(w)) => Some(w),
                _ => None,
            };
            return Ok(LookupResult::Rdap {
                data: Box::new(rdap_data),
                whois_fallback,
            });
        }

        // RDAP was not useful (NoData, Error, or GraceTimeout). Prefer WHOIS
        // if it returned any response, even a thin one — this is safer than
        // falling back to the availability heuristic when we have actual
        // registry data in hand.
        //
        // We separately track whether RDAP returned an HTTP 200 (NoData):
        // even a thin RDAP 200 is positive evidence the domain object
        // exists. In that case we must NOT reclassify a WHOIS "no match"
        // signal as availability — WHOIS lag against a freshly-provisioned
        // domain would otherwise produce a false "available" verdict.
        let rdap_returned_200 = matches!(rdap_outcome, RdapOutcome::NoData(_));
        let (rdap_error_str, rdap_fallback_data, rdap_seer_error) = match rdap_outcome {
            RdapOutcome::Useful(_) => {
                // Unreachable in this branch (we returned above), but handle
                // defensively rather than panicking across the FFI boundary.
                debug!("Unexpected RdapOutcome::Useful in fallback branch");
                (String::from("RDAP ok"), None, None)
            }
            RdapOutcome::NoData(data) => (
                "RDAP response incomplete".to_string(),
                Some(Box::new(data)),
                None,
            ),
            RdapOutcome::Error(e) => (e.to_string(), None, Some(e)),
            RdapOutcome::GraceTimeout => (grace_truncated_error("RDAP", "WHOIS"), None, None),
        };

        if let LegOutcome::Completed(Ok(whois_data)) = whois_leg {
            // Check Cases A and B: should we reclassify as Available? The
            // `should_route_to_availability` helper also enforces the
            // "RDAP returned 200 vetoes WHOIS availability claims" rule.
            let availability_match = should_route_to_availability(
                rdap_returned_200,
                rdap_seer_error.as_ref(),
                &whois_data,
            );

            if let Some((confidence, method)) = availability_match {
                debug!(
                    domain = %domain,
                    confidence = %confidence,
                    "Reclassifying WHOIS as availability signal"
                );
                if let Some(ref cb) = progress {
                    cb("Domain appears unregistered");
                }
                // Keyed off `method` (not confidence) so the text names the
                // signal that actually decided the verdict, matching
                // `availability::decide_fallback`'s wording for the same cases.
                let details = match method {
                    "whois" => Some("WHOIS indicates domain is not registered".to_string()),
                    "rdap" => Some("Registry RDAP reports no such domain (HTTP 404)".to_string()),
                    _ => None,
                };
                let avail = AvailabilityResult {
                    domain: domain.to_string(),
                    available: true,
                    confidence: confidence.to_string(),
                    method: method.to_string(),
                    details,
                };
                return Ok(LookupResult::Available {
                    data: Box::new(avail),
                    rdap_error: sanitize_error_for_public(&rdap_error_str),
                    whois_error: String::new(),
                    whois_data: Some(whois_data),
                });
            }

            // Fix #2 safety net: a thin WHOIS body plus an RDAP failure that was
            // not an authoritative 404 leaves us without registry data. Route the
            // verdict through `classify_thin_fallback`, which shares the issue-#45
            // precedence with `availability::decide_fallback` so the two fallback
            // paths cannot diverge: a registry refusal/throttle is inconclusive
            // (never inverted into "available" or fail-safed to "registered");
            // otherwise an NXDOMAIN apex reads as available and a delegated apex
            // reads as registered. The cheap thin / not-200 preconditions gate the
            // DNS probe so we don't pay for it on the common paths, and a refusal
            // short-circuits before the probe entirely.
            let whois_is_thin = whois_response_is_thin(&whois_data);
            if whois_is_thin && !rdap_returned_200 {
                let whois_refuses = whois_data.indicates_registry_refusal();
                let dns_presence = if whois_refuses {
                    // A refusal already settles the verdict; skip the DNS probe.
                    DnsPresence::Unknown
                } else {
                    self.dns_resolver.presence(domain).await
                };
                match classify_thin_fallback(
                    whois_is_thin,
                    rdap_returned_200,
                    whois_refuses,
                    dns_presence,
                ) {
                    ThinFallback::Inconclusive => {
                        debug!(domain = %domain, "Thin WHOIS is a registry refusal/throttle; availability inconclusive (issue #45)");
                        if let Some(ref cb) = progress {
                            cb("Registry refused or throttled the query (availability inconclusive)");
                        }
                        let avail = AvailabilityResult {
                            domain: domain.to_string(),
                            available: false,
                            confidence: "none".to_string(),
                            method: "inconclusive".to_string(),
                            details: Some(
                                "Registry refused or throttled the query; availability is inconclusive"
                                    .to_string(),
                            ),
                        };
                        return Ok(LookupResult::Available {
                            data: Box::new(avail),
                            rdap_error: sanitize_error_for_public(&rdap_error_str),
                            whois_error: String::new(),
                            whois_data: Some(whois_data),
                        });
                    }
                    ThinFallback::Available => {
                        debug!(domain = %domain, "Thin WHOIS + NXDOMAIN, reclassifying as available");
                        if let Some(ref cb) = progress {
                            cb("Domain appears unregistered (no DNS presence)");
                        }
                        let avail = AvailabilityResult {
                            domain: domain.to_string(),
                            available: true,
                            confidence: "medium".to_string(),
                            method: "dns_nxdomain".to_string(),
                            details: Some(
                                "No registry data available; domain has no DNS presence (NXDOMAIN)"
                                    .to_string(),
                            ),
                        };
                        return Ok(LookupResult::Available {
                            data: Box::new(avail),
                            rdap_error: sanitize_error_for_public(&rdap_error_str),
                            whois_error: String::new(),
                            whois_data: Some(whois_data),
                        });
                    }
                    ThinFallback::Registered => {
                        debug!(domain = %domain, "Thin/no-service WHOIS + DNS delegation, reporting registered");
                        if let Some(ref cb) = progress {
                            cb("Domain is registered (registry detail unavailable)");
                        }
                        let details = if whois_data.registry_unavailable() {
                            "Domain is registered (the apex is delegated in DNS). This TLD's \
                             registry provides no port-43 WHOIS data and RDAP was unavailable \
                             (rate-limited or unreachable); retry shortly for full RDAP detail."
                        } else {
                            "Domain is registered (the apex is delegated in DNS). Registry detail \
                             was unavailable (RDAP rate-limited or unreachable and WHOIS returned \
                             no data); retry shortly for full detail."
                        };
                        let avail = AvailabilityResult {
                            domain: domain.to_string(),
                            available: false,
                            confidence: "high".to_string(),
                            method: "dns_present".to_string(),
                            details: Some(details.to_string()),
                        };
                        return Ok(LookupResult::Available {
                            data: Box::new(avail),
                            rdap_error: sanitize_error_for_public(&rdap_error_str),
                            whois_error: String::new(),
                            whois_data: Some(whois_data),
                        });
                    }
                    ThinFallback::UseWhois => {}
                }
            }
            debug!("Using WHOIS result (RDAP not useful)");
            if let Some(ref cb) = progress {
                cb("RDAP not available (using WHOIS)");
            }
            return Ok(LookupResult::Whois {
                data: whois_data,
                rdap_error: Some(sanitize_error_for_public(&rdap_error_str)),
                rdap_fallback: rdap_fallback_data,
            });
        }

        // Both sides failed to provide useful data. Craft a precise WHOIS
        // error string that distinguishes true errors from grace-period
        // truncation. Borrow the leg here so we can move it into the reuse
        // token below.
        let whois_error_str = match &whois_leg {
            LegOutcome::Completed(Err(e)) => e.to_string(),
            LegOutcome::Completed(Ok(_)) => {
                // Already handled above; treat defensively.
                debug!("Unexpected completed-Ok WHOIS in availability fallback branch");
                "WHOIS returned but was not used".to_string()
            }
            // Unreachable under `race_with_grace` semantics: WHOIS is only
            // truncated behind a useful RDAP answer, and that path returned
            // early above. Kept as a defensive arm.
            LegOutcome::GraceTruncated => grace_truncated_error("WHOIS", "RDAP"),
        };

        // Reuse what the race already learned rather than re-querying the same
        // registries: a thin HTTP 200 still proves the object exists (feed it
        // back), a concrete error is reused as-is, and only a grace-truncated
        // leg (genuinely missing) is re-queried by the checker.
        let prior_rdap = if rdap_returned_200 {
            match rdap_fallback_data {
                // `rdap_fallback_data` is already the boxed NoData response.
                Some(resp) => PriorRdap::Response(resp),
                None => PriorRdap::Missing,
            }
        } else if let Some(e) = rdap_seer_error {
            PriorRdap::Failed(e)
        } else {
            PriorRdap::Missing
        };
        let prior_whois = match whois_leg {
            LegOutcome::Completed(Err(e)) => PriorWhois::Failed(e),
            // Handled above; the availability path never reuses an Ok WHOIS.
            LegOutcome::Completed(Ok(_)) => PriorWhois::Missing,
            LegOutcome::GraceTruncated => PriorWhois::Missing,
        };

        self.availability_fallback(
            domain,
            prior_rdap,
            prior_whois,
            rdap_error_str,
            whois_error_str,
            progress,
        )
        .await
    }

    async fn availability_fallback(
        &self,
        domain: &str,
        prior_rdap: PriorRdap,
        prior_whois: PriorWhois,
        rdap_error: String,
        whois_error: String,
        progress: Option<LookupProgressCallback>,
    ) -> Result<LookupResult> {
        if let Some(ref cb) = progress {
            cb("RDAP and WHOIS unavailable (checking availability)");
        }
        warn!(
            domain = %domain,
            rdap_error = %rdap_error,
            whois_error = %whois_error,
            "Both RDAP and WHOIS failed, falling back to availability check"
        );

        match self
            .availability_checker
            .check_with_prior(domain, prior_rdap, prior_whois)
            .await
        {
            Ok(avail) => Ok(LookupResult::Available {
                data: Box::new(avail),
                rdap_error: sanitize_error_for_public(&rdap_error),
                whois_error: sanitize_error_for_public(&whois_error),
                whois_data: None,
            }),
            Err(avail_err) => {
                let tld = get_tld(domain).unwrap_or("unknown");
                let registry_url = get_registry_url(tld).unwrap_or_else(|| {
                    format!("https://www.iana.org/domains/root/db/{}.html", tld)
                });
                Err(SeerError::LookupFailed {
                    domain: domain.to_string(),
                    details: format!(
                        "RDAP failed ({}), WHOIS failed ({}), availability check failed ({})",
                        rdap_error, whois_error, avail_err
                    ),
                    registry_url,
                })
            }
        }
    }

    /// DNS presence passthrough over this lookup's private resolver, exposing
    /// the same cheap availability pre-signal the fallback ladder uses. The
    /// confusables scan uses it to skip NXDOMAIN candidates before paying for a
    /// full RDAP+WHOIS race on each one.
    pub(crate) async fn presence(&self, domain: &str) -> DnsPresence {
        self.dns_resolver.presence(domain).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Global serialization mutex for the tests that share `LOOKUP_INFLIGHT`
    /// or `LOOKUP_CACHE` state (map coalescing, waiter coalescing, cache
    /// clear, poison recovery, drop recovery).
    /// Running them in parallel creates two races:
    ///   1. Guard drop uses `try_lock`; if another test holds the mutex, the
    ///      Drop path skips cleanup → stale entries fail later assertions.
    ///   2. Poisoning one test leaves the mutex poisoned for the next test,
    ///      which is handled by `unwrap_or_else` but still disturbs state.
    ///
    /// Per-test unique keys (see `unique_test_key`) prevent entry-level
    /// collisions; this mutex prevents lock-contention races on Drop.
    static INFLIGHT_TEST_SERIAL: Mutex<()> = Mutex::new(());

    #[test]
    fn test_lookup_result_domain_name_whois() {
        let result = LookupResult::Whois {
            data: WhoisResponse {
                domain: "example.com".to_string(),
                registrar: Some("Test Registrar".to_string()),
                registrant: None,
                organization: None,
                registrant_email: None,
                registrant_phone: None,
                registrant_address: None,
                registrant_country: None,
                admin_name: None,
                admin_organization: None,
                admin_email: None,
                admin_phone: None,
                tech_name: None,
                tech_organization: None,
                tech_email: None,
                tech_phone: None,
                creation_date: None,
                expiration_date: None,
                updated_date: None,
                status: vec![],
                nameservers: vec![],
                dnssec: None,
                whois_server: "whois.example.com".to_string(),
                raw_response: String::new(),
            },
            rdap_error: None,
            rdap_fallback: None,
        };

        assert_eq!(result.domain_name(), Some("example.com".to_string()));
        assert_eq!(result.registrar(), Some("Test Registrar".to_string()));
        assert!(result.is_whois());
        assert!(!result.is_rdap());
        assert!(!result.is_available());
    }

    #[test]
    fn test_lookup_result_serialization() {
        let result = LookupResult::Whois {
            data: WhoisResponse {
                domain: "test.com".to_string(),
                registrar: None,
                registrant: None,
                organization: None,
                registrant_email: None,
                registrant_phone: None,
                registrant_address: None,
                registrant_country: None,
                admin_name: None,
                admin_organization: None,
                admin_email: None,
                admin_phone: None,
                tech_name: None,
                tech_organization: None,
                tech_email: None,
                tech_phone: None,
                creation_date: None,
                expiration_date: None,
                updated_date: None,
                status: vec![],
                nameservers: vec![],
                dnssec: None,
                whois_server: String::new(),
                raw_response: String::new(),
            },
            rdap_error: Some("RDAP failed".to_string()),
            rdap_fallback: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"source\":\"whois\""));
        assert!(json.contains("RDAP failed"));
    }

    #[test]
    fn test_lookup_result_available_serialization() {
        let result = LookupResult::Available {
            data: Box::new(AvailabilityResult {
                domain: "test123.xyz".to_string(),
                available: true,
                confidence: "medium".to_string(),
                method: "whois_error".to_string(),
                details: Some("WHOIS server indicates no matching records".to_string()),
            }),
            rdap_error: "RDAP failed".to_string(),
            whois_error: "WHOIS failed".to_string(),
            whois_data: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"source\":\"available\""));
        assert!(json.contains("\"available\":true"));
        assert!(json.contains("test123.xyz"));

        assert_eq!(result.domain_name(), Some("test123.xyz".to_string()));
        assert!(result.is_available());
        assert!(!result.is_rdap());
        assert!(!result.is_whois());
        assert!(result.registrar().is_none());
        assert_eq!(result.expiration_info(), (None, None));
    }

    #[test]
    #[allow(deprecated)]
    fn test_smart_lookup_builder() {
        let lookup = SmartLookup::new().prefer_rdap(false).include_fallback(true);
        assert!(!lookup.prefer_rdap);
        assert!(lookup.include_fallback);
    }

    #[test]
    fn test_lookup_cache_clear() {
        // Serialized: the waiter-coalescing test inserts into LOOKUP_CACHE,
        // and an unsynchronized clear here would race both its insert (this
        // assert) and its waiters' cache read (that test's counter assert).
        let _serial = INFLIGHT_TEST_SERIAL
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        SmartLookup::clear_cache();
        assert!(LOOKUP_CACHE.is_empty());
    }

    // ---------------- trim_raw_response char-boundary safety ----------------

    #[test]
    fn truncate_on_char_boundary_does_not_panic_on_multibyte_straddle() {
        const MAX_RAW: usize = 32 * 1024;
        // Build a string longer than MAX_RAW with a 3-byte char straddling the
        // MAX_RAW byte offset: fill up to MAX_RAW-1 bytes of ASCII, then a
        // multi-byte char so byte MAX_RAW lands mid-character.
        let mut s = "a".repeat(MAX_RAW - 1);
        s.push('€'); // 3 bytes (E2 82 AC) — byte MAX_RAW is NOT a boundary
        s.push_str(&"b".repeat(100));
        assert!(!s.is_char_boundary(MAX_RAW));

        // Must not panic.
        truncate_on_char_boundary(&mut s, MAX_RAW);
        assert!(s.len() <= MAX_RAW);
        // Result is valid UTF-8 (String invariant upheld) — backed up below
        // the straddling char.
        assert_eq!(s.len(), MAX_RAW - 1);
    }

    #[test]
    fn trim_raw_response_truncates_multibyte_whois_without_panic() {
        const MAX_RAW: usize = 32 * 1024;
        let mut raw = "a".repeat(MAX_RAW - 1);
        raw.push('€');
        raw.push_str(&"b".repeat(1000));

        let mut w = empty_whois("example.com");
        w.raw_response = raw;
        let result = trim_raw_response(LookupResult::Whois {
            data: w,
            rdap_error: None,
            rdap_fallback: None,
        });
        if let LookupResult::Whois { data, .. } = result {
            assert!(data.raw_response.ends_with("[truncated]"));
        } else {
            panic!("expected Whois variant");
        }
    }

    // ---------------- sanitize_error_for_public ----------------

    #[test]
    fn test_sanitize_strips_ipv4() {
        let msg = "RDAP URL resolves to reserved IP 10.0.0.1 which is forbidden";
        let sanitized = sanitize_error_for_public(msg);
        assert!(
            !sanitized.contains("10.0.0.1"),
            "IPv4 should be stripped, got: {}",
            sanitized
        );
        assert!(sanitized.contains("[ip-redacted]"));
    }

    #[test]
    fn test_sanitize_strips_multiple_ipv4() {
        let msg = "Could not connect to 192.168.1.1 after trying 127.0.0.1";
        let sanitized = sanitize_error_for_public(msg);
        assert!(!sanitized.contains("192.168.1.1"));
        assert!(!sanitized.contains("127.0.0.1"));
        // Two redactions expected.
        assert_eq!(sanitized.matches("[ip-redacted]").count(), 2);
    }

    #[test]
    fn test_sanitize_strips_ipv6() {
        let msg = "RDAP URL resolves to reserved IP fe80::1 which is forbidden";
        let sanitized = sanitize_error_for_public(msg);
        assert!(!sanitized.contains("fe80::1"));
        assert!(sanitized.contains("[ip-redacted]"));
    }

    #[test]
    fn sanitize_leaves_mac_address_like_tokens_alone() {
        let msg = "error code af:ba:12 at line 5";
        let out = sanitize_error_for_public(msg);
        assert!(
            out.contains("af:ba:12"),
            "MAC fragment should not be stripped: {}",
            out
        );
    }

    #[test]
    fn sanitize_strips_real_ipv6() {
        let msg = "cannot reach 2001:db8::1 — timeout";
        let out = sanitize_error_for_public(msg);
        assert!(!out.contains("2001:db8::1"));
        assert!(out.contains("[ip-redacted]"));
    }

    #[test]
    fn sanitize_strips_fe80_link_local() {
        let msg = "peer at fe80::1 unreachable";
        let out = sanitize_error_for_public(msg);
        assert!(out.contains("[ip-redacted]"));
    }

    #[test]
    fn test_sanitize_truncates_long_message() {
        // Build a 500-char message with no IPs.
        let long = "a".repeat(500);
        let sanitized = sanitize_error_for_public(&long);
        // Should cap at MAX_PUBLIC_ERROR_LEN chars + ellipsis.
        let char_count = sanitized.chars().count();
        assert_eq!(char_count, MAX_PUBLIC_ERROR_LEN + 1);
        assert!(sanitized.ends_with('…'));
    }

    #[test]
    fn test_sanitize_preserves_short_messages() {
        let msg = "RDAP timed out after 15s";
        let sanitized = sanitize_error_for_public(msg);
        assert_eq!(sanitized, msg);
    }

    // ---------------- RdapOutcome classification ----------------

    #[test]
    fn test_is_rdap_response_useful_detects_no_data() {
        use crate::rdap::RdapResponse;
        // Construct a response with a name but no events, entities, NS, or status
        // — this is the "200 OK but no useful fields" case that should be
        // classified as RdapOutcome::NoData (not Useful, not Error).
        let resp = RdapResponse {
            ldh_name: Some("example.com".to_string()),
            ..Default::default()
        };
        assert!(
            !rdap_response_is_useful(&resp),
            "Response with only a name should be classified as NoData"
        );

        // And one with a name + status IS useful (sanity check).
        let useful = RdapResponse {
            ldh_name: Some("example.com".to_string()),
            status: vec!["active".to_string()],
            ..Default::default()
        };
        assert!(rdap_response_is_useful(&useful));
    }

    // ---------------- Coalescing ----------------

    // Verifies that when multiple concurrent lookups hit the in-flight map
    // for the same domain, later arrivals observe the existing Weak<Notify>
    // and become waiters rather than racing a second lookup. We test the
    // map-level primitive here because the full SmartLookup pipeline
    // requires network access to exercise.
    // INFLIGHT_TEST_SERIAL is a std Mutex held across awaits on purpose: it
    // serializes whole async tests that share process-global state; an
    // async-aware mutex would defeat that.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn test_inflight_coalescing_map() {
        // Serialize with sibling poisoning tests: we share LOOKUP_INFLIGHT
        // state, and `InflightGuard::drop` uses `try_lock` — if a sibling
        // holds the mutex during drop, cleanup is skipped and assertions
        // fail.
        let _serial = INFLIGHT_TEST_SERIAL
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // Poison-tolerant: the sibling poisoning regression tests may run
        // earlier under `cargo test` parallelism and leave LOOKUP_INFLIGHT
        // poisoned. The production code recovers via `unwrap_or_else`,
        // so this test does the same.
        //
        // Use a per-run unique key so this test cannot race with the other
        // tests that touch LOOKUP_INFLIGHT. Previously we `clear()`ed the
        // whole map, which raced with peer tests' entries.
        let domain = unique_test_key("__coalesce");

        // Defensive: ensure our specific key is not present.
        {
            let mut m = LOOKUP_INFLIGHT.lock().unwrap_or_else(|p| p.into_inner());
            m.remove(&domain);
        }

        // First caller: no entry → becomes owner.
        let owner_notify = Arc::new(Notify::new());
        {
            let mut m = LOOKUP_INFLIGHT.lock().unwrap_or_else(|p| p.into_inner());
            assert!(m.get(&domain).and_then(|w| w.upgrade()).is_none());
            m.insert(domain.clone(), Arc::downgrade(&owner_notify));
        }

        // Second caller: sees the existing Weak and upgrades.
        let waiter = {
            let m = LOOKUP_INFLIGHT.lock().unwrap_or_else(|p| p.into_inner());
            m.get(&domain)
                .and_then(|w| w.upgrade())
                .expect("Second caller must observe in-flight entry")
        };

        // Waiter listens in the background.
        let waiter_clone = waiter.clone();
        let handle = tokio::spawn(async move {
            waiter_clone.notified().await;
        });

        // Simulate owner completing.
        tokio::time::sleep(Duration::from_millis(20)).await;
        {
            let mut m = LOOKUP_INFLIGHT.lock().unwrap_or_else(|p| p.into_inner());
            m.remove(&domain);
        }
        owner_notify.notify_waiters();

        // Waiter should unblock quickly.
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("waiter must unblock after notify")
            .expect("waiter task joined cleanly");

        // After owner removes entry and drops its Arc, the Weak is dead.
        drop(owner_notify);
        drop(waiter);
        let m = LOOKUP_INFLIGHT.lock().unwrap_or_else(|p| p.into_inner());
        assert!(m.get(&domain).and_then(|w| w.upgrade()).is_none());
    }

    // Executes the real waiter branch of `lookup_with_progress` (not just the
    // map primitive above): two concurrent `lookup_with_progress` calls find
    // an in-flight entry for their domain, subscribe to its Notify, and — once
    // the owner populates the cache, removes the entry, and notifies (the
    // exact `InflightGuard::drop` sequence) — both return the cached result
    // WITHOUT running their own network race. `LOOKUP_CONCURRENT_CALLS` is the
    // coalescing proof: it is incremented at the top of `lookup_concurrent`
    // before any I/O, so if a waiter ever falls through to ownership the
    // counter moves and this test fails deterministically.
    //
    // The owner itself is simulated (cache insert + entry removal + notify)
    // rather than a third real lookup: a real owner's `lookup_concurrent`
    // needs RDAP bootstrap + WHOIS server discovery against live endpoints,
    // and those clients expose no in-scope hermetic seam for full-path
    // injection.
    // Deliberately holds INFLIGHT_TEST_SERIAL across awaits — see
    // test_inflight_coalescing_map.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn waiters_coalesce_on_inflight_lookup_and_read_owners_cache() {
        use std::sync::atomic::Ordering;

        let _serial = INFLIGHT_TEST_SERIAL
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        let raw = unique_test_key("coalesce-waiter");
        let normalized = crate::validation::normalize_domain(&raw).expect("test key normalizes");
        LOOKUP_CACHE.remove(&normalized);

        // Simulated owner claims the in-flight slot before the waiters arrive.
        let owner_notify = Arc::new(Notify::new());
        {
            let mut m = LOOKUP_INFLIGHT.lock().unwrap_or_else(|p| p.into_inner());
            m.insert(normalized.clone(), Arc::downgrade(&owner_notify));
        }

        let calls_before = LOOKUP_CONCURRENT_CALLS.load(Ordering::SeqCst);

        // Two real concurrent callers: both must take the Waiter branch.
        let lookup = SmartLookup::new();
        let spawn_waiter = |l: SmartLookup, d: String| {
            tokio::spawn(async move { l.lookup_with_progress(&d, None).await })
        };
        let h1 = spawn_waiter(lookup.clone(), raw.clone());
        let h2 = spawn_waiter(lookup, raw);

        // Current-thread runtime: awaiting here runs both waiters up to their
        // `notified` await (their path to it is fully synchronous), so the
        // owner's completion below cannot slip in before they subscribe.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Owner completes: populate the cache, then remove the entry and
        // notify — the same order `InflightGuard::drop` uses.
        let canned = LookupResult::Whois {
            data: empty_whois(&normalized),
            rdap_error: None,
            rdap_fallback: None,
        };
        LOOKUP_CACHE.insert(normalized.clone(), canned);
        {
            let mut m = LOOKUP_INFLIGHT.lock().unwrap_or_else(|p| p.into_inner());
            m.remove(&normalized);
        }
        owner_notify.notify_waiters();

        // Both waiters must wake promptly (well under DEFAULT_INFLIGHT_WAIT)
        // and observe the owner's result.
        for handle in [h1, h2] {
            let result = tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .expect("waiter must wake via notify, not the bounded-wait timeout")
                .expect("waiter task joined cleanly")
                .expect("waiter must read the owner's cached result");
            assert!(result.is_whois());
            assert_eq!(result.domain_name(), Some(normalized.clone()));
        }

        // Coalescing proof: neither waiter ran its own `lookup_concurrent`.
        let calls_after = LOOKUP_CONCURRENT_CALLS.load(Ordering::SeqCst);
        assert_eq!(
            calls_before, calls_after,
            "coalesced waiters must not start a second network race"
        );

        LOOKUP_CACHE.remove(&normalized);
    }

    /// Builds a domain key guaranteed unique per test invocation, so that
    /// tests touching the shared LOOKUP_INFLIGHT static never collide when
    /// `cargo test` runs them in parallel. We include a nanosecond timestamp
    /// plus an atomic counter to defeat even hash-identical calls within the
    /// same nanosecond.
    fn unique_test_key(prefix: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{}_{}_{}.example.", prefix, nanos, n)
    }

    // Demonstrates that the `sanitize_error_for_public` helper is applied
    // to the rdap_error / whois_error fields written into the `Available`
    // variant. We check the call site indirectly: construct a Available
    // manually and then verify a raw error with an IP becomes redacted.
    // (Integration via real clients would require network.)
    #[test]
    fn test_sanitize_applied_to_available_fields() {
        let rdap_raw = "RDAP URL resolves to reserved IP 10.0.0.1";
        let whois_raw = "connection refused at 192.168.0.5";
        let sanitized_rdap = sanitize_error_for_public(rdap_raw);
        let sanitized_whois = sanitize_error_for_public(whois_raw);
        let result = LookupResult::Available {
            data: Box::new(AvailabilityResult {
                domain: "unreg.test".to_string(),
                available: true,
                confidence: "low".to_string(),
                method: "heuristic".to_string(),
                details: None,
            }),
            rdap_error: sanitized_rdap,
            whois_error: sanitized_whois,
            whois_data: None,
        };
        if let LookupResult::Available {
            rdap_error,
            whois_error,
            ..
        } = result
        {
            assert!(!rdap_error.contains("10.0.0.1"));
            assert!(!whois_error.contains("192.168.0.5"));
            assert!(rdap_error.contains("[ip-redacted]"));
            assert!(whois_error.contains("[ip-redacted]"));
        } else {
            panic!("expected Available variant");
        }
    }

    #[test]
    fn rdap_error_is_404_matches_standard_404() {
        let e = SeerError::RdapError("query failed with status 404 Not Found".to_string());
        assert!(rdap_error_is_404(&e));
    }

    #[test]
    fn rdap_error_is_404_matches_without_reason_phrase() {
        let e = SeerError::RdapError("query failed with status 404".to_string());
        assert!(rdap_error_is_404(&e));
    }

    #[test]
    fn rdap_error_is_404_rejects_other_statuses() {
        let e = SeerError::RdapError("query failed with status 500 Server Error".to_string());
        assert!(!rdap_error_is_404(&e));
        let e = SeerError::RdapError("query failed with status 400 Bad Request".to_string());
        assert!(!rdap_error_is_404(&e));
    }

    #[test]
    fn rdap_error_is_404_rejects_non_http_errors() {
        let e = SeerError::RdapError("connection timeout".to_string());
        assert!(!rdap_error_is_404(&e));
        let e = SeerError::Timeout("rdap".to_string());
        assert!(!rdap_error_is_404(&e));
    }

    #[test]
    fn rdap_error_is_404_rejects_incidental_404_in_message() {
        // A 404 substring inside a non-status context must not match.
        let e = SeerError::RdapError("error 40404: database corruption".to_string());
        assert!(!rdap_error_is_404(&e));
    }

    // ---------------- whois_response_is_thin ----------------

    fn empty_whois(domain: &str) -> WhoisResponse {
        WhoisResponse {
            domain: domain.to_string(),
            registrar: None,
            registrant: None,
            organization: None,
            registrant_email: None,
            registrant_phone: None,
            registrant_address: None,
            registrant_country: None,
            admin_name: None,
            admin_organization: None,
            admin_email: None,
            admin_phone: None,
            tech_name: None,
            tech_organization: None,
            tech_email: None,
            tech_phone: None,
            creation_date: None,
            expiration_date: None,
            updated_date: None,
            nameservers: vec![],
            status: vec![],
            dnssec: None,
            whois_server: String::new(),
            raw_response: String::new(),
        }
    }

    #[test]
    fn whois_response_is_thin_when_all_key_fields_missing() {
        let w = empty_whois("example.com");
        assert!(whois_response_is_thin(&w));
    }

    #[test]
    fn whois_response_is_not_thin_when_registrar_present() {
        let mut w = empty_whois("example.com");
        w.registrar = Some("Test Registrar".to_string());
        assert!(!whois_response_is_thin(&w));
    }

    #[test]
    fn whois_response_is_not_thin_when_creation_date_present() {
        let mut w = empty_whois("example.com");
        w.creation_date = Some(Utc::now());
        assert!(!whois_response_is_thin(&w));
    }

    #[test]
    fn whois_response_is_not_thin_when_expiration_date_present() {
        let mut w = empty_whois("example.com");
        w.expiration_date = Some(Utc::now());
        assert!(!whois_response_is_thin(&w));
    }

    #[test]
    fn whois_response_is_thin_even_with_nameservers_alone() {
        let mut w = empty_whois("example.com");
        w.nameservers = vec!["ns1.example.net".to_string()];
        assert!(whois_response_is_thin(&w));
    }

    // ---------------- classify_whois_leg ----------------

    use crate::rdap::RdapResponse;

    #[allow(dead_code)]
    fn make_empty_rdap_response() -> RdapResponse {
        serde_json::from_value(serde_json::json!({
            "objectClassName": "domain",
        }))
        .expect("valid minimal RDAP response")
    }

    #[test]
    fn classify_whois_leg_case_a_high_confidence() {
        let mut w = empty_whois("zaccodes.com");
        w.raw_response = "No match for \"ZACCODES.COM\".".to_string();
        assert!(w.is_available());
        let rdap_err = SeerError::RdapError("query failed with status 404 Not Found".to_string());
        let (verdict, method) =
            classify_whois_leg(&w, &rdap_err).expect("expected a routing decision");
        assert_eq!(verdict, "high");
        assert_eq!(method, "whois");
    }

    #[test]
    fn classify_whois_leg_case_b_matches_decide_fallback() {
        // Case B (thin WHOIS + RDAP 404) must classify identically to
        // `availability::decide_fallback`'s branch for the same precondition:
        // the registry's own RDAP 404 is the authoritative signal, so both
        // ladders report ("high", "rdap"). Divergence here made `seer check`
        // say "available" while `seer lookup` said "likely_available" for the
        // same domain (2026-07-11 review).
        let w = empty_whois("example.xyz");
        assert!(!w.is_available(), "this WHOIS body has no 'no match' text");
        let rdap_err = SeerError::RdapError("query failed with status 404 Not Found".to_string());
        let (verdict, method) =
            classify_whois_leg(&w, &rdap_err).expect("expected a routing decision");
        assert_eq!(verdict, "high");
        assert_eq!(method, "rdap");
    }

    #[test]
    fn classify_whois_leg_rejects_thin_whois_without_404() {
        let w = empty_whois("example.xyz");
        let rdap_err = SeerError::RdapError("connection timeout".to_string());
        assert!(classify_whois_leg(&w, &rdap_err).is_none());
    }

    #[test]
    fn classify_whois_leg_rejects_whois_with_real_data() {
        let mut w = empty_whois("legacy.tld");
        w.registrar = Some("Legacy Registry".to_string());
        w.creation_date = Some(Utc::now());
        let rdap_err = SeerError::RdapError("query failed with status 404 Not Found".to_string());
        assert!(classify_whois_leg(&w, &rdap_err).is_none());
    }

    #[test]
    fn classify_whois_leg_case_a_wins_over_case_b() {
        let mut w = empty_whois("example.com");
        w.raw_response = "No match for \"EXAMPLE.COM\".".to_string();
        let rdap_err = SeerError::RdapError("query failed with status 404 Not Found".to_string());
        let (verdict, _) = classify_whois_leg(&w, &rdap_err).unwrap();
        assert_eq!(verdict, "high");
    }

    // ---------------- should_route_to_availability ----------------
    //
    // Regression coverage for the v0.26.6 fix: when RDAP returned an HTTP 200
    // (even with thin body), a WHOIS "no match" must NOT be treated as
    // evidence of availability — that would let propagation lag flip the
    // verdict for a domain the registry has already provisioned.

    #[test]
    fn rdap_200_vetoes_whois_no_match() {
        let mut w = empty_whois("freshly-registered.com");
        w.raw_response = "No match for \"FRESHLY-REGISTERED.COM\".".to_string();
        // rdap_returned_200 = true, no rdap_seer_error (NoData has no error).
        assert!(
            should_route_to_availability(true, None, &w).is_none(),
            "RDAP 200 must veto WHOIS-only availability claim",
        );
    }

    #[test]
    fn rdap_200_vetoes_even_with_thin_whois() {
        let w = empty_whois("freshly-registered.com");
        // Thin WHOIS without is_available() patterns.
        assert!(
            should_route_to_availability(true, None, &w).is_none(),
            "RDAP 200 must veto even when WHOIS is thin",
        );
    }

    #[test]
    fn rdap_404_with_whois_no_match_routes_to_available() {
        let mut w = empty_whois("genuinely-free.com");
        w.raw_response = "No match for \"GENUINELY-FREE.COM\".".to_string();
        let rdap_err = SeerError::RdapError("query failed with status 404".to_string());
        let result = should_route_to_availability(false, Some(&rdap_err), &w);
        assert_eq!(result, Some(("high", "whois")));
    }

    #[test]
    fn rdap_error_with_whois_is_available_still_routes_case_a() {
        let mut w = empty_whois("genuinely-free.com");
        w.raw_response = "Domain not found".to_string();
        // RDAP errored for a non-404 reason (e.g. bootstrap failure); WHOIS
        // signal alone should still route to availability.
        let rdap_err = SeerError::RdapBootstrapError("all registries failed".to_string());
        let result = should_route_to_availability(false, Some(&rdap_err), &w);
        assert_eq!(result, Some(("high", "whois")));
    }

    #[test]
    fn rdap_grace_timeout_with_whois_is_available_routes_case_a() {
        // GraceTimeout path: rdap_returned_200 = false, rdap_seer_error = None.
        let mut w = empty_whois("genuinely-free.com");
        w.raw_response = "No match".to_string();
        let result = should_route_to_availability(false, None, &w);
        assert_eq!(result, Some(("high", "whois")));
    }

    #[test]
    fn no_rdap_200_no_error_thick_whois_stays_in_whois_path() {
        let mut w = empty_whois("registered.com");
        w.registrar = Some("Example Registrar Ltd".to_string());
        // GraceTimeout-like: rdap_returned_200=false, no error, and WHOIS
        // does not look free. Must return None so the caller picks
        // `LookupResult::Whois`.
        assert!(should_route_to_availability(false, None, &w).is_none());
    }

    // ---------------- classify_thin_fallback ----------------

    #[test]
    fn thin_fallback_refusal_is_inconclusive_regardless_of_dns() {
        // issue #45: a registry refusal/throttle must never be guessed into
        // "available" (from NXDOMAIN) or "registered" (from delegation). This
        // is the inversion that was fixed in `availability::decide_fallback`
        // but previously bypassed on the smart-lookup hot path.
        for dns in [
            DnsPresence::Absent,
            DnsPresence::Present,
            DnsPresence::Unknown,
        ] {
            assert_eq!(
                classify_thin_fallback(true, false, true, dns),
                ThinFallback::Inconclusive
            );
        }
    }

    #[test]
    fn thin_fallback_nxdomain_is_available() {
        assert_eq!(
            classify_thin_fallback(true, false, false, DnsPresence::Absent),
            ThinFallback::Available
        );
    }

    #[test]
    fn thin_fallback_delegated_is_registered() {
        // The zac.email / Identity-Digital case: a no-service WHOIS leg, RDAP
        // unavailable (throttled / grace-truncated), but the apex IS delegated
        // in DNS — the domain is registered and must not render as blank.
        assert_eq!(
            classify_thin_fallback(true, false, false, DnsPresence::Present),
            ThinFallback::Registered
        );
    }

    #[test]
    fn thin_fallback_unknown_dns_uses_whois() {
        // A failed DNS probe is not positive evidence either way.
        assert_eq!(
            classify_thin_fallback(true, false, false, DnsPresence::Unknown),
            ThinFallback::UseWhois
        );
    }

    #[test]
    fn thin_fallback_requires_thin_whois() {
        // A WHOIS body with real registration data uses the normal Whois path.
        assert_eq!(
            classify_thin_fallback(false, false, false, DnsPresence::Absent),
            ThinFallback::UseWhois
        );
    }

    #[test]
    fn thin_fallback_vetoed_by_rdap_200() {
        // A 200 from RDAP (object exists) vetoes any DNS-derived reclassification
        // — and even a refusal banner — because the object provably exists.
        assert_eq!(
            classify_thin_fallback(true, true, false, DnsPresence::Absent),
            ThinFallback::UseWhois
        );
        assert_eq!(
            classify_thin_fallback(true, true, true, DnsPresence::Present),
            ThinFallback::UseWhois
        );
    }

    // ---------------- race_with_grace ----------------
    //
    // Paused-clock tests of the RDAP/WHOIS race semantics: the losing leg is
    // grace-truncated ONLY when the winner brought usable data. A winner that
    // failed (or returned an unusable body) leaves the other leg as the sole
    // possible source of registry data, so it must run to its own completion.
    // This is the .ru case: the RDAP bootstrap miss fails in microseconds and
    // must not shave the WHOIS budget down to the grace period.

    /// A leg that resolves to `value` after `secs` of (paused, auto-advanced)
    /// tokio time.
    async fn leg<T>(secs: u64, value: T) -> T {
        tokio::time::sleep(Duration::from_secs(secs)).await;
        value
    }

    #[tokio::test(start_paused = true)]
    async fn race_awaits_whois_fully_when_rdap_errors_first() {
        let rdap = leg(0, Err::<&str, &str>("no RDAP server for example.ru"));
        // Well beyond the grace period, within the WHOIS client's own budget.
        let whois = leg(20, Ok::<&str, &str>("whois data"));
        let (r, w) = race_with_grace(rdap, whois, |r| r.is_ok(), |w| w.is_ok()).await;
        assert!(matches!(r, LegOutcome::Completed(Err(_))));
        assert!(
            matches!(w, LegOutcome::Completed(Ok("whois data"))),
            "WHOIS must not be grace-truncated behind an RDAP failure"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn race_awaits_rdap_fully_when_whois_errors_first() {
        let rdap = leg(20, Ok::<&str, &str>("rdap data"));
        let whois = leg(0, Err::<&str, &str>("connection refused"));
        let (r, w) = race_with_grace(rdap, whois, |r| r.is_ok(), |w| w.is_ok()).await;
        assert!(
            matches!(r, LegOutcome::Completed(Ok("rdap data"))),
            "RDAP must not be grace-truncated behind a WHOIS failure"
        );
        assert!(matches!(w, LegOutcome::Completed(Err(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn race_truncates_whois_when_rdap_answers_with_data() {
        let rdap = leg(0, Ok::<&str, &str>("useful rdap"));
        let whois = leg(20, Ok::<&str, &str>("whois data"));
        let (r, w) = race_with_grace(rdap, whois, |r| r.is_ok(), |w| w.is_ok()).await;
        assert!(matches!(r, LegOutcome::Completed(Ok(_))));
        assert!(
            matches!(w, LegOutcome::GraceTruncated),
            "a data-bearing RDAP winner only owes WHOIS the grace period"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn race_truncates_rdap_when_whois_answers_with_data() {
        let rdap = leg(20, Ok::<&str, &str>("rdap data"));
        let whois = leg(0, Ok::<&str, &str>("whois data"));
        let (r, w) = race_with_grace(rdap, whois, |r| r.is_ok(), |w| w.is_ok()).await;
        assert!(matches!(r, LegOutcome::GraceTruncated));
        assert!(matches!(w, LegOutcome::Completed(Ok(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn race_loser_inside_grace_period_still_completes() {
        let rdap = leg(0, Ok::<&str, &str>("useful rdap"));
        // Within the 5s grace period.
        let whois = leg(2, Ok::<&str, &str>("whois data"));
        let (r, w) = race_with_grace(rdap, whois, |r| r.is_ok(), |w| w.is_ok()).await;
        assert!(matches!(r, LegOutcome::Completed(Ok(_))));
        assert!(matches!(w, LegOutcome::Completed(Ok("whois data"))));
    }

    #[tokio::test(start_paused = true)]
    async fn race_awaits_whois_fully_when_rdap_wins_with_unusable_data() {
        // An Ok the predicate rejects (e.g. a thin RDAP 200 with no useful
        // fields) is not "data in hand" — WHOIS still runs to completion.
        let rdap = leg(0, Ok::<&str, &str>("thin"));
        let whois = leg(20, Ok::<&str, &str>("whois data"));
        let (r, w) = race_with_grace(
            rdap,
            whois,
            |r| matches!(r, Ok(s) if *s == "useful"),
            |w| w.is_ok(),
        )
        .await;
        assert!(matches!(r, LegOutcome::Completed(Ok("thin"))));
        assert!(matches!(w, LegOutcome::Completed(Ok("whois data"))));
    }

    #[tokio::test(start_paused = true)]
    async fn race_awaits_rdap_fully_when_whois_wins_with_thin_body() {
        // The Identity-Digital case from the WHOIS side: the registry's
        // port-43 endpoint answers Ok instantly but the body carries no
        // registration data (a "no service"/"not supported" sentinel). Under
        // the old bare `is_ok()` predicate that thin win grace-truncated the
        // only viable protocol — RDAP — guaranteeing a thin result. With the
        // production `whois_leg_has_data` predicate, RDAP runs to its own
        // bounded completion, mirroring the RDAP-side usefulness gate.
        let rdap = leg(20, Ok::<&str, &str>("rdap data"));
        let whois = leg(0, Ok::<_, SeerError>(empty_whois("zac.email")));
        let (r, w) = race_with_grace(rdap, whois, |r| r.is_ok(), whois_leg_has_data).await;
        assert!(
            matches!(r, LegOutcome::Completed(Ok("rdap data"))),
            "RDAP must not be grace-truncated behind a thin WHOIS answer"
        );
        assert!(matches!(w, LegOutcome::Completed(Ok(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn race_truncates_rdap_when_whois_wins_with_real_data() {
        // Complement: a WHOIS win that DOES carry registration data still
        // only owes RDAP the grace period.
        let mut whois_data = empty_whois("example.com");
        whois_data.registrar = Some("Mock Registrar".to_string());
        let rdap = leg(20, Ok::<&str, &str>("rdap data"));
        let whois = leg(0, Ok::<_, SeerError>(whois_data));
        let (r, w) = race_with_grace(rdap, whois, |r| r.is_ok(), whois_leg_has_data).await;
        assert!(
            matches!(r, LegOutcome::GraceTruncated),
            "a data-bearing WHOIS winner only owes RDAP the grace period"
        );
        assert!(matches!(w, LegOutcome::Completed(Ok(_))));
    }

    // ---------------- whois_leg_has_data ----------------

    #[test]
    fn whois_leg_has_data_rejects_thin_ok_and_errors() {
        // Thin Ok bodies — including "No match" availability sentinels — are
        // not data in hand: the race must keep RDAP alive so a late RDAP 200
        // can still veto a stale WHOIS "no match" (v0.26.6 rule).
        assert!(!whois_leg_has_data(&Ok(empty_whois("example.email"))));
        let mut no_match = empty_whois("example.com");
        no_match.raw_response = "No match for \"EXAMPLE.COM\".".to_string();
        assert!(!whois_leg_has_data(&Ok(no_match)));
        assert!(!whois_leg_has_data(&Err(SeerError::WhoisError(
            "connection refused".to_string()
        ))));
    }

    #[test]
    fn whois_leg_has_data_accepts_registration_data() {
        // Stays in lockstep with `whois_response_is_thin`: any of the three
        // key registration signals makes the leg a data-bearing winner.
        let mut w = empty_whois("example.com");
        w.registrar = Some("Mock Registrar".to_string());
        assert!(whois_leg_has_data(&Ok(w)));
        let mut w = empty_whois("example.com");
        w.expiration_date = Some(Utc::now());
        assert!(whois_leg_has_data(&Ok(w)));
    }

    // ---------------- grace_truncated_error ----------------

    #[test]
    fn grace_truncated_error_says_answered_not_won() {
        // Truncation only happens behind a data-bearing winner, so the message
        // must say the winner *answered* — the old "after RDAP won" wording
        // misled when the winner had merely finished first with an error.
        let msg = grace_truncated_error("WHOIS", "RDAP");
        assert_eq!(
            msg,
            format!(
                "WHOIS did not respond within the {}s grace period after RDAP answered",
                PROTOCOL_GRACE_PERIOD.as_secs()
            )
        );
        assert!(!msg.contains("won"));
    }

    #[test]
    fn grace_truncated_error_is_symmetric() {
        let msg = grace_truncated_error("RDAP", "WHOIS");
        assert!(msg.starts_with("RDAP did not respond"));
        assert!(msg.ends_with("after WHOIS answered"));
    }

    // ---------------- Mutex poisoning recovery ----------------

    /// Regression: a panic inside `LOOKUP_INFLIGHT.lock()` must not wedge
    /// the tracker forever. After the mutex is poisoned, subsequent
    /// acquisition attempts must still succeed via `unwrap_or_else`.
    ///
    /// This isolates the lookup_with_progress acquisition site (formerly a
    /// `.expect("LOOKUP_INFLIGHT mutex poisoned")`) by exercising the same
    /// `.lock().unwrap_or_else(|p| p.into_inner())` pattern directly.
    #[test]
    fn lookup_inflight_recovers_from_poisoned_mutex() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        // Serialize with sibling tests that also touch LOOKUP_INFLIGHT.
        let _serial = INFLIGHT_TEST_SERIAL
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        // Poison the real static by panicking while holding the guard.
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _guard = LOOKUP_INFLIGHT.lock().unwrap();
            panic!("poisoning LOOKUP_INFLIGHT for test");
        }));

        // At this point LOOKUP_INFLIGHT is poisoned. Plain .lock() would
        // return Err(PoisonError). The recovery pattern used in
        // lookup_with_progress must still yield a usable guard.
        let mut guard = LOOKUP_INFLIGHT.lock().unwrap_or_else(|p| p.into_inner());
        // Use a per-run unique canary so parallel tests cannot collide.
        let canary = unique_test_key("__poison_recovery");
        guard.insert(canary.clone(), Weak::new());
        assert!(guard.contains_key(&canary));
        guard.remove(&canary);
    }

    /// Regression: InflightGuard::drop must also tolerate mutex poisoning
    /// without panicking — the Poisoned arm should still remove the entry.
    #[test]
    fn inflight_guard_drop_recovers_from_poisoned_mutex() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        // Serialize with sibling tests that also touch LOOKUP_INFLIGHT —
        // the critical race was `InflightGuard::drop` using `try_lock`
        // and silently skipping cleanup when a parallel test held the
        // mutex, leaving this test's entry in the map and failing the
        // final assertion.
        let _serial = INFLIGHT_TEST_SERIAL
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        // Seed an entry and arm a guard for it. Use a per-run unique key
        // so this test can never collide with siblings under parallel
        // `cargo test` — previously a hard-coded key raced with the peer
        // coalescing test's `m.clear()` call.
        let key = unique_test_key("__drop_poison");
        let notify = Arc::new(Notify::new());
        {
            let mut map = LOOKUP_INFLIGHT.lock().unwrap_or_else(|p| p.into_inner());
            map.insert(key.clone(), Arc::downgrade(&notify));
        }
        let guard = InflightGuard {
            key: key.clone(),
            notify: notify.clone(),
        };

        // Poison the mutex.
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _g = LOOKUP_INFLIGHT.lock().unwrap();
            panic!("poisoning LOOKUP_INFLIGHT for drop test");
        }));

        // Dropping the guard must not panic and must remove the entry via
        // the Poisoned branch of the new try_lock match.
        drop(guard);

        let map = LOOKUP_INFLIGHT.lock().unwrap_or_else(|p| p.into_inner());
        assert!(
            !map.contains_key(&key),
            "poisoned-mutex drop path should still remove the in-flight entry"
        );
    }
}
