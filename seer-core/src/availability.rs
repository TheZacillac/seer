//! Domain availability checking.
//!
//! Determines if a domain is available for registration by interpreting
//! WHOIS/RDAP "not found" responses.

use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use crate::dns::{DnsPresence, DnsResolver};
use crate::error::{Result, SeerError};
use crate::rdap::{rdap_error_is_404, RdapClient};
use crate::whois::{WhoisClient, WhoisResponse};

/// Result of a domain availability check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailabilityResult {
    /// The domain that was checked.
    pub domain: String,
    /// Whether the domain appears to be available for registration.
    pub available: bool,
    /// Confidence level of the result ("high", "medium", "low").
    pub confidence: String,
    /// How availability was determined.
    pub method: String,
    /// Additional details about the check.
    pub details: Option<String>,
}

impl AvailabilityResult {
    /// A verdict with no details; chain [`with_details`](Self::with_details)
    /// to explain it.
    pub(crate) fn new(domain: &str, available: bool, confidence: &str, method: &str) -> Self {
        Self {
            domain: domain.to_string(),
            available,
            confidence: confidence.to_string(),
            method: method.to_string(),
            details: None,
        }
    }

    pub(crate) fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Stable verdict string derived from `(available, confidence)`. Use this
    /// instead of branching on `confidence` alone — a `confidence: "high"`
    /// result can still mean "registered" when `available == false`.
    pub fn verdict(&self) -> &'static str {
        match (self.available, self.confidence.as_str()) {
            (true, "high") => "available",
            (true, "medium") => "likely_available",
            (false, "high") => "registered",
            (false, "medium") => "likely_registered",
            _ => "unknown",
        }
    }
}

/// A prior RDAP attempt handed to [`AvailabilityChecker::check_with_prior`], so
/// the checker can reuse the smart-lookup race's result instead of re-issuing
/// the identical query that just ran (and re-hammering a throttling registry).
pub(crate) enum PriorRdap {
    /// RDAP returned a response (HTTP 200); reuse it rather than re-querying.
    /// Boxed because an `RdapResponse` dwarfs the other variants.
    Response(Box<crate::rdap::RdapResponse>),
    /// RDAP failed with this error; reuse it rather than re-querying.
    Failed(SeerError),
    /// No usable RDAP result (e.g. grace-truncated); query fresh.
    Missing,
}

/// A prior WHOIS attempt handed to [`AvailabilityChecker::check_with_prior`].
///
/// There is no `Response` variant: a successful WHOIS is consumed before the
/// smart-lookup ever reaches the availability fallback, so the checker only
/// ever reuses a failed leg or re-queries a genuinely missing one.
pub(crate) enum PriorWhois {
    /// WHOIS failed with this error; reuse it rather than re-querying.
    Failed(SeerError),
    /// No usable WHOIS result (e.g. grace-truncated); query fresh.
    Missing,
}

/// Checks domain availability by attempting lookups and interpreting failures.
#[derive(Debug, Clone, Default)]
pub struct AvailabilityChecker {
    rdap_client: RdapClient,
    whois_client: WhoisClient,
    dns_resolver: DnsResolver,
}

impl AvailabilityChecker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a checker whose sub-clients honor the timeouts in `config`.
    pub fn from_config(config: &crate::config::SeerConfig) -> Self {
        Self {
            rdap_client: RdapClient::from_config(config),
            whois_client: WhoisClient::from_config(config),
            dns_resolver: DnsResolver::from_config(config),
        }
    }

    /// Check if a domain is available for registration.
    ///
    /// A name below its registrable domain (`mail.google.com`) is never
    /// reported available on the strength of the registry having no object
    /// for it: its verdict comes from a check of the registrable parent
    /// (`google.com`) instead, since only the parent can be registered.
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn check(&self, domain: &str) -> Result<AvailabilityResult> {
        let domain = crate::validation::normalize_domain(domain)?;
        debug!(domain = %domain, "Checking domain availability");
        let result = self.check_registry(&domain).await;
        Ok(self.guard_subdomain_claim(result).await)
    }

    /// The RDAP → WHOIS + DNS ladder for an already-normalized name, without
    /// the subdomain guard.
    async fn check_registry(&self, domain: &str) -> AvailabilityResult {
        // Try RDAP first - it gives structured error responses.
        match self.rdap_client.lookup_domain(domain).await {
            Ok(response) => decide_from_rdap(domain, response),
            Err(rdap_err) => {
                debug!(error = %rdap_err, "RDAP lookup failed, falling back to WHOIS + DNS");
                // Probe WHOIS and the apex DNS presence concurrently. DNS is
                // only the tie-breaker when WHOIS is thin/blocked/errored and
                // the RDAP failure was not an authoritative 404, so running it
                // alongside WHOIS (rather than on demand) adds no extra
                // wall-clock time.
                let (whois_result, dns_presence) = tokio::join!(
                    self.whois_client.lookup(domain),
                    self.dns_resolver.presence(domain),
                );
                decide_fallback(domain, &rdap_err, whois_result, dns_presence)
            }
        }
    }

    /// Re-derives an "available" claim for a name that sits *below* its
    /// registrable domain.
    ///
    /// Registries hold objects only for registrable names, so for
    /// `mail.google.com` both RDAP (404) and WHOIS ("No match") answer "no
    /// such domain" — which used to be reported as AVAILABLE with high
    /// confidence. Only the registrable parent (`google.com`) can be
    /// registered, so the verdict is taken from a check of the parent (see
    /// [`subdomain_verdict`]). Results for registrable names, and every
    /// not-available result, pass through untouched with no extra queries.
    pub(crate) async fn guard_subdomain_claim(
        &self,
        result: AvailabilityResult,
    ) -> AvailabilityResult {
        if !result.available {
            return result;
        }
        let Some(parent) = crate::psl::registrable_parent(&result.domain) else {
            return result;
        };
        debug!(
            domain = %result.domain,
            parent = %parent,
            "No registry object for a subdomain; checking its registrable parent"
        );
        let parent_result = self.check_registry(parent).await;
        subdomain_verdict(&result.domain, &parent_result)
    }

    /// Like [`check`](Self::check), but reuses protocol outcomes already
    /// gathered by the caller (the smart-lookup RDAP+WHOIS race), issuing only
    /// the queries that are genuinely missing or were grace-truncated. The DNS
    /// presence probe runs exactly as in `check`.
    ///
    /// Routing through the same pure deciders (`decide_from_rdap` /
    /// [`classify_fallback`]) guarantees an identical verdict to `check` for
    /// the same protocol outcomes — this path only removes redundant network
    /// calls.
    #[instrument(skip(self, prior_rdap, prior_whois), fields(domain = %domain))]
    pub(crate) async fn check_with_prior(
        &self,
        domain: &str,
        prior_rdap: PriorRdap,
        prior_whois: PriorWhois,
    ) -> Result<AvailabilityResult> {
        let domain = crate::validation::normalize_domain(domain)?;
        debug!(domain = %domain, "Checking availability (reusing prior protocol outcomes)");

        // Reuse the prior RDAP result; only re-query when it is truly absent
        // (grace-truncated), never when it already succeeded or errored.
        let rdap = match prior_rdap {
            PriorRdap::Response(r) => Ok(*r),
            PriorRdap::Failed(e) => Err(e),
            PriorRdap::Missing => self.rdap_client.lookup_domain(&domain).await,
        };

        let result = match rdap {
            Ok(response) => decide_from_rdap(&domain, response),
            Err(rdap_err) => {
                // Reuse the prior WHOIS result; only re-query when absent. The
                // DNS presence probe always runs (it is the tie-breaker
                // `decide_fallback` consults), concurrently with a fresh WHOIS
                // query when one is needed.
                let (whois_result, dns_presence) = match prior_whois {
                    PriorWhois::Failed(e) => (Err(e), self.dns_resolver.presence(&domain).await),
                    PriorWhois::Missing => tokio::join!(
                        self.whois_client.lookup(&domain),
                        self.dns_resolver.presence(&domain),
                    ),
                };
                decide_fallback(&domain, &rdap_err, whois_result, dns_presence)
            }
        };
        Ok(self.guard_subdomain_claim(result).await)
    }
}

/// Details for a thin WHOIS body the registry refused or throttled. Shared
/// with the smart-lookup thin fallback so both paths word it the same.
pub(crate) const REFUSED_DETAILS: &str =
    "Registry refused or throttled the query; availability is inconclusive";

/// Details for a thin WHOIS body with an NXDOMAIN apex (shared as above).
pub(crate) const THIN_NXDOMAIN_DETAILS: &str =
    "No registry data available; domain has no DNS presence (NXDOMAIN)";

/// Verdict for a name below its registrable domain, derived from the check
/// of that registrable `parent` (see
/// [`AvailabilityChecker::guard_subdomain_claim`]).
///
/// The name itself is never "available": it cannot be registered on its
/// own. Under a (likely) registered parent it inherits the parent's
/// registered verdict and confidence; under an available or undetermined
/// parent the verdict is unknown (confidence `none`) and the details say
/// which name to register instead.
fn subdomain_verdict(domain: &str, parent: &AvailabilityResult) -> AvailabilityResult {
    let p = &parent.domain;
    let (confidence, status) = match parent.verdict() {
        "registered" | "likely_registered" => {
            (parent.confidence.clone(), format!("{p} is registered"))
        }
        "available" | "likely_available" => (
            "none".to_string(),
            format!("{p} appears available; register {p} to obtain {domain}"),
        ),
        _ => (
            "none".to_string(),
            format!("the registration status of {p} could not be determined"),
        ),
    };
    AvailabilityResult::new(domain, false, &confidence, "registrable_parent").with_details(format!(
        "{domain} is not itself registrable: it is a name under the registrable domain {p}, \
         and registries hold no object for subdomains. {status}."
    ))
}

/// Pure decision function: build an `AvailabilityResult` from a successful
/// RDAP lookup. Extracted from `check()` so the decision matrix can be
/// table-tested without a network stack.
fn decide_from_rdap(domain: &str, response: crate::rdap::RdapResponse) -> AvailabilityResult {
    let statuses: Vec<String> = response.status.clone();
    let is_redemption = statuses.iter().any(|s| {
        // RDAP/EPP status tokens are a controlled vocabulary; match the
        // standard redemption / pending-delete tokens exactly (case- and
        // whitespace-insensitive) rather than by substring, so a verbose
        // status such as "clientHold (no redemption requested)" is not
        // misread as the redemption state, and a capitalized "Redemption
        // Period" is still detected.
        let norm: String = s
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_lowercase();
        matches!(norm.as_str(), "redemptionperiod" | "pendingdelete")
    });

    if is_redemption {
        return AvailabilityResult::new(domain, false, "medium", "rdap")
            .with_details("Domain is in redemption/pending delete period");
    }

    AvailabilityResult::new(domain, false, "high", "rdap").with_details(format!(
        "Domain is registered (status: {})",
        statuses.join(", ")
    ))
}

/// Details for an authoritative RDAP 404.
const RDAP_404_DETAILS: &str = "Registry RDAP reports no such domain (HTTP 404)";

/// Reading of a failed (non-200) RDAP leg together with the WHOIS leg: the
/// one availability ladder behind both [`AvailabilityChecker`] and the smart
/// lookup's fallback, so the two cannot disagree for the same outcomes.
pub(crate) enum Fallback {
    /// WHOIS carries registration data (registrar, dates or nameservers): the
    /// domain is registered and that record is the answer.
    Registered,
    /// Settled by the registry signals alone.
    Verdict(AvailabilityResult),
    /// The registry signals are silent; the apex's DNS presence decides (see
    /// [`DnsTieBreak::decide`]). Callers only probe DNS for this variant.
    NeedsDns(DnsTieBreak),
}

/// A verdict pending the apex DNS-presence probe.
pub(crate) struct DnsTieBreak {
    domain: String,
    cause: SilentRegistry,
}

/// Why the registry legs left the verdict to DNS.
enum SilentRegistry {
    /// WHOIS answered without registration data (and without a refusal)
    /// while RDAP failed without a 404. `no_service` marks a registry that
    /// runs no port-43 WHOIS data service at all.
    ThinWhois { no_service: bool },
    /// Both registry legs failed; their sanitized error messages.
    BothFailed { rdap: String, whois: String },
}

/// Classifies a failed RDAP leg plus the WHOIS leg.
///
/// `rdap_err` is `None` when RDAP produced no verdict at all (the smart
/// lookup's grace-truncated leg): like any non-404 failure, it is not
/// evidence either way. Precedence, highest first:
///
/// 1. WHOIS says "no match" → available (high, `whois`).
/// 2. WHOIS carries registration data → [`Fallback::Registered`].
/// 3. RDAP 404 → available (high, `rdap`): the registry's own answer.
/// 4. A thin WHOIS refusal/throttle → inconclusive (issue #45): never
///    inverted into "available" or guessed from DNS.
/// 5. Otherwise the registry is silent → [`Fallback::NeedsDns`].
pub(crate) fn classify_fallback(
    domain: &str,
    rdap_err: Option<&SeerError>,
    whois: std::result::Result<&WhoisResponse, &SeerError>,
) -> Fallback {
    let rdap_404 = rdap_err.is_some_and(rdap_error_is_404);
    let rdap_404_verdict = || {
        Fallback::Verdict(
            AvailabilityResult::new(domain, true, "high", "rdap").with_details(RDAP_404_DETAILS),
        )
    };
    let cause = match whois {
        Ok(w) if w.is_available() => {
            return Fallback::Verdict(
                AvailabilityResult::new(domain, true, "high", "whois")
                    .with_details("WHOIS indicates domain is not registered"),
            )
        }
        Ok(w) if !w.is_thin() => return Fallback::Registered,
        // Thin WHOIS — often an access-blocked refusal like SWITCH's ".ch" —
        // but the registry's own RDAP authoritatively 404'd.
        Ok(_) if rdap_404 => return rdap_404_verdict(),
        Ok(w) if w.indicates_registry_refusal() => {
            return Fallback::Verdict(
                AvailabilityResult::new(domain, false, "none", "inconclusive")
                    .with_details(REFUSED_DETAILS),
            )
        }
        Ok(w) => SilentRegistry::ThinWhois {
            no_service: w.registry_unavailable(),
        },
        // RDAP 404 is authoritative even when the WHOIS leg errored.
        Err(_) if rdap_404 => return rdap_404_verdict(),
        // A WHOIS error carries no registry text, so it is never read as
        // "no match" — only as a failed leg.
        Err(whois_err) => SilentRegistry::BothFailed {
            rdap: rdap_err.map_or_else(|| "no response".to_string(), SeerError::sanitized_message),
            whois: whois_err.sanitized_message(),
        },
    };
    Fallback::NeedsDns(DnsTieBreak {
        domain: domain.to_string(),
        cause,
    })
}

impl DnsTieBreak {
    /// The verdict given the apex's DNS presence: NXDOMAIN reads as likely
    /// available, a delegated apex as likely registered (delegation in the
    /// TLD zone is strong evidence, but no registry confirmed it), and a
    /// failed probe as inconclusive. Confidence depends only on the evidence,
    /// never on which registry leg happened to be silent.
    pub(crate) fn decide(self, dns: DnsPresence) -> AvailabilityResult {
        let d = self.domain.as_str();
        match (dns, self.cause) {
            (DnsPresence::Absent, SilentRegistry::ThinWhois { .. }) => {
                AvailabilityResult::new(d, true, "medium", "dns_nxdomain")
                    .with_details(THIN_NXDOMAIN_DETAILS)
            }
            (DnsPresence::Absent, SilentRegistry::BothFailed { .. }) => {
                AvailabilityResult::new(d, true, "medium", "dns_nxdomain")
                    .with_details("Registry lookups failed; domain has no DNS presence (NXDOMAIN)")
            }
            (DnsPresence::Present, SilentRegistry::ThinWhois { no_service: true }) => {
                AvailabilityResult::new(d, false, "medium", "dns_present").with_details(
                    "The apex is delegated in DNS, so the domain is almost certainly \
                     registered. This TLD's registry provides no port-43 WHOIS data and \
                     RDAP was unavailable (rate-limited or unreachable); retry shortly for \
                     full RDAP detail.",
                )
            }
            (DnsPresence::Present, SilentRegistry::ThinWhois { no_service: false }) => {
                AvailabilityResult::new(d, false, "medium", "dns_present").with_details(
                    "The apex is delegated in DNS, so the domain is almost certainly \
                     registered. Registry detail was unavailable (RDAP rate-limited or \
                     unreachable and WHOIS returned no data); retry shortly for full detail.",
                )
            }
            (DnsPresence::Present, SilentRegistry::BothFailed { .. }) => {
                AvailabilityResult::new(d, false, "medium", "dns_present").with_details(
                    "Registry lookups failed, but the apex is delegated in DNS \
                     (NS records present) — the domain is almost certainly registered",
                )
            }
            (DnsPresence::Unknown, SilentRegistry::ThinWhois { .. }) => {
                AvailabilityResult::new(d, false, "none", "inconclusive").with_details(
                    "Could not determine availability: WHOIS returned no registration data, \
                     RDAP failed and the DNS presence probe failed",
                )
            }
            // The details use the sanitized error projections so this string —
            // which flows into JSON / CSV / MCP output — never carries raw
            // ANSI escapes or internal IPs from a third-party server's error.
            (DnsPresence::Unknown, SilentRegistry::BothFailed { rdap, whois }) => {
                AvailabilityResult::new(d, false, "none", "inconclusive").with_details(format!(
                    "Could not determine availability. RDAP: {rdap}. WHOIS: {whois}"
                ))
            }
        }
    }
}

/// [`classify_fallback`] resolved to a verdict, for [`AvailabilityChecker`]:
/// registration data in WHOIS reads as registered (high, `whois`), and a
/// silent registry is decided by `dns_presence`.
fn decide_fallback(
    domain: &str,
    rdap_err: &SeerError,
    whois_result: Result<WhoisResponse>,
    dns_presence: DnsPresence,
) -> AvailabilityResult {
    match classify_fallback(domain, Some(rdap_err), whois_result.as_ref()) {
        Fallback::Registered => AvailabilityResult {
            details: whois_result
                .ok()
                .and_then(|w| w.registrar)
                .map(|r| format!("Registered with {}", r)),
            ..AvailabilityResult::new(domain, false, "high", "whois")
        },
        Fallback::Verdict(verdict) => verdict,
        Fallback::NeedsDns(tie_break) => tie_break.decide(dns_presence),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SeerError;
    use crate::rdap::RdapResponse;
    use crate::whois::WhoisResponse;

    #[test]
    fn verdict_matrix() {
        let make = |available, confidence: &str| {
            AvailabilityResult::new("example.test", available, confidence, "whois")
        };
        assert_eq!(make(true, "high").verdict(), "available");
        assert_eq!(make(true, "medium").verdict(), "likely_available");
        assert_eq!(make(false, "high").verdict(), "registered");
        assert_eq!(make(false, "medium").verdict(), "likely_registered");
        assert_eq!(make(false, "none").verdict(), "unknown");
        assert_eq!(make(true, "low").verdict(), "unknown");
    }

    #[test]
    fn test_availability_result_serialization() {
        let result = AvailabilityResult::new("example.com", false, "high", "rdap")
            .with_details("Domain is registered");
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"available\":false"));
        assert!(json.contains("\"confidence\":\"high\""));
    }

    // ------------------------------------------------------------------
    // M11: Decision matrix coverage for `check()`.
    //
    // Tests the pure decision helpers — `decide_from_rdap` and
    // `decide_fallback` — that were extracted from `check()` for
    // hermetic testing. Each case asserts (available, confidence, method)
    // against a realistic input shape.
    // ------------------------------------------------------------------

    /// Small helper to build an empty WhoisResponse with the given fields
    /// populated; used to keep the test table concise.
    fn whois_with(raw: &str, registrar: Option<&str>) -> WhoisResponse {
        WhoisResponse {
            domain: "example.test".to_string(),
            registrar: registrar.map(str::to_string),
            whois_server: "whois.test".to_string(),
            raw_response: raw.to_string(),
            ..Default::default()
        }
    }

    fn rdap_with(statuses: &[&str]) -> RdapResponse {
        RdapResponse {
            status: statuses.iter().map(|s| s.to_string()).collect(),
            ldh_name: Some("example.test".to_string()),
            ..Default::default()
        }
    }

    // --- RDAP success branches ---------------------------------------

    #[test]
    fn rdap_success_registered_marks_taken_high_confidence() {
        let rdap = rdap_with(&["active"]);
        let r = decide_from_rdap("example.test", rdap);
        assert!(!r.available, "registered domain must be marked taken");
        assert_eq!(r.confidence, "high");
        assert_eq!(r.method, "rdap");
        assert!(
            r.details.as_deref().unwrap().contains("active"),
            "details should include status list"
        );
    }

    #[test]
    fn rdap_success_empty_status_marks_taken_high_confidence() {
        // Some RDAP servers return 200 with no status array populated; the
        // existence of the object still means the domain is registered.
        let rdap = rdap_with(&[]);
        let r = decide_from_rdap("example.test", rdap);
        assert!(!r.available);
        assert_eq!(r.confidence, "high");
        assert_eq!(r.method, "rdap");
    }

    #[test]
    fn rdap_success_redemption_period_marks_taken_medium_confidence() {
        let rdap = rdap_with(&["redemption period"]);
        let r = decide_from_rdap("example.test", rdap);
        assert!(!r.available, "redemption period still means taken");
        assert_eq!(r.confidence, "medium", "redemption drops confidence");
        assert_eq!(r.method, "rdap");
        assert!(r.details.as_deref().unwrap().contains("redemption"));
    }

    #[test]
    fn rdap_success_pending_delete_marks_taken_medium_confidence() {
        let rdap = rdap_with(&["pending delete"]);
        let r = decide_from_rdap("example.test", rdap);
        assert!(!r.available);
        assert_eq!(r.confidence, "medium");
        assert!(r.details.as_deref().unwrap().contains("redemption"));
    }

    #[test]
    fn rdap_status_substring_redemption_not_misclassified() {
        // A non-standard verbose status that merely CONTAINS the word
        // "redemption" must not be misread as the redemption-period state
        // (which would wrongly drop confidence to medium).
        let rdap = rdap_with(&["clientHold (no redemption requested)"]);
        let r = decide_from_rdap("example.test", rdap);
        assert!(!r.available, "still registered");
        assert_eq!(
            r.confidence, "high",
            "verbose status must not be downgraded to redemption/medium"
        );
    }

    #[test]
    fn rdap_status_redemption_detected_case_insensitively() {
        // A capitalized standard token must still be detected (the old
        // case-sensitive `contains` missed "Redemption Period").
        let rdap = rdap_with(&["Redemption Period"]);
        let r = decide_from_rdap("example.test", rdap);
        assert_eq!(
            r.confidence, "medium",
            "standard token detected regardless of case"
        );
    }

    // --- WHOIS fallback branches -------------------------------------

    #[test]
    fn rdap_fail_whois_says_available_high_confidence() {
        // is_available() reads raw_response and looks for the patterns
        // that every TLD uses to signal unregistered.
        let whois = whois_with("No match for \"example.test\".\n", None);
        let rdap_err = SeerError::RdapError("404 not found".to_string());
        let r = decide_fallback("example.test", &rdap_err, Ok(whois), DnsPresence::Unknown);
        assert!(r.available, "WHOIS 'no match' must mark available");
        assert_eq!(r.confidence, "high");
        assert_eq!(r.method, "whois");
    }

    #[test]
    fn rdap_fail_whois_says_registered_high_confidence() {
        let whois = whois_with("Domain Name: example.test\n", Some("Test Registrar"));
        let rdap_err = SeerError::RdapError("404 not found".to_string());
        let r = decide_fallback("example.test", &rdap_err, Ok(whois), DnsPresence::Unknown);
        assert!(!r.available);
        assert_eq!(r.confidence, "high");
        assert_eq!(r.method, "whois");
        assert!(r.details.as_deref().unwrap().contains("Test Registrar"));
    }

    #[test]
    fn rdap_fail_whois_without_registration_data_is_not_called_registered() {
        // A bare "Domain Name:" echo carries no registration data (thin). With
        // a non-404 RDAP failure and no DNS evidence the verdict used to be a
        // confident "registered" backed by nothing; it is inconclusive.
        let whois = whois_with("Domain Name: example.test\n", None);
        let rdap_err = SeerError::RdapError("404".to_string());
        let r = decide_fallback("example.test", &rdap_err, Ok(whois), DnsPresence::Unknown);
        assert!(!r.available);
        assert_eq!(r.confidence, "none");
        assert_eq!(r.method, "inconclusive");
    }

    // --- Both-fail branches ------------------------------------------

    #[test]
    fn rdap_fail_whois_timeout_marks_inconclusive_none_confidence() {
        let rdap_err = SeerError::Timeout("rdap timed out".to_string());
        let whois_err = SeerError::Timeout("whois timed out".to_string());
        let r = decide_fallback(
            "example.test",
            &rdap_err,
            Err(whois_err),
            DnsPresence::Unknown,
        );
        assert!(
            !r.available,
            "inconclusive means NOT available (fail-safe default)"
        );
        assert_eq!(r.confidence, "none");
        assert_eq!(r.method, "inconclusive");
        assert!(r.details.as_deref().unwrap().contains("RDAP:"));
        assert!(r.details.as_deref().unwrap().contains("WHOIS:"));
    }

    #[test]
    fn rdap_fail_whois_transport_error_with_phrase_not_available() {
        // A transport-level WHOIS failure (here a timeout) whose message
        // merely contains "no match" must NOT be read as available — only a
        // WHOIS-*protocol* error (WhoisError) can carry a registry no-match
        // signal. Otherwise an error string that incidentally quotes the
        // phrase flips a possibly-registered domain to "available".
        let rdap_err = SeerError::RdapError("503 service unavailable".to_string());
        let whois_err =
            SeerError::Timeout("no match within deadline querying whois.nic.test".to_string());
        let r = decide_fallback(
            "example.test",
            &rdap_err,
            Err(whois_err),
            DnsPresence::Present,
        );
        assert!(
            !r.available,
            "transport error text must not infer availability"
        );
    }

    #[test]
    fn rdap_fail_whois_connection_error_marks_inconclusive_none_confidence() {
        let rdap_err = SeerError::RdapError("connection refused".to_string());
        let whois_err = SeerError::WhoisError(
            "failed to connect to whois.example: connection refused".to_string(),
        );
        let r = decide_fallback(
            "example.test",
            &rdap_err,
            Err(whois_err),
            DnsPresence::Unknown,
        );
        assert!(!r.available);
        assert_eq!(r.confidence, "none");
        assert_eq!(r.method, "inconclusive");
    }

    // --- RDAP-404-is-authoritative branches (Fix #4) -----------------

    #[test]
    fn rdap_404_with_blocked_whois_marks_available() {
        // SWITCH (.ch) blocks port-43 WHOIS with a refusal carrying no
        // registration data and no availability phrase. The registry's own
        // RDAP authoritatively 404s for an unregistered domain — that 404 is
        // the signal and must win over the unhelpful WHOIS body.
        let whois = whois_with("Requests of this client are not permitted.\n", None);
        let rdap_err = SeerError::RdapError("query failed with status 404 Not Found".to_string());
        let r = decide_fallback("example.ch", &rdap_err, Ok(whois), DnsPresence::Unknown);
        assert!(
            r.available,
            "RDAP 404 must mark available even with blocked WHOIS"
        );
        assert_eq!(r.confidence, "high");
        assert_eq!(r.method, "rdap");
    }

    #[test]
    fn rdap_404_with_whois_error_marks_available() {
        // RDAP 404 is authoritative even when WHOIS itself errored out.
        let rdap_err = SeerError::RdapError("query failed with status 404".to_string());
        let whois_err = SeerError::WhoisError("connection refused".to_string());
        let r = decide_fallback(
            "example.test",
            &rdap_err,
            Err(whois_err),
            DnsPresence::Unknown,
        );
        assert!(r.available);
        assert_eq!(r.confidence, "high");
        assert_eq!(r.method, "rdap");
    }

    #[test]
    fn rdap_404_but_whois_has_full_registration_marks_registered() {
        // Conflict case: RDAP 404 but WHOIS returns real registration data
        // (registrar + dates + nameservers). Prefer the concrete registration
        // so we never tell the user a registered domain is free.
        let mut whois = whois_with("Domain Name: example.test\n", Some("Real Registrar"));
        whois.creation_date = Some(chrono::Utc::now());
        whois.nameservers = vec!["ns1.example.net".to_string()];
        let rdap_err = SeerError::RdapError("query failed with status 404 Not Found".to_string());
        let r = decide_fallback("example.test", &rdap_err, Ok(whois), DnsPresence::Unknown);
        assert!(
            !r.available,
            "concrete WHOIS registration must win over RDAP 404"
        );
        assert_eq!(r.confidence, "high");
        assert_eq!(r.method, "whois");
    }

    // --- DNS-NXDOMAIN safety net (Fix #2) ----------------------------

    #[test]
    fn thin_whois_non404_dns_absent_marks_likely_available() {
        // Red.es (.es) returns a port-43 "Conditions of use" banner that
        // parses to nothing, and .es has no RDAP server (a non-404 failure).
        // The apex is NXDOMAIN, so the domain is likely available.
        let whois = whois_with(
            "Conditions of use for the whois service via port 43\n",
            None,
        );
        let rdap_err = SeerError::RdapBootstrapError("no RDAP server for example.es".to_string());
        let r = decide_fallback("example.es", &rdap_err, Ok(whois), DnsPresence::Absent);
        assert!(r.available);
        assert_eq!(r.confidence, "medium");
        assert_eq!(r.method, "dns_nxdomain");
    }

    #[test]
    fn thin_whois_non404_dns_present_stays_unavailable() {
        // Same thin WHOIS + non-404 RDAP failure, but the apex resolves — we
        // must not claim availability.
        let whois = whois_with(
            "Conditions of use for the whois service via port 43\n",
            None,
        );
        let rdap_err = SeerError::RdapBootstrapError("no RDAP server for example.es".to_string());
        let r = decide_fallback("example.es", &rdap_err, Ok(whois), DnsPresence::Present);
        assert!(!r.available);
        assert_ne!(r.method, "dns_nxdomain");
    }

    #[test]
    fn thin_whois_non404_dns_unknown_is_inconclusive() {
        // Thin WHOIS, non-404 RDAP failure, DNS itself failed → genuinely
        // unknown: not available, and never a confident "registered" with no
        // evidence behind it.
        let whois = whois_with(
            "Conditions of use for the whois service via port 43\n",
            None,
        );
        let rdap_err = SeerError::RdapBootstrapError("no RDAP server".to_string());
        let r = decide_fallback("example.es", &rdap_err, Ok(whois), DnsPresence::Unknown);
        assert!(!r.available);
        assert_eq!(r.confidence, "none");
        assert_eq!(r.method, "inconclusive");
        assert!(r.details.is_some());
    }

    // --- the shared ladder: every input combination --------------------

    /// Expected reading of [`classify_fallback`] + [`DnsTieBreak::decide`].
    #[derive(Debug, PartialEq)]
    enum Expect {
        Registered,
        Verdict(bool, &'static str, &'static str),
    }

    fn read(
        rdap: Option<&SeerError>,
        whois: std::result::Result<&WhoisResponse, &SeerError>,
        dns: DnsPresence,
    ) -> Expect {
        let v = match classify_fallback("example.test", rdap, whois) {
            Fallback::Registered => return Expect::Registered,
            Fallback::Verdict(v) => v,
            Fallback::NeedsDns(t) => t.decide(dns),
        };
        assert!(v.details.is_some(), "every verdict explains itself: {v:?}");
        Expect::Verdict(
            v.available,
            match v.confidence.as_str() {
                "high" => "high",
                "medium" => "medium",
                "none" => "none",
                other => panic!("unexpected confidence {other}"),
            },
            match v.method.as_str() {
                "whois" => "whois",
                "rdap" => "rdap",
                "inconclusive" => "inconclusive",
                "dns_nxdomain" => "dns_nxdomain",
                "dns_present" => "dns_present",
                other => panic!("unexpected method {other}"),
            },
        )
    }

    /// Every (RDAP failure × WHOIS leg × DNS presence) combination, pinned.
    /// The smart lookup reads its fallback through the same function, so this
    /// table is the contract for both ladders.
    #[test]
    fn fallback_ladder_covers_every_input_combination() {
        use Expect::*;
        let r404 = SeerError::RdapError("query failed with status 404 Not Found".to_string());
        let r503 = SeerError::RdapError("query failed with status 503".to_string());
        let no_match = whois_with("No match for \"EXAMPLE.TEST\".\n", None);
        let mut registered = whois_with("Domain Name: example.test\n", Some("Registrar Inc."));
        registered.creation_date = Some(chrono::Utc::now());
        let thin = whois_with(
            "Conditions of use for the whois service via port 43\n",
            None,
        );
        let no_service = whois_with("TLD is not supported.\n", None);
        let refusal = whois_with("Access rate limited; please try again later.\n", None);
        let failed = SeerError::Timeout("whois timed out".to_string());
        assert!(no_service.registry_unavailable() && !no_service.indicates_registry_refusal());
        assert!(!thin.registry_unavailable() && !thin.indicates_registry_refusal());

        let all_dns = [
            DnsPresence::Absent,
            DnsPresence::Present,
            DnsPresence::Unknown,
        ];
        for rdap in [Some(&r404), Some(&r503), None] {
            let is_404 = matches!(rdap, Some(e) if rdap_error_is_404(e));
            for dns in all_dns {
                // DNS-independent rows.
                assert_eq!(
                    read(rdap, Ok(&no_match), dns),
                    Verdict(true, "high", "whois")
                );
                assert_eq!(read(rdap, Ok(&registered), dns), Registered);
                if is_404 {
                    for w in [Ok(&thin), Ok(&no_service), Ok(&refusal), Err(&failed)] {
                        assert_eq!(read(rdap, w, dns), Verdict(true, "high", "rdap"));
                    }
                    continue;
                }
                assert_eq!(
                    read(rdap, Ok(&refusal), dns),
                    Verdict(false, "none", "inconclusive"),
                    "refusal is inconclusive whatever DNS says (#45)"
                );
                // DNS decides for a silent registry.
                let expected = match dns {
                    DnsPresence::Absent => Verdict(true, "medium", "dns_nxdomain"),
                    DnsPresence::Present => Verdict(false, "medium", "dns_present"),
                    DnsPresence::Unknown => Verdict(false, "none", "inconclusive"),
                };
                for w in [Ok(&thin), Ok(&no_service), Err(&failed)] {
                    assert_eq!(read(rdap, w, dns), expected, "{rdap:?} {w:?} {dns:?}");
                }
            }
        }
    }

    #[test]
    fn both_legs_failed_dns_absent_marks_likely_available() {
        // RDAP errored (non-404), WHOIS errored (not a "not found" message),
        // but the apex is NXDOMAIN.
        let rdap_err = SeerError::Timeout("rdap timed out".to_string());
        let whois_err = SeerError::WhoisError("connection refused".to_string());
        let r = decide_fallback(
            "example.test",
            &rdap_err,
            Err(whois_err),
            DnsPresence::Absent,
        );
        assert!(r.available);
        assert_eq!(r.confidence, "medium");
        assert_eq!(r.method, "dns_nxdomain");
    }

    #[test]
    fn both_legs_failed_dns_present_marks_likely_registered() {
        // The .ru-behind-a-firewall case: the TLD has no RDAP server at all
        // (bootstrap miss) and WHOIS is unreachable (transport timeout), but
        // the apex IS delegated in DNS. Delegation in the TLD zone is strong
        // evidence of registration — report likely_registered rather than a
        // blank "unknown".
        let rdap_err = SeerError::RdapBootstrapError("no RDAP server for example.ru".to_string());
        let whois_err = SeerError::Timeout(
            "Operation failed after 3 attempts: Operation timed out".to_string(),
        );
        let r = decide_fallback(
            "example.ru",
            &rdap_err,
            Err(whois_err),
            DnsPresence::Present,
        );
        assert!(
            !r.available,
            "a delegated apex must never read as available"
        );
        assert_eq!(r.confidence, "medium");
        assert_eq!(r.method, "dns_present");
        assert_eq!(r.verdict(), "likely_registered");
        assert!(
            r.details.as_deref().unwrap().contains("delegated"),
            "details should explain the DNS-delegation evidence"
        );
    }

    // --- #45: refusal/throttle bodies route to inconclusive --------------

    #[test]
    fn rdap_fail_thin_whois_refusal_marks_inconclusive() {
        // A throttled thin WHOIS body (no registration data) with a non-404
        // RDAP failure must route to an inconclusive verdict — even with DNS
        // absent, which would otherwise read as likely-available — instead of
        // inverting a rate-limit banner ("no data found") into "available".
        let whois = whois_with(
            "Access rate limited; no data found for unauthenticated clients\n",
            None,
        );
        let rdap_err = SeerError::RdapError("503 service unavailable".to_string());
        let r = decide_fallback("example.test", &rdap_err, Ok(whois), DnsPresence::Absent);
        assert!(
            !r.available,
            "refusal/throttle must not be called available"
        );
        assert_eq!(r.confidence, "none");
        assert_eq!(r.method, "inconclusive");
    }

    #[test]
    fn rdap_fail_thin_whois_not_available_for_registration_marks_inconclusive() {
        // "not available for registration" (reserved/premium) previously
        // inverted to available; with RDAP also failing non-404 it must be
        // inconclusive, not a DNS-presence guess.
        let whois = whois_with(
            "This domain name is not available for registration.\n",
            None,
        );
        let rdap_err = SeerError::RdapBootstrapError("no RDAP server".to_string());
        let r = decide_fallback("example.test", &rdap_err, Ok(whois), DnsPresence::Absent);
        assert!(!r.available);
        assert_eq!(r.confidence, "none");
        assert_eq!(r.method, "inconclusive");
    }

    #[test]
    fn rdap_404_with_refusal_whois_still_marks_available() {
        // The refusal routing must NOT override an authoritative RDAP 404: a
        // refused/throttled port-43 body with an RDAP 404 is still available.
        let whois = whois_with("Access rate limited; please try again later.\n", None);
        let rdap_err = SeerError::RdapError("query failed with status 404 Not Found".to_string());
        let r = decide_fallback("example.test", &rdap_err, Ok(whois), DnsPresence::Unknown);
        assert!(r.available, "RDAP 404 is authoritative over a refusal body");
        assert_eq!(r.confidence, "high");
        assert_eq!(r.method, "rdap");
    }

    // --- check_with_prior: reuse without re-querying ------------------

    #[tokio::test]
    async fn check_with_prior_reuses_rdap_response_without_network() {
        // A prior successful RDAP response short-circuits to `decide_from_rdap`
        // with no WHOIS or DNS I/O — proving the in-hand outcome is reused
        // rather than re-queried, and yielding the same verdict `check` would
        // for that response.
        let checker = AvailabilityChecker::new();
        let rdap = rdap_with(&["active"]);
        let r = checker
            .check_with_prior(
                "example.test",
                PriorRdap::Response(Box::new(rdap)),
                PriorWhois::Missing,
            )
            .await
            .expect("prior-response path must not error");
        assert!(!r.available, "an existing RDAP object means registered");
        assert_eq!(r.confidence, "high");
        assert_eq!(r.method, "rdap");
    }

    #[tokio::test]
    async fn check_with_prior_reuses_redemption_status_verdict() {
        // The reused response flows through the identical redemption decision as
        // `decide_from_rdap`, so a redemption status still drops to medium.
        let checker = AvailabilityChecker::new();
        let rdap = rdap_with(&["redemption period"]);
        let r = checker
            .check_with_prior(
                "example.test",
                PriorRdap::Response(Box::new(rdap)),
                PriorWhois::Missing,
            )
            .await
            .expect("prior-response path must not error");
        assert!(!r.available);
        assert_eq!(r.confidence, "medium");
        assert_eq!(r.method, "rdap");
    }

    // --- nameservers count as registration data (DENIC, .de) ----------

    /// A DENIC-shaped parsed body: nameservers + status + changed date, but
    /// DENIC never publishes a registrar or creation/expiry dates.
    fn denic_whois() -> WhoisResponse {
        let mut w = whois_with(
            "Domain: example.de\nNserver: ns1.example.net\nStatus: connect\n",
            None,
        );
        w.nameservers = vec!["ns1.example.net".to_string()];
        w.status = vec!["active".to_string()];
        w
    }

    #[test]
    fn whois_with_nameservers_is_not_thin() {
        assert!(whois_with("", None).is_thin());
        assert!(!denic_whois().is_thin());
    }

    #[test]
    fn denic_style_whois_without_registrar_or_dates_is_registered() {
        // .de has no RDAP (a non-404 bootstrap miss). Before nameservers
        // counted, this body was "thin" and an NXDOMAIN apex flipped a
        // registered .de domain to likely-available.
        let rdap_err = SeerError::RdapBootstrapError("no RDAP server for example.de".to_string());
        let r = decide_fallback(
            "example.de",
            &rdap_err,
            Ok(denic_whois()),
            DnsPresence::Absent,
        );
        assert!(!r.available, "a delegated DENIC record is registered");
        assert_eq!(r.confidence, "high");
        assert_eq!(r.method, "whois");
    }

    // --- subdomain guard (names below the registrable domain) ---------

    fn avail(domain: &str, available: bool, confidence: &str) -> AvailabilityResult {
        AvailabilityResult::new(domain, available, confidence, "rdap")
    }

    #[test]
    fn subdomain_under_registered_parent_is_registered_not_available() {
        let r = subdomain_verdict("mail.google.com", &avail("google.com", false, "high"));
        assert!(!r.available);
        assert_eq!(r.domain, "mail.google.com");
        assert_eq!(r.verdict(), "registered");
        assert_eq!(r.method, "registrable_parent");
        let details = r.details.unwrap();
        assert!(details.contains("google.com is registered"), "{details}");
    }

    #[test]
    fn subdomain_under_available_parent_is_never_claimed_available() {
        let r = subdomain_verdict("mail.freebrand.com", &avail("freebrand.com", true, "high"));
        assert!(!r.available, "a subdomain itself is never registrable");
        assert_eq!(r.verdict(), "unknown");
        assert!(r.details.unwrap().contains("register freebrand.com"));

        let r = subdomain_verdict("a.b.co.uk", &avail("b.co.uk", false, "none"));
        assert!(!r.available);
        assert_eq!(r.verdict(), "unknown");
        assert!(r.details.unwrap().contains("could not be determined"));
    }

    #[tokio::test]
    async fn subdomain_guard_leaves_registrable_names_and_negative_results_alone() {
        // Both cases return before any network: a registrable name has no
        // parent to consult, and a not-available verdict is never rewritten.
        let checker = AvailabilityChecker::new();
        let r = checker
            .guard_subdomain_claim(avail("example.co.uk", true, "high"))
            .await;
        assert!(r.available);
        assert_eq!(r.method, "rdap");

        let r = checker
            .guard_subdomain_claim(avail("mail.example.com", false, "high"))
            .await;
        assert!(!r.available);
        assert_eq!(r.method, "rdap");
    }
}
