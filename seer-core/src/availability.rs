//! Domain availability checking.
//!
//! Determines if a domain is available for registration by interpreting
//! WHOIS/RDAP "not found" responses.

use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use crate::dns::{DnsPresence, DnsResolver};
use crate::error::Result;
use crate::rdap::{rdap_error_is_404, RdapClient};
use crate::whois::WhoisClient;

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
    Failed(crate::error::SeerError),
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
    Failed(crate::error::SeerError),
    /// No usable WHOIS result (e.g. grace-truncated); query fresh.
    Missing,
}

/// Checks domain availability by attempting lookups and interpreting failures.
#[derive(Debug, Clone)]
pub struct AvailabilityChecker {
    rdap_client: RdapClient,
    whois_client: WhoisClient,
    dns_resolver: DnsResolver,
}

impl Default for AvailabilityChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl AvailabilityChecker {
    pub fn new() -> Self {
        Self {
            rdap_client: RdapClient::new(),
            whois_client: WhoisClient::new(),
            dns_resolver: DnsResolver::new(),
        }
    }

    /// Builds a checker whose sub-clients honor the timeouts in `config`.
    pub fn from_config(config: &crate::config::SeerConfig) -> Self {
        Self {
            rdap_client: RdapClient::new().with_timeout(config.rdap_timeout()),
            whois_client: WhoisClient::new().with_timeout(config.whois_timeout()),
            dns_resolver: DnsResolver::new().with_timeout(config.dns_timeout()),
        }
    }

    /// Check if a domain is available for registration.
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn check(&self, domain: &str) -> Result<AvailabilityResult> {
        let domain = crate::validation::normalize_domain(domain)?;
        debug!(domain = %domain, "Checking domain availability");

        // Try RDAP first - it gives structured error responses.
        match self.rdap_client.lookup_domain(&domain).await {
            Ok(response) => Ok(decide_from_rdap(&domain, response)),
            Err(rdap_err) => {
                debug!(error = %rdap_err, "RDAP lookup failed, falling back to WHOIS + DNS");
                // Probe WHOIS and the apex DNS presence concurrently. DNS is
                // only the tie-breaker when WHOIS is thin/blocked/errored and
                // the RDAP failure was not an authoritative 404, so running it
                // alongside WHOIS (rather than on demand) adds no extra
                // wall-clock time.
                let (whois_result, dns_presence) = tokio::join!(
                    self.whois_client.lookup(&domain),
                    self.dns_resolver.presence(&domain),
                );
                Ok(decide_fallback(
                    &domain,
                    &rdap_err,
                    whois_result,
                    dns_presence,
                ))
            }
        }
    }

    /// Like [`check`](Self::check), but reuses protocol outcomes already
    /// gathered by the caller (the smart-lookup RDAP+WHOIS race), issuing only
    /// the queries that are genuinely missing or were grace-truncated. The DNS
    /// presence probe runs exactly as in `check`.
    ///
    /// Routing through the same pure deciders (`decide_from_rdap` /
    /// `decide_fallback`) guarantees an identical verdict to `check` for the
    /// same protocol outcomes — this path only removes redundant network calls,
    /// so the two availability ladders stay in lockstep.
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

        match rdap {
            Ok(response) => Ok(decide_from_rdap(&domain, response)),
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
                Ok(decide_fallback(
                    &domain,
                    &rdap_err,
                    whois_result,
                    dns_presence,
                ))
            }
        }
    }
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
        return AvailabilityResult {
            domain: domain.to_string(),
            available: false,
            confidence: "medium".to_string(),
            method: "rdap".to_string(),
            details: Some("Domain is in redemption/pending delete period".to_string()),
        };
    }

    AvailabilityResult {
        domain: domain.to_string(),
        available: false,
        confidence: "high".to_string(),
        method: "rdap".to_string(),
        details: Some(format!(
            "Domain is registered (status: {})",
            statuses.join(", ")
        )),
    }
}

/// Pure decision function: build an `AvailabilityResult` when RDAP failed
/// and WHOIS (plus a DNS presence probe) is the fallback. Extracted from
/// `check()` for table-testing. `dns_presence` is only consulted when the
/// registry signals are inconclusive — a thin/blocked WHOIS body or a
/// transport-failed WHOIS leg, with a non-404 RDAP failure. An apex with no
/// DNS presence (NXDOMAIN) then reads as likely-available at medium
/// confidence; a delegated apex behind two transport failures reads as
/// likely-registered at medium confidence.
fn decide_fallback(
    domain: &str,
    rdap_err: &crate::error::SeerError,
    whois_result: Result<crate::whois::WhoisResponse>,
    dns_presence: DnsPresence,
) -> AvailabilityResult {
    match whois_result {
        Ok(whois_response) => {
            // "Thin" = no positive registration signal at all (no registrar,
            // no creation/expiry dates). A thin body is what blocked or
            // RDAP-first registries return for an unregistered domain.
            let thin = whois_response.registrar.is_none()
                && whois_response.creation_date.is_none()
                && whois_response.expiration_date.is_none();

            if whois_response.is_available() {
                AvailabilityResult {
                    domain: domain.to_string(),
                    available: true,
                    confidence: "high".to_string(),
                    method: "whois".to_string(),
                    details: Some("WHOIS indicates domain is not registered".to_string()),
                }
            } else if !thin {
                // A concrete registration signal (registrar / dates) is
                // present → the domain is registered.
                AvailabilityResult {
                    domain: domain.to_string(),
                    available: false,
                    confidence: "high".to_string(),
                    method: "whois".to_string(),
                    details: whois_response
                        .registrar
                        .map(|r| format!("Registered with {}", r)),
                }
            } else if rdap_error_is_404(rdap_err) {
                // Thin WHOIS — often an access-blocked refusal like SWITCH's
                // ".ch" — but the registry's own RDAP authoritatively 404'd.
                AvailabilityResult {
                    domain: domain.to_string(),
                    available: true,
                    confidence: "high".to_string(),
                    method: "rdap".to_string(),
                    details: Some("Registry RDAP reports no such domain (HTTP 404)".to_string()),
                }
            } else if whois_response.indicates_registry_refusal() {
                // Thin WHOIS that explicitly refused / throttled / negated the
                // query (rate limit, access denied, reserved, "not available
                // for registration") while RDAP did not authoritatively 404.
                // There is no usable registration signal — report inconclusive
                // rather than inverting the refusal into "available" or guessing
                // from DNS presence / fail-safing to "registered" (issue #45).
                AvailabilityResult {
                    domain: domain.to_string(),
                    available: false,
                    confidence: "none".to_string(),
                    method: "inconclusive".to_string(),
                    details: Some(
                        "Registry refused or throttled the query; availability is inconclusive"
                            .to_string(),
                    ),
                }
            } else if dns_presence == DnsPresence::Absent {
                // Thin WHOIS, RDAP did not 404, and the apex is NXDOMAIN —
                // corroborating evidence the domain is unregistered.
                AvailabilityResult {
                    domain: domain.to_string(),
                    available: true,
                    confidence: "medium".to_string(),
                    method: "dns_nxdomain".to_string(),
                    details: Some(
                        "No registry data available; domain has no DNS presence (NXDOMAIN)"
                            .to_string(),
                    ),
                }
            } else {
                // Thin WHOIS we could not interpret and no corroborating
                // NXDOMAIN — fail safe toward "registered".
                AvailabilityResult {
                    domain: domain.to_string(),
                    available: false,
                    confidence: "high".to_string(),
                    method: "whois".to_string(),
                    details: None,
                }
            }
        }
        Err(whois_err) => {
            // RDAP 404 is authoritative even when the WHOIS leg errored: the
            // registry's RDAP server reports no such object, so the domain is
            // unregistered regardless of why WHOIS failed.
            if rdap_error_is_404(rdap_err) {
                return AvailabilityResult {
                    domain: domain.to_string(),
                    available: true,
                    confidence: "high".to_string(),
                    method: "rdap".to_string(),
                    details: Some("Registry RDAP reports no such domain (HTTP 404)".to_string()),
                };
            }
            // Both registry legs failed. Only a WHOIS-*protocol* error can
            // carry a registry "no match" signal; a transport failure
            // (timeout, connection reset, DNS, SSRF refusal) tells us nothing
            // about registration, so we must not infer availability from its
            // text even if it incidentally contains a phrase like "no match".
            let likely_available = matches!(whois_err, crate::error::SeerError::WhoisError(_)) && {
                let whois_msg = whois_err.to_string().to_lowercase();
                whois_msg.contains("no match")
                    || whois_msg.contains("not found")
                    || whois_msg.contains("no data found")
                    || whois_msg.contains("no entries found")
            };

            if likely_available {
                AvailabilityResult {
                    domain: domain.to_string(),
                    available: true,
                    confidence: "medium".to_string(),
                    method: "whois_error".to_string(),
                    details: Some("WHOIS server indicates no matching records".to_string()),
                }
            } else if dns_presence == DnsPresence::Absent {
                // Both registry legs failed, but the apex is NXDOMAIN — the
                // domain has no DNS presence, so it is likely unregistered.
                AvailabilityResult {
                    domain: domain.to_string(),
                    available: true,
                    confidence: "medium".to_string(),
                    method: "dns_nxdomain".to_string(),
                    details: Some(
                        "Registry lookups failed; domain has no DNS presence (NXDOMAIN)"
                            .to_string(),
                    ),
                }
            } else if dns_presence == DnsPresence::Present {
                // Both registry legs failed with transport errors, but the
                // apex IS delegated in DNS. Delegation in the TLD zone is
                // strong evidence of registration (mirrors the
                // `classify_thin_fallback` Present → Registered route), so
                // report likely_registered instead of a blank "unknown".
                // This is the safe direction: it can never call a taken
                // domain free. Note this arm is a transport failure, not a
                // registry refusal — refusals arrive as an Ok body and are
                // kept inconclusive above (issue #45).
                AvailabilityResult {
                    domain: domain.to_string(),
                    available: false,
                    confidence: "medium".to_string(),
                    method: "dns_present".to_string(),
                    details: Some(
                        "Registry lookups failed, but the apex is delegated in DNS \
                         (NS records present) — the domain is almost certainly registered"
                            .to_string(),
                    ),
                }
            } else {
                // Both queries failed with non-"not found" errors and DNS was
                // unknown. We genuinely don't know — could be registered,
                // blocked, or servers down. Default to available=false so we
                // never tell the user a taken domain is free.
                AvailabilityResult {
                    domain: domain.to_string(),
                    available: false,
                    confidence: "none".to_string(),
                    method: "inconclusive".to_string(),
                    // Use the sanitized error projection so this string —
                    // which flows into JSON / CSV / MCP output paths —
                    // never carries raw ANSI escapes or internal IPs from
                    // a third-party WHOIS/RDAP server's error message.
                    details: Some(format!(
                        "Could not determine availability. RDAP: {}. WHOIS: {}",
                        rdap_err.sanitized_message(),
                        whois_err.sanitized_message()
                    )),
                }
            }
        }
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
        let make = |available, confidence: &str| AvailabilityResult {
            domain: "example.test".to_string(),
            available,
            confidence: confidence.to_string(),
            method: "whois".to_string(),
            details: None,
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
        let result = AvailabilityResult {
            domain: "example.com".to_string(),
            available: false,
            confidence: "high".to_string(),
            method: "rdap".to_string(),
            details: Some("Domain is registered".to_string()),
        };
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
            whois_server: "whois.test".to_string(),
            raw_response: raw.to_string(),
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
    fn rdap_fail_whois_registered_without_registrar_no_detail() {
        // Corner case: has_core_data is false but not-available, so the
        // details string is None (registrar field is None).
        let whois = whois_with("Domain Name: example.test\n", None);
        let rdap_err = SeerError::RdapError("404".to_string());
        let r = decide_fallback("example.test", &rdap_err, Ok(whois), DnsPresence::Unknown);
        assert!(!r.available);
        assert_eq!(r.confidence, "high");
        assert!(
            r.details.is_none(),
            "no registrar means no details string, got: {:?}",
            r.details
        );
    }

    // --- Both-fail branches ------------------------------------------

    #[test]
    fn rdap_fail_whois_error_contains_no_match_marks_available_medium() {
        let rdap_err = SeerError::RdapError("500".to_string());
        let whois_err =
            SeerError::WhoisError("whois server returned 'No match for this domain'".to_string());
        let r = decide_fallback(
            "example.test",
            &rdap_err,
            Err(whois_err),
            DnsPresence::Unknown,
        );
        assert!(
            r.available,
            "whois error containing 'no match' is available"
        );
        assert_eq!(r.confidence, "medium");
        assert_eq!(r.method, "whois_error");
    }

    #[test]
    fn rdap_fail_whois_error_not_found_marks_available_medium() {
        let rdap_err = SeerError::RdapError("500".to_string());
        let whois_err = SeerError::WhoisError("Domain not found".to_string());
        let r = decide_fallback(
            "example.test",
            &rdap_err,
            Err(whois_err),
            DnsPresence::Unknown,
        );
        assert!(r.available);
        assert_eq!(r.confidence, "medium");
        assert_eq!(r.method, "whois_error");
    }

    #[test]
    fn rdap_fail_whois_error_no_data_found_marks_available_medium() {
        let rdap_err = SeerError::RdapError("no".to_string());
        let whois_err = SeerError::WhoisError("No Data Found for query".to_string());
        let r = decide_fallback(
            "example.test",
            &rdap_err,
            Err(whois_err),
            DnsPresence::Unknown,
        );
        assert!(r.available);
        assert_eq!(r.confidence, "medium");
    }

    #[test]
    fn rdap_fail_whois_error_no_entries_marks_available_medium() {
        let rdap_err = SeerError::RdapError("no".to_string());
        let whois_err =
            SeerError::WhoisError("No entries found for the selected source".to_string());
        let r = decide_fallback(
            "example.test",
            &rdap_err,
            Err(whois_err),
            DnsPresence::Unknown,
        );
        assert!(r.available);
        assert_eq!(r.confidence, "medium");
    }

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

    #[test]
    fn rdap_fail_whois_error_case_insensitive_not_found() {
        // The real code lowercases before matching; verify the Uppercase
        // form still classifies correctly.
        let rdap_err = SeerError::RdapError("500".to_string());
        let whois_err = SeerError::WhoisError("NOT FOUND in registry".to_string());
        let r = decide_fallback(
            "example.test",
            &rdap_err,
            Err(whois_err),
            DnsPresence::Unknown,
        );
        assert!(r.available, "'NOT FOUND' should classify as available");
        assert_eq!(r.confidence, "medium");
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
    fn thin_whois_non404_dns_unknown_stays_unavailable_failsafe() {
        // Thin WHOIS, non-404 RDAP failure, DNS itself failed → genuinely
        // unknown; fail safe to not-available so we never call a taken domain
        // free on a transient DNS blip.
        let whois = whois_with(
            "Conditions of use for the whois service via port 43\n",
            None,
        );
        let rdap_err = SeerError::RdapBootstrapError("no RDAP server".to_string());
        let r = decide_fallback("example.es", &rdap_err, Ok(whois), DnsPresence::Unknown);
        assert!(!r.available);
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
}
