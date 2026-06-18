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
                // only the tie-breaker when WHOIS is thin/blocked and the RDAP
                // failure was not an authoritative 404, so running it alongside
                // WHOIS (rather than on demand) adds no extra wall-clock time.
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
/// registry signals are inconclusive — a thin/blocked WHOIS body and a
/// non-404 RDAP failure; an apex with no DNS presence (NXDOMAIN) then reads
/// as likely-available at medium confidence.
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
            } else {
                // Both queries failed with non-"not found" errors and the
                // domain still resolves (or DNS was unknown). We genuinely
                // don't know — could be registered, blocked, or servers down.
                // Default to available=false so we never tell the user a taken
                // domain is free.
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
}
