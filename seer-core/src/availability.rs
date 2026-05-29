//! Domain availability checking.
//!
//! Determines if a domain is available for registration by interpreting
//! WHOIS/RDAP "not found" responses.

use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use crate::error::Result;
use crate::rdap::RdapClient;
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
                debug!(error = %rdap_err, "RDAP lookup failed, falling back to WHOIS");
                let whois_result = self.whois_client.lookup(&domain).await;
                Ok(decide_fallback(&domain, &rdap_err, whois_result))
            }
        }
    }
}

/// Pure decision function: build an `AvailabilityResult` from a successful
/// RDAP lookup. Extracted from `check()` so the decision matrix can be
/// table-tested without a network stack.
fn decide_from_rdap(domain: &str, response: crate::rdap::RdapResponse) -> AvailabilityResult {
    let statuses: Vec<String> = response.status.clone();
    let is_redemption = statuses
        .iter()
        .any(|s| s.contains("redemption") || s.contains("pending delete"));

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
/// and WHOIS is the fallback. Extracted from `check()` for table-testing.
fn decide_fallback(
    domain: &str,
    rdap_err: &crate::error::SeerError,
    whois_result: Result<crate::whois::WhoisResponse>,
) -> AvailabilityResult {
    match whois_result {
        Ok(whois_response) => {
            if whois_response.is_available() {
                AvailabilityResult {
                    domain: domain.to_string(),
                    available: true,
                    confidence: "high".to_string(),
                    method: "whois".to_string(),
                    details: Some("WHOIS indicates domain is not registered".to_string()),
                }
            } else {
                AvailabilityResult {
                    domain: domain.to_string(),
                    available: false,
                    confidence: "high".to_string(),
                    method: "whois".to_string(),
                    details: whois_response
                        .registrar
                        .map(|r| format!("Registered with {}", r)),
                }
            }
        }
        Err(whois_err) => {
            // Both failed - domain might be available or queries blocked
            let whois_msg = whois_err.to_string().to_lowercase();
            let likely_available = whois_msg.contains("no match")
                || whois_msg.contains("not found")
                || whois_msg.contains("no data found")
                || whois_msg.contains("no entries found");

            if likely_available {
                AvailabilityResult {
                    domain: domain.to_string(),
                    available: true,
                    confidence: "medium".to_string(),
                    method: "whois_error".to_string(),
                    details: Some("WHOIS server indicates no matching records".to_string()),
                }
            } else {
                // Both queries failed with non-"not found" errors.
                // We genuinely don't know — could be registered, could be
                // blocked by the registrar, or servers could be down.
                // Default to available=false to avoid misleading the user
                // into thinking they can register a domain that's actually taken.
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

    // --- WHOIS fallback branches -------------------------------------

    #[test]
    fn rdap_fail_whois_says_available_high_confidence() {
        // is_available() reads raw_response and looks for the patterns
        // that every TLD uses to signal unregistered.
        let whois = whois_with("No match for \"example.test\".\n", None);
        let rdap_err = SeerError::RdapError("404 not found".to_string());
        let r = decide_fallback("example.test", &rdap_err, Ok(whois));
        assert!(r.available, "WHOIS 'no match' must mark available");
        assert_eq!(r.confidence, "high");
        assert_eq!(r.method, "whois");
    }

    #[test]
    fn rdap_fail_whois_says_registered_high_confidence() {
        let whois = whois_with("Domain Name: example.test\n", Some("Test Registrar"));
        let rdap_err = SeerError::RdapError("404 not found".to_string());
        let r = decide_fallback("example.test", &rdap_err, Ok(whois));
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
        let r = decide_fallback("example.test", &rdap_err, Ok(whois));
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
        let r = decide_fallback("example.test", &rdap_err, Err(whois_err));
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
        let r = decide_fallback("example.test", &rdap_err, Err(whois_err));
        assert!(r.available);
        assert_eq!(r.confidence, "medium");
        assert_eq!(r.method, "whois_error");
    }

    #[test]
    fn rdap_fail_whois_error_no_data_found_marks_available_medium() {
        let rdap_err = SeerError::RdapError("no".to_string());
        let whois_err = SeerError::WhoisError("No Data Found for query".to_string());
        let r = decide_fallback("example.test", &rdap_err, Err(whois_err));
        assert!(r.available);
        assert_eq!(r.confidence, "medium");
    }

    #[test]
    fn rdap_fail_whois_error_no_entries_marks_available_medium() {
        let rdap_err = SeerError::RdapError("no".to_string());
        let whois_err =
            SeerError::WhoisError("No entries found for the selected source".to_string());
        let r = decide_fallback("example.test", &rdap_err, Err(whois_err));
        assert!(r.available);
        assert_eq!(r.confidence, "medium");
    }

    #[test]
    fn rdap_fail_whois_timeout_marks_inconclusive_none_confidence() {
        let rdap_err = SeerError::Timeout("rdap timed out".to_string());
        let whois_err = SeerError::Timeout("whois timed out".to_string());
        let r = decide_fallback("example.test", &rdap_err, Err(whois_err));
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
    fn rdap_fail_whois_connection_error_marks_inconclusive_none_confidence() {
        let rdap_err = SeerError::RdapError("connection refused".to_string());
        let whois_err = SeerError::WhoisError(
            "failed to connect to whois.example: connection refused".to_string(),
        );
        let r = decide_fallback("example.test", &rdap_err, Err(whois_err));
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
        let r = decide_fallback("example.test", &rdap_err, Err(whois_err));
        assert!(r.available, "'NOT FOUND' should classify as available");
        assert_eq!(r.confidence, "medium");
    }
}
