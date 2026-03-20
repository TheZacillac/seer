//! Domain availability checking.
//!
//! Determines if a domain is available for registration by interpreting
//! WHOIS/RDAP "not found" responses.

use serde::{Deserialize, Serialize};
use tracing::debug;

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

/// Checks domain availability by attempting lookups and interpreting failures.
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
    pub async fn check(&self, domain: &str) -> Result<AvailabilityResult> {
        let domain = crate::validation::normalize_domain(domain)?;
        debug!(domain = %domain, "Checking domain availability");

        // Try RDAP first - it gives structured error responses
        match self.rdap_client.lookup_domain(&domain).await {
            Ok(response) => {
                // Domain exists in RDAP - check status
                let statuses: Vec<String> = response.status.clone();
                let is_redemption = statuses
                    .iter()
                    .any(|s| s.contains("redemption") || s.contains("pending delete"));

                if is_redemption {
                    return Ok(AvailabilityResult {
                        domain,
                        available: false,
                        confidence: "medium".to_string(),
                        method: "rdap".to_string(),
                        details: Some("Domain is in redemption/pending delete period".to_string()),
                    });
                }

                Ok(AvailabilityResult {
                    domain,
                    available: false,
                    confidence: "high".to_string(),
                    method: "rdap".to_string(),
                    details: Some(format!(
                        "Domain is registered (status: {})",
                        statuses.join(", ")
                    )),
                })
            }
            Err(_rdap_err) => {
                // RDAP failed - try WHOIS
                match self.whois_client.lookup(&domain).await {
                    Ok(whois_response) => {
                        if whois_response.is_available() {
                            Ok(AvailabilityResult {
                                domain,
                                available: true,
                                confidence: "high".to_string(),
                                method: "whois".to_string(),
                                details: Some(
                                    "WHOIS indicates domain is not registered".to_string(),
                                ),
                            })
                        } else {
                            Ok(AvailabilityResult {
                                domain,
                                available: false,
                                confidence: "high".to_string(),
                                method: "whois".to_string(),
                                details: whois_response
                                    .registrar
                                    .map(|r| format!("Registered with {}", r)),
                            })
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
                            Ok(AvailabilityResult {
                                domain,
                                available: true,
                                confidence: "medium".to_string(),
                                method: "whois_error".to_string(),
                                details: Some(
                                    "WHOIS server indicates no matching records".to_string(),
                                ),
                            })
                        } else {
                            Ok(AvailabilityResult {
                                domain,
                                available: false,
                                confidence: "low".to_string(),
                                method: "inconclusive".to_string(),
                                details: Some("Could not determine availability - both RDAP and WHOIS queries failed".to_string()),
                            })
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
