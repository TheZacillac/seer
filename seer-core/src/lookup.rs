use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::availability::{AvailabilityChecker, AvailabilityResult};
use crate::cache::TtlCache;
use crate::error::{Result, SeerError};
use crate::rdap::{RdapClient, RdapResponse};
use crate::whois::{get_registry_url, get_tld, WhoisClient, WhoisResponse};

/// Cache TTL for lookup results (5 minutes).
const LOOKUP_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Global cache for lookup results to avoid redundant network calls.
static LOOKUP_CACHE: Lazy<TtlCache<String, LookupResult>> =
    Lazy::new(|| TtlCache::new(LOOKUP_CACHE_TTL));

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
    },
    Available {
        data: Box<AvailabilityResult>,
        rdap_error: String,
        whois_error: String,
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

#[derive(Debug, Clone)]
pub struct SmartLookup {
    rdap_client: RdapClient,
    whois_client: WhoisClient,
    availability_checker: AvailabilityChecker,
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
            prefer_rdap: true,
            include_fallback: false,
        }
    }

    /// Deprecated: both protocols are now always attempted concurrently.
    /// This method is kept for API compatibility but has no effect.
    pub fn prefer_rdap(mut self, prefer: bool) -> Self {
        self.prefer_rdap = prefer;
        self
    }

    /// Deprecated: WHOIS data is now always attached when available.
    /// This method is kept for API compatibility but has no effect.
    pub fn include_fallback(mut self, include: bool) -> Self {
        self.include_fallback = include;
        self
    }

    /// Performs a smart lookup for a domain, trying both RDAP and WHOIS concurrently.
    /// Falls back to an availability check if both fail.
    /// Results are cached for 5 minutes to avoid redundant network calls.
    pub async fn lookup(&self, domain: &str) -> Result<LookupResult> {
        self.lookup_with_progress(domain, None).await
    }

    /// Performs a lookup with an optional progress callback.
    /// The callback is called with messages describing the current phase.
    /// Results are cached for 5 minutes.
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

        let result = self.lookup_concurrent(domain, progress).await?;

        // Cache the result
        LOOKUP_CACHE.insert(normalized, result.clone());

        Ok(result)
    }

    /// Clears the lookup result cache.
    pub fn clear_cache() {
        LOOKUP_CACHE.clear();
    }

    async fn lookup_concurrent(
        &self,
        domain: &str,
        progress: Option<LookupProgressCallback>,
    ) -> Result<LookupResult> {
        debug!(domain = %domain, "Attempting RDAP and WHOIS concurrently");

        if let Some(ref cb) = progress {
            cb("Querying RDAP and WHOIS concurrently");
        }

        let (rdap_result, whois_result) = tokio::join!(
            self.rdap_client.lookup_domain(domain),
            self.whois_client.lookup(domain)
        );

        // Phase 1: If RDAP returned useful data, use it as primary
        if let Ok(rdap_data) = rdap_result {
            if self.is_rdap_response_useful(&rdap_data) {
                debug!("RDAP lookup successful");
                let whois_fallback = whois_result.ok();
                return Ok(LookupResult::Rdap {
                    data: Box::new(rdap_data),
                    whois_fallback,
                });
            }

            // RDAP succeeded but response wasn't useful — try WHOIS
            if let Ok(whois_data) = whois_result {
                debug!("RDAP response incomplete, using WHOIS result");
                if let Some(ref cb) = progress {
                    cb("RDAP response incomplete (using WHOIS)");
                }
                return Ok(LookupResult::Whois {
                    data: whois_data,
                    rdap_error: Some("RDAP response incomplete".to_string()),
                });
            }

            // RDAP not useful, WHOIS also failed — availability fallback
            let whois_error_str = whois_result.unwrap_err().to_string();
            return self
                .availability_fallback(
                    domain,
                    "RDAP response incomplete".to_string(),
                    whois_error_str,
                    progress,
                )
                .await;
        }

        // Phase 2: RDAP failed — use WHOIS if it succeeded
        let rdap_error_str = rdap_result.unwrap_err().to_string();

        if let Ok(whois_data) = whois_result {
            debug!("RDAP failed, using WHOIS result");
            if let Some(ref cb) = progress {
                cb("RDAP not available (using WHOIS)");
            }
            return Ok(LookupResult::Whois {
                data: whois_data,
                rdap_error: Some(rdap_error_str),
            });
        }

        // Phase 3: Both failed — try availability check as last resort
        let whois_error_str = whois_result.unwrap_err().to_string();
        self.availability_fallback(domain, rdap_error_str, whois_error_str, progress)
            .await
    }

    async fn availability_fallback(
        &self,
        domain: &str,
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

        match self.availability_checker.check(domain).await {
            Ok(avail) => Ok(LookupResult::Available {
                data: Box::new(avail),
                rdap_error,
                whois_error,
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

    fn is_rdap_response_useful(&self, response: &RdapResponse) -> bool {
        // Check if we have at least some meaningful data
        let has_name = response.ldh_name.is_some() || response.unicode_name.is_some();
        let has_dates = response
            .events
            .iter()
            .any(|e| e.event_action == "registration" || e.event_action == "expiration");
        let has_entities = !response.entities.is_empty();
        let has_nameservers = !response.nameservers.is_empty();
        let has_status = !response.status.is_empty();

        // Consider useful if we have the name plus at least one other piece of info
        has_name && (has_dates || has_entities || has_nameservers || has_status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_smart_lookup_builder() {
        let lookup = SmartLookup::new().prefer_rdap(false).include_fallback(true);
        assert!(!lookup.prefer_rdap);
        assert!(lookup.include_fallback);
    }

    #[test]
    fn test_lookup_cache_clear() {
        SmartLookup::clear_cache();
        assert!(LOOKUP_CACHE.is_empty());
    }
}
