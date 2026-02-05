use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::error::{Result, SeerError};
use crate::rdap::{RdapClient, RdapResponse};
use crate::whois::{WhoisClient, WhoisResponse, get_registry_url, get_tld};

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
}

impl LookupResult {
    /// Returns the domain name from the lookup result.
    pub fn domain_name(&self) -> Option<String> {
        match self {
            LookupResult::Rdap { data, .. } => data.domain_name().map(String::from),
            LookupResult::Whois { data, .. } => Some(data.domain.clone()),
        }
    }

    /// Returns the registrar name, preferring RDAP data with WHOIS fallback.
    pub fn registrar(&self) -> Option<String> {
        match self {
            LookupResult::Rdap { data, whois_fallback } => {
                data.get_registrar().or_else(|| {
                    whois_fallback.as_ref().and_then(|w| w.registrar.clone())
                })
            }
            LookupResult::Whois { data, .. } => data.registrar.clone(),
        }
    }

    /// Returns the registrant organization, preferring RDAP data with WHOIS fallback.
    pub fn organization(&self) -> Option<String> {
        match self {
            LookupResult::Rdap { data, whois_fallback } => {
                data.get_registrant_organization().or_else(|| {
                    whois_fallback.as_ref().and_then(|w| w.organization.clone())
                })
            }
            LookupResult::Whois { data, .. } => data.organization.clone(),
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

    /// Returns the expiration date and registrar info from the lookup result.
    pub fn expiration_info(&self) -> (Option<DateTime<Utc>>, Option<String>) {
        match self {
            LookupResult::Rdap { data, whois_fallback } => {
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

                let registrar = data.get_registrar().or_else(|| {
                    whois_fallback.as_ref().and_then(|w| w.registrar.clone())
                });

                (expiration_date, registrar)
            }
            LookupResult::Whois { data, .. } => {
                (data.expiration_date, data.registrar.clone())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct SmartLookup {
    rdap_client: RdapClient,
    whois_client: WhoisClient,
    prefer_rdap: bool,
    include_fallback: bool,
}

impl Default for SmartLookup {
    fn default() -> Self {
        Self::new()
    }
}

impl SmartLookup {
    /// Creates a new SmartLookup with default settings (RDAP-first with WHOIS fallback).
    pub fn new() -> Self {
        Self {
            rdap_client: RdapClient::new(),
            whois_client: WhoisClient::new(),
            prefer_rdap: true,
            include_fallback: false,
        }
    }

    /// Sets whether to try RDAP first, falling back to WHOIS on failure.
    pub fn prefer_rdap(mut self, prefer: bool) -> Self {
        self.prefer_rdap = prefer;
        self
    }

    /// Includes WHOIS data as fallback even when RDAP succeeds (for additional fields).
    pub fn include_fallback(mut self, include: bool) -> Self {
        self.include_fallback = include;
        self
    }

    /// Performs a smart lookup for a domain, trying RDAP first with WHOIS fallback.
    pub async fn lookup(&self, domain: &str) -> Result<LookupResult> {
        self.lookup_with_progress(domain, None).await
    }

    /// Performs a lookup with an optional progress callback.
    /// The callback is called with messages describing the current phase.
    pub async fn lookup_with_progress(
        &self,
        domain: &str,
        progress: Option<LookupProgressCallback>,
    ) -> Result<LookupResult> {
        if self.prefer_rdap {
            self.lookup_rdap_first(domain, progress).await
        } else {
            self.lookup_whois_first(domain, progress).await
        }
    }

    async fn lookup_rdap_first(
        &self,
        domain: &str,
        progress: Option<LookupProgressCallback>,
    ) -> Result<LookupResult> {
        debug!(domain = %domain, "Attempting RDAP lookup first");

        match self.rdap_client.lookup_domain(domain).await {
            Ok(rdap_data) => {
                // Check if RDAP response has meaningful data
                if self.is_rdap_response_useful(&rdap_data) {
                    debug!("RDAP lookup successful");

                    // Optionally fetch WHOIS for additional data
                    let whois_fallback = if self.include_fallback {
                        match self.whois_client.lookup(domain).await {
                            Ok(whois) => Some(whois),
                            Err(e) => {
                                debug!(error = %e, "WHOIS fallback failed");
                                None
                            }
                        }
                    } else {
                        None
                    };

                    Ok(LookupResult::Rdap {
                        data: Box::new(rdap_data),
                        whois_fallback,
                    })
                } else {
                    debug!("RDAP response lacks useful data, falling back to WHOIS");
                    if let Some(ref cb) = progress {
                        cb("RDAP not available (trying WHOIS)");
                    }
                    self.fallback_to_whois(domain, Some("RDAP response incomplete")).await
                }
            }
            Err(e) => {
                warn!(error = %e, "RDAP lookup failed, falling back to WHOIS");
                if let Some(ref cb) = progress {
                    cb("RDAP not available (trying WHOIS)");
                }
                self.fallback_to_whois(domain, Some(&e.to_string())).await
            }
        }
    }

    async fn lookup_whois_first(
        &self,
        domain: &str,
        progress: Option<LookupProgressCallback>,
    ) -> Result<LookupResult> {
        debug!(domain = %domain, "Attempting WHOIS lookup first");

        match self.whois_client.lookup(domain).await {
            Ok(whois_data) => {
                Ok(LookupResult::Whois {
                    data: whois_data,
                    rdap_error: None,
                })
            }
            Err(e) => {
                warn!(error = %e, "WHOIS lookup failed, trying RDAP");
                if let Some(ref cb) = progress {
                    cb("WHOIS not available (trying RDAP)");
                }
                // Try RDAP as fallback
                let rdap_data = self.rdap_client.lookup_domain(domain).await?;
                Ok(LookupResult::Rdap {
                    data: Box::new(rdap_data),
                    whois_fallback: None,
                })
            }
        }
    }

    async fn fallback_to_whois(&self, domain: &str, rdap_error: Option<&str>) -> Result<LookupResult> {
        match self.whois_client.lookup(domain).await {
            Ok(whois_data) => Ok(LookupResult::Whois {
                data: whois_data,
                rdap_error: rdap_error.map(String::from),
            }),
            Err(whois_err) => {
                // Both RDAP and WHOIS failed - provide helpful error with registry suggestion
                let tld = get_tld(domain).unwrap_or("unknown");
                let registry_url = get_registry_url(tld)
                    .unwrap_or_else(|| format!("https://www.iana.org/domains/root/db/{}.html", tld));

                let details = match rdap_error {
                    Some(rdap_err) => format!(
                        "RDAP failed ({}), WHOIS also failed ({})",
                        rdap_err, whois_err
                    ),
                    None => format!("WHOIS lookup failed ({})", whois_err),
                };

                Err(SeerError::LookupFailed {
                    domain: domain.to_string(),
                    details,
                    registry_url,
                })
            }
        }
    }

    fn is_rdap_response_useful(&self, response: &RdapResponse) -> bool {
        // Check if we have at least some meaningful data
        let has_name = response.ldh_name.is_some() || response.unicode_name.is_some();
        let has_dates = response.events.iter().any(|e| {
            e.event_action == "registration" || e.event_action == "expiration"
        });
        let has_entities = !response.entities.is_empty();
        let has_nameservers = !response.nameservers.is_empty();
        let has_status = !response.status.is_empty();

        // Consider useful if we have the name plus at least one other piece of info
        has_name && (has_dates || has_entities || has_nameservers || has_status)
    }
}
