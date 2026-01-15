use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::error::Result;
use crate::rdap::{RdapClient, RdapResponse};
use crate::whois::{WhoisClient, WhoisResponse};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "lowercase")]
pub enum LookupResult {
    Rdap {
        data: RdapResponse,
        #[serde(skip_serializing_if = "Option::is_none")]
        whois_fallback: Option<WhoisResponse>,
    },
    Whois {
        data: WhoisResponse,
        rdap_error: Option<String>,
    },
}

impl LookupResult {
    pub fn domain_name(&self) -> Option<String> {
        match self {
            LookupResult::Rdap { data, .. } => data.domain_name().map(String::from),
            LookupResult::Whois { data, .. } => Some(data.domain.clone()),
        }
    }

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

    pub fn is_rdap(&self) -> bool {
        matches!(self, LookupResult::Rdap { .. })
    }

    pub fn is_whois(&self) -> bool {
        matches!(self, LookupResult::Whois { .. })
    }

    /// Get expiration date and registrar info from the lookup result
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
    pub fn new() -> Self {
        Self {
            rdap_client: RdapClient::new(),
            whois_client: WhoisClient::new(),
            prefer_rdap: true,
            include_fallback: false,
        }
    }

    /// Always try RDAP first, fall back to WHOIS on failure
    pub fn prefer_rdap(mut self, prefer: bool) -> Self {
        self.prefer_rdap = prefer;
        self
    }

    /// Include WHOIS data as fallback even when RDAP succeeds (for additional fields)
    pub fn include_fallback(mut self, include: bool) -> Self {
        self.include_fallback = include;
        self
    }

    pub async fn lookup(&self, domain: &str) -> Result<LookupResult> {
        if self.prefer_rdap {
            self.lookup_rdap_first(domain).await
        } else {
            self.lookup_whois_first(domain).await
        }
    }

    async fn lookup_rdap_first(&self, domain: &str) -> Result<LookupResult> {
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
                        data: rdap_data,
                        whois_fallback,
                    })
                } else {
                    debug!("RDAP response lacks useful data, falling back to WHOIS");
                    self.fallback_to_whois(domain, Some("RDAP response incomplete")).await
                }
            }
            Err(e) => {
                warn!(error = %e, "RDAP lookup failed, falling back to WHOIS");
                self.fallback_to_whois(domain, Some(&e.to_string())).await
            }
        }
    }

    async fn lookup_whois_first(&self, domain: &str) -> Result<LookupResult> {
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
                // Try RDAP as fallback
                let rdap_data = self.rdap_client.lookup_domain(domain).await?;
                Ok(LookupResult::Rdap {
                    data: rdap_data,
                    whois_fallback: None,
                })
            }
        }
    }

    async fn fallback_to_whois(&self, domain: &str, rdap_error: Option<&str>) -> Result<LookupResult> {
        let whois_data = self.whois_client.lookup(domain).await?;
        Ok(LookupResult::Whois {
            data: whois_data,
            rdap_error: rdap_error.map(String::from),
        })
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
