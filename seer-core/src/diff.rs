use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use crate::error::Result;
use crate::lookup::{LookupResult, SmartLookup};
use crate::status::{StatusClient, StatusResponse};

/// Side-by-side comparison of two domains across registration, DNS, and SSL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainDiff {
    pub domain_a: String,
    pub domain_b: String,
    pub registration: RegistrationDiff,
    pub dns: DnsDiff,
    pub ssl: SslDiff,
}

/// Registration data comparison (registrar, organization, dates).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationDiff {
    pub registrar: (Option<String>, Option<String>),
    pub organization: (Option<String>, Option<String>),
    pub created: (Option<String>, Option<String>),
    pub expires: (Option<String>, Option<String>),
}

/// DNS resolution comparison (A records, nameservers, reachability).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsDiff {
    pub a_records: (Vec<String>, Vec<String>),
    pub nameservers: (Vec<String>, Vec<String>),
    pub resolves: (bool, bool),
}

/// SSL certificate comparison (issuer, validity, remaining days).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslDiff {
    pub issuer: (Option<String>, Option<String>),
    pub valid_until: (Option<String>, Option<String>),
    pub days_remaining: (Option<i64>, Option<i64>),
    pub is_valid: (Option<bool>, Option<bool>),
}

/// Compares two domains by running lookups and status checks concurrently.
pub struct DomainDiffer {
    lookup: SmartLookup,
    status_client: StatusClient,
}

impl Default for DomainDiffer {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainDiffer {
    pub fn new() -> Self {
        Self {
            lookup: SmartLookup::new(),
            status_client: StatusClient::new(),
        }
    }

    /// Compares two domains, returning their registration, DNS, and SSL differences.
    ///
    /// All four network calls (lookup + status for each domain) run concurrently.
    #[instrument(skip(self), fields(domain_a = %domain_a, domain_b = %domain_b))]
    pub async fn diff(&self, domain_a: &str, domain_b: &str) -> Result<DomainDiff> {
        let domain_a = crate::validation::normalize_domain(domain_a)?;
        let domain_b = crate::validation::normalize_domain(domain_b)?;

        let (lookup_a, lookup_b, status_a, status_b) = tokio::join!(
            self.lookup.lookup(&domain_a),
            self.lookup.lookup(&domain_b),
            self.status_client.check(&domain_a),
            self.status_client.check(&domain_b),
        );

        let registration = build_registration_diff(lookup_a.ok().as_ref(), lookup_b.ok().as_ref());
        let dns = build_dns_diff(status_a.as_ref().ok(), status_b.as_ref().ok());
        let ssl = build_ssl_diff(status_a.as_ref().ok(), status_b.as_ref().ok());

        debug!("Domain diff complete");

        Ok(DomainDiff {
            domain_a,
            domain_b,
            registration,
            dns,
            ssl,
        })
    }
}

fn build_registration_diff(a: Option<&LookupResult>, b: Option<&LookupResult>) -> RegistrationDiff {
    let registrar_a = a.and_then(|r| r.registrar());
    let registrar_b = b.and_then(|r| r.registrar());
    let org_a = a.and_then(|r| r.organization());
    let org_b = b.and_then(|r| r.organization());

    let (expires_a, created_a) = extract_dates(a);
    let (expires_b, created_b) = extract_dates(b);

    RegistrationDiff {
        registrar: (registrar_a, registrar_b),
        organization: (org_a, org_b),
        created: (created_a, created_b),
        expires: (expires_a, expires_b),
    }
}

/// Extracts (expiration, creation) date strings from a lookup result.
fn extract_dates(result: Option<&LookupResult>) -> (Option<String>, Option<String>) {
    result
        .map(|r| {
            let (exp, _) = r.expiration_info();
            let created = match r {
                LookupResult::Rdap { data, .. } => data
                    .creation_date()
                    .map(|d| d.format("%Y-%m-%d").to_string()),
                LookupResult::Whois { data, .. } => {
                    data.creation_date.map(|d| d.format("%Y-%m-%d").to_string())
                }
                _ => None,
            };
            (exp.map(|d| d.format("%Y-%m-%d").to_string()), created)
        })
        .unwrap_or((None, None))
}

fn build_dns_diff(a: Option<&StatusResponse>, b: Option<&StatusResponse>) -> DnsDiff {
    let (a_records_a, ns_a, resolves_a) = a
        .and_then(|s| s.dns_resolution.as_ref())
        .map(|d| (d.a_records.clone(), d.nameservers.clone(), d.resolves))
        .unwrap_or((vec![], vec![], false));

    let (a_records_b, ns_b, resolves_b) = b
        .and_then(|s| s.dns_resolution.as_ref())
        .map(|d| (d.a_records.clone(), d.nameservers.clone(), d.resolves))
        .unwrap_or((vec![], vec![], false));

    DnsDiff {
        a_records: (a_records_a, a_records_b),
        nameservers: (ns_a, ns_b),
        resolves: (resolves_a, resolves_b),
    }
}

fn build_ssl_diff(a: Option<&StatusResponse>, b: Option<&StatusResponse>) -> SslDiff {
    let (issuer_a, valid_until_a, days_a, is_valid_a) = a
        .and_then(|s| s.certificate.as_ref())
        .map(|c| {
            (
                Some(c.issuer.clone()),
                Some(c.valid_until.format("%Y-%m-%d").to_string()),
                Some(c.days_until_expiry),
                Some(c.is_valid),
            )
        })
        .unwrap_or((None, None, None, None));

    let (issuer_b, valid_until_b, days_b, is_valid_b) = b
        .and_then(|s| s.certificate.as_ref())
        .map(|c| {
            (
                Some(c.issuer.clone()),
                Some(c.valid_until.format("%Y-%m-%d").to_string()),
                Some(c.days_until_expiry),
                Some(c.is_valid),
            )
        })
        .unwrap_or((None, None, None, None));

    SslDiff {
        issuer: (issuer_a, issuer_b),
        valid_until: (valid_until_a, valid_until_b),
        days_remaining: (days_a, days_b),
        is_valid: (is_valid_a, is_valid_b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_diff_serialization() {
        let diff = DomainDiff {
            domain_a: "example.com".to_string(),
            domain_b: "google.com".to_string(),
            registration: RegistrationDiff {
                registrar: (Some("IANA".to_string()), Some("MarkMonitor".to_string())),
                organization: (None, Some("Google LLC".to_string())),
                created: (
                    Some("1995-08-14".to_string()),
                    Some("1997-09-15".to_string()),
                ),
                expires: (
                    Some("2026-08-13".to_string()),
                    Some("2028-09-14".to_string()),
                ),
            },
            dns: DnsDiff {
                a_records: (
                    vec!["93.184.216.34".to_string()],
                    vec!["142.250.185.46".to_string()],
                ),
                nameservers: (
                    vec!["a.iana-servers.net".to_string()],
                    vec!["ns1.google.com".to_string()],
                ),
                resolves: (true, true),
            },
            ssl: SslDiff {
                issuer: (
                    Some("DigiCert Inc".to_string()),
                    Some("Google Trust Services".to_string()),
                ),
                valid_until: (
                    Some("2025-03-01".to_string()),
                    Some("2025-02-15".to_string()),
                ),
                days_remaining: (Some(89), Some(75)),
                is_valid: (Some(true), Some(true)),
            },
        };

        let json = serde_json::to_string(&diff).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("google.com"));
        assert!(json.contains("IANA"));
        assert!(json.contains("MarkMonitor"));
    }

    #[test]
    fn test_build_registration_diff_both_none() {
        let diff = build_registration_diff(None, None);
        assert!(diff.registrar.0.is_none());
        assert!(diff.registrar.1.is_none());
        assert!(diff.organization.0.is_none());
        assert!(diff.organization.1.is_none());
        assert!(diff.created.0.is_none());
        assert!(diff.created.1.is_none());
        assert!(diff.expires.0.is_none());
        assert!(diff.expires.1.is_none());
    }

    #[test]
    fn test_build_dns_diff_both_none() {
        let diff = build_dns_diff(None, None);
        assert!(diff.a_records.0.is_empty());
        assert!(diff.a_records.1.is_empty());
        assert!(diff.nameservers.0.is_empty());
        assert!(diff.nameservers.1.is_empty());
        assert!(!diff.resolves.0);
        assert!(!diff.resolves.1);
    }

    #[test]
    fn test_build_ssl_diff_both_none() {
        let diff = build_ssl_diff(None, None);
        assert!(diff.issuer.0.is_none());
        assert!(diff.issuer.1.is_none());
        assert!(diff.valid_until.0.is_none());
        assert!(diff.valid_until.1.is_none());
        assert!(diff.days_remaining.0.is_none());
        assert!(diff.days_remaining.1.is_none());
        assert!(diff.is_valid.0.is_none());
        assert!(diff.is_valid.1.is_none());
    }

    #[test]
    fn test_domain_differ_default() {
        let differ = DomainDiffer::default();
        // Just verify construction works
        let _ = differ;
    }

    #[test]
    fn test_extract_dates_none() {
        let (exp, created) = extract_dates(None);
        assert!(exp.is_none());
        assert!(created.is_none());
    }
}
