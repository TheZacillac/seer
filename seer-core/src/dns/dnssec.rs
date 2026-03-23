//! DNSSEC validation reporting.
//!
//! Checks the DNSSEC chain for a domain by querying DS and DNSKEY records
//! and reporting on the validation status.

use serde::{Deserialize, Serialize};
use tracing::debug;

use super::records::{RecordData, RecordType};
use super::resolver::DnsResolver;
use crate::error::Result;

/// DNSSEC validation report for a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecReport {
    /// The domain that was checked.
    pub domain: String,
    /// Whether the domain has DNSSEC enabled.
    pub enabled: bool,
    /// Whether DS records exist at the parent zone.
    pub has_ds_records: bool,
    /// Whether DNSKEY records exist at the domain.
    pub has_dnskey_records: bool,
    /// DS records found at the parent zone.
    pub ds_records: Vec<DsInfo>,
    /// DNSKEY records found at the domain.
    pub dnskey_records: Vec<DnskeyInfo>,
    /// Validation issues found.
    pub issues: Vec<String>,
    /// Overall status: "secure", "insecure", "partial", or "error".
    pub status: String,
}

/// Summary of a DS record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsInfo {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: String,
    pub algorithm_name: String,
    pub digest_type_name: String,
}

/// Summary of a DNSKEY record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnskeyInfo {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub key_tag_hint: String,
    pub is_ksk: bool,
    pub is_zsk: bool,
    pub algorithm_name: String,
}

/// Checks DNSSEC configuration for a domain.
pub struct DnssecChecker {
    resolver: DnsResolver,
}

impl Default for DnssecChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl DnssecChecker {
    pub fn new() -> Self {
        Self {
            resolver: DnsResolver::new(),
        }
    }

    /// Generate a DNSSEC validation report for a domain.
    pub async fn check(&self, domain: &str) -> Result<DnssecReport> {
        let domain = crate::validation::normalize_domain(domain)?;
        debug!(domain = %domain, "Checking DNSSEC");

        let mut issues = Vec::new();

        // Query DS records (at parent zone)
        let ds_records: Vec<crate::dns::DnsRecord> = match self
            .resolver
            .resolve(&domain, RecordType::DS, None)
            .await
        {
            Ok(records) => records,
            Err(e) => {
                issues.push(format!("DS query failed: {}", e));
                vec![]
            }
        };

        // Query DNSKEY records (at the domain itself)
        let dnskey_records: Vec<crate::dns::DnsRecord> = match self
            .resolver
            .resolve(&domain, RecordType::DNSKEY, None)
            .await
        {
            Ok(records) => records,
            Err(e) => {
                issues.push(format!("DNSKEY query failed: {}", e));
                vec![]
            }
        };

        let has_ds = !ds_records.is_empty();
        let has_dnskey = !dnskey_records.is_empty();

        // Parse DS record info
        let ds_info: Vec<DsInfo> = ds_records
            .iter()
            .filter_map(|r| {
                if let RecordData::DS {
                    key_tag,
                    algorithm,
                    digest_type,
                    ref digest,
                } = r.data
                {
                    Some(DsInfo {
                        key_tag,
                        algorithm,
                        digest_type,
                        digest: digest.clone(),
                        algorithm_name: algorithm_name(algorithm),
                        digest_type_name: digest_type_name(digest_type),
                    })
                } else {
                    None
                }
            })
            .collect();

        // Parse DNSKEY record info
        let dnskey_info: Vec<DnskeyInfo> = dnskey_records
            .iter()
            .filter_map(|r| {
                if let RecordData::DNSKEY {
                    flags,
                    protocol,
                    algorithm,
                    ref public_key,
                } = r.data
                {
                    let is_sep = flags & 0x0001 != 0; // SEP flag (bit 15)
                    let is_zone = flags & 0x0100 != 0; // Zone flag (bit 7)
                    let is_ksk = is_sep && is_zone;
                    let is_zsk = is_zone && !is_sep;
                    let key_tag_hint = if public_key.len() > 12 {
                        format!(
                            "{}...{}",
                            &public_key[..8],
                            &public_key[public_key.len() - 4..]
                        )
                    } else {
                        public_key.clone()
                    };
                    Some(DnskeyInfo {
                        flags,
                        protocol,
                        algorithm,
                        key_tag_hint,
                        is_ksk,
                        is_zsk,
                        algorithm_name: algorithm_name(algorithm),
                    })
                } else {
                    None
                }
            })
            .collect();

        // Validate
        if has_ds && !has_dnskey {
            issues.push(
                "DS records exist but no DNSKEY records found - DNSSEC may be broken".to_string(),
            );
        }
        if !has_ds && has_dnskey {
            issues.push(
                "DNSKEY records exist but no DS records at parent - DNSSEC chain incomplete"
                    .to_string(),
            );
        }

        // Check for deprecated algorithms in DS records
        for ds in &ds_info {
            if ds.algorithm == 1 || ds.algorithm == 3 || ds.algorithm == 5 || ds.algorithm == 6 {
                issues.push(format!(
                    "DS record uses deprecated algorithm {} ({})",
                    ds.algorithm, ds.algorithm_name
                ));
            }
            if ds.digest_type == 1 {
                issues.push(
                    "DS record uses SHA-1 digest (type 1) - consider upgrading to SHA-256 (type 2)"
                        .to_string(),
                );
            }
        }

        // Check for deprecated algorithms in DNSKEY records
        for key in &dnskey_info {
            if key.algorithm == 1 || key.algorithm == 3 || key.algorithm == 5 || key.algorithm == 6
            {
                issues.push(format!(
                    "DNSKEY record uses deprecated algorithm {} ({})",
                    key.algorithm, key.algorithm_name
                ));
            }
        }

        let enabled = has_ds || has_dnskey;
        let status = if has_ds && has_dnskey && issues.is_empty() {
            "secure".to_string()
        } else if has_ds && has_dnskey {
            "partial".to_string()
        } else if !has_ds && !has_dnskey {
            "insecure".to_string()
        } else {
            "partial".to_string()
        };

        Ok(DnssecReport {
            domain,
            enabled,
            has_ds_records: has_ds,
            has_dnskey_records: has_dnskey,
            ds_records: ds_info,
            dnskey_records: dnskey_info,
            issues,
            status,
        })
    }
}

fn algorithm_name(algo: u8) -> String {
    match algo {
        1 => "RSA/MD5 (deprecated)".to_string(),
        3 => "DSA/SHA-1 (deprecated)".to_string(),
        5 => "RSA/SHA-1 (deprecated)".to_string(),
        6 => "DSA-NSEC3-SHA1 (deprecated)".to_string(),
        7 => "RSASHA1-NSEC3-SHA1".to_string(),
        8 => "RSA/SHA-256".to_string(),
        10 => "RSA/SHA-512".to_string(),
        13 => "ECDSA P-256/SHA-256".to_string(),
        14 => "ECDSA P-384/SHA-384".to_string(),
        15 => "Ed25519".to_string(),
        16 => "Ed448".to_string(),
        _ => format!("Unknown ({})", algo),
    }
}

fn digest_type_name(dtype: u8) -> String {
    match dtype {
        1 => "SHA-1".to_string(),
        2 => "SHA-256".to_string(),
        4 => "SHA-384".to_string(),
        _ => format!("Unknown ({})", dtype),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_names() {
        assert_eq!(algorithm_name(8), "RSA/SHA-256");
        assert_eq!(algorithm_name(13), "ECDSA P-256/SHA-256");
        assert_eq!(algorithm_name(15), "Ed25519");
        assert!(algorithm_name(5).contains("deprecated"));
    }

    #[test]
    fn test_digest_type_names() {
        assert_eq!(digest_type_name(1), "SHA-1");
        assert_eq!(digest_type_name(2), "SHA-256");
    }

    #[test]
    fn test_report_serialization() {
        let report = DnssecReport {
            domain: "example.com".to_string(),
            enabled: true,
            has_ds_records: true,
            has_dnskey_records: true,
            ds_records: vec![],
            dnskey_records: vec![],
            issues: vec![],
            status: "secure".to_string(),
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"enabled\":true"));
    }
}
