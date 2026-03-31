//! DNSSEC validation reporting.
//!
//! Checks the DNSSEC chain for a domain by querying DS and DNSKEY records
//! and reporting on the validation status.

use std::collections::HashMap;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::dnssec::rdata::{DNSSECRData, DNSKEY};
use hickory_resolver::proto::rr::dnssec::DigestType;
use hickory_resolver::proto::rr::{Name, RData, RecordType as HickoryRecordType};
use hickory_resolver::TokioAsyncResolver;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

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
    /// Overall status: "secure", "insecure", "partial", or "misconfigured".
    pub status: String,
    /// Whether the full DS-to-DNSKEY chain validates.
    /// True only when every DS record matches a DNSKEY and all digests verify.
    pub chain_valid: bool,
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
    /// Whether this DS record's key_tag+algorithm matched a DNSKEY.
    pub matched_key: bool,
    /// Whether the computed digest from the matched DNSKEY equals this DS digest.
    pub digest_verified: bool,
}

/// Summary of a DNSKEY record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnskeyInfo {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    /// The RFC 4034 computed key tag.
    pub key_tag: u16,
    pub is_ksk: bool,
    pub is_zsk: bool,
    pub algorithm_name: String,
}

/// Checks DNSSEC configuration for a domain.
pub struct DnssecChecker {
    resolver: DnsResolver,
    raw_resolver: TokioAsyncResolver,
}

impl Default for DnssecChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl DnssecChecker {
    pub fn new() -> Self {
        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(5);
        opts.attempts = 2;
        opts.use_hosts_file = false;

        Self {
            resolver: DnsResolver::new(),
            raw_resolver: TokioAsyncResolver::tokio(ResolverConfig::google(), opts),
        }
    }

    /// Resolves raw hickory DNSKEY records for crypto operations.
    /// Returns a vec of (DNSKEY, computed_key_tag) pairs.
    async fn resolve_raw_dnskeys(&self, domain: &str) -> Vec<(DNSKEY, u16)> {
        let lookup = match self.raw_resolver.lookup(domain, HickoryRecordType::DNSKEY).await {
            Ok(lookup) => lookup,
            Err(_) => return vec![],
        };

        lookup
            .record_iter()
            .filter_map(|record| {
                if let Some(RData::DNSSEC(DNSSECRData::DNSKEY(dnskey))) = record.data() {
                    match dnskey.calculate_key_tag() {
                        Ok(tag) => Some((dnskey.clone(), tag)),
                        Err(_) => None,
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    /// Converts a DS digest type number to hickory's DigestType.
    fn to_hickory_digest_type(digest_type: u8) -> Option<DigestType> {
        DigestType::from_u8(digest_type).ok()
    }

    /// Generate a DNSSEC validation report for a domain.
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn check(&self, domain: &str) -> Result<DnssecReport> {
        let domain = crate::validation::normalize_domain(domain)?;
        debug!(domain = %domain, "Checking DNSSEC");

        let mut issues = Vec::new();

        // Query DS records (at parent zone)
        let ds_records: Vec<crate::dns::DnsRecord> =
            match self.resolver.resolve(&domain, RecordType::DS, None).await {
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

        // Resolve raw hickory DNSKEYs for crypto operations
        let raw_dnskeys = self.resolve_raw_dnskeys(&domain).await;

        // Build lookup map: (key_tag, algorithm) -> raw DNSKEY
        let dnskey_map: HashMap<(u16, u8), &DNSKEY> = raw_dnskeys
            .iter()
            .map(|(dnskey, tag)| ((*tag, u8::from(dnskey.algorithm())), dnskey))
            .collect();

        // Build set of DS key_tags for KSK orphan detection
        let ds_key_tags: std::collections::HashSet<u16> = ds_records
            .iter()
            .filter_map(|r| {
                if let RecordData::DS { key_tag, .. } = r.data {
                    Some(key_tag)
                } else {
                    None
                }
            })
            .collect();

        // Build a map from (flags, algorithm) -> vec of computed key_tags
        // to reliably match our RecordData DNSKEYs to the raw hickory ones.
        let key_tag_by_algo_flags: HashMap<(u16, u8), Vec<u16>> = {
            let mut map: HashMap<(u16, u8), Vec<u16>> = HashMap::new();
            for (dnskey, tag) in &raw_dnskeys {
                map.entry((dnskey.flags(), u8::from(dnskey.algorithm())))
                    .or_default()
                    .push(*tag);
            }
            map
        };

        // Parse DNSKEY record info with computed key tags
        let mut dnskey_tag_indices: HashMap<(u16, u8), usize> = HashMap::new();
        let dnskey_info: Vec<DnskeyInfo> = dnskey_records
            .iter()
            .filter_map(|r| {
                if let RecordData::DNSKEY {
                    flags,
                    protocol,
                    algorithm,
                    ..
                } = r.data
                {
                    let is_sep = flags & 0x0001 != 0;
                    let is_zone = flags & 0x0100 != 0;
                    let is_ksk = is_sep && is_zone;
                    let is_zsk = is_zone && !is_sep;

                    // Find the computed key tag for this DNSKEY
                    let idx = dnskey_tag_indices
                        .entry((flags, algorithm))
                        .or_insert(0);
                    let key_tag = key_tag_by_algo_flags
                        .get(&(flags, algorithm))
                        .and_then(|tags| tags.get(*idx))
                        .copied()
                        .unwrap_or(0);
                    *idx += 1;

                    Some(DnskeyInfo {
                        flags,
                        protocol,
                        algorithm,
                        key_tag,
                        is_ksk,
                        is_zsk,
                        algorithm_name: algorithm_name(algorithm),
                    })
                } else {
                    None
                }
            })
            .collect();

        // Build Name for digest computation
        let domain_name = Name::from_ascii(&domain)
            .unwrap_or_else(|_| Name::from_ascii("invalid.").unwrap());

        // Parse DS record info with cross-validation
        let ds_info: Vec<DsInfo> = ds_records
            .iter()
            .map(|r| {
                if let RecordData::DS {
                    key_tag,
                    algorithm,
                    digest_type,
                    ref digest,
                } = r.data
                {
                    let mut matched_key = false;
                    let mut digest_verified = false;

                    // Try to match this DS to a DNSKEY
                    if let Some(raw_dnskey) = dnskey_map.get(&(key_tag, algorithm)) {
                        matched_key = true;

                        // Verify digest
                        if let Some(hickory_dt) = Self::to_hickory_digest_type(digest_type) {
                            if let Ok(computed) = raw_dnskey.to_digest(&domain_name, hickory_dt) {
                                let computed_hex: String = computed
                                    .as_ref()
                                    .iter()
                                    .map(|b| format!("{:02X}", b))
                                    .collect();
                                digest_verified = computed_hex.eq_ignore_ascii_case(digest);
                            }
                        }

                        if !digest_verified {
                            issues.push(format!(
                                "DS record (key_tag={}) digest mismatch \u{2014} registry and DNS keys do not match",
                                key_tag
                            ));
                        }
                    } else if has_dnskey {
                        issues.push(format!(
                            "DS record (key_tag={}) has no matching DNSKEY",
                            key_tag
                        ));
                    }

                    DsInfo {
                        key_tag,
                        algorithm,
                        digest_type,
                        digest: digest.clone(),
                        algorithm_name: algorithm_name(algorithm),
                        digest_type_name: digest_type_name(digest_type),
                        matched_key,
                        digest_verified,
                    }
                } else {
                    // Should not happen — we only have DS records here
                    DsInfo {
                        key_tag: 0,
                        algorithm: 0,
                        digest_type: 0,
                        digest: String::new(),
                        algorithm_name: String::new(),
                        digest_type_name: String::new(),
                        matched_key: false,
                        digest_verified: false,
                    }
                }
            })
            .collect();

        // Check for KSK orphans (DNSKEY KSKs with no corresponding DS)
        for key in &dnskey_info {
            if key.is_ksk && !ds_key_tags.contains(&key.key_tag) {
                issues.push(format!(
                    "DNSKEY (key_tag={}) is a KSK with no corresponding DS record",
                    key.key_tag
                ));
            }
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

        // Derive chain_valid
        let chain_valid = has_ds
            && has_dnskey
            && !ds_info.is_empty()
            && ds_info.iter().all(|ds| ds.matched_key && ds.digest_verified);

        // Derive status from chain validity (not from issues list)
        let enabled = has_ds || has_dnskey;
        let status = if has_ds && has_dnskey {
            if chain_valid {
                "secure".to_string()
            } else {
                "misconfigured".to_string()
            }
        } else if !has_ds && !has_dnskey {
            "insecure".to_string()
        } else {
            "partial".to_string()
        };

        // Also flag the old structural issues
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

        Ok(DnssecReport {
            domain,
            enabled,
            has_ds_records: has_ds,
            has_dnskey_records: has_dnskey,
            ds_records: ds_info,
            dnskey_records: dnskey_info,
            issues,
            status,
            chain_valid,
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
            ds_records: vec![DsInfo {
                key_tag: 12345,
                algorithm: 13,
                digest_type: 2,
                digest: "ABCDEF".to_string(),
                algorithm_name: "ECDSA P-256/SHA-256".to_string(),
                digest_type_name: "SHA-256".to_string(),
                matched_key: true,
                digest_verified: true,
            }],
            dnskey_records: vec![DnskeyInfo {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                key_tag: 12345,
                is_ksk: true,
                is_zsk: false,
                algorithm_name: "ECDSA P-256/SHA-256".to_string(),
            }],
            issues: vec![],
            status: "secure".to_string(),
            chain_valid: true,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"enabled\":true"));
        assert!(json.contains("\"chain_valid\":true"));
        assert!(json.contains("\"matched_key\":true"));
        assert!(json.contains("\"digest_verified\":true"));
        assert!(json.contains("\"key_tag\":12345"));
    }

    #[test]
    fn test_chain_valid_all_verified() {
        let report = DnssecReport {
            domain: "example.com".to_string(),
            enabled: true,
            has_ds_records: true,
            has_dnskey_records: true,
            ds_records: vec![
                DsInfo {
                    key_tag: 12345,
                    algorithm: 13,
                    digest_type: 2,
                    digest: "ABCDEF".to_string(),
                    algorithm_name: "ECDSA P-256/SHA-256".to_string(),
                    digest_type_name: "SHA-256".to_string(),
                    matched_key: true,
                    digest_verified: true,
                },
                DsInfo {
                    key_tag: 12345,
                    algorithm: 13,
                    digest_type: 4,
                    digest: "FEDCBA".to_string(),
                    algorithm_name: "ECDSA P-256/SHA-256".to_string(),
                    digest_type_name: "SHA-384".to_string(),
                    matched_key: true,
                    digest_verified: true,
                },
            ],
            dnskey_records: vec![DnskeyInfo {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                key_tag: 12345,
                is_ksk: true,
                is_zsk: false,
                algorithm_name: "ECDSA P-256/SHA-256".to_string(),
            }],
            issues: vec![],
            status: "secure".to_string(),
            chain_valid: true,
        };
        assert!(report.chain_valid);
        assert_eq!(report.status, "secure");
    }

    #[test]
    fn test_chain_valid_ds_unmatched() {
        let report = DnssecReport {
            domain: "broken.com".to_string(),
            enabled: true,
            has_ds_records: true,
            has_dnskey_records: true,
            ds_records: vec![DsInfo {
                key_tag: 65000,
                algorithm: 13,
                digest_type: 2,
                digest: "ABCDEF".to_string(),
                algorithm_name: "ECDSA P-256/SHA-256".to_string(),
                digest_type_name: "SHA-256".to_string(),
                matched_key: false,
                digest_verified: false,
            }],
            dnskey_records: vec![DnskeyInfo {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                key_tag: 12345,
                is_ksk: true,
                is_zsk: false,
                algorithm_name: "ECDSA P-256/SHA-256".to_string(),
            }],
            issues: vec!["DS record (key_tag=65000) has no matching DNSKEY".to_string()],
            status: "misconfigured".to_string(),
            chain_valid: false,
        };
        assert!(!report.chain_valid);
        assert_eq!(report.status, "misconfigured");
    }

    #[test]
    fn test_chain_valid_digest_mismatch() {
        let report = DnssecReport {
            domain: "mismatch.com".to_string(),
            enabled: true,
            has_ds_records: true,
            has_dnskey_records: true,
            ds_records: vec![DsInfo {
                key_tag: 12345,
                algorithm: 13,
                digest_type: 2,
                digest: "WRONG".to_string(),
                algorithm_name: "ECDSA P-256/SHA-256".to_string(),
                digest_type_name: "SHA-256".to_string(),
                matched_key: true,
                digest_verified: false,
            }],
            dnskey_records: vec![DnskeyInfo {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                key_tag: 12345,
                is_ksk: true,
                is_zsk: false,
                algorithm_name: "ECDSA P-256/SHA-256".to_string(),
            }],
            issues: vec![],
            status: "misconfigured".to_string(),
            chain_valid: false,
        };
        assert!(!report.chain_valid);
        assert!(report.ds_records[0].matched_key);
        assert!(!report.ds_records[0].digest_verified);
    }

    #[tokio::test]
    async fn test_live_dnssec_check_cloudflare() {
        let checker = DnssecChecker::new();
        let report = checker.check("cloudflare.com").await.unwrap();

        // cloudflare.com has DNSSEC enabled
        assert!(report.enabled, "cloudflare.com should have DNSSEC enabled");
        assert!(report.has_ds_records, "should have DS records");
        assert!(report.has_dnskey_records, "should have DNSKEY records");
        assert!(report.chain_valid, "cloudflare.com chain should be valid");
        assert_eq!(report.status, "secure");

        // All DS records should be verified
        for ds in &report.ds_records {
            assert!(ds.matched_key, "DS key_tag={} should match", ds.key_tag);
            assert!(
                ds.digest_verified,
                "DS key_tag={} digest should verify",
                ds.key_tag
            );
        }

        // Should have computed key tags on DNSKEYs
        for key in &report.dnskey_records {
            assert!(key.key_tag > 0, "key_tag should be computed");
        }
    }

    #[tokio::test]
    async fn test_live_dnssec_check_insecure() {
        let checker = DnssecChecker::new();
        // wikipedia.org does not have DNSSEC (no DS or DNSKEY records)
        let report = checker.check("wikipedia.org").await.unwrap();

        assert!(!report.chain_valid);
        assert_eq!(report.status, "insecure");
    }
}
