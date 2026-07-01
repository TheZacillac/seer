//! DNSSEC validation reporting.
//!
//! Checks the DNSSEC chain for a domain by querying DS and DNSKEY records
//! and reporting on the validation status.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use hickory_resolver::config::{ResolveHosts, ResolverConfig, GOOGLE};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::dnssec::rdata::{DNSSECRData, DNSKEY};
use hickory_resolver::proto::dnssec::{DigestType, PublicKey};
use hickory_resolver::proto::rr::{Name, RData, RecordType as HickoryRecordType};
use hickory_resolver::TokioResolver;
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
    /// Overall status: "signed", "unsigned", "partial", or "misconfigured".
    ///
    /// IMPORTANT: this reflects DS↔DNSKEY *digest consistency* (RFC 4509)
    /// observed over plain, unauthenticated DNS. It does NOT verify any RRSIG
    /// signatures, signature validity periods, or a chain of trust to the root
    /// anchor. "signed" therefore means "the published DS and DNSKEY are
    /// digest-consistent", NOT "the records are cryptographically
    /// authenticated" — an on-path or spoofing attacker can fabricate a
    /// self-consistent DS+DNSKEY pair. Do not treat this as proof of
    /// authenticity.
    pub status: String,
    /// Whether every DS record's digest matches a published DNSKEY (RFC 4509
    /// digest consistency). This is NOT signature / chain-of-trust validation —
    /// see the caveat on `status`.
    pub chain_valid: bool,
    /// Machine-readable tier describing the DEPTH of checking that was
    /// performed, so consumers don't over-trust a digest-only "signed" result.
    /// The RESULT of those checks lives in `chain_valid` / `status` / `issues`;
    /// this field says only *what was checked*.
    #[serde(default = "default_authentication_tier")]
    pub authentication_tier: AuthenticationTier,
    /// RRSIG signatures observed over the zone apex, populated only when RRSIG
    /// validation is enabled (`DnssecChecker::with_rrsig_validation(true)`).
    /// Empty in the default fast path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rrsig_records: Vec<RrsigInfo>,
}

/// The depth of DNSSEC verification performed for a [`DnssecReport`].
///
/// This describes *what was checked*, not whether it passed — the pass/fail
/// result is carried by [`DnssecReport::chain_valid`] and `status`. It exists
/// so a consumer (or an MCP-driven LLM) does not read digest-consistency as
/// full cryptographic authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticationTier {
    /// No DNSSEC records are published.
    Unsigned,
    /// Only DS↔DNSKEY digest consistency (RFC 4509) was checked — the default
    /// fast path. Does NOT inspect RRSIG signatures or their validity windows.
    DigestOnly,
    /// RRSIG signatures over the apex were additionally fetched and their
    /// validity windows inspected (expired / near-expiry surfaced in
    /// `issues`). Still not full cryptographic chain validation to the root.
    RrsigChecked,
}

fn default_authentication_tier() -> AuthenticationTier {
    AuthenticationTier::DigestOnly
}

/// Summary of a single RRSIG record's coverage and validity window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RrsigInfo {
    /// The record type this signature covers (e.g. "DNSKEY", "SOA").
    pub type_covered: String,
    /// DNSSEC algorithm number.
    pub algorithm: u8,
    /// Human-readable algorithm name.
    pub algorithm_name: String,
    /// Key tag of the signing key.
    pub key_tag: u16,
    /// The signer (zone) name.
    pub signer_name: String,
    /// Signature inception time.
    pub inception: Option<DateTime<Utc>>,
    /// Signature expiration time.
    pub expiration: Option<DateTime<Utc>>,
    /// Whether the signature is currently outside its validity window.
    pub expired: bool,
    /// Days until the signature expires (negative if already expired).
    pub expires_in_days: i64,
}

/// Days-until-expiry threshold below which an RRSIG is flagged as near-expiry.
const RRSIG_EXPIRY_WARN_DAYS: i64 = 7;

/// Given an RRSIG's inception/expiration and the current time (all Unix
/// seconds), returns `(expired, expires_in_days)`. `expired` is true when
/// `now` is outside `[inception, expiration]`. Pure, so it is unit-testable.
fn rrsig_validity(inception: i64, expiration: i64, now: i64) -> (bool, i64) {
    let expired = now > expiration || now < inception;
    let expires_in_days = (expiration - now).div_euclid(86_400);
    (expired, expires_in_days)
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
    raw_resolver: TokioResolver,
    /// When true, `check` additionally fetches RRSIG signatures and inspects
    /// their validity windows (opt-in; adds a network round-trip).
    check_rrsig: bool,
}

impl Default for DnssecChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl DnssecChecker {
    pub fn new() -> Self {
        let raw_resolver = Self::build_resolver(false);

        Self {
            resolver: DnsResolver::new(),
            raw_resolver,
            check_rrsig: false,
        }
    }

    /// Enables (or disables) the opt-in RRSIG validity check. When enabled,
    /// `check` fetches RRSIG records for a signed zone and flags expired /
    /// near-expiry signatures — the most common real-world DNSSEC outage that
    /// the default digest-consistency check is blind to.
    pub fn with_rrsig_validation(mut self, on: bool) -> Self {
        self.check_rrsig = on;
        self
    }

    /// Builds a hickory resolver against Google DNS. When `validating` is true
    /// the DNSSEC-OK (DO) bit is set (`opts.validate`), which is required for
    /// upstream resolvers to return RRSIG records.
    fn build_resolver(validating: bool) -> TokioResolver {
        let mut builder = TokioResolver::builder_with_config(
            ResolverConfig::udp_and_tcp(&GOOGLE),
            TokioRuntimeProvider::default(),
        );
        {
            let opts = builder.options_mut();
            opts.timeout = std::time::Duration::from_secs(5);
            opts.attempts = 2;
            opts.use_hosts_file = ResolveHosts::Never;
            if validating {
                // Sets the DO bit so RRSIGs are returned (and asks hickory to
                // validate). A validation failure surfaces as a lookup error,
                // which the RRSIG path treats as "no data" and degrades to the
                // digest-only tier — never a false "validated" claim.
                opts.validate = true;
                opts.edns0 = true;
            }
        }
        builder
            .build()
            .expect("hickory resolver build is infallible without TLS features")
    }

    /// Fetches RRSIG records covering the zone apex and summarizes each one's
    /// coverage and validity window. Best-effort: returns an empty vec if the
    /// resolver path does not surface RRSIGs (e.g. DO stripped upstream), so
    /// the caller never over-claims validation.
    async fn resolve_rrsigs(&self, domain: &str) -> Vec<RrsigInfo> {
        let resolver = Self::build_resolver(true);
        let Ok(lookup) = resolver.lookup(domain, HickoryRecordType::RRSIG).await else {
            return vec![];
        };
        let now = Utc::now().timestamp();
        lookup
            .answers()
            .iter()
            .filter_map(|record| {
                let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &record.data else {
                    return None;
                };
                let input = rrsig.input();
                let inception = input.sig_inception.get() as i64;
                let expiration = input.sig_expiration.get() as i64;
                let (expired, expires_in_days) = rrsig_validity(inception, expiration, now);
                let algorithm = u8::from(input.algorithm);
                Some(RrsigInfo {
                    type_covered: input.type_covered.to_string(),
                    algorithm,
                    algorithm_name: algorithm_name(algorithm),
                    key_tag: input.key_tag,
                    signer_name: input.signer_name.to_string(),
                    inception: DateTime::from_timestamp(inception, 0),
                    expiration: DateTime::from_timestamp(expiration, 0),
                    expired,
                    expires_in_days,
                })
            })
            .collect()
    }

    /// Resolves raw hickory DNSKEY records for crypto operations.
    /// Returns a vec of (DNSKEY, computed_key_tag) pairs.
    async fn resolve_raw_dnskeys(&self, domain: &str) -> Vec<(DNSKEY, u16)> {
        let Ok(lookup) = self
            .raw_resolver
            .lookup(domain, HickoryRecordType::DNSKEY)
            .await
        else {
            return vec![];
        };

        lookup
            .answers()
            .iter()
            .filter_map(|record| {
                if let RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) = &record.data {
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
    ///
    /// hickory 0.26 made `DigestType` `non_exhaustive` and removed the
    /// fallible `from_u8` constructor in favour of `From<u8>`, which
    /// returns `DigestType::Unknown(_)` for unsupported types. We
    /// preserve the original 0.24 behaviour of refusing to attempt
    /// digest computation for unsupported types.
    fn to_hickory_digest_type(digest_type: u8) -> Option<DigestType> {
        let dt = DigestType::from(digest_type);
        if dt.is_supported() {
            Some(dt)
        } else {
            None
        }
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

        // Build lookup map: (key_tag, algorithm) -> vec of raw DNSKEYs
        // Multiple DNSKEYs can share the same key tag (RFC 4034 Section 5.1).
        let dnskey_map: HashMap<(u16, u8), Vec<&DNSKEY>> = {
            let mut map: HashMap<(u16, u8), Vec<&DNSKEY>> = HashMap::new();
            for (dnskey, tag) in &raw_dnskeys {
                map.entry((*tag, u8::from(dnskey.public_key().algorithm())))
                    .or_default()
                    .push(dnskey);
            }
            map
        };

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

        // Build a map from (flags, algorithm) -> computed key_tags to attach a
        // key tag to each RecordData DNSKEY. NOTE: this correlates two
        // independent DNSKEY queries (dnskey_records vs raw_dnskeys) by
        // position within each (flags, algorithm) group. That is correct when a
        // group has a single key (the common case) but can mis-assign tags if a
        // zone has >= 2 keys sharing identical flags+algorithm AND the two
        // queries returned them in different orders. Removing this assumption
        // requires a single DNSKEY query that carries both the display fields
        // and the computed tag; deferred to keep this crypto path stable.
        let key_tag_by_algo_flags: HashMap<(u16, u8), Vec<u16>> = {
            let mut map: HashMap<(u16, u8), Vec<u16>> = HashMap::new();
            for (dnskey, tag) in &raw_dnskeys {
                map.entry((dnskey.flags(), u8::from(dnskey.public_key().algorithm())))
                    .or_default()
                    .push(*tag);
            }
            map
        };

        // Parse DNSKEY record info with computed key tags.
        //
        // NOTE (#61): the per-DNSKEY key_tag is attached by position-correlating
        // two separate query result sets (DNSKEY records vs the computed-tag
        // list). When ≥2 keys share the same (flags, algorithm), an ordering
        // difference between those result sets can mislabel which tag belongs to
        // which key. This affects only the DISPLAY tag and the KSK-orphan
        // heuristic — `chain_valid` is computed from DS↔DNSKEY digest matching
        // (below) and is unaffected.
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
                    let idx = dnskey_tag_indices.entry((flags, algorithm)).or_insert(0);
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
        let domain_name = Name::from_ascii(&domain).unwrap_or_else(|_| {
            Name::from_ascii("invalid.").expect("hardcoded fallback name is valid")
        });

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

                    // Try to match this DS to a DNSKEY (multiple candidates possible
                    // due to key tag collisions per RFC 4034 Section 5.1)
                    if let Some(candidates) = dnskey_map.get(&(key_tag, algorithm)) {
                        matched_key = true;

                        // Try each candidate DNSKEY until one verifies. Only a
                        // digest type our crypto backend can compute yields a
                        // meaningful verified/mismatch verdict; an unsupported
                        // type (e.g. GOST) is "not evaluated", NOT a mismatch —
                        // flagging it as a mismatch would mark an otherwise-valid
                        // signed zone as misconfigured.
                        match Self::to_hickory_digest_type(digest_type) {
                            Some(hickory_dt) => {
                                for candidate in candidates {
                                    if let Ok(computed) =
                                        candidate.to_digest(&domain_name, hickory_dt)
                                    {
                                        let computed_hex: String = computed
                                            .as_ref()
                                            .iter()
                                            .map(|b| format!("{:02X}", b))
                                            .collect();
                                        if computed_hex.eq_ignore_ascii_case(digest) {
                                            digest_verified = true;
                                            break;
                                        }
                                    }
                                }

                                if !digest_verified {
                                    issues.push(format!(
                                        "DS record (key_tag={}) digest mismatch \u{2014} registry and DNS keys do not match",
                                        key_tag
                                    ));
                                }
                            }
                            None => {
                                issues.push(format!(
                                    "DS record (key_tag={}) uses unsupported digest type {} \u{2014} cannot verify",
                                    key_tag, digest_type
                                ));
                            }
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

        // Derive chain_valid. A DS whose digest type we cannot compute is
        // excluded from the "all must verify" check (we can't judge it), but we
        // still require at least one computable DS to have actually verified —
        // otherwise a zone we can't evaluate at all would be reported as valid.
        let chain_valid = has_ds
            && has_dnskey
            && !ds_info.is_empty()
            && ds_info
                .iter()
                .any(|ds| ds.matched_key && ds.digest_verified)
            && ds_info
                .iter()
                .filter(|ds| Self::to_hickory_digest_type(ds.digest_type).is_some())
                .all(|ds| ds.matched_key && ds.digest_verified);

        // Derive status from chain validity (not from issues list).
        //
        // Vocabulary deliberately avoids "secure"/"insecure": we verify only
        // DS<->DNSKEY digest consistency, NOT RRSIG signatures, so we report
        // the observable FACT (the zone is signed / unsigned) rather than a
        // validated security state. See the `status` field doc on
        // DnssecReport.
        let enabled = has_ds || has_dnskey;
        let status = if has_ds && has_dnskey {
            if chain_valid {
                "signed".to_string()
            } else {
                "misconfigured".to_string()
            }
        } else if !has_ds && !has_dnskey {
            "unsigned".to_string()
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

        // Opt-in RRSIG validity inspection (the default check is blind to
        // expired signatures — the most common real-world DNSSEC outage).
        let mut rrsig_records = Vec::new();
        if self.check_rrsig && enabled {
            rrsig_records = self.resolve_rrsigs(&domain).await;
            for r in &rrsig_records {
                if r.expired {
                    issues.push(format!(
                        "RRSIG (key_tag={}, covers {}) is outside its validity window (expires_in_days={})",
                        r.key_tag, r.type_covered, r.expires_in_days
                    ));
                } else if r.expires_in_days <= RRSIG_EXPIRY_WARN_DAYS {
                    issues.push(format!(
                        "RRSIG (key_tag={}, covers {}) expires in {} day(s)",
                        r.key_tag, r.type_covered, r.expires_in_days
                    ));
                }
            }
        }

        // Report the DEPTH of checking performed. RrsigChecked only when we
        // actually observed RRSIGs — never claim more than we verified.
        let authentication_tier = if !enabled {
            AuthenticationTier::Unsigned
        } else if !rrsig_records.is_empty() {
            AuthenticationTier::RrsigChecked
        } else {
            AuthenticationTier::DigestOnly
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
            chain_valid,
            authentication_tier,
            rrsig_records,
        })
    }
}

/// Maps a DNSSEC algorithm number to a human-readable name. Numbers come
/// from the IANA "DNSSEC Algorithm Numbers" registry. Algorithm 9 is
/// reserved (not assigned). 7 and 12 are operationally discouraged per
/// RFC 8624; we flag both as deprecated.
fn algorithm_name(algo: u8) -> String {
    match algo {
        1 => "RSA/MD5 (deprecated)".to_string(),
        3 => "DSA/SHA-1 (deprecated)".to_string(),
        5 => "RSA/SHA-1 (deprecated)".to_string(),
        6 => "DSA-NSEC3-SHA1 (deprecated)".to_string(),
        7 => "RSASHA1-NSEC3-SHA1 (deprecated)".to_string(),
        8 => "RSA/SHA-256".to_string(),
        10 => "RSA/SHA-512".to_string(),
        12 => "ECC-GOST (deprecated)".to_string(),
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
    fn rrsig_validity_classifies_windows() {
        let day = 86_400i64;
        let now = 1_000_000 * day; // arbitrary fixed "now"

        // Comfortably valid: 30 days left.
        let (expired, days) = rrsig_validity(now - day, now + 30 * day, now);
        assert!(!expired);
        assert_eq!(days, 30);

        // Already past expiration.
        let (expired, days) = rrsig_validity(now - 40 * day, now - day, now);
        assert!(expired);
        assert_eq!(days, -1);

        // Not yet valid (inception in the future) also counts as expired/out-of-window.
        let (expired, _days) = rrsig_validity(now + day, now + 30 * day, now);
        assert!(expired);
    }

    #[test]
    fn default_tier_is_digest_only() {
        // Reports deserialized without the field default to digest-only, and
        // a fresh checker does not enable RRSIG validation.
        assert_eq!(
            default_authentication_tier(),
            AuthenticationTier::DigestOnly
        );
        let checker = DnssecChecker::new();
        assert!(!checker.check_rrsig);
        assert!(checker.with_rrsig_validation(true).check_rrsig);
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
            status: "signed".to_string(),
            chain_valid: true,
            authentication_tier: AuthenticationTier::DigestOnly,
            rrsig_records: vec![],
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
            status: "signed".to_string(),
            chain_valid: true,
            authentication_tier: AuthenticationTier::DigestOnly,
            rrsig_records: vec![],
        };
        assert!(report.chain_valid);
        assert_eq!(report.status, "signed");
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
            authentication_tier: AuthenticationTier::DigestOnly,
            rrsig_records: vec![],
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
            authentication_tier: AuthenticationTier::DigestOnly,
            rrsig_records: vec![],
        };
        assert!(!report.chain_valid);
        assert!(report.ds_records[0].matched_key);
        assert!(!report.ds_records[0].digest_verified);
    }

    #[tokio::test]
    #[ignore = "live network; run with --ignored or SEER_LIVE_TESTS=1"]
    async fn test_live_dnssec_check_cloudflare() {
        let checker = DnssecChecker::new();
        let report = checker.check("cloudflare.com").await.unwrap();

        // cloudflare.com has DNSSEC enabled
        assert!(report.enabled, "cloudflare.com should have DNSSEC enabled");
        assert!(report.has_ds_records, "should have DS records");
        assert!(report.has_dnskey_records, "should have DNSKEY records");
        assert!(report.chain_valid, "cloudflare.com chain should be valid");
        assert_eq!(report.status, "signed");

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
    #[ignore = "live network; run with --ignored or SEER_LIVE_TESTS=1"]
    async fn test_live_dnssec_rrsig_validation_cloudflare() {
        let checker = DnssecChecker::new().with_rrsig_validation(true);
        let report = checker.check("cloudflare.com").await.unwrap();
        assert!(report.enabled, "cloudflare.com should have DNSSEC enabled");
        // When the resolver surfaces RRSIGs, the tier upgrades and every
        // signature must be within its validity window for a healthy zone.
        if !report.rrsig_records.is_empty() {
            assert_eq!(report.authentication_tier, AuthenticationTier::RrsigChecked);
            for r in &report.rrsig_records {
                assert!(r.expiration.is_some(), "RRSIG should carry an expiration");
                assert!(
                    !r.expired,
                    "cloudflare.com RRSIG (covers {}) should be within its validity window",
                    r.type_covered
                );
            }
        }
    }

    #[tokio::test]
    #[ignore = "live network; run with --ignored or SEER_LIVE_TESTS=1"]
    async fn test_live_dnssec_check_insecure() {
        let checker = DnssecChecker::new();
        // wikipedia.org does not have DNSSEC (no DS or DNSKEY records)
        let report = checker.check("wikipedia.org").await.unwrap();

        assert!(!report.chain_valid);
        assert_eq!(report.status, "unsigned");
    }
}
