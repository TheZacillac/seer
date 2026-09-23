//! DNSSEC validation reporting.
//!
//! Checks the DNSSEC chain for a domain by querying DS and DNSKEY records
//! and reporting on the validation status. The records are read at the apex
//! of the zone that holds the name (found by an SOA walk), so a host inside
//! a signed zone — `api.cloudflare.com` — reports on `cloudflare.com` rather
//! than as "unsigned".

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use hickory_resolver::config::ResolverOpts;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::dnssec::rdata::{DNSSECRData, DNSKEY, DS};
use hickory_resolver::proto::dnssec::{DigestType, PublicKey};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType as HickoryRecordType};
use hickory_resolver::TokioResolver;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use super::resolver::{apply_standard_opts, fqdn, google_or_pinned};
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
    /// "misconfigured" covers a DS↔DNSKEY mismatch and a DS at the parent
    /// with no (or an unobtainable) DNSKEY behind it — validating resolvers
    /// fail such a zone. "partial" is a DNSKEY with no DS (an island of
    /// security), or a DS set validators would ignore entirely.
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

/// Upper bound on names probed while walking up to the enclosing zone apex.
/// A negative answer usually names the apex directly (the SOA in its
/// AUTHORITY section), so the walk rarely takes more than one step.
const MAX_ZONE_WALK: usize = 8;

/// Per-query timeout, matching the resolver default.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Where [`DnssecChecker::find_zone_apex`] landed.
#[derive(Debug, PartialEq, Eq)]
enum ZoneApex {
    /// The zone apex that owns (or encloses) the name.
    Found(String),
    /// The name does not exist (NXDOMAIN) — there is no zone to walk to.
    NxDomain,
    /// The apex could not be determined; the reason, when a query failed.
    Unknown(Option<String>),
}

/// Checks DNSSEC configuration for a domain.
pub struct DnssecChecker {
    /// Plain (non-validating) resolver for the SOA / DS / DNSKEY reads. A
    /// single resolver and a single DNSKEY query feed both the displayed key
    /// list and the digest verification, so the two can never disagree.
    resolver: TokioResolver,
    /// When true, `check` additionally fetches RRSIG signatures and inspects
    /// their validity windows (opt-in; adds a network round-trip).
    check_rrsig: bool,
    /// Test-only: pin every resolver this checker builds to a loopback mock.
    #[cfg(test)]
    upstream: Option<(IpAddr, u16)>,
}

impl Default for DnssecChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl DnssecChecker {
    pub fn new() -> Self {
        Self {
            resolver: Self::build_resolver(false, None),
            check_rrsig: false,
            #[cfg(test)]
            upstream: None,
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

    /// Test-only: point the checker at a loopback mock server.
    #[cfg(test)]
    fn with_upstream(mut self, ip: IpAddr, port: u16) -> Self {
        self.upstream = Some((ip, port));
        self.resolver = Self::build_resolver(false, self.upstream);
        self
    }

    #[cfg(test)]
    fn upstream(&self) -> Option<(IpAddr, u16)> {
        self.upstream
    }

    #[cfg(not(test))]
    fn upstream(&self) -> Option<(IpAddr, u16)> {
        None
    }

    /// Builds a hickory resolver against Google DNS (or, in tests only, the
    /// pinned loopback `upstream`) with the shared option set from
    /// [`apply_standard_opts`]. When `validating` is true the DNSSEC-OK (DO)
    /// bit is set (`opts.validate`), which is required for upstream
    /// resolvers to return RRSIG records.
    fn build_resolver(validating: bool, upstream: Option<(IpAddr, u16)>) -> TokioResolver {
        let mut builder = TokioResolver::builder_with_config(
            google_or_pinned(upstream),
            TokioRuntimeProvider::default(),
        );
        apply_dnssec_opts(builder.options_mut(), validating);
        builder
            .build()
            .expect("hickory resolver build is infallible without TLS features")
    }

    /// Fetches RRSIG records covering the zone apex and summarizes each one's
    /// coverage and validity window. Best-effort: returns an empty vec if the
    /// resolver path does not surface RRSIGs (e.g. DO stripped upstream), so
    /// the caller never over-claims validation.
    async fn resolve_rrsigs(&self, zone: &str) -> Vec<RrsigInfo> {
        let resolver = Self::build_resolver(true, self.upstream());
        let Ok(lookup) = resolver.lookup(fqdn(zone), HickoryRecordType::RRSIG).await else {
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

    /// Queries the DS RRset for `zone` (served by the parent zone).
    /// NXDOMAIN/NODATA fold to an empty set; a failed query is an `Err` with
    /// a human-readable reason.
    async fn lookup_ds(&self, zone: &str) -> std::result::Result<Vec<DS>, String> {
        match self
            .resolver
            .lookup(fqdn(zone), HickoryRecordType::DS)
            .await
        {
            Ok(lookup) => Ok(lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::DNSSEC(DNSSECRData::DS(ds)) => Some(ds.clone()),
                    _ => None,
                })
                .collect()),
            Err(e) if e.is_no_records_found() => Ok(Vec::new()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Queries the DNSKEY RRset for `zone`, pairing each key with its
    /// RFC 4034 key tag (`None` when the tag cannot be computed). This one
    /// answer feeds both the report's key list and the DS digest checks —
    /// they used to come from two independent queries, so a failure of only
    /// the second silently turned every DS into "no matching DNSKEY".
    async fn lookup_dnskeys(
        &self,
        zone: &str,
    ) -> std::result::Result<Vec<(DNSKEY, Option<u16>)>, String> {
        match self
            .resolver
            .lookup(fqdn(zone), HickoryRecordType::DNSKEY)
            .await
        {
            Ok(lookup) => Ok(lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::DNSSEC(DNSSECRData::DNSKEY(key)) => {
                        Some((key.clone(), key.calculate_key_tag().ok()))
                    }
                    _ => None,
                })
                .collect()),
            Err(e) if e.is_no_records_found() => Ok(Vec::new()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Finds the apex of the zone that holds `name`.
    ///
    /// DS lives at a zone cut and DNSKEY at a zone apex, so querying them at
    /// a name inside a zone (`api.cloudflare.com`) finds neither and used to
    /// report a signed zone as "unsigned". Each step asks for the SOA:
    /// an SOA owned by the candidate makes it the apex, and a negative
    /// answer's AUTHORITY-section SOA names the enclosing apex directly.
    /// Otherwise the walk moves up one label (bounded by [`MAX_ZONE_WALK`],
    /// never above two labels).
    ///
    /// A failed SOA query is not trusted blindly: a validating upstream
    /// SERVFAILs every name in a zone with a broken chain, apex included —
    /// but the DS RRset is served by the healthy parent, so a DS answer still
    /// identifies the (broken) zone cut. Without one the walk stops rather
    /// than guess past the failure.
    async fn find_zone_apex(&self, name: &str) -> ZoneApex {
        let mut candidate = name;
        for step in 0..MAX_ZONE_WALK {
            match self
                .resolver
                .lookup(fqdn(candidate), HickoryRecordType::SOA)
                .await
            {
                Ok(lookup) => {
                    if let Some(apex) = soa_apex(
                        candidate,
                        lookup.answers().iter().chain(lookup.authorities()),
                    ) {
                        return ZoneApex::Found(apex);
                    }
                }
                Err(NetError::Dns(DnsError::NoRecordsFound(no_records))) => {
                    if no_records.response_code == ResponseCode::NXDomain && step == 0 {
                        return ZoneApex::NxDomain;
                    }
                    let soa_owner = no_records.soa.as_ref().map(|soa| &soa.name);
                    if let Some(apex) = soa_owner.and_then(|owner| {
                        let owner = normalize_owner(owner);
                        is_self_or_ancestor(&owner, candidate).then_some(owner)
                    }) {
                        return ZoneApex::Found(apex);
                    }
                }
                Err(e) => {
                    return match self.lookup_ds(candidate).await {
                        Ok(ds) if !ds.is_empty() => ZoneApex::Found(candidate.to_string()),
                        _ => ZoneApex::Unknown(Some(format!(
                            "SOA query for {candidate} failed: {e}"
                        ))),
                    };
                }
            }
            match candidate.split_once('.') {
                Some((_, parent)) if parent.contains('.') => candidate = parent,
                _ => break,
            }
        }
        ZoneApex::Unknown(None)
    }

    /// Generate a DNSSEC validation report for a domain.
    ///
    /// The DS/DNSKEY checks run at the apex of the zone enclosing `domain`
    /// (see [`find_zone_apex`](Self::find_zone_apex)); when that is not
    /// `domain` itself, the first entry of `issues` names the zone that was
    /// evaluated. `DnssecReport::domain` is always the (normalized) name that
    /// was asked about.
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn check(&self, domain: &str) -> Result<DnssecReport> {
        // `normalize_host`, not `normalize_domain`: the zone walk below
        // decides where the records live, so `www.` must not be pre-stripped
        // (a `www` zone cut, however rare, would otherwise be skipped).
        let domain = crate::validation::normalize_host(domain)?;
        debug!(domain = %domain, "Checking DNSSEC");

        let mut issues = Vec::new();
        let zone = match self.find_zone_apex(&domain).await {
            ZoneApex::Found(zone) => {
                if zone != domain {
                    issues.push(format!(
                        "{domain} is not a zone apex \u{2014} DS/DNSKEY were evaluated at its \
                         enclosing zone {zone}"
                    ));
                }
                zone
            }
            ZoneApex::NxDomain => {
                issues.push(format!("{domain} does not exist (NXDOMAIN)"));
                domain.clone()
            }
            ZoneApex::Unknown(reason) => {
                // Fall back to the pre-walk behaviour: the name with `www.`
                // stripped (`www` is virtually never a zone cut).
                let fallback = crate::validation::normalize_domain(&domain)?;
                if let Some(reason) = reason {
                    issues.push(format!(
                        "could not determine the zone enclosing {domain} ({reason}); \
                         evaluated {fallback}"
                    ));
                }
                fallback
            }
        };

        // DS (at the parent) and DNSKEY (at the apex), concurrently.
        let (ds_result, dnskey_result) =
            tokio::join!(self.lookup_ds(&zone), self.lookup_dnskeys(&zone));
        let ds_records = ds_result.unwrap_or_else(|e| {
            issues.push(format!("DS query failed: {e}"));
            Vec::new()
        });
        let dnskey_query_failed = dnskey_result.is_err();
        let dnskeys = dnskey_result.unwrap_or_else(|e| {
            issues.push(format!("DNSKEY query failed: {e}"));
            Vec::new()
        });

        let has_ds = !ds_records.is_empty();
        let has_dnskey = !dnskeys.is_empty();

        // (key_tag, algorithm) -> candidate DNSKEYs. Multiple DNSKEYs can
        // share a key tag (RFC 4034 §5.1). Keys whose tag cannot be computed
        // cannot be matched.
        let mut dnskey_map: HashMap<(u16, u8), Vec<&DNSKEY>> = HashMap::new();
        for (key, tag) in &dnskeys {
            if let Some(tag) = tag {
                dnskey_map
                    .entry((*tag, u8::from(key.public_key().algorithm())))
                    .or_default()
                    .push(key);
            }
        }

        let dnskey_info: Vec<DnskeyInfo> = dnskeys
            .iter()
            .map(|(key, tag)| {
                let flags = key.flags();
                let algorithm = u8::from(key.public_key().algorithm());
                let is_sep = flags & 0x0001 != 0;
                let is_zone = flags & 0x0100 != 0;
                DnskeyInfo {
                    flags,
                    // Protocol is always 3 for DNSSEC (RFC 4034)
                    protocol: 3,
                    algorithm,
                    key_tag: tag.unwrap_or(0),
                    is_ksk: is_sep && is_zone,
                    is_zsk: is_zone && !is_sep,
                    algorithm_name: algorithm_name(algorithm),
                }
            })
            .collect();

        // Build Name for digest computation (the DNSKEY owner = the apex).
        let zone_name = Name::from_ascii(&zone).unwrap_or_else(|_| {
            Name::from_ascii("invalid.").expect("hardcoded fallback name is valid")
        });

        // Parse DS record info with cross-validation
        let ds_info: Vec<DsInfo> = ds_records
            .iter()
            .map(|ds| {
                let key_tag = ds.key_tag();
                let algorithm = u8::from(ds.algorithm());
                let digest_type = u8::from(ds.digest_type());
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
                            digest_verified = candidates.iter().any(|candidate| {
                                candidate
                                    .to_digest(&zone_name, hickory_dt)
                                    .is_ok_and(|computed| computed.as_ref() == ds.digest())
                            });
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
                    digest: ds.digest().iter().map(|b| format!("{:02X}", b)).collect(),
                    algorithm_name: algorithm_name(algorithm),
                    digest_type_name: digest_type_name(digest_type),
                    matched_key,
                    digest_verified,
                }
            })
            .collect();

        // Check for KSK orphans (DNSKEY KSKs with no corresponding DS)
        let ds_key_tags: std::collections::HashSet<u16> =
            ds_info.iter().map(|ds| ds.key_tag).collect();
        for key in &dnskey_info {
            if key.is_ksk && !ds_key_tags.contains(&key.key_tag) {
                issues.push(format!(
                    "DNSKEY (key_tag={}) is a KSK with no corresponding DS record",
                    key.key_tag
                ));
            }
        }

        issues.extend(deprecation_issues(&ds_info, &dnskey_info));

        let (chain_valid, status) = derive_chain_status(&ds_info, has_dnskey);

        // Structural explanations for the non-"signed" verdicts.
        if has_ds && !has_dnskey {
            issues.push(if status == "partial" {
                "DS records exist at the parent, but every one uses an algorithm or digest \
                 type validating resolvers do not support \u{2014} the zone is treated as unsigned"
                    .to_string()
            } else if dnskey_query_failed {
                "DS records exist at the parent but the DNSKEY query failed \u{2014} a \
                 validating upstream returns SERVFAIL when the chain is broken, so validating \
                 resolvers are likely failing this zone"
                    .to_string()
            } else {
                "DS records exist at the parent but the zone publishes no DNSKEY \u{2014} \
                 validating resolvers will fail (SERVFAIL) this zone"
                    .to_string()
            });
        }
        if !has_ds && has_dnskey {
            issues.push(
                "DNSKEY records exist but no DS records at parent - DNSSEC chain incomplete"
                    .to_string(),
            );
        }

        // Opt-in RRSIG validity inspection (the default check is blind to
        // expired signatures — the most common real-world DNSSEC outage).
        let enabled = has_ds || has_dnskey;
        let mut rrsig_records = Vec::new();
        if self.check_rrsig && enabled {
            rrsig_records = self.resolve_rrsigs(&zone).await;
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
            status: status.to_string(),
            chain_valid,
            authentication_tier,
            rrsig_records,
        })
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
}

/// The checker's resolver options: the shared set from
/// [`apply_standard_opts`] (hand-copied here it had drifted and lacked the
/// pinned server ordering), plus — when `validating` — the DNSSEC-OK bit.
fn apply_dnssec_opts(opts: &mut ResolverOpts, validating: bool) {
    apply_standard_opts(opts, DEFAULT_TIMEOUT);
    if validating {
        // Sets the DO bit so RRSIGs are returned (and asks hickory to
        // validate). A validation failure surfaces as a lookup error, which
        // the RRSIG path treats as "no data" and degrades to the digest-only
        // tier — never a false "validated" claim.
        opts.validate = true;
        opts.edns0 = true;
    }
}

/// Derives `(chain_valid, status)` from the DS cross-validation results and
/// whether the zone publishes a DNSKEY RRset. Pure, so the verdict policy is
/// unit-testable without DNS.
///
/// Vocabulary deliberately avoids "secure"/"insecure": we verify only
/// DS<->DNSKEY digest consistency, NOT RRSIG signatures, so we report the
/// observable FACT (the zone is signed / unsigned) rather than a validated
/// security state. See the `status` field doc on [`DnssecReport`].
fn derive_chain_status(ds_info: &[DsInfo], has_dnskey: bool) -> (bool, &'static str) {
    let has_ds = !ds_info.is_empty();

    // A DS whose digest type we cannot compute is excluded from the "all
    // must verify" check (we can't judge it), but at least one computable DS
    // must actually verify — otherwise a zone we can't evaluate at all would
    // be reported as valid.
    let chain_valid = has_ds
        && has_dnskey
        && ds_info
            .iter()
            .any(|ds| ds.matched_key && ds.digest_verified)
        && ds_info
            .iter()
            .filter(|ds| DnssecChecker::to_hickory_digest_type(ds.digest_type).is_some())
            .all(|ds| ds.matched_key && ds.digest_verified);

    let status = match (has_ds, has_dnskey) {
        (true, true) if chain_valid => "signed",
        (true, true) => "misconfigured",
        // A DS the parent publishes tells validating resolvers to expect a
        // signed zone; with no DNSKEY behind it (absent, or its query failed
        // — a validating upstream SERVFAILs a broken chain) they fail the
        // zone outright. That is a broken zone, not a "partial" one — unless
        // no DS is usable by validators, in which case they treat the zone
        // as unsigned (RFC 4035 §5.2).
        (true, false) if ds_info.iter().any(ds_is_validatable) => "misconfigured",
        (true, false) => "partial",
        // An island of security: signed, but no chain from the parent.
        (false, true) => "partial",
        (false, false) => "unsigned",
    };
    (chain_valid, status)
}

/// Whether a validating resolver would act on this DS: its DNSKEY algorithm
/// is one validators implement (RFC 8624 §3.1 MUST/RECOMMENDED/commonly
/// deployed: RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256, RSASHA512, ECDSA
/// P-256/P-384, Ed25519, Ed448) and its digest type is SHA-1/256/384. A DS
/// failing either is ignored by validators (RFC 4035 §5.2, RFC 6840 §5.2).
fn ds_is_validatable(ds: &DsInfo) -> bool {
    matches!(ds.algorithm, 5 | 7 | 8 | 10 | 13 | 14 | 15 | 16)
        && matches!(ds.digest_type, 1 | 2 | 4)
}

/// DNSSEC algorithms that must not (1, 3, 6) or should no longer (5, 7, 12)
/// be used for signing (RFC 8624 §3.1), matching the "(deprecated)" labels
/// from [`algorithm_name`].
fn is_deprecated_algorithm(algorithm: u8) -> bool {
    matches!(algorithm, 1 | 3 | 5 | 6 | 7 | 12)
}

/// Deprecated-algorithm and SHA-1-digest advisories for the published DS and
/// DNSKEY records. Pure.
fn deprecation_issues(ds_info: &[DsInfo], dnskey_info: &[DnskeyInfo]) -> Vec<String> {
    let mut issues = Vec::new();
    for ds in ds_info {
        if is_deprecated_algorithm(ds.algorithm) {
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
    for key in dnskey_info {
        if is_deprecated_algorithm(key.algorithm) {
            issues.push(format!(
                "DNSKEY record uses deprecated algorithm {} ({})",
                key.algorithm, key.algorithm_name
            ));
        }
    }
    issues
}

/// The ASCII owner name of a DNS record: lowercase, no trailing root dot.
/// `to_ascii`, not `to_string` — `Display` decodes `xn--` labels to Unicode.
fn normalize_owner(name: &Name) -> String {
    name.to_ascii().trim_end_matches('.').to_ascii_lowercase()
}

/// True when `owner` is `name` itself or one of its ancestors (label-wise).
/// Both are lowercase ASCII without a trailing dot.
fn is_self_or_ancestor(owner: &str, name: &str) -> bool {
    !owner.is_empty()
        && (owner == name
            || name
                .strip_suffix(owner)
                .is_some_and(|prefix| prefix.ends_with('.')))
}

/// The zone apex named by an SOA among `records`: an SOA owned by `name`
/// itself, or (in a negative answer's AUTHORITY section) by an ancestor of
/// `name`. Anything else — e.g. the SOA of a CNAME target's zone — is ignored.
fn soa_apex<'a>(name: &str, records: impl Iterator<Item = &'a Record>) -> Option<String> {
    records
        .filter(|record| matches!(record.data, RData::SOA(_)))
        .map(|record| normalize_owner(&record.name))
        .find(|owner| is_self_or_ancestor(owner, name))
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

    fn ds(key_tag: u16, algorithm: u8, digest_type: u8, matched: bool, verified: bool) -> DsInfo {
        DsInfo {
            key_tag,
            algorithm,
            digest_type,
            digest: "ABCDEF".to_string(),
            algorithm_name: algorithm_name(algorithm),
            digest_type_name: digest_type_name(digest_type),
            matched_key: matched,
            digest_verified: verified,
        }
    }

    // --- derive_chain_status: the verdict policy, pure --------------------
    //
    // These replace three tests that built a `DnssecReport` with
    // `chain_valid`/`status` already filled in and asserted them back (they
    // could not fail). The derivation is now a pure function under test.

    #[test]
    fn chain_status_signed_when_every_computable_ds_verifies() {
        let all = [ds(12345, 13, 2, true, true), ds(12345, 13, 4, true, true)];
        assert_eq!(derive_chain_status(&all, true), (true, "signed"));
    }

    #[test]
    fn chain_status_misconfigured_when_ds_unmatched() {
        let unmatched = [ds(65000, 13, 2, false, false)];
        assert_eq!(
            derive_chain_status(&unmatched, true),
            (false, "misconfigured")
        );
    }

    #[test]
    fn chain_status_misconfigured_on_digest_mismatch() {
        let mismatch = [ds(12345, 13, 2, true, false)];
        assert_eq!(
            derive_chain_status(&mismatch, true),
            (false, "misconfigured")
        );
        // One good DS does not excuse a computable one that fails.
        let mixed = [ds(1, 13, 2, true, true), ds(2, 13, 2, true, false)];
        assert_eq!(derive_chain_status(&mixed, true), (false, "misconfigured"));
    }

    #[test]
    fn chain_status_uncomputable_digest_is_excluded_but_not_sufficient() {
        // A GOST (type 3) DS can't be computed: it is skipped by the
        // all-verify rule, but alone it cannot make the chain valid.
        let gost_only = [ds(1, 13, 3, true, false)];
        assert_eq!(
            derive_chain_status(&gost_only, true),
            (false, "misconfigured")
        );
        let with_sha256 = [ds(1, 13, 3, true, false), ds(1, 13, 2, true, true)];
        assert_eq!(derive_chain_status(&with_sha256, true), (true, "signed"));
    }

    #[test]
    fn chain_status_ds_without_dnskey_is_misconfigured() {
        // Regression: this was "partial" (yellow), yet validating resolvers
        // SERVFAIL a zone whose parent publishes a DS with no DNSKEY behind
        // it — including when a validating upstream SERVFAILs the DNSKEY
        // query itself, which folds to "no DNSKEY" here.
        let stale = [ds(12345, 13, 2, false, false)];
        assert_eq!(derive_chain_status(&stale, false), (false, "misconfigured"));
    }

    #[test]
    fn chain_status_ds_validators_ignore_stays_partial() {
        // Every DS uses an algorithm (RSAMD5, ECC-GOST, private) or digest
        // type validators don't implement → they treat the zone as unsigned.
        let unusable = [ds(1, 1, 2, false, false), ds(2, 12, 3, false, false)];
        assert_eq!(derive_chain_status(&unusable, false), (false, "partial"));
        let unknown_digest = [ds(3, 13, 99, false, false)];
        assert_eq!(
            derive_chain_status(&unknown_digest, false),
            (false, "partial")
        );
    }

    #[test]
    fn chain_status_island_and_unsigned() {
        assert_eq!(derive_chain_status(&[], true), (false, "partial"));
        assert_eq!(derive_chain_status(&[], false), (false, "unsigned"));
    }

    #[test]
    fn resolver_opts_share_the_standard_set() {
        // Regression: the hand-copied option set lacked the pinned
        // `UserProvidedOrder` server ordering.
        for validating in [false, true] {
            let mut opts = ResolverOpts::default();
            apply_dnssec_opts(&mut opts, validating);
            assert_eq!(
                opts.server_ordering_strategy,
                hickory_resolver::config::ServerOrderingStrategy::UserProvidedOrder
            );
            assert_eq!(opts.validate, validating);
        }
    }

    #[test]
    fn deprecated_algorithms_include_7_and_12() {
        // Regression: the check was `1|3|5|6` although algorithm_name already
        // labelled 7 (RSASHA1-NSEC3-SHA1) and 12 (ECC-GOST) deprecated.
        let key = |algorithm: u8| DnskeyInfo {
            flags: 257,
            protocol: 3,
            algorithm,
            key_tag: 1,
            is_ksk: true,
            is_zsk: false,
            algorithm_name: algorithm_name(algorithm),
        };
        let issues = deprecation_issues(
            &[
                ds(1, 7, 2, true, true),
                ds(2, 12, 2, true, true),
                ds(3, 13, 2, true, true),
            ],
            &[key(7), key(12), key(8)],
        );
        assert_eq!(
            issues
                .iter()
                .filter(|i| i.contains("deprecated algorithm"))
                .count(),
            4,
            "{issues:?}"
        );
        assert!(issues
            .iter()
            .any(|i| i.starts_with("DS") && i.contains("algorithm 7")));
        assert!(issues
            .iter()
            .any(|i| i.starts_with("DS") && i.contains("algorithm 12")));
        assert!(!issues.iter().any(|i| i.contains("algorithm 13")));
        assert!(!issues.iter().any(|i| i.contains("algorithm 8 ")));
    }

    #[test]
    fn soa_apex_matches_self_or_ancestor_only() {
        assert!(is_self_or_ancestor("example.com", "example.com"));
        assert!(is_self_or_ancestor("example.com", "api.example.com"));
        assert!(!is_self_or_ancestor("ample.com", "api.example.com"));
        assert!(!is_self_or_ancestor("api.example.com", "example.com"));

        let soa = |owner: &str| {
            Record::from_rdata(
                Name::from_ascii(owner).unwrap(),
                300,
                soa_rdata(owner.trim_end_matches('.')),
            )
        };
        let records = [soa("cdn-target.test."), soa("Example.COM.")];
        assert_eq!(
            soa_apex("api.example.com", records.iter()),
            Some("example.com".to_string()),
            "a CNAME target's SOA must be skipped; the enclosing one is found"
        );
        assert_eq!(soa_apex("api.other.test", records.iter()), None);
    }

    // --- Hermetic end-to-end checks against the scripted mock fixture -----

    use hickory_resolver::proto::dnssec::{Algorithm, PublicKeyBuf};
    use hickory_resolver::proto::rr::RecordType as WireType;

    use crate::dns::test_support::{soa_rdata, spawn_mock_dns_fn, MockReply};

    /// A KSK for the tests. Any 32 bytes serve: key tags and DS digests are
    /// computed over the wire form and never checked as a curve point.
    fn test_key() -> DNSKEY {
        DNSKEY::new(
            true,
            true,
            false,
            PublicKeyBuf::new(vec![7u8; 32], Algorithm::ED25519),
        )
    }

    /// The DS the parent of `zone` would publish for `key` (SHA-256).
    fn ds_for(zone: &str, key: &DNSKEY) -> DS {
        let digest = key
            .to_digest(&Name::from_ascii(zone).unwrap(), DigestType::SHA256)
            .unwrap();
        DS::new(
            key.calculate_key_tag().unwrap(),
            Algorithm::ED25519,
            DigestType::SHA256,
            digest.as_ref().to_vec(),
        )
    }

    fn dnskey_rdata(key: DNSKEY) -> RData {
        RData::DNSSEC(DNSSECRData::DNSKEY(key))
    }

    fn ds_rdata(ds: DS) -> RData {
        RData::DNSSEC(DNSSECRData::DS(ds))
    }

    fn mock_checker(port: u16) -> DnssecChecker {
        DnssecChecker::new().with_upstream("127.0.0.1".parse().unwrap(), port)
    }

    /// Regression: DS/DNSKEY were queried at the name itself, so a host
    /// inside a signed zone (api.cloudflare.com) reported "unsigned". The
    /// walk climbs to the SOA owner and reports on that zone.
    #[tokio::test]
    async fn check_evaluates_the_enclosing_zone_of_a_non_apex_name() {
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("signed.test", WireType::SOA) => MockReply::Answer(vec![soa_rdata("signed.test")]),
            ("signed.test", WireType::DS) => {
                MockReply::Answer(vec![ds_rdata(ds_for("signed.test", &test_key()))])
            }
            ("signed.test", WireType::DNSKEY) => MockReply::Answer(vec![dnskey_rdata(test_key())]),
            // Nothing lives at the name itself.
            _ => MockReply::NoData,
        })
        .await;

        let report = mock_checker(port).check("api.signed.test").await.unwrap();
        assert_eq!(report.domain, "api.signed.test");
        assert_eq!(report.status, "signed", "{report:?}");
        assert!(report.chain_valid);
        assert!(
            report.issues[0].contains("enclosing zone signed.test"),
            "the evaluated zone must be named: {:?}",
            report.issues
        );
        assert_eq!(report.issues.len(), 1, "{:?}", report.issues);
        // One DNSKEY query feeds both the listing and the verification.
        let tag = test_key().calculate_key_tag().unwrap();
        assert_eq!(report.dnskey_records[0].key_tag, tag);
        assert!(report.ds_records[0].matched_key && report.ds_records[0].digest_verified);
    }

    /// A negative answer's AUTHORITY-section SOA names the apex in one step.
    /// SERVFAIL on the intermediate name proves the walk never needed it.
    #[tokio::test]
    async fn check_uses_the_negative_answer_soa_to_find_the_apex() {
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("deep.api.signed.test", WireType::SOA) => MockReply::NoDataWithSoa("signed.test"),
            ("api.signed.test", _) => MockReply::ServFail,
            ("signed.test", WireType::DS) => {
                MockReply::Answer(vec![ds_rdata(ds_for("signed.test", &test_key()))])
            }
            ("signed.test", WireType::DNSKEY) => MockReply::Answer(vec![dnskey_rdata(test_key())]),
            _ => MockReply::NoData,
        })
        .await;

        let report = mock_checker(port)
            .check("deep.api.signed.test")
            .await
            .unwrap();
        assert_eq!(report.status, "signed", "{report:?}");
        assert!(report.issues[0].contains("enclosing zone signed.test"));
    }

    /// Regression (finding: stale DS behind a validating upstream): Google
    /// SERVFAILs every query into a zone whose DS matches no key, DNSKEY
    /// included. That used to read as "partial"; it is "misconfigured". The
    /// SOA SERVFAIL must not derail zone discovery either — the parent still
    /// serves the DS, which identifies the zone cut.
    #[tokio::test]
    async fn check_reports_stale_ds_with_servfailing_dnskey_as_misconfigured() {
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("broken.test", WireType::DS) => {
                MockReply::Answer(vec![ds_rdata(ds_for("broken.test", &test_key()))])
            }
            ("broken.test", _) => MockReply::ServFail,
            _ => MockReply::NoData,
        })
        .await;

        let report = mock_checker(port).check("broken.test").await.unwrap();
        assert!(report.has_ds_records);
        assert!(!report.has_dnskey_records);
        assert_eq!(report.status, "misconfigured", "{report:?}");
        assert!(!report.chain_valid);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.contains("DNSKEY query failed")),
            "{:?}",
            report.issues
        );
        assert!(
            !report.issues.iter().any(|i| i.contains("not a zone apex")),
            "{:?}",
            report.issues
        );
    }

    #[tokio::test]
    async fn check_reports_nxdomain_names_as_unsigned_without_walking() {
        let port = spawn_mock_dns_fn(|_, _| MockReply::NxDomain).await;
        let report = mock_checker(port).check("nope.signed.test").await.unwrap();
        assert_eq!(report.status, "unsigned");
        assert!(
            report.issues.iter().any(|i| i.contains("does not exist")),
            "{:?}",
            report.issues
        );
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
