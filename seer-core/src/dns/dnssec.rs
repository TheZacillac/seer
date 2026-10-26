//! DNSSEC validation reporting.
//!
//! Checks the DNSSEC chain for a domain by querying DS and DNSKEY records
//! and reporting on the validation status. The records are read at the apex
//! of the zone that holds the name (found by an SOA walk), so a host inside
//! a signed zone — `api.cloudflare.com` — reports on `cloudflare.com` rather
//! than as "unsigned".
//!
//! **Bounds:** the whole check runs under one deadline of
//! [`CHECK_BUDGET_TIMEOUTS`] per-query timeouts (30s at the default 5s): the
//! SOA walk gets [`ZONE_WALK_BUDGET_TIMEOUTS`] of them, and a walk still
//! running then fails the check with a timeout rather than evaluate a guessed
//! zone; the concurrent DS and DNSKEY reads get the rest, and one cut off
//! there is reported as a failed query in `issues`.
//!
//! **No verdict without evidence:** when both the DS and the DNSKEY read fail
//! the check fails too, rather than read the empty result as "unsigned".

use std::collections::HashMap;
use std::time::Duration;

use hickory_resolver::config::ResolverConfig;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::NetError;
use hickory_resolver::proto::dnssec::rdata::{DNSSECRData, DNSKEY, DS};
use hickory_resolver::proto::dnssec::{DigestType, PublicKey};
use hickory_resolver::proto::op::{Message, ResponseCode};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType as HickoryRecordType};
use hickory_resolver::TokioResolver;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use super::resolver::{build_plain_resolver, fqdn, google_or_pinned, lookup_with_tcp_fallback};
use super::transport::Transport;
use super::DEFAULT_DNS_TIMEOUT;
use crate::error::{Result, SeerError};

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
    /// "signed" needs one DS that authenticates a published DNSKEY — all a
    /// validator needs (RFC 4035 §5.2), so a DS left over from a key
    /// rollover (RFC 7583) is an issue, not a failure. "misconfigured" is a
    /// DS set validators would use in which no DS matches a DNSKEY, or such a
    /// DS at the parent with no (or an unobtainable) DNSKEY behind it —
    /// validating resolvers fail the zone. "partial" is a DNSKEY with no DS
    /// (an island of security), or a DS set validators ignore entirely
    /// (unsupported algorithms or digest types), which leaves the zone
    /// unsigned in their eyes.
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
    /// Whether at least one DS record's digest matches a published DNSKEY
    /// (RFC 4509 digest consistency) — the link a validator follows. DS
    /// records that match nothing are listed in `issues`. This is NOT
    /// signature / chain-of-trust validation — see the caveat on `status`.
    pub chain_valid: bool,
    /// Machine-readable tier describing the DEPTH of checking that was
    /// performed, so consumers don't over-trust a digest-only "signed" result.
    /// The RESULT of those checks lives in `chain_valid` / `status` / `issues`;
    /// this field says only *what was checked*.
    #[serde(default = "default_authentication_tier")]
    pub authentication_tier: AuthenticationTier,
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
    /// Only DS↔DNSKEY digest consistency (RFC 4509) was checked. Does NOT
    /// inspect RRSIG signatures or their validity windows.
    DigestOnly,
}

fn default_authentication_tier() -> AuthenticationTier {
    AuthenticationTier::DigestOnly
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

/// The SOA walk's deadline, in per-query timeouts: a lookup hickory
/// retransmits (`attempts = 2`) takes two, so this covers two such steps —
/// or the whole walk when the upstream answers promptly. Without it a slow
/// upstream held the caller for up to [`MAX_ZONE_WALK`] × 2 timeouts before
/// the records were even asked for.
const ZONE_WALK_BUDGET_TIMEOUTS: u32 = 4;

/// The whole check's deadline, in per-query timeouts: the walk, then the
/// concurrent DS and DNSKEY reads (two: one retransmitted lookup).
const CHECK_BUDGET_TIMEOUTS: u32 = ZONE_WALK_BUDGET_TIMEOUTS + 2;

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
    /// Plain (non-validating) resolver for the DS / DNSKEY reads. A single
    /// resolver and a single DNSKEY query feed both the displayed key list
    /// and the digest verification, so the two can never disagree.
    resolver: TokioResolver,
    /// The upstream `resolver` was built from: Google DNS, or a loopback mock
    /// in tests. The SOA walk asks these servers directly, and a truncated
    /// DS/DNSKEY answer is asked again over their TCP.
    config: ResolverConfig,
    /// Sends the SOA walk's queries and returns the responses as sent, so
    /// the walk sees a CNAME the name owns (see `find_zone_apex`).
    transport: Transport,
    /// The per-query timeout the resolver was built with.
    timeout: Duration,
}

impl Default for DnssecChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// A failed DS or DNSKEY read: what went wrong, and whether it was the
/// resolver or the check's deadline running out of time.
#[derive(Debug)]
struct ReadFailure {
    detail: String,
    timed_out: bool,
}

impl From<&NetError> for ReadFailure {
    fn from(e: &NetError) -> Self {
        Self {
            detail: e.to_string(),
            timed_out: matches!(e, NetError::Timeout),
        }
    }
}

impl std::fmt::Display for ReadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl DnssecChecker {
    pub fn new() -> Self {
        Self::with_config(google_or_pinned(None), DEFAULT_DNS_TIMEOUT)
    }

    /// A checker reading through `config`'s servers with `timeout` per query.
    fn with_config(config: ResolverConfig, timeout: Duration) -> Self {
        Self {
            resolver: build_plain_resolver(config.clone(), timeout),
            config,
            transport: Transport::new(timeout),
            timeout,
        }
    }

    /// Builds a checker honoring `~/.seer/config.toml` (`timeouts.dns_secs`).
    /// The records are always read through the default upstream, so the
    /// configured nameserver does not apply.
    pub fn from_config(config: &crate::config::SeerConfig) -> Self {
        Self::new().with_timeout(config.dns_timeout())
    }

    /// Sets the per-query timeout.
    pub fn with_timeout(self, timeout: Duration) -> Self {
        Self::with_config(self.config, timeout)
    }

    /// Test-only: point the checker at a loopback mock server.
    #[cfg(test)]
    fn with_upstream(self, ip: std::net::IpAddr, port: u16) -> Self {
        Self::with_config(google_or_pinned(Some((ip, port))), self.timeout)
    }

    /// `zone`'s `wire_type` RRset, asked over TCP too when the answer is too
    /// big for UDP (a DNSKEY set mid-rollover) — see
    /// [`lookup_with_tcp_fallback`].
    async fn lookup(
        &self,
        zone: &str,
        wire_type: HickoryRecordType,
    ) -> std::result::Result<Lookup, NetError> {
        lookup_with_tcp_fallback(
            &self.resolver,
            &self.config,
            self.timeout,
            &fqdn(zone),
            wire_type,
        )
        .await
    }

    /// Queries the DS RRset for `zone` (served by the parent zone).
    /// NXDOMAIN/NODATA fold to an empty set; a failed query is an `Err` with
    /// a human-readable reason.
    async fn lookup_ds(&self, zone: &str) -> std::result::Result<Vec<DS>, ReadFailure> {
        match self.lookup(zone, HickoryRecordType::DS).await {
            Ok(lookup) => Ok(lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::DNSSEC(DNSSECRData::DS(ds)) => Some(ds.clone()),
                    _ => None,
                })
                .collect()),
            Err(e) if e.is_no_records_found() => Ok(Vec::new()),
            Err(e) => Err(ReadFailure::from(&e)),
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
    ) -> std::result::Result<Vec<(DNSKEY, Option<u16>)>, ReadFailure> {
        match self.lookup(zone, HickoryRecordType::DNSKEY).await {
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
            Err(e) => Err(ReadFailure::from(&e)),
        }
    }

    /// Finds the apex of the zone that holds `name`.
    ///
    /// DS lives at a zone cut and DNSKEY at a zone apex, so querying them at
    /// a name inside a zone (`api.cloudflare.com`) finds neither and used to
    /// report a signed zone as "unsigned". Each step asks for the SOA and
    /// reads the response with [`soa_step`]; when it names no apex the walk
    /// moves up one label (bounded by [`MAX_ZONE_WALK`], never above two
    /// labels).
    ///
    /// The queries go through `dns::transport`, not the resolver: hickory's
    /// resolver chases a CNAME and folds a negative outcome into an error
    /// that drops the chain, so a dangling `www` CNAME read as "does not
    /// exist", and a CNAME target's zone SOA was taken for the name's apex.
    /// A transport query also repeats a truncated reply over TCP itself.
    ///
    /// A failed SOA query is not trusted blindly: a validating upstream
    /// SERVFAILs every name in a zone with a broken chain, apex included —
    /// but the DS RRset is served by the healthy parent, so a DS answer still
    /// identifies the (broken) zone cut. Without one the walk stops rather
    /// than guess past the failure.
    async fn find_zone_apex(&self, name: &str) -> ZoneApex {
        let mut candidate = name;
        for step in 0..MAX_ZONE_WALK {
            let qname = match Name::from_ascii(fqdn(candidate)) {
                Ok(qname) => qname,
                Err(e) => return ZoneApex::Unknown(Some(format!("invalid name {candidate}: {e}"))),
            };
            let request = self.transport.request(qname, HickoryRecordType::SOA, true);
            let response = self
                .transport
                .query(
                    self.config.name_servers(),
                    &request,
                    self.transport.deadline(),
                )
                .await;
            let failure = match response {
                Ok(message) => match soa_step(candidate, &message, step == 0) {
                    SoaStep::Apex(apex) => return ZoneApex::Found(apex),
                    SoaStep::NxDomain => return ZoneApex::NxDomain,
                    SoaStep::Up => None,
                    SoaStep::Failed(code) => Some(code.to_string()),
                },
                Err(no_response) => Some(no_response.to_string()),
            };
            if let Some(reason) = failure {
                return match self.lookup_ds(candidate).await {
                    Ok(ds) if !ds.is_empty() => ZoneApex::Found(candidate.to_string()),
                    _ => ZoneApex::Unknown(Some(format!(
                        "SOA query for {candidate} failed: {reason}"
                    ))),
                };
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
    /// The DS/DNSKEY checks run at the apex of the zone enclosing `domain`,
    /// found by walking up its labels with SOA queries; when that is not
    /// `domain` itself, the first entry of `issues` names the zone that was
    /// evaluated. `DnssecReport::domain` is always the (normalized) name that
    /// was asked about.
    ///
    /// Bounded by six per-query timeouts overall (`CHECK_BUDGET_TIMEOUTS`):
    /// a walk that has not found the zone within four of them
    /// (`ZONE_WALK_BUDGET_TIMEOUTS`) is a [`SeerError::Timeout`], and a DS or
    /// DNSKEY read the deadline cuts off is a failed query in `issues`.
    ///
    /// When both the DS and the DNSKEY query fail there is nothing to judge,
    /// so the check fails ([`SeerError::Timeout`] if both ran out of time,
    /// else [`SeerError::DnsError`]) rather than report "unsigned".
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn check(&self, domain: &str) -> Result<DnssecReport> {
        // `normalize_host`, not `normalize_domain`: the zone walk below
        // decides where the records live, so `www.` must not be pre-stripped
        // (a `www` zone cut, however rare, would otherwise be skipped).
        let domain = crate::validation::normalize_host(domain)?;
        debug!(domain = %domain, "Checking DNSSEC");

        // One deadline for the whole check; the walk must end early enough
        // to leave the DS/DNSKEY reads theirs.
        let started = tokio::time::Instant::now();
        let walk_budget = self.timeout.saturating_mul(ZONE_WALK_BUDGET_TIMEOUTS);
        let budget = self.timeout.saturating_mul(CHECK_BUDGET_TIMEOUTS);
        let apex = tokio::time::timeout_at(started + walk_budget, self.find_zone_apex(&domain))
            .await
            .map_err(|_| {
                // No zone to report on: evaluating a guessed one could read
                // a signed zone as unsigned.
                SeerError::Timeout(format!(
                    "DNSSEC check for {domain} gave up after {walk_budget:?} without finding \
                     the zone that holds it"
                ))
            })?;

        let mut issues = Vec::new();
        let zone = match apex {
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

        // DS (at the parent) and DNSKEY (at the apex), concurrently, by the
        // check's deadline; one cut off is a failed query.
        let deadline = started + budget;
        let out_of_time = || ReadFailure {
            detail: format!("timed out \u{2014} the check's {budget:?} budget ran out"),
            timed_out: true,
        };
        let (ds_result, dnskey_result) = tokio::join!(
            tokio::time::timeout_at(deadline, self.lookup_ds(&zone)),
            tokio::time::timeout_at(deadline, self.lookup_dnskeys(&zone)),
        );
        let ds_result = ds_result.unwrap_or_else(|_| Err(out_of_time()));
        let dnskey_result = dnskey_result.unwrap_or_else(|_| Err(out_of_time()));
        // With neither record set read there is no evidence either way:
        // "unsigned" would be a verdict on a zone never seen. One failed
        // query still leaves the other's answer to report on.
        if let (Err(ds), Err(dnskey)) = (&ds_result, &dnskey_result) {
            let detail =
                format!("DNSSEC check for {zone} read neither DS ({ds}) nor DNSKEY ({dnskey})");
            return Err(if ds.timed_out && dnskey.timed_out {
                SeerError::Timeout(detail)
            } else {
                SeerError::DnsError(detail)
            });
        }
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
        if has_ds && status == "partial" {
            issues.push(
                "DS records exist at the parent, but every one uses an algorithm or digest \
                 type validating resolvers do not support \u{2014} the zone is treated as unsigned"
                    .to_string(),
            );
        } else if has_ds && !has_dnskey {
            issues.push(if dnskey_query_failed {
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

        let enabled = has_ds || has_dnskey;
        let authentication_tier = if enabled {
            AuthenticationTier::DigestOnly
        } else {
            AuthenticationTier::Unsigned
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

    // One DS that authenticates a DNSKEY is all a validator needs (RFC 4035
    // §5.2): during a double-DS rollover (RFC 7583) the parent lists a DS
    // for a key the zone no longer (or does not yet) publish, and the zone
    // still validates. Unmatched DS records are reported as issues.
    let chain_valid = has_dnskey
        && ds_info
            .iter()
            .any(|ds| ds.matched_key && ds.digest_verified);

    let status = match (has_ds, has_dnskey) {
        (true, true) if chain_valid => "signed",
        // A DS the parent publishes tells validating resolvers to expect a
        // signed zone; when none authenticates a DNSKEY (no key behind them,
        // their query failed — a validating upstream SERVFAILs a broken
        // chain — or every digest mismatches) they fail the zone outright.
        // That is a broken zone, not a "partial" one — unless no DS is
        // usable by validators, in which case they treat the zone as
        // unsigned (RFC 4035 §5.2), with or without a DNSKEY.
        (true, _) if ds_info.iter().any(ds_is_validatable) => "misconfigured",
        (true, _) => "partial",
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

/// What one SOA response says about the walk's `candidate`.
#[derive(Debug, PartialEq, Eq)]
enum SoaStep {
    /// The apex of the zone holding `candidate`.
    Apex(String),
    /// `candidate` does not exist.
    NxDomain,
    /// No apex named here: ask the parent.
    Up,
    /// The query failed with this response code (SERVFAIL, REFUSED, …).
    Failed(ResponseCode),
}

/// Reads an SOA response for `candidate`, exactly as the server sent it.
///
/// A CNAME owned by `candidate` comes first: an alias is never a zone apex
/// (RFC 1034 §3.6.2), and the response code and any SOA beside it describe
/// the chain's target (RFC 6604 §2), so the walk moves up. Otherwise an
/// NXDOMAIN on the name asked about (`first`) means it does not exist; any
/// other non-NOERROR code is a failed query; and an SOA owned by `candidate`
/// or by an ancestor (a negative answer's AUTHORITY section) names the apex.
fn soa_step(candidate: &str, message: &Message, first: bool) -> SoaStep {
    let owns_cname = message
        .answers
        .iter()
        .any(|r| matches!(r.data, RData::CNAME(_)) && normalize_owner(&r.name) == candidate);
    if owns_cname {
        return SoaStep::Up;
    }
    match message.metadata.response_code {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain if first => return SoaStep::NxDomain,
        // An ancestor reported missing would contradict the name below it;
        // its AUTHORITY SOA still names the zone the server answers for.
        ResponseCode::NXDomain => {}
        code => return SoaStep::Failed(code),
    }
    match soa_apex(
        candidate,
        message.answers.iter().chain(&message.authorities),
    ) {
        Some(apex) => SoaStep::Apex(apex),
        None => SoaStep::Up,
    }
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
    fn default_tier_is_digest_only() {
        // Reports deserialized without the field default to digest-only.
        assert_eq!(
            default_authentication_tier(),
            AuthenticationTier::DigestOnly
        );
    }

    #[test]
    fn from_config_applies_dns_timeout() {
        let mut config = crate::config::SeerConfig::default();
        config.timeouts.dns_secs = 9;
        assert_eq!(
            DnssecChecker::from_config(&config).timeout,
            Duration::from_secs(9)
        );
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
    }

    #[test]
    fn chain_status_one_authenticating_ds_is_enough() {
        // Regression: any computable DS that failed made the zone
        // "misconfigured", although validators need only one DS that
        // authenticates a DNSKEY (RFC 4035 §5.2) — the parent's DS set during
        // a double-DS key rollover (RFC 7583) holds one for a key the zone
        // does not publish yet (or any more).
        let rollover = [ds(1, 13, 2, true, true), ds(2, 13, 2, false, false)];
        assert_eq!(derive_chain_status(&rollover, true), (true, "signed"));
        let mixed = [ds(1, 13, 2, true, true), ds(2, 13, 2, true, false)];
        assert_eq!(derive_chain_status(&mixed, true), (true, "signed"));
    }

    #[test]
    fn chain_status_uncomputable_digest_alone_is_partial() {
        // Regression: a DS set whose only digest is one validators do not
        // implement (GOST, type 3) was "misconfigured" beside a DNSKEY but
        // "partial" without one. Validators ignore such a set (RFC 4035
        // §5.2) and treat the zone as unsigned either way.
        let gost_only = [ds(1, 13, 3, true, false)];
        assert_eq!(derive_chain_status(&gost_only, true), (false, "partial"));
        assert_eq!(derive_chain_status(&gost_only, false), (false, "partial"));
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
            ("api.signed.test", _) => MockReply::Rcode(ResponseCode::ServFail),
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
            ("broken.test", _) => MockReply::Rcode(ResponseCode::ServFail),
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

    /// Regression: with both DS and DNSKEY failing, the empty record sets
    /// read as "unsigned", so a signed zone behind a flaky upstream got a
    /// `dns.dnssec.unsigned` audit finding instead of an incomplete check.
    #[tokio::test]
    async fn both_queries_failing_is_an_error_not_unsigned() {
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("signed.test", WireType::SOA) => MockReply::Answer(vec![soa_rdata("signed.test")]),
            ("signed.test", WireType::DS | WireType::DNSKEY) => {
                MockReply::Rcode(ResponseCode::ServFail)
            }
            _ => MockReply::NoData,
        })
        .await;

        let err = mock_checker(port).check("signed.test").await.unwrap_err();
        assert!(matches!(err, SeerError::DnsError(_)), "{err:?}");
        assert!(err.to_string().contains("neither DS"), "{err}");
    }

    /// Both reads cut off by the check's deadline are a timeout, not a
    /// verdict.
    #[tokio::test]
    async fn both_queries_cut_off_by_the_deadline_is_a_timeout() {
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("signed.test", WireType::SOA) => MockReply::Answer(vec![soa_rdata("signed.test")]),
            (_, WireType::DS | WireType::DNSKEY) => MockReply::NoReply,
            _ => MockReply::NoData,
        })
        .await;

        let err = mock_checker(port)
            .with_timeout(Duration::from_millis(100))
            .check("signed.test")
            .await
            .unwrap_err();
        assert!(matches!(err, SeerError::Timeout(_)), "{err:?}");
    }

    /// Regression: a dangling CNAME (`www` → a removed target in another
    /// zone) makes the recursive resolver answer NXDOMAIN with the CNAME in
    /// ANSWER (RFC 6604 §2: the code is about the chain's last target).
    /// hickory's resolver dropped the chain, so the walk read the name as
    /// nonexistent and graded it unsigned, though its zone is signed.
    #[tokio::test]
    async fn a_dangling_cname_is_not_read_as_a_nonexistent_name() {
        use crate::dns::test_support::{cname_rdata, record};
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("www.signed.test", _) => MockReply::Negative {
                code: ResponseCode::NXDomain,
                chain: vec![record(
                    "www.signed.test",
                    300,
                    cname_rdata("gone.elsewhere.test"),
                )],
                soa: "elsewhere.test",
            },
            ("signed.test", WireType::SOA) => MockReply::Answer(vec![soa_rdata("signed.test")]),
            ("signed.test", WireType::DS) => {
                MockReply::Answer(vec![ds_rdata(ds_for("signed.test", &test_key()))])
            }
            ("signed.test", WireType::DNSKEY) => MockReply::Answer(vec![dnskey_rdata(test_key())]),
            _ => MockReply::NoData,
        })
        .await;

        let report = mock_checker(port).check("www.signed.test").await.unwrap();
        assert!(
            !report.issues.iter().any(|i| i.contains("does not exist")),
            "www.signed.test owns a CNAME, it exists: {:?}",
            report.issues
        );
        assert_eq!(report.status, "signed", "{report:?}");
    }

    /// Regression: the checker's production upstream is Google's group
    /// (several servers, two asked in parallel, UDP with TCP fallback). A
    /// DNSKEY RRset too big for UDP (RSA keys mid-rollover) hits the
    /// hickory-resolver 0.26.3 truncation race that
    /// `resolver::lookup_with_tcp_fallback` works around; the checker used
    /// to call `lookup` directly, so the DNSKEY read failed and a healthy
    /// signed zone was graded "misconfigured". The checker here reads
    /// through two loopback servers, as production reads through Google's.
    #[tokio::test]
    async fn a_truncated_dnskey_rrset_is_asked_over_tcp() {
        use crate::dns::resolver::single_server_config;
        use crate::dns::test_support::spawn_mock_dns_split;
        use hickory_resolver::config::ResolverConfig;

        let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
        for _ in 0..2 {
            let answer = |qname: &str, qtype| match (qname, qtype) {
                ("signed.test", WireType::SOA) => MockReply::Answer(vec![soa_rdata("signed.test")]),
                ("signed.test", WireType::DS) => {
                    MockReply::Answer(vec![ds_rdata(ds_for("signed.test", &test_key()))])
                }
                ("signed.test", WireType::DNSKEY) => {
                    MockReply::Answer(vec![dnskey_rdata(test_key())])
                }
                _ => MockReply::NoData,
            };
            let port = spawn_mock_dns_split(
                move |qname, qtype| match qtype {
                    // Too big for UDP: only the DNSKEY RRset truncates.
                    WireType::DNSKEY => MockReply::Truncated,
                    _ => answer(qname, qtype),
                },
                answer,
            )
            .await;
            for server in
                single_server_config("127.0.0.1".parse().unwrap(), port, true).name_servers()
            {
                config.add_name_server(server.clone());
            }
        }
        let checker = DnssecChecker::with_config(config, Duration::from_secs(2));

        let report = checker.check("signed.test").await.unwrap();
        assert!(
            !report
                .issues
                .iter()
                .any(|i| i.contains("DNSKEY query failed")),
            "{:?}",
            report.issues
        );
        assert_eq!(report.status, "signed", "{report:?}");
    }

    /// Regression: `cdn.shop.signed.test` lives in its own (delegated,
    /// signed) zone `shop.signed.test` and is a CNAME to `lb.signed.test`.
    /// Its SOA query comes back NOERROR with the CNAME in ANSWER and the
    /// *target's* zone SOA (`signed.test`) in AUTHORITY. That SOA owner is an
    /// ancestor of the queried name, so the walk took it for the name's apex
    /// and evaluated DS/DNSKEY at `signed.test` instead of `shop.signed.test`.
    #[tokio::test]
    async fn a_cname_targets_soa_is_not_taken_for_the_names_apex() {
        use crate::dns::test_support::{cname_rdata, record};
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("cdn.shop.signed.test", _) => MockReply::Negative {
                code: ResponseCode::NoError,
                chain: vec![record(
                    "cdn.shop.signed.test",
                    300,
                    cname_rdata("lb.signed.test"),
                )],
                soa: "signed.test",
            },
            // hickory chases the CNAME itself: the target's own NODATA,
            // with its zone's SOA, as any recursive resolver returns it.
            ("lb.signed.test", _) => MockReply::NoDataWithSoa("signed.test"),
            ("shop.signed.test", WireType::SOA) => {
                MockReply::Answer(vec![soa_rdata("shop.signed.test")])
            }
            ("shop.signed.test", WireType::DS) => {
                MockReply::Answer(vec![ds_rdata(ds_for("shop.signed.test", &test_key()))])
            }
            ("shop.signed.test", WireType::DNSKEY) => {
                MockReply::Answer(vec![dnskey_rdata(test_key())])
            }
            ("signed.test", WireType::SOA) => MockReply::Answer(vec![soa_rdata("signed.test")]),
            _ => MockReply::NoData,
        })
        .await;

        let report = mock_checker(port)
            .check("cdn.shop.signed.test")
            .await
            .unwrap();
        assert!(
            report.issues[0].contains("enclosing zone shop.signed.test"),
            "evaluated the wrong zone: {:?}",
            report.issues
        );
        assert_eq!(report.status, "signed", "{report:?}");
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
    async fn test_live_dnssec_check_insecure() {
        let checker = DnssecChecker::new();
        // wikipedia.org does not have DNSSEC (no DS or DNSKEY records)
        let report = checker.check("wikipedia.org").await.unwrap();

        assert!(!report.chain_valid);
        assert_eq!(report.status, "unsigned");
    }

    /// Regression: the SOA walk had no overall deadline, so an upstream
    /// slow on every name held the check for ~`MAX_ZONE_WALK` + 1 queries,
    /// and then evaluated a guessed zone. The walk now ends at its budget,
    /// with a timeout rather than a made-up verdict. Here the first server is
    /// black-holed (as Google's IPv6 servers are on a host without IPv6
    /// transit), so every step waits out a timeout before the second answers
    /// NODATA without an SOA.
    #[tokio::test]
    async fn the_zone_walk_is_held_to_its_budget() {
        use std::net::Ipv4Addr;
        use std::sync::{Arc, Mutex};

        use hickory_resolver::config::ResolverConfig;

        use crate::dns::resolver::single_server_config;
        use crate::dns::test_support::{spawn_mock_dns_fn, MockReply};

        let timeout = Duration::from_millis(200);
        let seen: Arc<Mutex<HashMap<String, usize>>> = Arc::default();
        let log = seen.clone();
        let silent = spawn_mock_dns_fn(|_, _| MockReply::NoReply).await;
        let answering = spawn_mock_dns_fn(move |qname, qtype| {
            *log.lock()
                .unwrap()
                .entry(format!("{qname} {qtype}"))
                .or_insert(0) += 1;
            MockReply::NoData
        })
        .await;
        let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
        for port in [silent, answering] {
            for server in
                single_server_config(Ipv4Addr::LOCALHOST.into(), port, false).name_servers()
            {
                config.add_name_server(server.clone());
            }
        }
        let checker = DnssecChecker::with_config(config, timeout);

        let started = std::time::Instant::now();
        let err = checker
            .check("a.b.c.d.e.f.g.h.i.seer.test")
            .await
            .expect_err("the walk runs out of time");
        let elapsed = started.elapsed();
        assert!(matches!(err, SeerError::Timeout(_)), "{err:?}");
        assert!(err.to_string().contains("zone"), "{err}");
        // The walk's budget, with slack — never the whole check's.
        let walk_budget = timeout * ZONE_WALK_BUDGET_TIMEOUTS;
        assert!(elapsed < walk_budget + timeout, "took {elapsed:?}");
        // Neither DS nor DNSKEY was asked for a guessed zone.
        assert!(
            !seen.lock().unwrap().keys().any(|k| k.ends_with(" DNSKEY")),
            "{:?}",
            seen.lock().unwrap().keys()
        );
    }
}
