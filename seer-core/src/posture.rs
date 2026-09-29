//! Email / DNS security-posture inspection.
//!
//! Resolves and interprets the DNS-published mail-security policies for a
//! domain — SPF, DMARC, MTA-STS, BIMI, and DANE (TLSA) — and returns a
//! per-mechanism verdict with advisory notes. A lax or absent DMARC policy is
//! the single strongest signal that a domain is spoofable, which directly feeds
//! phishing-risk assessment.
//!
//! This mirrors [`crate::caa`]'s tree-walk-plus-advisory shape and reuses the
//! [`DnsResolver`] TXT/MX/TLSA path — no new network protocol. The follow-up
//! lookups the RFCs require (SPF `redirect=`, DMARC's organizational-domain
//! fallback, DANE at the MX hosts) are DNS-only and bounded. All parsing is
//! pure and unit-tested; only the record fetch is async.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::dns::{DnsResolver, RecordData, RecordType};
use crate::error::Result;
use crate::validation::{normalize_domain, normalize_host};

/// A coarse enforcement verdict for one posture mechanism, HTTP security
/// header, or cookie. `seer headers` grades on this same scale (exported
/// there as [`crate::headers::HeaderVerdict`]) so both reports read alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PostureVerdict {
    /// Not configured / not sent at all.
    Absent,
    /// Configured, but permissive / monitoring-only (offers little protection).
    Weak,
    /// Configured with partial enforcement.
    Moderate,
    /// Configured with full enforcement.
    Strict,
    /// Configured; the mechanism has no weak/strict axis (presence is the signal).
    Present,
    /// The DNS lookup failed (SERVFAIL, timeout, …), so the state is not
    /// known. Posture only: never read it as `Absent` — a transient resolver
    /// error is no evidence that the domain is spoofable.
    Unknown,
}

impl PostureVerdict {
    /// The kebab-case label serde emits, for text renderers and CSV cells.
    pub fn as_str(self) -> &'static str {
        match self {
            PostureVerdict::Absent => "absent",
            PostureVerdict::Weak => "weak",
            PostureVerdict::Moderate => "moderate",
            PostureVerdict::Strict => "strict",
            PostureVerdict::Present => "present",
            PostureVerdict::Unknown => "unknown",
        }
    }
}

/// SPF (Sender Policy Framework) posture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfPolicy {
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record: Option<String>,
    /// The qualifier on the terminal `all` mechanism: `-` (fail), `~`
    /// (softfail), `?` (neutral), `+` (pass — permits anyone).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub all_qualifier: Option<String>,
    pub verdict: PostureVerdict,
}

/// DMARC posture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmarcPolicy {
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record: Option<String>,
    /// The `p=` policy: `none`, `quarantine`, or `reject`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// The `sp=` subdomain policy, if set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subdomain_policy: Option<String>,
    /// Aggregate report (`rua=`) destinations.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub aggregate_reports: Vec<String>,
    /// The `pct=` percentage of mail the policy applies to (defaults to 100).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent: Option<u8>,
    pub verdict: PostureVerdict,
}

/// MTA-STS posture (DNS signal only; enforcement mode lives in the HTTPS
/// policy file and is not fetched here to avoid an outbound SSRF surface).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtaStsPolicy {
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record: Option<String>,
    /// The policy `id=` from the TXT record (changes when the policy updates).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub verdict: PostureVerdict,
}

/// BIMI posture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BimiPolicy {
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record: Option<String>,
    /// The `l=` logo URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    /// The `a=` VMC (verified mark certificate) authority URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_url: Option<String>,
    pub verdict: PostureVerdict,
}

/// A single DANE TLSA record with the port/protocol scope it was found at.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsaRecord {
    /// The owner scope: `_25._tcp.<mx-host>` for SMTP records at an MX host
    /// (RFC 7672), `_25._tcp` for a domain without MX (its implicit MX is the
    /// domain itself), or `_443._tcp` (HTTPS).
    pub scope: String,
    pub cert_usage: u8,
    pub selector: u8,
    pub matching: u8,
    pub cert_data: String,
}

/// DANE (TLSA) posture across the common SMTP and HTTPS scopes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DanePolicy {
    pub present: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<TlsaRecord>,
    pub verdict: PostureVerdict,
}

/// The aggregate email/DNS security posture for a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailPosture {
    pub domain: String,
    pub spf: SpfPolicy,
    pub dmarc: DmarcPolicy,
    pub mta_sts: MtaStsPolicy,
    pub bimi: BimiPolicy,
    pub dane: DanePolicy,
    /// Human-readable advisory findings (e.g. "domain is spoofable").
    pub notes: Vec<String>,
}

// --- Bounds -----------------------------------------------------------------

/// The SPF DNS-lookup limit (RFC 7208 §4.6.4): evaluation that needs more
/// than this many `include`/`a`/`mx`/`ptr`/`exists`/`redirect` terms is a
/// permerror. It also bounds the `redirect=` hops and `include:` records
/// seer fetches — each one counts toward it. Every fetch is one DNS TXT
/// query — no outbound connection, so no SSRF surface.
const MAX_SPF_LOOKUPS: usize = 10;

/// Maximum parent names tried when looking for an inherited DMARC record
/// (the walk also never leaves the organizational domain).
const MAX_DMARC_WALK: usize = 7;

/// Maximum MX hosts (in preference order) probed for SMTP DANE records.
const MAX_DANE_MX_HOSTS: usize = 5;

// --- Pure parsers -------------------------------------------------------

/// True when `record` begins with the version tag `tag` (ASCII
/// case-insensitive) followed by the end of the record, whitespace, or —
/// for the `k=v;` policy records (`allow_semicolon`) — a `;`. A bare prefix
/// test accepted `v=spf10 …` as SPF.
fn has_version_tag(record: &str, tag: &str, allow_semicolon: bool) -> bool {
    let record = record.trim_start();
    let Some(head) = record.get(..tag.len()) else {
        return false;
    };
    if !head.eq_ignore_ascii_case(tag) {
        return false;
    }
    match record[tag.len()..].chars().next() {
        None => true,
        Some(c) => c.is_whitespace() || (allow_semicolon && c == ';'),
    }
}

/// How many records in a TXT set carry a given version tag.
#[derive(Debug, PartialEq, Eq)]
enum Selection<'a> {
    None,
    One(&'a str),
    /// More than one — SPF evaluation is a permerror (RFC 7208 §4.5) and
    /// DMARC is not applied at all (RFC 7489 §6.6.3).
    Multiple(usize),
}

fn select<'a>(records: &'a [String], tag: &str, allow_semicolon: bool) -> Selection<'a> {
    let mut matching = records
        .iter()
        .filter(|r| has_version_tag(r, tag, allow_semicolon));
    match (matching.next(), matching.count()) {
        (None, _) => Selection::None,
        (Some(record), 0) => Selection::One(record),
        (Some(_), rest) => Selection::Multiple(rest + 1),
    }
}

fn select_spf(records: &[String]) -> Selection<'_> {
    select(records, "v=spf1", false)
}

fn select_dmarc(records: &[String]) -> Selection<'_> {
    select(records, "v=DMARC1", true)
}

/// Returns the qualifier on the terminal `all` mechanism of an SPF record
/// (`-`, `~`, `?`, or `+`), or `None` if the record has no `all` mechanism.
fn parse_spf_all_qualifier(record: &str) -> Option<String> {
    for token in record.split_whitespace() {
        let t = token.to_ascii_lowercase();
        if t == "all" {
            return Some("+".to_string());
        }
        if let Some(qual) = t.strip_suffix("all") {
            if matches!(qual, "-" | "~" | "?" | "+") {
                return Some(qual.to_string());
            }
        }
    }
    None
}

/// The target of an SPF `redirect=` modifier, if any.
fn parse_spf_redirect(record: &str) -> Option<String> {
    record.split_whitespace().find_map(|token| {
        let (name, value) = token.split_once('=')?;
        name.eq_ignore_ascii_case("redirect")
            .then(|| value.to_string())
    })
}

/// What decides a single SPF record's verdict.
#[derive(Debug, PartialEq, Eq)]
enum SpfTerminal {
    /// The `all` mechanism's qualifier.
    All(String),
    /// No `all`, but a `redirect=` modifier: the target record governs
    /// (RFC 7208 §6.1 — `redirect` is ignored when `all` is present).
    Redirect(String),
    /// Neither: the default result is neutral, i.e. no protection.
    Neither,
}

fn spf_terminal(record: &str) -> SpfTerminal {
    match (parse_spf_all_qualifier(record), parse_spf_redirect(record)) {
        (Some(qualifier), _) => SpfTerminal::All(qualifier),
        (None, Some(target)) => SpfTerminal::Redirect(target),
        (None, None) => SpfTerminal::Neither,
    }
}

/// The DNS-querying terms of one SPF record (RFC 7208 §4.6.4): how many it
/// has, and the `include:` / effective `redirect=` targets whose records
/// count too.
fn spf_lookup_terms(record: &str) -> (usize, Vec<String>) {
    let mut count = 0;
    let mut targets = Vec::new();
    // The first token is the `v=spf1` version tag.
    for token in record.split_whitespace().skip(1) {
        let term = token.trim_start_matches(['+', '-', '~', '?']);
        if term.contains('=') {
            continue; // a modifier; `redirect=` is handled below
        }
        let name = term.split([':', '/']).next().unwrap_or(term);
        if name.eq_ignore_ascii_case("include") {
            count += 1;
            targets.extend(term.split_once(':').map(|(_, t)| t.to_string()));
        } else if ["a", "mx", "ptr", "exists"]
            .iter()
            .any(|m| name.eq_ignore_ascii_case(m))
        {
            count += 1;
        }
    }
    // `redirect=` is only used (and so only counted) without an `all`.
    if let SpfTerminal::Redirect(target) = spf_terminal(record) {
        count += 1;
        targets.push(target);
    }
    (count, targets)
}

/// Maps an SPF `all` qualifier to a verdict.
fn spf_verdict(all_qualifier: Option<&str>) -> PostureVerdict {
    match all_qualifier {
        Some("-") => PostureVerdict::Strict,
        Some("~") => PostureVerdict::Moderate,
        // "?all" (neutral), "+all" (pass-all), or a record with no `all` term
        // provides effectively no protection.
        Some(_) | None => PostureVerdict::Weak,
    }
}

/// Splits a `k=v; k=v` policy record (DMARC/BIMI/MTA-STS) into a tag map with
/// lowercased keys.
fn parse_tag_value(record: &str) -> HashMap<String, String> {
    record
        .split(';')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((k.trim().to_ascii_lowercase(), v.trim().to_string()))
        })
        .collect()
}

/// Maps a DMARC `p=`/`sp=` policy to a verdict.
fn dmarc_verdict(policy: Option<&str>) -> PostureVerdict {
    match policy.map(|p| p.to_ascii_lowercase()) {
        Some(ref p) if p == "reject" => PostureVerdict::Strict,
        Some(ref p) if p == "quarantine" => PostureVerdict::Moderate,
        // `none`, a missing or an invalid policy: monitoring only.
        _ => PostureVerdict::Weak,
    }
}

/// One enforcement band weaker (a `pct=` below 100 applies the policy to only
/// part of the failing mail; RFC 7489 §6.6.4 gives the rest the next-lower
/// policy).
fn downgrade(verdict: PostureVerdict) -> PostureVerdict {
    match verdict {
        PostureVerdict::Strict => PostureVerdict::Moderate,
        PostureVerdict::Moderate => PostureVerdict::Weak,
        other => other,
    }
}

/// Extracts the TXT record strings from a resolved record set.
fn txt_strings(records: &[crate::dns::DnsRecord]) -> Vec<String> {
    records
        .iter()
        .filter_map(|r| match &r.data {
            RecordData::TXT { text } => Some(text.clone()),
            _ => None,
        })
        .collect()
}

// --- Assemblers (pure given the fetched records) -----------------------

/// A mechanism's policy plus the advisory notes it contributes.
#[derive(Debug)]
struct Assessed<T> {
    policy: T,
    notes: Vec<String>,
}

/// A TXT record set, or the sanitized reason its lookup failed.
type TxtLookup = std::result::Result<Vec<String>, String>;

/// The result of following an SPF `redirect=` chain.
#[derive(Debug)]
enum RedirectOutcome {
    /// The chain ended at `target`, whose record's `all` qualifier (if any)
    /// is the effective one.
    Resolved {
        target: String,
        qualifier: Option<String>,
    },
    /// The chain cannot be evaluated (a permerror, or a macro seer does not
    /// expand).
    Failed { target: String, reason: String },
    /// A DNS lookup on the chain failed: the effective policy is unknown.
    LookupFailed { target: String, reason: String },
}

/// What SPF evaluation found beyond the apex record itself.
#[derive(Debug, Default)]
struct SpfFollowUp {
    /// The `redirect=` outcome, when the record has one and no `all`.
    redirect: Option<RedirectOutcome>,
    /// DNS-querying terms counted across the record and the records it
    /// includes or redirects to (stops once past [`MAX_SPF_LOOKUPS`]).
    lookups: usize,
}

fn spf_verdict_note(verdict: PostureVerdict) -> Option<String> {
    match verdict {
        PostureVerdict::Weak => Some(
            "SPF does not end in -all/~all — it permits unlisted senders (spoofable).".to_string(),
        ),
        PostureVerdict::Moderate => {
            Some("SPF uses ~all (softfail); -all provides stricter enforcement.".to_string())
        }
        _ => None,
    }
}

/// The SPF policy when the apex TXT lookup itself failed.
fn unknown_spf(reason: &str) -> Assessed<SpfPolicy> {
    Assessed {
        policy: SpfPolicy {
            present: false,
            record: None,
            all_qualifier: None,
            verdict: PostureVerdict::Unknown,
        },
        notes: vec![format!(
            "SPF lookup failed ({reason}) — SPF posture is unknown, not absent."
        )],
    }
}

/// Assembles the SPF policy from the apex TXT set and what evaluating its
/// record found (see [`assess_spf`]).
fn build_spf(apex_txt: &[String], follow_up: &SpfFollowUp) -> Assessed<SpfPolicy> {
    let record = match select_spf(apex_txt) {
        Selection::None => {
            return Assessed {
                policy: SpfPolicy {
                    present: false,
                    record: None,
                    all_qualifier: None,
                    verdict: PostureVerdict::Absent,
                },
                notes: vec!["No SPF record — sending sources are undeclared.".to_string()],
            };
        }
        Selection::Multiple(count) => {
            return Assessed {
                policy: SpfPolicy {
                    present: true,
                    record: None,
                    all_qualifier: None,
                    verdict: PostureVerdict::Weak,
                },
                notes: vec![format!(
                    "{count} SPF records are published — SPF evaluation fails with permerror \
                     (RFC 7208 §4.5), so receivers get no SPF result. Merge them into one record."
                )],
            };
        }
        Selection::One(record) => record,
    };

    // A policy whose verdict is decided before its `all` qualifier.
    let settled = |verdict: PostureVerdict, note: String| Assessed {
        policy: SpfPolicy {
            present: true,
            record: Some(record.to_string()),
            all_qualifier: None,
            verdict,
        },
        notes: vec![note],
    };

    if follow_up.lookups > MAX_SPF_LOOKUPS {
        return settled(
            PostureVerdict::Weak,
            format!(
                "SPF needs more than {MAX_SPF_LOOKUPS} DNS lookups (include/a/mx/ptr/exists/\
                 redirect, counted through its includes) — evaluation fails with permerror \
                 (RFC 7208 §4.6.4), so receivers get no SPF result. Flatten or trim the record."
            ),
        );
    }

    let mut notes = Vec::new();
    let all_qualifier = match (spf_terminal(record), &follow_up.redirect) {
        (SpfTerminal::All(qualifier), _) => Some(qualifier),
        (SpfTerminal::Redirect(_), Some(RedirectOutcome::Resolved { target, qualifier })) => {
            notes.push(format!(
                "SPF delegates to {target} via redirect= — the verdict reflects that record."
            ));
            qualifier.clone()
        }
        (SpfTerminal::Redirect(_), Some(RedirectOutcome::Failed { target, reason })) => {
            return settled(
                PostureVerdict::Weak,
                format!(
                    "SPF redirect={target} could not be evaluated ({reason}) — receivers get \
                     no usable SPF result."
                ),
            );
        }
        (SpfTerminal::Redirect(_), Some(RedirectOutcome::LookupFailed { target, reason })) => {
            return settled(
                PostureVerdict::Unknown,
                format!(
                    "SPF redirect={target} lookup failed ({reason}) — the effective SPF policy \
                     is unknown."
                ),
            );
        }
        (SpfTerminal::Redirect(_), None) | (SpfTerminal::Neither, _) => None,
    };
    let verdict = spf_verdict(all_qualifier.as_deref());
    notes.extend(spf_verdict_note(verdict));
    Assessed {
        policy: SpfPolicy {
            present: true,
            verdict,
            all_qualifier,
            record: Some(record.to_string()),
        },
        notes,
    }
}

/// Where the applicable DMARC record set was found.
#[derive(Debug)]
struct DmarcSource {
    /// The TXT strings at `_dmarc.<at>`.
    txts: Vec<String>,
    /// The domain whose `_dmarc` name held the records.
    at: String,
    /// True when `at` is a parent of the checked domain.
    inherited: bool,
}

/// The outcome of looking for the DMARC record set that applies.
#[derive(Debug)]
enum DmarcDiscovery {
    Found(DmarcSource),
    /// No DMARC record at the domain or any name up to its organizational
    /// domain.
    NotFound,
    /// A lookup on the way failed, so a record may exist unseen.
    LookupFailed {
        name: String,
        reason: String,
    },
}

fn absent_dmarc() -> DmarcPolicy {
    DmarcPolicy {
        present: false,
        record: None,
        policy: None,
        subdomain_policy: None,
        aggregate_reports: Vec::new(),
        percent: None,
        verdict: PostureVerdict::Absent,
    }
}

/// Assembles the DMARC policy for `domain` from the discovered record set.
fn build_dmarc(domain: &str, discovery: &DmarcDiscovery) -> Assessed<DmarcPolicy> {
    let spoofable =
        || vec!["No DMARC record — the domain is trivially spoofable in phishing.".to_string()];
    let source = match discovery {
        DmarcDiscovery::Found(source) => source,
        DmarcDiscovery::NotFound => {
            return Assessed {
                policy: absent_dmarc(),
                notes: spoofable(),
            }
        }
        DmarcDiscovery::LookupFailed { name, reason } => {
            return Assessed {
                policy: DmarcPolicy {
                    verdict: PostureVerdict::Unknown,
                    ..absent_dmarc()
                },
                notes: vec![format!(
                    "DMARC lookup at {name} failed ({reason}) — DMARC posture is unknown, \
                     not absent."
                )],
            }
        }
    };
    let record = match select_dmarc(&source.txts) {
        Selection::None => {
            return Assessed {
                policy: absent_dmarc(),
                notes: spoofable(),
            };
        }
        Selection::Multiple(count) => {
            return Assessed {
                policy: DmarcPolicy {
                    present: true,
                    ..absent_dmarc()
                },
                notes: vec![format!(
                    "{count} DMARC records at _dmarc.{} — receivers do not apply DMARC at all \
                     when more than one is published (RFC 7489 §6.6.3). Publish exactly one.",
                    source.at
                )],
            };
        }
        Selection::One(record) => record,
    };

    let tags = parse_tag_value(record);
    let policy = tags.get("p").cloned();
    let subdomain_policy = tags.get("sp").cloned();
    let percent: Option<u8> = tags.get("pct").and_then(|p| p.parse().ok());
    let aggregate_reports = tags
        .get("rua")
        .map(|rua| {
            rua.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    // A subdomain governed by its organizational domain's record gets that
    // record's `sp=` policy, falling back to `p=` (RFC 7489 §6.6.3 / §6.3).
    let (label, effective) = match (&subdomain_policy, source.inherited) {
        (Some(sp), true) => ("sp", Some(sp.as_str())),
        _ => ("p", policy.as_deref()),
    };
    let base = dmarc_verdict(effective);
    let partial_pct = percent.filter(|pct| *pct < 100);
    let verdict = if partial_pct.is_some() {
        downgrade(base)
    } else {
        base
    };

    let mut notes = Vec::new();
    if source.inherited {
        notes.push(format!(
            "No DMARC record at _dmarc.{domain} — it inherits the organizational record at \
             _dmarc.{} (RFC 7489 §6.6.3), whose {label}= policy applies.",
            source.at
        ));
    }
    let effective_lc = effective.map(str::to_ascii_lowercase);
    match (base, effective_lc.as_deref()) {
        (PostureVerdict::Moderate, _) => notes.push(format!(
            "DMARC policy is {label}=quarantine — spoofed mail is filtered but not rejected."
        )),
        (PostureVerdict::Weak, Some("none")) => notes.push(format!(
            "DMARC policy is {label}=none (monitoring only) — receivers will not reject spoofed mail."
        )),
        (PostureVerdict::Weak, _) => notes.push(format!(
            "DMARC record has no valid {label}= policy — receivers treat it as monitoring only (p=none)."
        )),
        _ => {}
    }
    if let (Some(pct), Some(value)) = (partial_pct, effective_lc.as_deref()) {
        if base != PostureVerdict::Weak {
            notes.push(format!(
                "DMARC pct={pct} — the {label}={value} policy is applied to only {pct}% of \
                 failing mail (the rest gets the next-weaker treatment), so enforcement is partial."
            ));
        }
    }

    Assessed {
        policy: DmarcPolicy {
            present: true,
            verdict,
            subdomain_policy,
            percent,
            aggregate_reports,
            policy,
            record: Some(record.to_string()),
        },
        notes,
    }
}

fn build_mta_sts(txt: &TxtLookup) -> MtaStsPolicy {
    let absent = |verdict| MtaStsPolicy {
        present: false,
        record: None,
        id: None,
        verdict,
    };
    let Ok(txt) = txt else {
        return absent(PostureVerdict::Unknown);
    };
    match txt.iter().find(|t| has_version_tag(t, "v=STSv1", true)) {
        Some(record) => {
            let tags = parse_tag_value(record);
            MtaStsPolicy {
                present: true,
                id: tags.get("id").cloned(),
                record: Some(record.clone()),
                verdict: PostureVerdict::Present,
            }
        }
        None => absent(PostureVerdict::Absent),
    }
}

fn build_bimi(txt: &TxtLookup) -> BimiPolicy {
    let absent = |verdict| BimiPolicy {
        present: false,
        record: None,
        logo_url: None,
        authority_url: None,
        verdict,
    };
    let Ok(txt) = txt else {
        return absent(PostureVerdict::Unknown);
    };
    match txt.iter().find(|t| has_version_tag(t, "v=BIMI1", true)) {
        Some(record) => {
            let tags = parse_tag_value(record);
            BimiPolicy {
                present: true,
                logo_url: tags.get("l").filter(|s| !s.is_empty()).cloned(),
                authority_url: tags.get("a").filter(|s| !s.is_empty()).cloned(),
                record: Some(record.clone()),
                verdict: PostureVerdict::Present,
            }
        }
        None => absent(PostureVerdict::Absent),
    }
}

/// The TLSA record sets DANE looked at, each with its owner scope, and
/// whether any lookup on the way (MX included) failed.
#[derive(Debug, Default)]
struct TlsaSets {
    sets: Vec<(String, Vec<crate::dns::DnsRecord>)>,
    lookup_failed: bool,
}

/// Assembles the DANE policy from the TLSA sets. Records found are
/// `Present` even when another lookup failed; with none found, a failed
/// lookup makes the state `Unknown` rather than `Absent`.
fn build_dane(tlsa: &TlsaSets) -> DanePolicy {
    let mut records = Vec::new();
    for (scope, set) in &tlsa.sets {
        for r in set {
            if let RecordData::TLSA {
                cert_usage,
                selector,
                matching,
                cert_data,
            } = &r.data
            {
                records.push(TlsaRecord {
                    scope: scope.clone(),
                    cert_usage: *cert_usage,
                    selector: *selector,
                    matching: *matching,
                    cert_data: cert_data.clone(),
                });
            }
        }
    }
    let verdict = if !records.is_empty() {
        PostureVerdict::Present
    } else if tlsa.lookup_failed {
        PostureVerdict::Unknown
    } else {
        PostureVerdict::Absent
    };
    DanePolicy {
        present: !records.is_empty(),
        verdict,
        records,
    }
}

/// Orders the advisory notes: DMARC, SPF, then the transport mechanisms.
fn build_notes(
    spf: &Assessed<SpfPolicy>,
    dmarc: &Assessed<DmarcPolicy>,
    mta_sts: &MtaStsPolicy,
    bimi: &BimiPolicy,
    dane: &DanePolicy,
) -> Vec<String> {
    let mut notes = dmarc.notes.clone();
    notes.extend(spf.notes.iter().cloned());
    let mta_sts_note = match mta_sts.verdict {
        PostureVerdict::Absent => {
            Some("MTA-STS is not configured — SMTP is vulnerable to downgrade.")
        }
        PostureVerdict::Unknown => Some("MTA-STS lookup failed — its state is unknown."),
        _ => None,
    };
    let bimi_note = (bimi.verdict == PostureVerdict::Unknown)
        .then_some("BIMI lookup failed — its state is unknown.");
    let dane_note = match dane.verdict {
        PostureVerdict::Absent => {
            Some("No DANE (TLSA) records — no DNS-based TLS pinning for mail/HTTPS.")
        }
        PostureVerdict::Unknown => Some(
            "DANE (TLSA/MX) lookup failed and no TLSA records were found — DANE state is unknown.",
        ),
        _ => None,
    };
    notes.extend(
        [mta_sts_note, bimi_note, dane_note]
            .into_iter()
            .flatten()
            .map(str::to_string),
    );
    notes
}

// --- Network steps (each bounded; DNS only) ------------------------------

/// The resolver plus the caller's nameserver (`None` = the default
/// upstream), so every posture query goes to the same server.
#[derive(Clone, Copy)]
struct Dns<'a> {
    resolver: &'a DnsResolver,
    nameserver: Option<&'a str>,
}

impl Dns<'_> {
    async fn resolve(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<Vec<crate::dns::DnsRecord>> {
        self.resolver
            .resolve(name, record_type, self.nameserver)
            .await
    }

    async fn txt(&self, name: &str) -> TxtLookup {
        self.resolve(name, RecordType::TXT)
            .await
            .map(|records| txt_strings(&records))
            .map_err(|e| e.sanitized_message())
    }

    /// The one SPF record at `target`, or `None` when it cannot be read
    /// (macros, an invalid name, a failed lookup, none or several records).
    async fn spf_record(&self, target: &str) -> Option<String> {
        if target.contains('%') {
            return None;
        }
        let name = normalize_host(target).ok()?;
        match select_spf(&self.txt(&name).await.ok()?) {
            Selection::One(record) => Some(record.to_string()),
            _ => None,
        }
    }
}

/// Follows an SPF `redirect=` chain; each hop counts toward the
/// [`MAX_SPF_LOOKUPS`] limit, so a longer chain is a permerror.
async fn follow_spf_redirect(dns: Dns<'_>, first_target: String) -> RedirectOutcome {
    let mut target = first_target;
    for _ in 0..MAX_SPF_LOOKUPS {
        if target.contains('%') {
            return RedirectOutcome::Failed {
                target,
                reason: "it uses SPF macros, which seer does not expand".to_string(),
            };
        }
        let Ok(name) = normalize_host(&target) else {
            return RedirectOutcome::Failed {
                target,
                reason: "not a valid domain name — permerror".to_string(),
            };
        };
        let txts = match dns.txt(&name).await {
            Ok(txts) => txts,
            Err(reason) => {
                return RedirectOutcome::LookupFailed {
                    target: name,
                    reason,
                }
            }
        };
        match select_spf(&txts) {
            Selection::None => {
                return RedirectOutcome::Failed {
                    target: name,
                    reason: "it publishes no SPF record — permerror".to_string(),
                }
            }
            Selection::Multiple(count) => {
                return RedirectOutcome::Failed {
                    target: name,
                    reason: format!("it publishes {count} SPF records — permerror"),
                }
            }
            Selection::One(record) => match spf_terminal(record) {
                SpfTerminal::All(qualifier) => {
                    return RedirectOutcome::Resolved {
                        target: name,
                        qualifier: Some(qualifier),
                    }
                }
                SpfTerminal::Neither => {
                    return RedirectOutcome::Resolved {
                        target: name,
                        qualifier: None,
                    }
                }
                SpfTerminal::Redirect(next) => target = next,
            },
        }
    }
    RedirectOutcome::Failed {
        target,
        reason: format!("the redirect chain exceeds the {MAX_SPF_LOOKUPS} DNS-lookup limit"),
    }
}

/// Counts the DNS-querying terms evaluating `record` needs (RFC 7208
/// §4.6.4), following `include:` and `redirect=` into their records. Stops
/// as soon as the count passes [`MAX_SPF_LOOKUPS`], so at most that many
/// records are fetched; a target that cannot be read adds nothing beyond its
/// own term (the count is then a lower bound).
async fn count_spf_lookups(dns: Dns<'_>, record: &str) -> usize {
    let (mut count, mut pending) = spf_lookup_terms(record);
    while let Some(target) = pending.pop() {
        if count > MAX_SPF_LOOKUPS {
            break;
        }
        if let Some(included) = dns.spf_record(&target).await {
            let (terms, targets) = spf_lookup_terms(&included);
            count += terms;
            pending.extend(targets);
        }
    }
    count
}

/// SPF for the apex TXT lookup: follows `redirect=` when the record has no
/// `all` term (RFC 7208 §6.1: the redirected record then governs — grading
/// such a record on its own as "no -all/~all" called well-run delegated
/// setups spoofable), and counts its DNS lookups against the §4.6.4 limit.
async fn assess_spf(dns: Dns<'_>, apex_txt: &TxtLookup) -> Assessed<SpfPolicy> {
    let apex_txt = match apex_txt {
        Ok(txts) => txts,
        Err(reason) => return unknown_spf(reason),
    };
    let mut follow_up = SpfFollowUp::default();
    if let Selection::One(record) = select_spf(apex_txt) {
        let redirect = async {
            match spf_terminal(record) {
                SpfTerminal::Redirect(target) => Some(follow_spf_redirect(dns, target).await),
                _ => None,
            }
        };
        (follow_up.redirect, follow_up.lookups) =
            tokio::join!(redirect, count_spf_lookups(dns, record));
    }
    build_spf(apex_txt, &follow_up)
}

/// Finds the DMARC record set that applies to `domain`: its own
/// `_dmarc.<domain>`, or — when that has no DMARC record — the nearest parent
/// that has one, walking one label at a time (at most [`MAX_DMARC_WALK`])
/// but never above the Organizational Domain (RFC 7489 §3.2: the registrable
/// domain under the Public Suffix List). RFC 7489 §6.6.3 falls back to the
/// Organizational Domain itself; the nearest publishing ancestor below it is
/// what the DMARCbis tree walk adds. A query error stops the walk rather than
/// skipping past a record we could not see.
async fn discover_dmarc(dns: Dns<'_>, domain: &str, own: TxtLookup) -> DmarcDiscovery {
    let failed = |name: String, reason: String| DmarcDiscovery::LookupFailed { name, reason };
    let own = match own {
        Ok(own) => own,
        Err(reason) => return failed(format!("_dmarc.{domain}"), reason),
    };
    if select_dmarc(&own) != Selection::None {
        return DmarcDiscovery::Found(DmarcSource {
            txts: own,
            at: domain.to_string(),
            inherited: false,
        });
    }
    // A registrable domain (or a bare suffix) has no organizational parent.
    let Some(org) = crate::psl::registrable_parent(domain) else {
        return DmarcDiscovery::NotFound;
    };
    let mut current = domain;
    for _ in 0..MAX_DMARC_WALK {
        let Some((_, parent)) = current.split_once('.') else {
            break;
        };
        if parent.len() < org.len() {
            break;
        }
        let name = format!("_dmarc.{parent}");
        let txts = match dns.txt(&name).await {
            Ok(txts) => txts,
            Err(reason) => return failed(name, reason),
        };
        if select_dmarc(&txts) != Selection::None {
            return DmarcDiscovery::Found(DmarcSource {
                txts,
                at: parent.to_string(),
                inherited: true,
            });
        }
        current = parent;
    }
    DmarcDiscovery::NotFound
}

/// SMTP DANE records per RFC 7672 §2.2: TLSA lives at `_25._tcp.<MX host>`,
/// not at the mail domain. Probes the first [`MAX_DANE_MX_HOSTS`] exchanges
/// (preference order) concurrently; a domain with no MX falls back to its
/// implicit MX, the domain itself (RFC 5321 §5.1). A null MX (RFC 7505)
/// accepts no mail, so there is nothing to pin. A failed MX lookup leaves
/// the hosts unknown: nothing is probed and the sets are marked failed.
async fn smtp_tlsa_records(
    dns: Dns<'_>,
    domain: &str,
    mx: Result<Vec<crate::dns::DnsRecord>>,
) -> TlsaSets {
    let Ok(mx) = mx else {
        return TlsaSets {
            sets: Vec::new(),
            lookup_failed: true,
        };
    };
    let mut hosts: Vec<String> = Vec::new();
    for record in &mx {
        if let RecordData::MX { exchange, .. } = &record.data {
            let host = exchange.trim_end_matches('.').to_ascii_lowercase();
            if !hosts.contains(&host) {
                hosts.push(host);
            }
        }
    }
    if hosts.iter().any(|h| h.is_empty()) {
        return TlsaSets::default();
    }

    let owners: Vec<(String, String)> = if hosts.is_empty() {
        vec![("_25._tcp".to_string(), format!("_25._tcp.{domain}"))]
    } else {
        hosts
            .into_iter()
            .take(MAX_DANE_MX_HOSTS)
            .map(|host| {
                let owner = format!("_25._tcp.{host}");
                (owner.clone(), owner)
            })
            .collect()
    };
    let results = futures::future::join_all(
        owners
            .iter()
            .map(|(_, owner)| Box::pin(dns.resolve(owner, RecordType::TLSA))),
    )
    .await;
    let mut tlsa = TlsaSets::default();
    for ((scope, _), result) in owners.into_iter().zip(results) {
        match result {
            Ok(set) => tlsa.sets.push((scope, set)),
            Err(_) => tlsa.lookup_failed = true,
        }
    }
    tlsa
}

/// Resolves and interprets the email/DNS security posture for `domain`,
/// querying `nameserver` (a nameserver spec as for
/// [`DnsResolver::resolve`]; `None` = the resolver's default upstream).
///
/// Each mechanism degrades independently: a resolver error (SERVFAIL,
/// timeout) for one record set yields that mechanism's
/// [`PostureVerdict::Unknown`] with a "lookup failed" note — never `Absent`,
/// which would call the domain spoofable on a transient failure — rather
/// than failing the whole report. Returns an error only if the domain itself
/// is invalid.
pub async fn lookup_email_posture(
    resolver: &DnsResolver,
    domain: &str,
    nameserver: Option<&str>,
) -> Result<EmailPosture> {
    let domain = normalize_domain(domain)?;
    let dns = Dns {
        resolver,
        nameserver,
    };

    let dmarc_name = format!("_dmarc.{domain}");
    let mta_sts_name = format!("_mta-sts.{domain}");
    let bimi_name = format!("default._bimi.{domain}");
    let https_tlsa_name = format!("_443._tcp.{domain}");

    // Resolve every independent record set concurrently. Futures are boxed so
    // the combined `join!` frame stays small (avoids the large-future debug
    // stack pressure seen in diff.rs).
    let (apex_txt, dmarc, mta_sts, bimi, mx, https_tlsa) = tokio::join!(
        Box::pin(dns.txt(&domain)),
        Box::pin(dns.txt(&dmarc_name)),
        Box::pin(dns.txt(&mta_sts_name)),
        Box::pin(dns.txt(&bimi_name)),
        Box::pin(dns.resolve(&domain, RecordType::MX)),
        Box::pin(dns.resolve(&https_tlsa_name, RecordType::TLSA)),
    );

    // Second round: steps that depend on a first-round answer (SPF redirect
    // and lookup count, DMARC inheritance, TLSA at the MX hosts), again
    // concurrently.
    let (spf, dmarc_discovery, mut tlsa) = tokio::join!(
        Box::pin(assess_spf(dns, &apex_txt)),
        Box::pin(discover_dmarc(dns, &domain, dmarc)),
        Box::pin(smtp_tlsa_records(dns, &domain, mx)),
    );
    match https_tlsa {
        Ok(set) => tlsa.sets.push(("_443._tcp".to_string(), set)),
        Err(_) => tlsa.lookup_failed = true,
    }

    let dmarc = build_dmarc(&domain, &dmarc_discovery);
    let mta_sts = build_mta_sts(&mta_sts);
    let bimi = build_bimi(&bimi);
    let dane = build_dane(&tlsa);
    let notes = build_notes(&spf, &dmarc, &mta_sts, &bimi, &dane);

    Ok(EmailPosture {
        domain,
        spf: spf.policy,
        dmarc: dmarc.policy,
        mta_sts,
        bimi,
        dane,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    fn own_dmarc(domain: &str, txts: &[&str]) -> DmarcDiscovery {
        DmarcDiscovery::Found(DmarcSource {
            txts: strings(txts),
            at: domain.to_string(),
            inherited: false,
        })
    }

    #[test]
    fn spf_qualifier_parsing() {
        assert_eq!(
            parse_spf_all_qualifier("v=spf1 include:_spf.google.com -all"),
            Some("-".to_string())
        );
        assert_eq!(
            parse_spf_all_qualifier("v=spf1 mx ~all"),
            Some("~".to_string())
        );
        assert_eq!(
            parse_spf_all_qualifier("v=spf1 +all"),
            Some("+".to_string())
        );
        assert_eq!(parse_spf_all_qualifier("v=spf1 a mx"), None);
    }

    #[test]
    fn spf_verdict_bands() {
        assert_eq!(spf_verdict(Some("-")), PostureVerdict::Strict);
        assert_eq!(spf_verdict(Some("~")), PostureVerdict::Moderate);
        assert_eq!(spf_verdict(Some("?")), PostureVerdict::Weak);
        assert_eq!(spf_verdict(Some("+")), PostureVerdict::Weak);
        assert_eq!(spf_verdict(None), PostureVerdict::Weak);
    }

    #[test]
    fn verdict_as_str_matches_serde_label() {
        // Text/CSV renderers use as_str(); it must never disagree with JSON.
        for v in [
            PostureVerdict::Absent,
            PostureVerdict::Weak,
            PostureVerdict::Moderate,
            PostureVerdict::Strict,
            PostureVerdict::Present,
        ] {
            assert_eq!(serde_json::to_value(v).unwrap(), v.as_str());
        }
    }

    #[test]
    fn version_tag_must_be_followed_by_a_delimiter() {
        // Regression: a prefix test accepted `v=spf10`.
        assert!(!has_version_tag("v=spf10 -all", "v=spf1", false));
        assert!(has_version_tag("v=spf1 -all", "v=spf1", false));
        assert!(has_version_tag("V=SPF1 -all", "v=spf1", false));
        assert!(has_version_tag("v=spf1", "v=spf1", false));
        assert!(!has_version_tag("v=spf1;-all", "v=spf1", false));
        assert!(has_version_tag("v=DMARC1; p=reject", "v=DMARC1", true));
        assert!(has_version_tag("v=DMARC1;p=reject", "v=DMARC1", true));
        assert!(!has_version_tag("v=DMARC10; p=reject", "v=DMARC1", true));
        assert!(
            !has_version_tag("v=é", "v=spf1", false),
            "no panic on short multibyte"
        );
        assert_eq!(select_spf(&strings(&["v=spf10 -all"])), Selection::None);
    }

    #[test]
    fn multiple_spf_records_are_a_permerror() {
        // RFC 7208 §4.5: two SPF records → permerror, not "the first wins".
        let spf = build_spf(
            &strings(&["v=spf1 -all", "v=spf1 include:x.test ~all"]),
            &SpfFollowUp::default(),
        );
        assert!(spf.policy.present);
        assert_eq!(spf.policy.verdict, PostureVerdict::Weak);
        assert_eq!(spf.policy.all_qualifier, None);
        assert!(
            spf.notes.iter().any(|n| n.contains("permerror")),
            "{:?}",
            spf.notes
        );
    }

    #[test]
    fn multiple_dmarc_records_disable_dmarc() {
        // RFC 7489 §6.6.3: more than one record → DMARC is not applied.
        let source = own_dmarc("x.test", &["v=DMARC1; p=reject", "v=DMARC1; p=none"]);
        let dmarc = build_dmarc("x.test", &source);
        assert!(dmarc.policy.present);
        assert_eq!(dmarc.policy.verdict, PostureVerdict::Absent);
        assert!(
            dmarc.notes[0].contains("2 DMARC records"),
            "{:?}",
            dmarc.notes
        );
    }

    #[test]
    fn dmarc_parsing_and_verdict() {
        let record =
            "v=DMARC1; p=reject; sp=quarantine; rua=mailto:a@x.com,mailto:b@x.com; pct=100";
        let dmarc = build_dmarc("x.com", &own_dmarc("x.com", &[record])).policy;
        assert!(dmarc.present);
        assert_eq!(dmarc.policy.as_deref(), Some("reject"));
        assert_eq!(dmarc.subdomain_policy.as_deref(), Some("quarantine"));
        assert_eq!(dmarc.percent, Some(100));
        assert_eq!(dmarc.aggregate_reports.len(), 2);
        assert_eq!(dmarc.verdict, PostureVerdict::Strict);
    }

    #[test]
    fn dmarc_none_is_weak_and_absent_is_absent() {
        let weak = build_dmarc("x.test", &own_dmarc("x.test", &["v=DMARC1; p=none"]));
        assert_eq!(weak.policy.verdict, PostureVerdict::Weak);
        assert!(weak.notes[0].contains("p=none (monitoring only)"));
        let absent = build_dmarc("x.test", &own_dmarc("x.test", &["v=spf1 -all"]));
        assert!(!absent.policy.present);
        assert_eq!(absent.policy.verdict, PostureVerdict::Absent);
    }

    #[test]
    fn dmarc_partial_pct_downgrades_one_band() {
        // Regression: `pct=` was ignored, so p=reject;pct=0 graded Strict.
        let verdict = |record: &str| {
            let dmarc = build_dmarc("x.test", &own_dmarc("x.test", &[record]));
            (dmarc.policy.verdict, dmarc.notes)
        };
        let (v, notes) = verdict("v=DMARC1; p=reject; pct=0");
        assert_eq!(v, PostureVerdict::Moderate);
        assert!(notes.iter().any(|n| n.contains("pct=0")), "{notes:?}");
        assert_eq!(
            verdict("v=DMARC1; p=quarantine; pct=50").0,
            PostureVerdict::Weak
        );
        assert_eq!(
            verdict("v=DMARC1; p=reject; pct=100").0,
            PostureVerdict::Strict
        );
        assert_eq!(verdict("v=DMARC1; p=none; pct=10").0, PostureVerdict::Weak);
    }

    #[test]
    fn inherited_dmarc_applies_sp_then_p() {
        let inherited = |txt: &str| {
            DmarcDiscovery::Found(DmarcSource {
                txts: strings(&[txt]),
                at: "org.test".to_string(),
                inherited: true,
            })
        };
        let dmarc = build_dmarc("mail.org.test", &inherited("v=DMARC1; p=none; sp=reject"));
        assert_eq!(dmarc.policy.verdict, PostureVerdict::Strict);
        assert!(dmarc.notes[0].contains("inherits"), "{:?}", dmarc.notes);
        assert!(dmarc.notes[0].contains("_dmarc.org.test"));

        let dmarc = build_dmarc("mail.org.test", &inherited("v=DMARC1; p=quarantine"));
        assert_eq!(dmarc.policy.verdict, PostureVerdict::Moderate);
    }

    #[test]
    fn spf_prefers_the_spf_record_among_txt() {
        // The apex TXT set carries a verification token AND the SPF record.
        let txts = strings(&[
            "google-site-verification=abc123",
            "v=spf1 include:_spf.google.com -all",
        ]);
        let spf = build_spf(&txts, &SpfFollowUp::default()).policy;
        assert!(spf.present);
        assert_eq!(spf.all_qualifier.as_deref(), Some("-"));
        assert_eq!(spf.verdict, PostureVerdict::Strict);
    }

    #[test]
    fn spf_redirect_parsing_prefers_all() {
        assert_eq!(
            spf_terminal("v=spf1 redirect=_spf.x.test"),
            SpfTerminal::Redirect("_spf.x.test".to_string())
        );
        assert_eq!(
            spf_terminal("v=spf1 Redirect=_spf.x.test"),
            SpfTerminal::Redirect("_spf.x.test".to_string())
        );
        // RFC 7208 §6.1: redirect is ignored when an `all` is present.
        assert_eq!(
            spf_terminal("v=spf1 redirect=_spf.x.test ~all"),
            SpfTerminal::All("~".to_string())
        );
        assert_eq!(spf_terminal("v=spf1 mx"), SpfTerminal::Neither);
    }

    #[test]
    fn bimi_and_mta_sts_parse_tags() {
        let bimi = build_bimi(&Ok(vec![
            "v=BIMI1; l=https://x.com/logo.svg; a=https://x.com/vmc.pem".into(),
        ]));
        assert!(bimi.present);
        assert_eq!(bimi.logo_url.as_deref(), Some("https://x.com/logo.svg"));
        assert_eq!(bimi.authority_url.as_deref(), Some("https://x.com/vmc.pem"));

        let mta = build_mta_sts(&Ok(vec!["v=STSv1; id=20240101T000000".into()]));
        assert!(mta.present);
        assert_eq!(mta.id.as_deref(), Some("20240101T000000"));
        assert_eq!(mta.verdict, PostureVerdict::Present);
    }

    #[test]
    fn notes_flag_a_spoofable_domain() {
        // No DMARC, no SPF, no MTA-STS, no DANE → several advisory notes.
        let spf = build_spf(&[], &SpfFollowUp::default());
        let dmarc = build_dmarc("x.test", &DmarcDiscovery::NotFound);
        let mta = build_mta_sts(&Ok(Vec::new()));
        let dane = build_dane(&TlsaSets::default());
        let notes = build_notes(&spf, &dmarc, &mta, &build_bimi(&Ok(Vec::new())), &dane);
        assert!(notes[0].contains("No DMARC"), "DMARC first: {notes:?}");
        assert!(notes.iter().any(|n| n.contains("No SPF")));
        assert!(notes.iter().any(|n| n.contains("MTA-STS")));
        assert!(notes.iter().any(|n| n.contains("DANE")));
    }

    // --- End to end against the scripted mock DNS fixture ----------------

    use hickory_resolver::proto::rr::rdata as wire;
    use hickory_resolver::proto::rr::{Name, RData, RecordType as WireType};

    use crate::dns::test_support::{
        mock_dns_resolver, mock_dns_resolver_default, spawn_mock_dns_fn, MockReply,
    };

    fn txt(value: &str) -> MockReply {
        MockReply::Answer(vec![RData::TXT(wire::TXT::new(vec![value.to_string()]))])
    }

    fn mx(preference: u16, exchange: &str) -> RData {
        RData::MX(wire::MX::new(
            preference,
            Name::from_ascii(exchange).unwrap(),
        ))
    }

    fn tlsa() -> MockReply {
        MockReply::Answer(vec![RData::TLSA(wire::TLSA::new(
            wire::tlsa::CertUsage::from(3),
            wire::tlsa::Selector::from(1),
            wire::tlsa::Matching::from(1),
            vec![0xAB, 0xCD],
        ))])
    }

    /// Regression: SMTP DANE was looked up at `_25._tcp.<domain>`, but
    /// RFC 7672 publishes it at `_25._tcp.<MX host>` — a DANE-protected
    /// mail domain read as "no DANE".
    #[tokio::test]
    async fn dane_smtp_is_read_at_the_mx_hosts() {
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("mail.test", WireType::MX) => {
                MockReply::Answer(vec![mx(20, "mx2.mail.test."), mx(10, "mx1.mail.test.")])
            }
            ("_25._tcp.mx2.mail.test", WireType::TLSA) => tlsa(),
            _ => MockReply::NxDomain,
        })
        .await;
        let posture = lookup_email_posture(&mock_dns_resolver_default(port), "mail.test", None)
            .await
            .unwrap();
        assert!(posture.dane.present, "{:?}", posture.dane);
        assert_eq!(posture.dane.records.len(), 1);
        assert_eq!(posture.dane.records[0].scope, "_25._tcp.mx2.mail.test");
    }

    /// A domain with no MX is its own (implicit) MX: TLSA at the domain.
    #[tokio::test]
    async fn dane_smtp_falls_back_to_the_domain_without_mx() {
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("_25._tcp.nomx.test", WireType::TLSA) => tlsa(),
            _ => MockReply::NoData,
        })
        .await;
        let posture = lookup_email_posture(&mock_dns_resolver_default(port), "nomx.test", None)
            .await
            .unwrap();
        assert_eq!(posture.dane.records.len(), 1, "{:?}", posture.dane);
        assert_eq!(posture.dane.records[0].scope, "_25._tcp");
    }

    /// Regression: only `_dmarc.<domain>` was queried, so a subdomain
    /// covered by its organizational domain's record read as "No DMARC".
    #[tokio::test]
    async fn dmarc_is_inherited_from_a_parent() {
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("_dmarc.org.test", WireType::TXT) => txt("v=DMARC1; p=none; sp=reject"),
            _ => MockReply::NxDomain,
        })
        .await;
        let posture =
            lookup_email_posture(&mock_dns_resolver_default(port), "news.mail.org.test", None)
                .await
                .unwrap();
        assert!(posture.dmarc.present);
        assert_eq!(posture.dmarc.verdict, PostureVerdict::Strict);
        assert!(
            posture
                .notes
                .iter()
                .any(|n| n.contains("inherits") && n.contains("_dmarc.org.test")),
            "{:?}",
            posture.notes
        );
    }

    /// Regression: `v=spf1 redirect=…` (no `all`) was graded Weak /
    /// "spoofable"; per RFC 7208 §6.1 the redirected record governs. Two
    /// hops are followed.
    #[tokio::test]
    async fn spf_redirect_is_followed() {
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("brand.test", WireType::TXT) => txt("v=spf1 redirect=_spf.brand.test"),
            ("_spf.brand.test", WireType::TXT) => txt("v=spf1 redirect=_spf.esp.test"),
            ("_spf.esp.test", WireType::TXT) => txt("v=spf1 ip4:192.0.2.0/24 -all"),
            ("broken.test", WireType::TXT) => txt("v=spf1 redirect=_spf.nowhere.test"),
            _ => MockReply::NxDomain,
        })
        .await;
        let resolver = mock_dns_resolver_default(port);

        let posture = lookup_email_posture(&resolver, "brand.test", None)
            .await
            .unwrap();
        assert_eq!(
            posture.spf.verdict,
            PostureVerdict::Strict,
            "{:?}",
            posture.notes
        );
        assert_eq!(posture.spf.all_qualifier.as_deref(), Some("-"));
        assert!(posture.notes.iter().any(|n| n.contains("_spf.esp.test")));

        // A redirect to a name with no SPF record is a permerror.
        let posture = lookup_email_posture(&resolver, "broken.test", None)
            .await
            .unwrap();
        assert_eq!(posture.spf.verdict, PostureVerdict::Weak);
        assert!(
            posture.notes.iter().any(|n| n.contains("permerror")),
            "{:?}",
            posture.notes
        );
    }

    #[test]
    fn spf_lookup_terms_count_the_querying_mechanisms() {
        // include, a, mx, ptr, exists count (with any qualifier); ip4/all don't.
        let (count, targets) = spf_lookup_terms(
            "v=spf1 include:_spf.a.test ~include:_spf.b.test a a:x.test/24 MX:y.test \
             ptr exists:%{i}.z.test ip4:192.0.2.1 -all",
        );
        assert_eq!(count, 7);
        assert_eq!(targets, vec!["_spf.a.test", "_spf.b.test"]);
        // redirect= counts only when there is no `all`.
        assert_eq!(
            spf_lookup_terms("v=spf1 redirect=_spf.c.test"),
            (1, vec!["_spf.c.test".to_string()])
        );
        assert_eq!(spf_lookup_terms("v=spf1 redirect=_spf.c.test -all").0, 0);
    }

    #[test]
    fn spf_over_the_lookup_limit_is_a_permerror() {
        let record = strings(&["v=spf1 include:a.test -all"]);
        let at_limit = SpfFollowUp {
            redirect: None,
            lookups: MAX_SPF_LOOKUPS,
        };
        assert_eq!(
            build_spf(&record, &at_limit).policy.verdict,
            PostureVerdict::Strict
        );
        let over = SpfFollowUp {
            redirect: None,
            lookups: MAX_SPF_LOOKUPS + 1,
        };
        let spf = build_spf(&record, &over);
        assert_eq!(spf.policy.verdict, PostureVerdict::Weak);
        assert!(
            spf.notes.iter().any(|n| n.contains("§4.6.4")),
            "{:?}",
            spf.notes
        );
    }

    /// RFC 7208 §4.6.4: the 10-lookup limit counts through includes. A
    /// `-all` record whose includes need 11 lookups is a permerror, not
    /// Strict.
    #[tokio::test]
    async fn spf_lookups_are_counted_through_includes() {
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("heavy.test", WireType::TXT) => {
                txt("v=spf1 include:_a.heavy.test include:_b.heavy.test -all")
            }
            ("_a.heavy.test", WireType::TXT) => txt("v=spf1 a mx ptr exists:x.test a:y.test ~all"),
            ("_b.heavy.test", WireType::TXT) => txt("v=spf1 mx:m1.test mx:m2.test mx:m3.test ~all"),
            _ => MockReply::NxDomain,
        })
        .await;
        let resolver = mock_dns_resolver_default(port);

        // 2 includes + 5 terms in _a + 3 in _b = 10: at the limit, still valid.
        let posture = lookup_email_posture(&resolver, "heavy.test", None)
            .await
            .unwrap();
        assert_eq!(
            posture.spf.verdict,
            PostureVerdict::Strict,
            "{:?}",
            posture.notes
        );

        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("heavy.test", WireType::TXT) => {
                txt("v=spf1 include:_a.heavy.test include:_b.heavy.test a -all")
            }
            ("_a.heavy.test", WireType::TXT) => txt("v=spf1 a mx ptr exists:x.test a:y.test ~all"),
            ("_b.heavy.test", WireType::TXT) => txt("v=spf1 mx:m1.test mx:m2.test mx:m3.test ~all"),
            _ => MockReply::NxDomain,
        })
        .await;
        let posture = lookup_email_posture(&mock_dns_resolver_default(port), "heavy.test", None)
            .await
            .unwrap();
        assert_eq!(posture.spf.verdict, PostureVerdict::Weak);
        assert!(
            posture.notes.iter().any(|n| n.contains("§4.6.4")),
            "{:?}",
            posture.notes
        );
    }

    /// Regression: a SERVFAIL on `_dmarc` or the apex TXT read as "No
    /// DMARC/SPF — trivially spoofable". A failed lookup is Unknown.
    #[tokio::test]
    async fn failed_lookups_are_unknown_not_absent() {
        let port = spawn_mock_dns_fn(|_, _| MockReply::ServFail).await;
        let posture = lookup_email_posture(&mock_dns_resolver_default(port), "down.test", None)
            .await
            .unwrap();
        assert_eq!(posture.spf.verdict, PostureVerdict::Unknown);
        assert_eq!(posture.dmarc.verdict, PostureVerdict::Unknown);
        assert_eq!(posture.mta_sts.verdict, PostureVerdict::Unknown);
        assert_eq!(posture.bimi.verdict, PostureVerdict::Unknown);
        assert_eq!(posture.dane.verdict, PostureVerdict::Unknown);
        assert!(
            !posture.notes.iter().any(|n| n.contains("spoofable")
                || n.contains("No SPF")
                || n.contains("not configured")
                || n.contains("No DANE")),
            "{:?}",
            posture.notes
        );
        assert!(posture
            .notes
            .iter()
            .any(|n| n.contains("SPF lookup failed")));
        assert!(posture.notes.iter().any(|n| n.contains("DMARC lookup")));
    }

    /// RFC 7489 §3.2: the DMARC fallback stops at the Organizational Domain
    /// (the registrable domain), never querying `_dmarc.co.uk`.
    #[tokio::test]
    async fn dmarc_walk_stops_at_the_organizational_domain() {
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("_dmarc.co.uk", WireType::TXT) => txt("v=DMARC1; p=reject"),
            _ => MockReply::NxDomain,
        })
        .await;
        let posture =
            lookup_email_posture(&mock_dns_resolver_default(port), "mail.example.co.uk", None)
                .await
                .unwrap();
        assert_eq!(posture.dmarc.verdict, PostureVerdict::Absent);

        // The organizational domain itself is still the fallback.
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("_dmarc.example.co.uk", WireType::TXT) => txt("v=DMARC1; p=reject"),
            _ => MockReply::NxDomain,
        })
        .await;
        let posture = lookup_email_posture(
            &mock_dns_resolver_default(port),
            "a.mail.example.co.uk",
            None,
        )
        .await
        .unwrap();
        assert_eq!(posture.dmarc.verdict, PostureVerdict::Strict);
    }

    /// The caller's nameserver is used for every posture query (it used to
    /// hardcode the default upstream, ignoring `config.nameserver`).
    #[tokio::test]
    async fn posture_queries_the_given_nameserver() {
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("ns.test", WireType::TXT) => txt("v=spf1 -all"),
            ("_dmarc.ns.test", WireType::TXT) => txt("v=DMARC1; p=reject"),
            _ => MockReply::NxDomain,
        })
        .await;
        // No default-nameserver seam: only the explicit spec reaches the mock.
        let posture = lookup_email_posture(&mock_dns_resolver(port), "ns.test", Some("127.0.0.1"))
            .await
            .unwrap();
        assert_eq!(posture.spf.verdict, PostureVerdict::Strict);
        assert_eq!(posture.dmarc.verdict, PostureVerdict::Strict);
    }
}
