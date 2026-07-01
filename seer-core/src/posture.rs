//! Email / DNS security-posture inspection.
//!
//! Resolves and interprets the DNS-published mail-security policies for a
//! domain — SPF, DMARC, MTA-STS, BIMI, and DANE (TLSA) — and returns a
//! per-mechanism verdict with advisory notes. A lax or absent DMARC policy is
//! the single strongest signal that a domain is spoofable, which directly feeds
//! phishing-risk assessment.
//!
//! This mirrors [`crate::caa`]'s tree-walk-plus-advisory shape and reuses the
//! [`DnsResolver`] TXT/TLSA path — no new network protocol. All parsing is
//! pure and unit-tested; only the record fetch is async.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::dns::{DnsResolver, RecordData, RecordType};
use crate::error::Result;
use crate::validation::normalize_domain;

/// A coarse enforcement verdict for one posture mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PostureVerdict {
    /// The mechanism is not configured at all.
    Absent,
    /// Configured, but permissive / monitoring-only (offers little protection).
    Weak,
    /// Configured with partial enforcement.
    Moderate,
    /// Configured with full enforcement.
    Strict,
    /// Configured; the mechanism has no weak/strict axis (presence is the signal).
    Present,
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
    /// The owner scope, e.g. `_25._tcp` (SMTP) or `_443._tcp` (HTTPS).
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

// --- Pure parsers -------------------------------------------------------

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

/// Maps a DMARC `p=` policy to a verdict.
fn dmarc_verdict(policy: Option<&str>) -> PostureVerdict {
    match policy.map(|p| p.to_ascii_lowercase()) {
        Some(ref p) if p == "reject" => PostureVerdict::Strict,
        Some(ref p) if p == "quarantine" => PostureVerdict::Moderate,
        Some(ref p) if p == "none" => PostureVerdict::Weak,
        _ => PostureVerdict::Weak,
    }
}

/// Case-insensitively finds the first TXT record whose text begins with
/// `version_prefix` (e.g. `v=spf1`, `v=DMARC1`).
fn find_txt_with_prefix<'a>(records: &'a [String], version_prefix: &str) -> Option<&'a String> {
    let prefix = version_prefix.to_ascii_lowercase();
    records
        .iter()
        .find(|t| t.trim().to_ascii_lowercase().starts_with(&prefix))
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

fn build_spf(apex_txt: &[String]) -> SpfPolicy {
    match find_txt_with_prefix(apex_txt, "v=spf1") {
        Some(record) => {
            let all_qualifier = parse_spf_all_qualifier(record);
            SpfPolicy {
                present: true,
                verdict: spf_verdict(all_qualifier.as_deref()),
                all_qualifier,
                record: Some(record.clone()),
            }
        }
        None => SpfPolicy {
            present: false,
            record: None,
            all_qualifier: None,
            verdict: PostureVerdict::Absent,
        },
    }
}

fn build_dmarc(dmarc_txt: &[String]) -> DmarcPolicy {
    match find_txt_with_prefix(dmarc_txt, "v=dmarc1") {
        Some(record) => {
            let tags = parse_tag_value(record);
            let policy = tags.get("p").cloned();
            let aggregate_reports = tags
                .get("rua")
                .map(|rua| {
                    rua.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            DmarcPolicy {
                present: true,
                verdict: dmarc_verdict(policy.as_deref()),
                subdomain_policy: tags.get("sp").cloned(),
                percent: tags.get("pct").and_then(|p| p.parse().ok()),
                aggregate_reports,
                policy,
                record: Some(record.clone()),
            }
        }
        None => DmarcPolicy {
            present: false,
            record: None,
            policy: None,
            subdomain_policy: None,
            aggregate_reports: Vec::new(),
            percent: None,
            verdict: PostureVerdict::Absent,
        },
    }
}

fn build_mta_sts(txt: &[String]) -> MtaStsPolicy {
    match find_txt_with_prefix(txt, "v=stsv1") {
        Some(record) => {
            let tags = parse_tag_value(record);
            MtaStsPolicy {
                present: true,
                id: tags.get("id").cloned(),
                record: Some(record.clone()),
                verdict: PostureVerdict::Present,
            }
        }
        None => MtaStsPolicy {
            present: false,
            record: None,
            id: None,
            verdict: PostureVerdict::Absent,
        },
    }
}

fn build_bimi(txt: &[String]) -> BimiPolicy {
    match find_txt_with_prefix(txt, "v=bimi1") {
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
        None => BimiPolicy {
            present: false,
            record: None,
            logo_url: None,
            authority_url: None,
            verdict: PostureVerdict::Absent,
        },
    }
}

fn build_dane(smtp: &[crate::dns::DnsRecord], https: &[crate::dns::DnsRecord]) -> DanePolicy {
    let mut records = Vec::new();
    let mut collect = |set: &[crate::dns::DnsRecord], scope: &str| {
        for r in set {
            if let RecordData::TLSA {
                cert_usage,
                selector,
                matching,
                cert_data,
            } = &r.data
            {
                records.push(TlsaRecord {
                    scope: scope.to_string(),
                    cert_usage: *cert_usage,
                    selector: *selector,
                    matching: *matching,
                    cert_data: cert_data.clone(),
                });
            }
        }
    };
    collect(smtp, "_25._tcp");
    collect(https, "_443._tcp");
    DanePolicy {
        present: !records.is_empty(),
        verdict: if records.is_empty() {
            PostureVerdict::Absent
        } else {
            PostureVerdict::Present
        },
        records,
    }
}

/// Builds the advisory notes from the assembled per-mechanism policies.
fn build_notes(
    spf: &SpfPolicy,
    dmarc: &DmarcPolicy,
    mta_sts: &MtaStsPolicy,
    dane: &DanePolicy,
) -> Vec<String> {
    let mut notes = Vec::new();

    match dmarc.verdict {
        PostureVerdict::Absent => notes
            .push("No DMARC record — the domain is trivially spoofable in phishing.".to_string()),
        PostureVerdict::Weak => notes.push(
            "DMARC policy is p=none (monitoring only) — receivers will not reject spoofed mail."
                .to_string(),
        ),
        PostureVerdict::Moderate => notes.push(
            "DMARC policy is p=quarantine — spoofed mail is filtered but not rejected.".to_string(),
        ),
        _ => {}
    }

    match spf.verdict {
        PostureVerdict::Absent => {
            notes.push("No SPF record — sending sources are undeclared.".to_string());
        }
        PostureVerdict::Weak => notes.push(
            "SPF does not end in -all/~all — it permits unlisted senders (spoofable).".to_string(),
        ),
        PostureVerdict::Moderate => {
            notes.push("SPF uses ~all (softfail); -all provides stricter enforcement.".to_string())
        }
        _ => {}
    }

    if !mta_sts.present {
        notes.push("MTA-STS is not configured — SMTP is vulnerable to downgrade.".to_string());
    }
    if !dane.present {
        notes.push("No DANE (TLSA) records — no DNS-based TLS pinning for mail/HTTPS.".to_string());
    }

    notes
}

/// Resolves and interprets the email/DNS security posture for `domain`.
///
/// Each mechanism degrades independently: a resolver error for one record set
/// simply yields that mechanism's `Absent`/empty state rather than failing the
/// whole report. Returns an error only if the domain itself is invalid.
pub async fn lookup_email_posture(resolver: &DnsResolver, domain: &str) -> Result<EmailPosture> {
    let domain = normalize_domain(domain)?;

    let dmarc_name = format!("_dmarc.{domain}");
    let mta_sts_name = format!("_mta-sts.{domain}");
    let bimi_name = format!("default._bimi.{domain}");
    let smtp_tlsa_name = format!("_25._tcp.{domain}");
    let https_tlsa_name = format!("_443._tcp.{domain}");

    // Resolve every record set concurrently. Futures are boxed so the combined
    // `join!` frame stays small (avoids the large-future debug stack pressure
    // seen in diff.rs). Each resolve error degrades to an empty record set.
    let (apex, dmarc, mta_sts, bimi, smtp_tlsa, https_tlsa) = tokio::join!(
        Box::pin(resolver.resolve(&domain, RecordType::TXT, None)),
        Box::pin(resolver.resolve(&dmarc_name, RecordType::TXT, None)),
        Box::pin(resolver.resolve(&mta_sts_name, RecordType::TXT, None)),
        Box::pin(resolver.resolve(&bimi_name, RecordType::TXT, None)),
        Box::pin(resolver.resolve(&smtp_tlsa_name, RecordType::TLSA, None)),
        Box::pin(resolver.resolve(&https_tlsa_name, RecordType::TLSA, None)),
    );

    let apex = apex.unwrap_or_default();
    let dmarc = dmarc.unwrap_or_default();
    let mta_sts = mta_sts.unwrap_or_default();
    let bimi = bimi.unwrap_or_default();
    let smtp_tlsa = smtp_tlsa.unwrap_or_default();
    let https_tlsa = https_tlsa.unwrap_or_default();

    let spf = build_spf(&txt_strings(&apex));
    let dmarc = build_dmarc(&txt_strings(&dmarc));
    let mta_sts = build_mta_sts(&txt_strings(&mta_sts));
    let bimi = build_bimi(&txt_strings(&bimi));
    let dane = build_dane(&smtp_tlsa, &https_tlsa);
    let notes = build_notes(&spf, &dmarc, &mta_sts, &dane);

    Ok(EmailPosture {
        domain,
        spf,
        dmarc,
        mta_sts,
        bimi,
        dane,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn dmarc_parsing_and_verdict() {
        let record =
            "v=DMARC1; p=reject; sp=quarantine; rua=mailto:a@x.com,mailto:b@x.com; pct=100";
        let dmarc = build_dmarc(&[record.to_string()]);
        assert!(dmarc.present);
        assert_eq!(dmarc.policy.as_deref(), Some("reject"));
        assert_eq!(dmarc.subdomain_policy.as_deref(), Some("quarantine"));
        assert_eq!(dmarc.percent, Some(100));
        assert_eq!(dmarc.aggregate_reports.len(), 2);
        assert_eq!(dmarc.verdict, PostureVerdict::Strict);
    }

    #[test]
    fn dmarc_none_is_weak_and_absent_is_absent() {
        let weak = build_dmarc(&["v=DMARC1; p=none".to_string()]);
        assert_eq!(weak.verdict, PostureVerdict::Weak);
        let absent = build_dmarc(&["v=spf1 -all".to_string()]);
        assert!(!absent.present);
        assert_eq!(absent.verdict, PostureVerdict::Absent);
    }

    #[test]
    fn spf_prefers_the_spf_record_among_txt() {
        // The apex TXT set carries a verification token AND the SPF record.
        let txts = vec![
            "google-site-verification=abc123".to_string(),
            "v=spf1 include:_spf.google.com -all".to_string(),
        ];
        let spf = build_spf(&txts);
        assert!(spf.present);
        assert_eq!(spf.all_qualifier.as_deref(), Some("-"));
        assert_eq!(spf.verdict, PostureVerdict::Strict);
    }

    #[test]
    fn bimi_and_mta_sts_parse_tags() {
        let bimi =
            build_bimi(&["v=BIMI1; l=https://x.com/logo.svg; a=https://x.com/vmc.pem".into()]);
        assert!(bimi.present);
        assert_eq!(bimi.logo_url.as_deref(), Some("https://x.com/logo.svg"));
        assert_eq!(bimi.authority_url.as_deref(), Some("https://x.com/vmc.pem"));

        let mta = build_mta_sts(&["v=STSv1; id=20240101T000000".into()]);
        assert!(mta.present);
        assert_eq!(mta.id.as_deref(), Some("20240101T000000"));
        assert_eq!(mta.verdict, PostureVerdict::Present);
    }

    #[test]
    fn notes_flag_a_spoofable_domain() {
        // No DMARC, no SPF, no MTA-STS, no DANE → several advisory notes.
        let spf = build_spf(&[]);
        let dmarc = build_dmarc(&[]);
        let mta = build_mta_sts(&[]);
        let dane = build_dane(&[], &[]);
        let notes = build_notes(&spf, &dmarc, &mta, &dane);
        assert!(notes.iter().any(|n| n.contains("No DMARC")));
        assert!(notes.iter().any(|n| n.contains("No SPF")));
        assert!(notes.iter().any(|n| n.contains("MTA-STS")));
        assert!(notes.iter().any(|n| n.contains("DANE")));
    }
}
