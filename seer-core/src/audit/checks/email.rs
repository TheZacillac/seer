//! Email anti-spoofing posture (SPF, DMARC, MX, MTA-STS, DANE, BIMI), one
//! check per mechanism so a failed lookup marks only that mechanism
//! incomplete. Reads `posture`'s structured fields (verdict, qualifiers,
//! `permerror`, `mx`), never its notes.

use futures::future::BoxFuture;

use super::{AuditContext, CheckOutput, CheckSpec};
use crate::audit::finding::{Category, Finding, Severity};
use crate::posture::{
    lookup_email_posture, DmarcPolicy, EmailPosture, MailExchangers, PostureVerdict, SpfPolicy,
};

const SPF: &str = "email.spf";
const DMARC: &str = "email.dmarc";
const MX: &str = "email.mx";
const MTA_STS: &str = "email.mta-sts";
const DANE: &str = "email.dane";
const BIMI: &str = "email.bimi";
const E: Category = Category::Email;

pub(crate) const SPEC: CheckSpec = CheckSpec {
    checks: &[
        (SPF, E),
        (DMARC, E),
        (MX, E),
        (MTA_STS, E),
        (DANE, E),
        (BIMI, E),
    ],
    run,
};

pub(crate) const IDS: &[&str] = &[
    "email.spf.missing",
    "email.spf.permissive",
    "email.spf.invalid",
    "email.dmarc.missing",
    "email.dmarc.policy-none",
    "email.dmarc.partial",
    "email.parked.spoofable",
    "email.mta-sts.missing",
    "email.dane.missing",
    "email.bimi.missing",
];

fn run<'a>(ctx: &'a AuditContext<'a>) -> BoxFuture<'a, CheckOutput> {
    Box::pin(async move {
        match lookup_email_posture(&ctx.auditor.dns, ctx.domain, None).await {
            Ok(posture) => assess(ctx.domain, &posture),
            Err(e) => {
                let mut out = CheckOutput::default();
                for &(check, category) in SPEC.checks {
                    out.failed(check, category, &e);
                }
                out
            }
        }
    })
}

/// The DMARC `p=` value, lowercased.
fn dmarc_policy(d: &DmarcPolicy) -> Option<String> {
    d.policy.as_deref().map(str::to_ascii_lowercase)
}

fn enforcing(d: &DmarcPolicy) -> bool {
    d.present && matches!(dmarc_policy(d).as_deref(), Some("reject" | "quarantine"))
}

/// Maps a posture report to per-mechanism runs and findings. Pure.
pub(crate) fn assess(domain: &str, p: &EmailPosture) -> CheckOutput {
    let mut out = CheckOutput::default();

    if p.spf.verdict == PostureVerdict::Unknown {
        out.incomplete(SPF, E, "SPF lookup failed");
    } else {
        out.ran(SPF, E, spf_findings(domain, &p.spf));
    }

    if p.dmarc.verdict == PostureVerdict::Unknown {
        out.incomplete(DMARC, E, "DMARC lookup failed");
    } else {
        out.ran(DMARC, E, dmarc_findings(domain, &p.dmarc));
    }

    let receives_mail = matches!(p.mx, MailExchangers::Hosts(_));
    match &p.mx {
        MailExchangers::Unknown => out.incomplete(MX, E, "MX lookup failed"),
        MailExchangers::Hosts(_) => out.ran(MX, E, Vec::new()),
        MailExchangers::Null | MailExchangers::Absent => {
            let locked = p.spf.all_qualifier.as_deref() == Some("-")
                && dmarc_policy(&p.dmarc).as_deref() == Some("reject");
            let unknown = p.spf.verdict == PostureVerdict::Unknown
                || p.dmarc.verdict == PostureVerdict::Unknown;
            if locked {
                out.ran(MX, E, Vec::new());
            } else if unknown {
                out.incomplete(MX, E, "SPF or DMARC lookup failed");
            } else {
                out.ran(
                    MX,
                    E,
                    vec![Finding::new(
                        "email.parked.spoofable",
                        E,
                        Severity::Medium,
                        domain,
                        "Domain sends no mail but can still be spoofed",
                    )
                    .fix("Publish `v=spf1 -all` and a DMARC `p=reject` record (and a null MX) for non-mail domains.")],
                );
            }
        }
    }

    // MTA-STS and DANE protect inbound mail: only meaningful with MX hosts.
    for (check, verdict, present, id, severity, title, fix) in [
        (
            MTA_STS,
            p.mta_sts.verdict,
            p.mta_sts.present,
            "email.mta-sts.missing",
            Severity::Low,
            "No MTA-STS policy",
            "Publish an MTA-STS policy so senders require TLS to your MX hosts.",
        ),
        (
            DANE,
            p.dane.verdict,
            p.dane
                .records
                .iter()
                .any(|r| r.scope.starts_with("_25._tcp")),
            "email.dane.missing",
            Severity::Info,
            "No DANE TLSA records at the MX hosts",
            "Publish TLSA records at _25._tcp.<mx-host> (needs DNSSEC).",
        ),
    ] {
        match &p.mx {
            MailExchangers::Unknown => out.incomplete(check, E, "MX lookup failed"),
            _ if !receives_mail => out.not_applicable(check, E, "domain receives no mail"),
            _ if verdict == PostureVerdict::Unknown => out.incomplete(check, E, "lookup failed"),
            _ if present => out.ran(check, E, Vec::new()),
            _ => out.ran(
                check,
                E,
                vec![Finding::new(id, E, severity, domain, title).fix(fix)],
            ),
        }
    }

    if !enforcing(&p.dmarc) {
        out.not_applicable(BIMI, E, "BIMI requires an enforcing DMARC policy");
    } else if p.bimi.verdict == PostureVerdict::Unknown {
        out.incomplete(BIMI, E, "BIMI lookup failed");
    } else if p.bimi.present {
        out.ran(BIMI, E, Vec::new());
    } else {
        out.ran(
            BIMI,
            E,
            vec![Finding::new(
                "email.bimi.missing",
                E,
                Severity::Info,
                domain,
                "No BIMI record",
            )
            .fix("Publish a BIMI record to show your logo in supporting inboxes.")],
        );
    }

    out
}

fn spf_findings(domain: &str, spf: &SpfPolicy) -> Vec<Finding> {
    if !spf.present {
        return vec![Finding::new(
            "email.spf.missing",
            E,
            Severity::High,
            domain,
            "No SPF record",
        )
        .fix("Publish an SPF record listing your senders and ending in -all.")];
    }
    if let Some(cause) = spf.permerror {
        return vec![Finding::new(
            "email.spf.invalid",
            E,
            Severity::Medium,
            domain,
            "SPF record is invalid (permerror)",
        )
        .evidence(cause.describe())
        .fix("Publish exactly one SPF record within the 10-lookup limit.")];
    }
    match spf.all_qualifier.as_deref() {
        Some("-" | "~") => Vec::new(),
        _ => {
            let mut f = Finding::new(
                "email.spf.permissive",
                E,
                Severity::High,
                domain,
                "SPF allows any sender",
            )
            .fix("End the SPF record in -all (or ~all while testing).");
            if let Some(record) = &spf.record {
                f = f.evidence(record.clone());
            }
            vec![f]
        }
    }
}

fn dmarc_findings(domain: &str, d: &DmarcPolicy) -> Vec<Finding> {
    if !d.present {
        return vec![Finding::new(
            "email.dmarc.missing",
            E,
            Severity::High,
            domain,
            "No DMARC record",
        )
        .fix("Publish _dmarc with p=none and rua= reporting, then move to quarantine or reject.")];
    }
    let with_record = |f: Finding| match &d.record {
        Some(r) => f.evidence(r.clone()),
        None => f,
    };
    if !enforcing(d) {
        return vec![with_record(
            Finding::new(
                "email.dmarc.policy-none",
                E,
                Severity::Medium,
                domain,
                "DMARC only monitors (p=none)",
            )
            .fix("Move the DMARC policy to quarantine, then reject."),
        )];
    }
    let partial_pct = d.percent.is_some_and(|pct| pct < 100);
    let weak_sp = d
        .subdomain_policy
        .as_deref()
        .is_some_and(|sp| sp.eq_ignore_ascii_case("none"));
    if partial_pct || weak_sp {
        return vec![with_record(
            Finding::new(
                "email.dmarc.partial",
                E,
                Severity::Low,
                domain,
                "DMARC enforcement is partial",
            )
            .fix("Use pct=100 and an enforcing sp= so every message and subdomain is covered."),
        )];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::finding::CheckStatus;
    use crate::posture::{BimiPolicy, DanePolicy, MtaStsPolicy, SpfPermerror, TlsaRecord};

    /// A fully hardened mail domain: no findings.
    fn hardened() -> EmailPosture {
        EmailPosture {
            domain: "example.com".into(),
            spf: SpfPolicy {
                present: true,
                record: Some("v=spf1 -all".into()),
                all_qualifier: Some("-".into()),
                verdict: PostureVerdict::Strict,
                permerror: None,
            },
            dmarc: DmarcPolicy {
                present: true,
                record: Some("v=DMARC1; p=reject".into()),
                policy: Some("reject".into()),
                subdomain_policy: None,
                aggregate_reports: vec![],
                percent: None,
                verdict: PostureVerdict::Strict,
            },
            mta_sts: MtaStsPolicy {
                present: true,
                record: Some("v=STSv1; id=1".into()),
                id: Some("1".into()),
                verdict: PostureVerdict::Present,
            },
            bimi: BimiPolicy {
                present: true,
                record: Some("v=BIMI1".into()),
                logo_url: None,
                authority_url: None,
                verdict: PostureVerdict::Present,
            },
            dane: DanePolicy {
                present: true,
                records: vec![TlsaRecord {
                    scope: "_25._tcp.mx.example.com".into(),
                    cert_usage: 3,
                    selector: 1,
                    matching: 1,
                    cert_data: "ab".into(),
                }],
                verdict: PostureVerdict::Present,
            },
            mx: MailExchangers::Hosts(vec!["mx.example.com".into()]),
            notes: vec![],
        }
    }

    fn ids(out: &CheckOutput) -> Vec<&'static str> {
        out.findings.iter().map(|f| f.id).collect()
    }

    #[test]
    fn hardened_domain_is_clean_and_every_check_ran() {
        let out = assess("example.com", &hardened());
        assert!(out.findings.is_empty(), "{:?}", out.findings);
        assert_eq!(out.runs.len(), 6);
        assert!(out.runs.iter().all(|r| r.status == CheckStatus::Ran));
    }

    #[test]
    fn missing_spf_and_dmarc_are_high() {
        let mut p = hardened();
        p.spf.present = false;
        p.spf.verdict = PostureVerdict::Absent;
        p.spf.all_qualifier = None;
        p.dmarc.present = false;
        p.dmarc.policy = None;
        p.dmarc.verdict = PostureVerdict::Absent;
        let out = assess("example.com", &p);
        let ids = ids(&out);
        assert!(ids.contains(&"email.spf.missing"));
        assert!(ids.contains(&"email.dmarc.missing"));
        assert!(
            out.findings.iter().all(|f| f.severity == Severity::High),
            "{:?}",
            out.findings
        );
    }

    #[test]
    fn permissive_and_permerror_spf() {
        let mut p = hardened();
        p.spf.all_qualifier = Some("+".into());
        p.spf.verdict = PostureVerdict::Weak;
        assert_eq!(
            ids(&assess("example.com", &p)),
            vec!["email.spf.permissive"]
        );

        let mut p = hardened();
        p.spf.permerror = Some(SpfPermerror::MultipleRecords);
        p.spf.all_qualifier = None;
        assert_eq!(ids(&assess("example.com", &p)), vec!["email.spf.invalid"]);
    }

    #[test]
    fn dmarc_none_and_partial() {
        let mut p = hardened();
        p.dmarc.policy = Some("none".into());
        p.dmarc.verdict = PostureVerdict::Weak;
        // BIMI needs an enforcing DMARC: not applicable now, so no BIMI finding.
        assert_eq!(
            ids(&assess("example.com", &p)),
            vec!["email.dmarc.policy-none"]
        );

        let mut p = hardened();
        p.dmarc.percent = Some(50);
        assert_eq!(ids(&assess("example.com", &p)), vec!["email.dmarc.partial"]);
    }

    #[test]
    fn a_failed_mechanism_is_incomplete_not_a_finding() {
        let mut p = hardened();
        p.dmarc.present = false;
        p.dmarc.verdict = PostureVerdict::Unknown;
        let out = assess("example.com", &p);
        assert!(!ids(&out).contains(&"email.dmarc.missing"));
        assert!(out.runs.iter().any(
            |r| r.check == "email.dmarc" && matches!(r.status, CheckStatus::Incomplete { .. })
        ));
    }

    #[test]
    fn a_parked_domain_must_lock_down_spf_and_dmarc() {
        let mut p = hardened();
        p.mx = MailExchangers::Absent;
        p.spf.all_qualifier = Some("~".into());
        let out = assess("example.com", &p);
        assert_eq!(ids(&out), vec!["email.parked.spoofable"]);
        // MTA-STS and DANE do not apply without mail.
        assert!(out
            .runs
            .iter()
            .any(|r| r.check == "email.mta-sts"
                && matches!(r.status, CheckStatus::NotApplicable { .. })));

        let mut p = hardened();
        p.mx = MailExchangers::Null;
        assert!(ids(&assess("example.com", &p)).is_empty());
    }

    #[test]
    fn mail_hardening_gaps_are_low_or_info() {
        let mut p = hardened();
        p.mta_sts.present = false;
        p.mta_sts.verdict = PostureVerdict::Absent;
        p.dane.present = false;
        p.dane.records.clear();
        p.dane.verdict = PostureVerdict::Absent;
        p.bimi.present = false;
        p.bimi.verdict = PostureVerdict::Absent;
        let out = assess("example.com", &p);
        assert_eq!(
            ids(&out),
            vec![
                "email.mta-sts.missing",
                "email.dane.missing",
                "email.bimi.missing"
            ]
        );
        assert!(out.findings.iter().all(|f| IDS.contains(&f.id)));
    }
}
