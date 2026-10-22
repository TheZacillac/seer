//! Subdomain takeover for the apex and `www` (wider discovery is the estate
//! phase). An HTTP-confirmed unclaimed-resource page is Critical; a dangling
//! CNAME that nothing answers for is High. Inconclusive hosts are unknown.

use futures::future::BoxFuture;

use super::{AuditContext, CheckOutput, CheckSpec};
use crate::audit::finding::{Category, Finding, Severity};
use crate::takeover::{scan_takeover, TakeoverReport, TakeoverVerdict};

const K: Category = Category::Takeover;
const CHECK: &str = "takeover";

pub(crate) const SPEC: CheckSpec = CheckSpec {
    checks: &[(CHECK, K)],
    run,
};

#[cfg(test)]
pub(crate) const IDS: &[&str] = &["takeover.cname.vulnerable", "takeover.cname.dangling"];

fn run<'a>(ctx: &'a AuditContext<'a>) -> BoxFuture<'a, CheckOutput> {
    Box::pin(async move {
        let hosts = vec![ctx.domain.to_string(), format!("www.{}", ctx.domain)];
        match scan_takeover(
            &ctx.auditor.dns,
            ctx.domain,
            hosts,
            2,
            ctx.auditor.http_timeout,
        )
        .await
        {
            Ok(report) => assess(&report),
            Err(e) => {
                let mut out = CheckOutput::default();
                out.failed(CHECK, K, &e);
                out
            }
        }
    })
}

/// Maps a takeover report to one run and per-host findings. Pure.
pub(crate) fn assess(r: &TakeoverReport) -> CheckOutput {
    let mut out = CheckOutput::default();
    let findings: Vec<Finding> = r
        .findings
        .iter()
        .filter_map(|f| {
            let evidence = [
                f.provider.as_deref(),
                f.cname.as_deref(),
                f.evidence.as_deref(),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" · ");
            let finding = match f.verdict {
                TakeoverVerdict::Vulnerable => Finding::new(
                    "takeover.cname.vulnerable",
                    K,
                    Severity::Critical,
                    &f.host,
                    "Subdomain can be taken over",
                )
                .fix("Remove the CNAME or reclaim the resource at the provider now."),
                TakeoverVerdict::Potential => Finding::new(
                    "takeover.cname.dangling",
                    K,
                    Severity::High,
                    &f.host,
                    "Dangling CNAME to a takeover-prone provider",
                )
                .fix("Remove the CNAME if the resource is gone."),
                TakeoverVerdict::Inconclusive | TakeoverVerdict::Safe => return None,
            };
            Some(if evidence.is_empty() {
                finding
            } else {
                finding.evidence(evidence)
            })
        })
        .collect();
    if findings.is_empty() && r.inconclusive > 0 {
        out.incomplete(CHECK, K, "provider CNAME could not be checked");
    } else {
        out.ran(CHECK, K, findings);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::finding::CheckStatus;
    use crate::takeover::{TakeoverFinding, TakeoverVerdict};

    fn finding(host: &str, verdict: TakeoverVerdict) -> TakeoverFinding {
        TakeoverFinding {
            host: host.into(),
            verdict,
            provider: Some("GitHub Pages".into()),
            cname: Some("x.github.io".into()),
            addresses: vec![],
            evidence: None,
            http_status: None,
            probe_note: None,
        }
    }
    fn report(findings: Vec<TakeoverFinding>) -> TakeoverReport {
        let count = |v| findings.iter().filter(|f| f.verdict == v).count();
        TakeoverReport {
            domain: "example.com".into(),
            hosts_checked: 2,
            hosts_skipped: 0,
            vulnerable: count(TakeoverVerdict::Vulnerable),
            potential: count(TakeoverVerdict::Potential),
            inconclusive: count(TakeoverVerdict::Inconclusive),
            findings,
            notes: vec![],
        }
    }

    #[test]
    fn verdicts_map_to_severities_per_host() {
        let out = assess(&report(vec![
            finding("www.example.com", TakeoverVerdict::Vulnerable),
            finding("example.com", TakeoverVerdict::Potential),
        ]));
        let got: Vec<(&str, Severity, &str)> = out
            .findings
            .iter()
            .map(|f| (f.id, f.severity, f.host.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                (
                    "takeover.cname.vulnerable",
                    Severity::Critical,
                    "www.example.com"
                ),
                ("takeover.cname.dangling", Severity::High, "example.com"),
            ]
        );
    }

    #[test]
    fn clean_is_ran_and_inconclusive_only_is_incomplete() {
        assert_eq!(assess(&report(vec![])).runs[0].status, CheckStatus::Ran);
        let out = assess(&report(vec![finding(
            "www.example.com",
            TakeoverVerdict::Inconclusive,
        )]));
        assert!(out.findings.is_empty());
        assert!(matches!(out.runs[0].status, CheckStatus::Incomplete { .. }));
    }
}
