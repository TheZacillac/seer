//! DKIM key strength from selector probing. Probing cannot prove absence,
//! so "no selector found" is Info only; when some selectors could not be
//! queried and none was found, the check is incomplete.

use std::collections::BTreeMap;

use futures::future::BoxFuture;

use super::{AuditContext, CheckOutput, CheckSpec};
use crate::audit::finding::{Category, Finding, Severity};
use crate::dkim::{probe_dkim, DkimKeyType, DkimReport, SelectorState, DEFAULT_DKIM_DEADLINE};

const CHECK: &str = "email.dkim";
const E: Category = Category::Email;

pub(crate) const SPEC: CheckSpec = CheckSpec {
    checks: &[(CHECK, E)],
    run,
};

pub(crate) const IDS: &[&str] = &[
    "email.dkim.weak-key",
    "email.dkim.1024-key",
    "email.dkim.testing",
    "email.dkim.none-found",
];

fn run<'a>(ctx: &'a AuditContext<'a>) -> BoxFuture<'a, CheckOutput> {
    Box::pin(async move {
        match probe_dkim(&ctx.auditor.dns, ctx.domain, DEFAULT_DKIM_DEADLINE).await {
            Ok(report) => assess(ctx.domain, &report),
            Err(e) => {
                let mut out = CheckOutput::default();
                out.failed(CHECK, E, &e);
                out
            }
        }
    })
}

/// Maps a probe report to one run and its findings (one per id, naming the
/// selectors it covers). Pure.
pub(crate) fn assess(domain: &str, r: &DkimReport) -> CheckOutput {
    let mut out = CheckOutput::default();
    let found = r
        .selectors
        .iter()
        .any(|s| matches!(s.state, SelectorState::Key { .. } | SelectorState::Revoked));
    if !found {
        let unknown = r
            .selectors
            .iter()
            .filter(|s| matches!(s.state, SelectorState::Unknown { .. }))
            .count();
        if unknown > 0 {
            out.incomplete(
                CHECK,
                E,
                format!("{unknown} selector(s) could not be queried"),
            );
        } else {
            out.ran(
                CHECK,
                E,
                vec![Finding::new(
                    "email.dkim.none-found",
                    E,
                    Severity::Info,
                    domain,
                    "No DKIM key found at common selectors",
                )
                .evidence(format!("probed {} common selectors", r.probed))
                .fix("Confirm your mail is DKIM-signed; a custom selector cannot be discovered from DNS.")],
            );
        }
        return out;
    }

    let mut by_id: BTreeMap<(Severity, &'static str), Vec<&str>> = BTreeMap::new();
    for s in &r.selectors {
        if let SelectorState::Key {
            key_type,
            bits,
            testing,
        } = &s.state
        {
            if *key_type == DkimKeyType::Rsa {
                match bits {
                    Some(b) if *b < 1024 => by_id
                        .entry((Severity::High, "email.dkim.weak-key"))
                        .or_default()
                        .push(&s.selector),
                    Some(1024) => by_id
                        .entry((Severity::Medium, "email.dkim.1024-key"))
                        .or_default()
                        .push(&s.selector),
                    _ => {}
                }
            }
            if *testing {
                by_id
                    .entry((Severity::Low, "email.dkim.testing"))
                    .or_default()
                    .push(&s.selector);
            }
        }
    }
    let findings = by_id
        .into_iter()
        .rev() // highest severity first
        .map(|((severity, id), selectors)| {
            let (title, fix) = match id {
                "email.dkim.weak-key" => (
                    "DKIM key shorter than 1024 bits",
                    "Rotate to a 2048-bit RSA (or Ed25519) key.",
                ),
                "email.dkim.1024-key" => (
                    "DKIM key is 1024-bit RSA",
                    "Rotate to a 2048-bit RSA key.",
                ),
                _ => (
                    "DKIM key in test mode (t=y)",
                    "Remove t=y once signing is verified.",
                ),
            };
            Finding::new(id, E, severity, domain, title)
                .evidence(selectors.join(", "))
                .fix(fix)
        })
        .collect();
    out.ran(CHECK, E, findings);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::finding::CheckStatus;
    use crate::dkim::DkimSelector;

    fn report(selectors: Vec<(&str, SelectorState)>) -> DkimReport {
        DkimReport {
            domain: "example.com".into(),
            probed: 19,
            selectors: selectors
                .into_iter()
                .map(|(s, state)| DkimSelector {
                    selector: s.into(),
                    state,
                })
                .collect(),
        }
    }
    fn rsa(bits: u32, testing: bool) -> SelectorState {
        SelectorState::Key {
            key_type: DkimKeyType::Rsa,
            bits: Some(bits),
            testing,
        }
    }

    #[test]
    fn strong_key_is_clean() {
        let out = assess("example.com", &report(vec![("google", rsa(2048, false))]));
        assert!(out.findings.is_empty());
        assert_eq!(out.runs[0].status, CheckStatus::Ran);
    }

    #[test]
    fn key_sizes_and_testing_flag() {
        let out = assess(
            "example.com",
            &report(vec![
                ("a", rsa(512, false)),
                ("b", rsa(1024, false)),
                ("c", rsa(1024, false)),
                ("d", rsa(2048, true)),
            ]),
        );
        let found: Vec<(&str, Severity)> =
            out.findings.iter().map(|f| (f.id, f.severity)).collect();
        assert_eq!(
            found,
            vec![
                ("email.dkim.weak-key", Severity::High),
                ("email.dkim.1024-key", Severity::Medium),
                ("email.dkim.testing", Severity::Low),
            ]
        );
        // Two 1024-bit selectors merge into one finding naming both.
        let merged = out
            .findings
            .iter()
            .find(|f| f.id == "email.dkim.1024-key")
            .unwrap();
        assert_eq!(merged.evidence.as_deref(), Some("b, c"));
    }

    #[test]
    fn nothing_found_is_info_and_unknowns_make_it_incomplete() {
        let out = assess("example.com", &report(vec![]));
        assert_eq!(out.findings[0].id, "email.dkim.none-found");
        assert_eq!(out.findings[0].severity, Severity::Info);

        let out = assess(
            "example.com",
            &report(vec![(
                "k1",
                SelectorState::Unknown {
                    reason: "DNS resolution failed".into(),
                },
            )]),
        );
        assert!(out.findings.is_empty());
        assert!(matches!(out.runs[0].status, CheckStatus::Incomplete { .. }));
    }

    #[test]
    fn a_revoked_key_counts_as_found() {
        let out = assess(
            "example.com",
            &report(vec![("old", SelectorState::Revoked)]),
        );
        assert!(out.findings.is_empty());
    }
}
