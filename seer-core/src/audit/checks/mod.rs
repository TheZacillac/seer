//! The adapter table: every check the audit runs, and how they run.
//!
//! Each adapter module owns one or more checks, a pure `assess`-style
//! function mapping its source report to [`Finding`]s, an async runner, its
//! [`CheckSpec`] row and its `IDS` list. [`CHECKS`] is the one table of
//! adapters — add a row here, never a second list. [`run_specs`] runs every
//! spec concurrently under one deadline; a spec still running at the
//! deadline has each of its checks recorded as incomplete.

mod dkim;
mod email;
mod registration;
mod web;

use std::time::Duration;

use futures::future::BoxFuture;

use super::finding::{Category, CheckRun, CheckStatus, Finding};
use super::Auditor;
use crate::error::SeerError;

/// What an adapter runs against.
pub(crate) struct AuditContext<'a> {
    pub auditor: &'a Auditor,
    /// `normalize_domain` form (registration, email, DNS checks).
    pub domain: &'a str,
    /// `normalize_host` form (web, TLS checks).
    pub host: &'a str,
}

/// Runs and findings produced by one adapter.
#[derive(Debug, Default)]
pub(crate) struct CheckOutput {
    pub runs: Vec<CheckRun>,
    pub findings: Vec<Finding>,
}

impl CheckOutput {
    /// Records a completed check and its findings.
    pub fn ran(&mut self, check: &'static str, category: Category, findings: Vec<Finding>) {
        self.runs.push(CheckRun {
            check,
            category,
            status: CheckStatus::Ran,
        });
        self.findings.extend(findings);
    }

    /// Records a check that could not finish: unknown, never a finding.
    pub fn incomplete(
        &mut self,
        check: &'static str,
        category: Category,
        reason: impl Into<String>,
    ) {
        self.runs.push(CheckRun {
            check,
            category,
            status: CheckStatus::Incomplete {
                reason: reason.into(),
            },
        });
    }

    /// Records a check that does not apply to this domain.
    pub fn not_applicable(
        &mut self,
        check: &'static str,
        category: Category,
        reason: impl Into<String>,
    ) {
        self.runs.push(CheckRun {
            check,
            category,
            status: CheckStatus::NotApplicable {
                reason: reason.into(),
            },
        });
    }

    /// A source error: incomplete with the sanitized message; full detail
    /// goes to the log only.
    pub fn failed(&mut self, check: &'static str, category: Category, error: &SeerError) {
        tracing::debug!(check, error = %error, "audit check failed");
        self.incomplete(check, category, error.sanitized_message());
    }
}

/// An adapter's async entry point.
pub(crate) type Runner = for<'a> fn(&'a AuditContext<'a>) -> BoxFuture<'a, CheckOutput>;

/// One row of [`CHECKS`]: the checks a runner owns (so they can be marked
/// incomplete if it misses the deadline) and the runner.
pub(crate) struct CheckSpec {
    pub checks: &'static [(&'static str, Category)],
    pub run: Runner,
}

/// Every adapter the audit runs.
pub(crate) static CHECKS: &[CheckSpec] = &[
    registration::SPEC,
    email::SPEC,
    dkim::SPEC,
    web::HEADERS,
    web::UPGRADE,
    web::SECURITY_TXT,
];

/// Every finding id any adapter can emit.
pub(crate) fn all_ids() -> Vec<&'static str> {
    let lists: &[&[&str]] = &[registration::IDS, email::IDS, dkim::IDS, web::IDS];
    lists.iter().flat_map(|ids| ids.iter().copied()).collect()
}

/// Runs `specs` concurrently, all bounded by one `deadline`.
pub(crate) async fn run_specs(
    specs: &[CheckSpec],
    ctx: &AuditContext<'_>,
    deadline: Duration,
) -> CheckOutput {
    let until = tokio::time::Instant::now() + deadline;
    let outputs = futures::future::join_all(specs.iter().map(|spec| async move {
        match tokio::time::timeout_at(until, (spec.run)(ctx)).await {
            Ok(output) => output,
            Err(_) => {
                let mut output = CheckOutput::default();
                for &(check, category) in spec.checks {
                    output.incomplete(check, category, "deadline exceeded");
                }
                output
            }
        }
    }))
    .await;
    let mut all = CheckOutput::default();
    for output in outputs {
        all.runs.extend(output.runs);
        all.findings.extend(output.findings);
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instant<'a>(_: &'a AuditContext<'a>) -> BoxFuture<'a, CheckOutput> {
        Box::pin(async {
            let mut out = CheckOutput::default();
            out.ran("fast", Category::Dns, Vec::new());
            out
        })
    }

    fn never<'a>(_: &'a AuditContext<'a>) -> BoxFuture<'a, CheckOutput> {
        Box::pin(futures::future::pending())
    }

    const SPECS: &[CheckSpec] = &[
        CheckSpec {
            checks: &[("fast", Category::Dns)],
            run: instant,
        },
        CheckSpec {
            checks: &[("slow.a", Category::Web), ("slow.b", Category::Web)],
            run: never,
        },
    ];

    #[tokio::test]
    async fn a_hanging_check_is_incomplete_and_the_rest_still_report() {
        let auditor = Auditor::new();
        let ctx = AuditContext {
            auditor: &auditor,
            domain: "example.com",
            host: "example.com",
        };
        let out = run_specs(SPECS, &ctx, Duration::from_millis(50)).await;
        assert_eq!(out.runs.len(), 3);
        assert_eq!(out.runs[0].status, CheckStatus::Ran);
        for run in &out.runs[1..] {
            assert_eq!(
                run.status,
                CheckStatus::Incomplete {
                    reason: "deadline exceeded".into()
                }
            );
        }
    }

    #[test]
    fn ids_are_unique_and_well_formed() {
        let ids = all_ids();
        let mut seen = std::collections::HashSet::new();
        for id in &ids {
            assert!(seen.insert(*id), "duplicate id {id}");
            let parts: Vec<&str> = id.split('.').collect();
            assert_eq!(
                parts.len(),
                3,
                "{id} must be <category>.<check>.<condition>"
            );
            assert!(
                Category::ALL.iter().any(|c| c.as_str() == parts[0]),
                "{id}: unknown category"
            );
            assert!(
                parts[1..].iter().all(|p| !p.is_empty()
                    && p.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')),
                "{id}: not kebab-case"
            );
        }
    }
}
