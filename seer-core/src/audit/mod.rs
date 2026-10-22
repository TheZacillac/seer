//! Graded, multi-layer security assessment of one domain (`seer audit`).
//!
//! Seer's single-purpose checks (email posture, HTTP headers, TLS, DNSSEC,
//! delegation, takeover, registration, plus DKIM, security.txt and the
//! HTTP→HTTPS upgrade) each report in their own shape. This module runs them
//! together and normalises their results into [`Finding`]s — one model the
//! later phases (profiling, estate, impersonator hunting) build on.
//!
//! - [`finding`] — the model. Ids are a stable contract.
//! - [`score`] — category grades, overall grade, severity caps, pass gate.
//! - `checks` — the adapter table; every adapter maps its source's typed
//!   report through a pure function, reading structured fields only.
//!
//! Unknown is never a fail: a source error marks its check incomplete and
//! produces no finding. [`Auditor::audit`] errors only for invalid input.
//! Every check runs concurrently under one deadline
//! ([`crate::config::SeerConfig::audit_timeout`]). Retry, SSRF and IPv4-first
//! rules are the sources' own, unchanged.

pub(crate) mod checks;
pub mod finding;
pub mod score;

use std::time::Duration;

use serde::Serialize;

pub use finding::{Category, CheckRun, CheckStatus, Finding, Severity};
pub use score::{CategoryGrade, CategoryState, OverallGrade};

use crate::config::SeerConfig;
use crate::dns::{DelegationChecker, DnsResolver, DnssecChecker};
use crate::error::Result;
use crate::grade::Letter;
use crate::http::GuardedFetcher;
use crate::lookup::SmartLookup;
use crate::ssl::SslChecker;
use crate::validation::{normalize_domain, normalize_host};

/// Per-run options.
#[derive(Debug, Clone, Copy, Default)]
pub struct AuditOptions {
    /// Fail the gate ([`AuditReport::passed`]) when the overall letter is
    /// below this.
    pub fail_under: Option<Letter>,
}

/// The graded audit of one domain.
#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    /// Registration-level name (`normalize_domain`).
    pub domain: String,
    /// The host probed by web/TLS checks (`normalize_host`).
    pub host: String,
    /// `None` when no category could be graded.
    pub overall: Option<OverallGrade>,
    /// Every category, in display order.
    pub categories: Vec<CategoryGrade>,
    /// Severity descending, then category, then id.
    pub findings: Vec<Finding>,
    /// Every check's outcome, including incomplete and not-applicable ones.
    pub runs: Vec<CheckRun>,
    /// False when any check was incomplete.
    pub complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_under: Option<Letter>,
    /// The gate: graded, no Critical finding, and at least `fail_under`.
    pub passed: bool,
}

impl AuditReport {
    /// Number of findings at `severity`.
    pub fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }

    /// Sorts, grades and gates the raw check output.
    fn assemble(
        domain: String,
        host: String,
        mut output: checks::CheckOutput,
        fail_under: Option<Letter>,
    ) -> Self {
        output.findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(a.category.cmp(&b.category))
                .then(a.id.cmp(b.id))
                .then(a.host.cmp(&b.host))
        });
        let categories = score::grade_categories(&output.runs, &output.findings);
        let overall = score::overall(&categories, &output.findings);
        let complete = !output
            .runs
            .iter()
            .any(|r| matches!(r.status, CheckStatus::Incomplete { .. }));
        let passed = score::passed(overall.as_ref(), &output.findings, fail_under);
        Self {
            domain,
            host,
            overall,
            categories,
            findings: output.findings,
            runs: output.runs,
            complete,
            fail_under,
            passed,
        }
    }
}

/// Runs the audit. Build once and reuse: it owns the clients.
pub struct Auditor {
    pub(crate) lookup: SmartLookup,
    pub(crate) dns: DnsResolver,
    pub(crate) ssl: SslChecker,
    pub(crate) dnssec: DnssecChecker,
    pub(crate) delegation: DelegationChecker,
    pub(crate) http_timeout: Duration,
    pub(crate) deadline: Duration,
}

impl Default for Auditor {
    fn default() -> Self {
        Self::new()
    }
}

impl Auditor {
    /// An auditor with default settings.
    pub fn new() -> Self {
        Self::from_config(&SeerConfig::default())
    }

    /// An auditor using the configured timeouts and resolver.
    pub fn from_config(config: &SeerConfig) -> Self {
        Self {
            lookup: SmartLookup::from_config(config),
            dns: DnsResolver::from_config(config),
            ssl: SslChecker::from_config(config),
            dnssec: DnssecChecker::from_config(config),
            delegation: DelegationChecker::from_config(config),
            http_timeout: config.http_timeout(),
            deadline: config.audit_timeout(),
        }
    }

    /// A guarded HTTP fetcher with the configured timeout.
    pub(crate) fn fetcher(&self) -> GuardedFetcher {
        GuardedFetcher::new().with_timeout(self.http_timeout)
    }

    /// Audits `input` (a domain or host).
    ///
    /// # Errors
    /// Only for input that fails normalization; every check failure is
    /// reported inside the [`AuditReport`] as an incomplete check.
    pub async fn audit(&self, input: &str, options: AuditOptions) -> Result<AuditReport> {
        let domain = normalize_domain(input)?;
        let host = normalize_host(input)?;
        let output = {
            let ctx = checks::AuditContext {
                auditor: self,
                domain: &domain,
                host: &host,
            };
            checks::run_specs(checks::CHECKS, &ctx, self.deadline).await
        };
        Ok(AuditReport::assemble(
            domain,
            host,
            output,
            options.fail_under,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn invalid_input_is_the_only_error() {
        assert!(Auditor::new()
            .audit("not a domain!!", AuditOptions::default())
            .await
            .is_err());
    }

    #[test]
    fn offline_like_run_is_ungraded_and_fails_the_gate() {
        let mut output = checks::CheckOutput::default();
        for category in Category::ALL {
            output.incomplete("x", category, "DNS resolution failed");
        }
        let report =
            AuditReport::assemble("example.com".into(), "example.com".into(), output, None);
        assert_eq!(report.overall, None);
        assert!(!report.complete);
        assert!(!report.passed);
    }

    #[test]
    fn findings_sort_by_severity_then_category_then_id() {
        let mut output = checks::CheckOutput::default();
        output.ran(
            "w",
            Category::Web,
            vec![
                Finding::new("web.b.low", Category::Web, Severity::Low, "h", "t"),
                Finding::new("web.a.high", Category::Web, Severity::High, "h", "t"),
            ],
        );
        output.ran(
            "e",
            Category::Email,
            vec![Finding::new(
                "email.a.high",
                Category::Email,
                Severity::High,
                "h",
                "t",
            )],
        );
        let report = AuditReport::assemble("h".into(), "h".into(), output, None);
        let ids: Vec<_> = report.findings.iter().map(|f| f.id).collect();
        assert_eq!(ids, vec!["email.a.high", "web.a.high", "web.b.low"]);
        assert!(report.complete);
    }

    #[tokio::test]
    #[ignore = "live network"]
    async fn live_audit_of_a_real_domain() {
        let report = Auditor::new()
            .audit("example.com", AuditOptions::default())
            .await
            .unwrap();
        assert_eq!(report.categories.len(), 6);
        assert!(report.runs.len() >= 16, "{:?}", report.runs);
        assert!(report.overall.is_some(), "{report:#?}");
        eprintln!("{}", serde_json::to_string_pretty(&report).unwrap());
    }
}
