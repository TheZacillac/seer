//! Human (colored) renderer for the security audit.

use super::{sanitize_line, HumanFormatter};
use crate::audit::{AuditReport, Category, CategoryState, CheckStatus, Severity};
use crate::grade::Letter;

impl HumanFormatter {
    /// A letter colored by band: A/A+ pass, B–C partial, D and below fail.
    fn letter(&self, letter: Letter) -> String {
        match letter {
            Letter::APlus | Letter::A => self.success(letter.as_str()),
            Letter::B | Letter::C => self.warning(letter.as_str()),
            _ => self.error(letter.as_str()),
        }
    }

    fn severity(&self, severity: Severity) -> String {
        let label = severity.as_str().to_ascii_uppercase();
        match severity {
            Severity::Critical | Severity::High => self.error(&label),
            Severity::Medium => self.warning(&label),
            Severity::Low | Severity::Info => self.dim(&label),
        }
    }

    pub(super) fn format_audit(&self, report: &AuditReport) -> String {
        let mut out =
            vec![self.header(&format!("Security audit: {}", sanitize_line(&report.host)))];

        let overall = match &report.overall {
            Some(o) => {
                let mut s = format!("{} ({}/100)", self.letter(o.letter), o.score);
                if let Some(cap) = o.capped_by {
                    s.push_str(&format!(
                        " {}",
                        self.dim(&format!("[capped by a {} finding]", cap.as_str()))
                    ));
                }
                s
            }
            None => self.dim("not graded (no check completed)"),
        };
        let strip = report
            .categories
            .iter()
            .map(|c| {
                let grade = match (c.state, c.letter) {
                    (CategoryState::Graded, Some(l)) => self.letter(l),
                    (CategoryState::NotApplicable, _) => self.dim("n/a"),
                    _ => self.dim("?"),
                };
                format!("{} {}", c.category.label(), grade)
            })
            .collect::<Vec<_>>()
            .join("  ");

        let mut rows = self.rows(&mut out, "");
        rows.kv("Overall", overall);
        rows.kv("Categories", strip);
        if !report.complete {
            rows.kv(
                "Completeness",
                self.warning("incomplete — some checks did not finish (see below)"),
            );
        }
        if let Some(threshold) = report.fail_under {
            let verdict = if report.passed {
                self.success("passed")
            } else {
                self.error("failed")
            };
            rows.kv(
                "Gate",
                format!("fail under {} — {verdict}", threshold.as_str()),
            );
        }

        if report.findings.is_empty() {
            out.push(String::new());
            out.push(self.success("No findings."));
        }
        for category in Category::ALL {
            let findings: Vec<_> = report
                .findings
                .iter()
                .filter(|f| f.category == category)
                .collect();
            if findings.is_empty() {
                continue;
            }
            out.push(String::new());
            out.push(self.label(category.label()));
            for f in findings {
                out.push(format!(
                    "  [{}] {} {}",
                    self.severity(f.severity),
                    sanitize_line(&f.title),
                    self.dim(&format!("({})", f.id))
                ));
                if f.host != report.host && f.host != report.domain {
                    out.push(format!(
                        "      host: {}",
                        self.value(&sanitize_line(&f.host))
                    ));
                }
                if let Some(e) = &f.evidence {
                    out.push(format!("      evidence: {}", self.value(&sanitize_line(e))));
                }
                if let Some(r) = &f.remediation {
                    out.push(format!("      fix: {}", sanitize_line(r)));
                }
            }
        }

        let skipped: Vec<(&str, &str, &str)> = report
            .runs
            .iter()
            .filter_map(|r| match &r.status {
                CheckStatus::Ran => None,
                CheckStatus::Incomplete { reason } => {
                    Some((r.check, "incomplete", reason.as_str()))
                }
                CheckStatus::NotApplicable { reason } => Some((r.check, "n/a", reason.as_str())),
            })
            .collect();
        if !skipped.is_empty() {
            out.push(String::new());
            out.push(self.label("Not run:"));
            for (check, word, reason) in skipped {
                out.push(format!(
                    "  {} — {}: {}",
                    check,
                    word,
                    self.dim(&sanitize_line(reason))
                ));
            }
        }
        out.join("\n")
    }
}
