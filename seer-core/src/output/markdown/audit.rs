//! Markdown renderer for the security audit.

use super::{heading, table_header, Bullets, MarkdownFormatter, MdCode, MdCodeCell, MdSafe};
use crate::audit::{AuditReport, CategoryState, CheckStatus};

impl MarkdownFormatter {
    pub(super) fn format_audit(&self, report: &AuditReport) -> String {
        let mut out = heading(format!("## Security audit: {}", MdSafe(&report.host)));
        let mut b = Bullets(&mut out);
        match &report.overall {
            Some(o) => {
                let cap = o
                    .capped_by
                    .map(|s| format!(" — capped by a {} finding", s.as_str()))
                    .unwrap_or_default();
                b.raw(
                    "Overall",
                    format_args!("**{}** ({}/100){}", o.letter.as_str(), o.score, cap),
                );
            }
            None => b.raw("Overall", "not graded (no check completed)"),
        }
        if !report.complete {
            b.raw("Completeness", "incomplete — some checks did not finish");
        }
        if let Some(t) = report.fail_under {
            b.raw(
                "Gate",
                format_args!(
                    "fail under {} — {}",
                    t.as_str(),
                    if report.passed { "passed" } else { "failed" }
                ),
            );
        }

        out.push(String::new());
        table_header(&mut out, &["Category", "Grade"]);
        for c in &report.categories {
            let grade = match (c.state, c.letter) {
                (CategoryState::Graded, Some(l)) => l.as_str(),
                (CategoryState::NotApplicable, _) => "n/a",
                _ => "?",
            };
            out.push(format!("| {} | {} |", c.category.label(), grade));
        }

        out.extend([String::new(), "### Findings".to_string(), String::new()]);
        if report.findings.is_empty() {
            out.push("No findings.".to_string());
        } else {
            table_header(
                &mut out,
                &["Severity", "Category", "Finding", "Host", "Evidence", "Fix"],
            );
            for f in &report.findings {
                out.push(format!(
                    "| {} | {} | {} (`{}`) | {} | {} | {} |",
                    f.severity.as_str(),
                    f.category.label(),
                    MdSafe(&f.title),
                    MdCodeCell(f.id),
                    MdSafe(&f.host),
                    MdSafe(f.evidence.as_deref().unwrap_or("")),
                    MdSafe(f.remediation.as_deref().unwrap_or("")),
                ));
            }
        }

        let skipped: Vec<String> = report
            .runs
            .iter()
            .filter_map(|r| match &r.status {
                CheckStatus::Ran => None,
                CheckStatus::Incomplete { reason } => Some(format!(
                    "- `{}` — incomplete: {}",
                    MdCode(r.check),
                    MdSafe(reason)
                )),
                CheckStatus::NotApplicable { reason } => {
                    Some(format!("- `{}` — n/a: {}", MdCode(r.check), MdSafe(reason)))
                }
            })
            .collect();
        if !skipped.is_empty() {
            out.extend([String::new(), "### Not run".to_string(), String::new()]);
            out.extend(skipped);
        }
        out.join("\n")
    }
}
