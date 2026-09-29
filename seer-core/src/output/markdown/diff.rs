use super::*;
use crate::output::diff_table::{build_diff_sections, DiffRow, EMPTY_PLACEHOLDER};

impl MarkdownFormatter {
    /// One table per section of the shared diff rows (the human formatter's
    /// rows), with a `=`/`≠` column for whether the two sides match.
    pub(super) fn format_diff(&self, diff: &crate::diff::DomainDiff) -> String {
        let (a, b) = (MdSafe(&diff.domain_a), MdSafe(&diff.domain_b));
        let mut output = vec![format!("## Domain Comparison: {a} vs {b}")];

        for section in build_diff_sections(diff) {
            output.extend([
                String::new(),
                format!("### {}", section.title),
                String::new(),
                format!("| Field | {a} | {b} | Match |"),
                "| --- | --- | --- | --- |".to_string(),
            ]);
            for row in &section.rows {
                output.push(format!(
                    "| {} | {} | {} | {} |",
                    row.label,
                    cell(row, &row.a_values),
                    cell(row, &row.b_values),
                    if row.matches { "=" } else { "≠" }
                ));
            }
        }

        // Failed checks: their cells above are empty, not real answers.
        if !diff.errors.is_empty() {
            output.push(String::new());
            output.push("### Errors".to_string());
            output.push(String::new());
            for error in &diff.errors {
                output.push(format!("- {}", MdSafe(error)));
            }
        }

        output.join("\n")
    }
}

/// One side of a diff row as a table cell: a list as code spans, a scalar
/// as text, the empty placeholder as is.
fn cell(row: &DiffRow, values: &[String]) -> String {
    match values {
        [only] if only == EMPTY_PLACEHOLDER => EMPTY_PLACEHOLDER.to_string(),
        _ if row.list => code_cells(values),
        _ => values
            .iter()
            .map(|v| MdSafe(v).to_string())
            .collect::<Vec<_>>()
            .join(", "),
    }
}

#[cfg(test)]
mod tests {
    use crate::diff::{DnsDiff, DomainDiff, RegistrationDiff, SslDiff};
    use crate::output::markdown::MarkdownFormatter;

    fn diff_with_nameservers(ns: Vec<String>) -> DomainDiff {
        DomainDiff {
            domain_a: "a.com".to_string(),
            domain_b: "b.com".to_string(),
            registration: RegistrationDiff {
                registrar: (None, None),
                organization: (None, None),
                created: (None, None),
                expires: (None, None),
            },
            dns: DnsDiff {
                a_records: (Vec::new(), Vec::new()),
                nameservers: (ns, Vec::new()),
                resolves: (Some(true), Some(false)),
            },
            ssl: SslDiff {
                issuer: (None, None),
                valid_until: (None, None),
                days_remaining: (None, None),
                is_valid: (None, None),
            },
            errors: Vec::new(),
        }
    }

    #[test]
    fn test_markdown_diff_list_renders_per_item_code_spans() {
        let diff = diff_with_nameservers(vec![
            "ns1.example.com".to_string(),
            "ns2.example.com".to_string(),
        ]);
        let output = MarkdownFormatter::new().format_diff(&diff);

        // Each item must be its own inline-code span, joined by a plain ", ".
        assert!(
            output.contains("`ns1.example.com`, `ns2.example.com`"),
            "expected per-item code spans, got:\n{}",
            output
        );
        // The separator backticks must NOT have been mangled into apostrophes.
        assert!(
            !output.contains("ns1.example.com', 'ns2.example.com"),
            "separator backticks were corrupted into apostrophes:\n{}",
            output
        );
    }
}
