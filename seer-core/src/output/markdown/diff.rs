use super::*;

impl MarkdownFormatter {
    pub(super) fn format_diff(&self, diff: &crate::diff::DomainDiff) -> String {
        let dash = "\u{2014}";
        let mut output = Vec::new();

        // Helper for "value or dash"; wraps attacker-controlled value in MdSafe.
        let opt_or_dash = |o: &Option<String>| -> String {
            match o {
                Some(v) => format!("{}", MdSafe(v)),
                None => dash.to_string(),
            }
        };
        // Sanitize and wrap each item in its own code span BEFORE joining, so
        // the `, ` separator's backticks aren't fed through MdSafe (which would
        // mangle them into apostrophes). Mirrors every other markdown formatter.
        let list_or_dash = |v: &Vec<String>| -> String {
            if v.is_empty() {
                dash.to_string()
            } else {
                v.iter()
                    .map(|s| format!("`{}`", MdSafe(s)))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        };

        output.push(format!(
            "## Domain Comparison: {} vs {}",
            MdSafe(&diff.domain_a),
            MdSafe(&diff.domain_b)
        ));
        output.push(String::new());

        // Registration table
        output.push("### Registration".to_string());
        output.push(String::new());
        output.push(format!(
            "| Field | {} | {} |",
            MdSafe(&diff.domain_a),
            MdSafe(&diff.domain_b)
        ));
        output.push("| --- | --- | --- |".to_string());

        let reg = &diff.registration;
        output.push(format!(
            "| Registrar | {} | {} |",
            opt_or_dash(&reg.registrar.0),
            opt_or_dash(&reg.registrar.1)
        ));
        output.push(format!(
            "| Organization | {} | {} |",
            opt_or_dash(&reg.organization.0),
            opt_or_dash(&reg.organization.1)
        ));
        output.push(format!(
            "| Created | {} | {} |",
            opt_or_dash(&reg.created.0),
            opt_or_dash(&reg.created.1)
        ));
        output.push(format!(
            "| Expires | {} | {} |",
            opt_or_dash(&reg.expires.0),
            opt_or_dash(&reg.expires.1)
        ));

        // DNS table
        output.push(String::new());
        output.push("### DNS".to_string());
        output.push(String::new());
        output.push(format!(
            "| Field | {} | {} |",
            MdSafe(&diff.domain_a),
            MdSafe(&diff.domain_b)
        ));
        output.push("| --- | --- | --- |".to_string());
        let dns = &diff.dns;
        output.push(format!(
            "| Resolves | {} | {} |",
            if dns.resolves.0 { "yes" } else { "no" },
            if dns.resolves.1 { "yes" } else { "no" }
        ));
        let a_recs_a = list_or_dash(&dns.a_records.0);
        let a_recs_b = list_or_dash(&dns.a_records.1);
        output.push(format!("| A Records | {} | {} |", a_recs_a, a_recs_b));
        let ns_a = list_or_dash(&dns.nameservers.0);
        let ns_b = list_or_dash(&dns.nameservers.1);
        output.push(format!("| Nameservers | {} | {} |", ns_a, ns_b));

        // SSL table
        output.push(String::new());
        output.push("### SSL".to_string());
        output.push(String::new());
        output.push(format!(
            "| Field | {} | {} |",
            MdSafe(&diff.domain_a),
            MdSafe(&diff.domain_b)
        ));
        output.push("| --- | --- | --- |".to_string());
        let ssl = &diff.ssl;
        output.push(format!(
            "| Issuer | {} | {} |",
            opt_or_dash(&ssl.issuer.0),
            opt_or_dash(&ssl.issuer.1)
        ));
        output.push(format!(
            "| Valid Until | {} | {} |",
            opt_or_dash(&ssl.valid_until.0),
            opt_or_dash(&ssl.valid_until.1)
        ));
        output.push(format!(
            "| Days Remaining | {} | {} |",
            ssl.days_remaining
                .0
                .map(|d| d.to_string())
                .as_deref()
                .unwrap_or(dash),
            ssl.days_remaining
                .1
                .map(|d| d.to_string())
                .as_deref()
                .unwrap_or(dash)
        ));
        output.push(format!(
            "| Valid | {} | {} |",
            ssl.is_valid
                .0
                .map(|v| if v { "yes" } else { "no" })
                .unwrap_or(dash),
            ssl.is_valid
                .1
                .map(|v| if v { "yes" } else { "no" })
                .unwrap_or(dash)
        ));

        output.join("\n")
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
                resolves: (true, false),
            },
            ssl: SslDiff {
                issuer: (None, None),
                valid_until: (None, None),
                days_remaining: (None, None),
                is_valid: (None, None),
            },
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
