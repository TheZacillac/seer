//! The rows of a domain comparison ([`crate::diff::DomainDiff`]), built once
//! for both the human and the Markdown table: each field's label, its values
//! on either side (one entry per rendered line) and whether they match.

use crate::diff::DomainDiff;

/// The placeholder rendered for `None` or empty values.
pub(super) const EMPTY_PLACEHOLDER: &str = "—";

/// One labeled row. `a_values` / `b_values` each hold one item per rendered
/// line — scalars are single-element; multi-value fields (A records,
/// nameservers) hold one entry per item and set `list`.
pub(super) struct DiffRow {
    pub label: &'static str,
    pub a_values: Vec<String>,
    pub b_values: Vec<String>,
    pub matches: bool,
    /// A multi-value field (A records, nameservers).
    pub list: bool,
}

pub(super) struct DiffSection {
    pub title: &'static str,
    pub rows: Vec<DiffRow>,
}

/// Compares two `Option<String>` values for equality after trimming whitespace.
/// Empty-after-trim is treated as `None`.
fn eq_opt_str_trimmed(a: &Option<String>, b: &Option<String>) -> bool {
    let norm = |o: &Option<String>| -> Option<String> {
        o.as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    norm(a) == norm(b)
}

/// Compares two string lists as sets: trims each item, drops empty items,
/// then checks that the sorted multisets are equal.
fn eq_as_set(a: &[String], b: &[String]) -> bool {
    let norm = |list: &[String]| {
        let mut out: Vec<String> = list
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        out.sort();
        out
    };
    norm(a) == norm(b)
}

fn opt_or_placeholder(o: &Option<String>) -> String {
    o.as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| EMPTY_PLACEHOLDER.to_string())
}

fn opt_i64_or_placeholder(o: &Option<i64>) -> String {
    o.map(|n| n.to_string())
        .unwrap_or_else(|| EMPTY_PLACEHOLDER.to_string())
}

fn opt_bool_or_placeholder(o: &Option<bool>) -> String {
    o.map(bool_as_str)
        .unwrap_or_else(|| EMPTY_PLACEHOLDER.to_string())
}

fn bool_as_str(b: bool) -> String {
    if b { "yes" } else { "no" }.to_string()
}

fn list_or_placeholder(list: &[String]) -> Vec<String> {
    let cleaned: Vec<String> = list
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if cleaned.is_empty() {
        vec![EMPTY_PLACEHOLDER.to_string()]
    } else {
        cleaned
    }
}

/// A single-value row from an `(a, b)` option pair.
fn text_row(label: &'static str, (a, b): &(Option<String>, Option<String>)) -> DiffRow {
    DiffRow {
        label,
        a_values: vec![opt_or_placeholder(a)],
        b_values: vec![opt_or_placeholder(b)],
        matches: eq_opt_str_trimmed(a, b),
        list: false,
    }
}

/// A multi-value row from an `(a, b)` list pair, compared as sets.
fn list_row(label: &'static str, (a, b): &(Vec<String>, Vec<String>)) -> DiffRow {
    DiffRow {
        label,
        a_values: list_or_placeholder(a),
        b_values: list_or_placeholder(b),
        matches: eq_as_set(a, b),
        list: true,
    }
}

/// A row whose two values render through `show` and compare with `==`.
fn value_row<T: PartialEq>(
    label: &'static str,
    (a, b): &(T, T),
    show: impl Fn(&T) -> String,
) -> DiffRow {
    DiffRow {
        label,
        a_values: vec![show(a)],
        b_values: vec![show(b)],
        matches: a == b,
        list: false,
    }
}

/// The Registration, DNS and SSL sections, in display order.
pub(super) fn build_diff_sections(diff: &DomainDiff) -> Vec<DiffSection> {
    let reg = &diff.registration;
    let dns = &diff.dns;
    let ssl = &diff.ssl;
    vec![
        DiffSection {
            title: "Registration",
            rows: vec![
                text_row("Registrar", &reg.registrar),
                text_row("Organization", &reg.organization),
                text_row("Created", &reg.created),
                text_row("Expires", &reg.expires),
            ],
        },
        DiffSection {
            title: "DNS",
            rows: vec![
                value_row("Resolves", &dns.resolves, opt_bool_or_placeholder),
                list_row("A Records", &dns.a_records),
                list_row("Nameservers", &dns.nameservers),
            ],
        },
        DiffSection {
            title: "SSL",
            rows: vec![
                text_row("Issuer", &ssl.issuer),
                text_row("Valid Until", &ssl.valid_until),
                value_row(
                    "Days Remaining",
                    &ssl.days_remaining,
                    opt_i64_or_placeholder,
                ),
                value_row("Valid", &ssl.is_valid, opt_bool_or_placeholder),
            ],
        },
    ]
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::diff::{DnsDiff, RegistrationDiff, SslDiff};

    pub(in crate::output) fn make_sample_diff() -> DomainDiff {
        DomainDiff {
            domain_a: "example.com".to_string(),
            domain_b: "google.com".to_string(),
            registration: RegistrationDiff {
                registrar: (Some("IANA".to_string()), Some("MarkMonitor".to_string())),
                organization: (None, Some("Google LLC".to_string())),
                created: (
                    Some("1995-08-14".to_string()),
                    Some("1997-09-15".to_string()),
                ),
                expires: (
                    Some("2026-08-13".to_string()),
                    Some("2028-09-14".to_string()),
                ),
            },
            dns: DnsDiff {
                a_records: (
                    vec!["93.184.216.34".to_string()],
                    vec!["142.250.185.46".to_string()],
                ),
                nameservers: (
                    vec!["ns1.example".to_string(), "ns2.example".to_string()],
                    vec!["ns2.example".to_string(), "ns1.example".to_string()],
                ),
                resolves: (Some(true), Some(true)),
            },
            ssl: SslDiff {
                issuer: (
                    Some("DigiCert".to_string()),
                    Some("Google Trust".to_string()),
                ),
                valid_until: (
                    Some("2025-03-01".to_string()),
                    Some("2025-02-15".to_string()),
                ),
                days_remaining: (Some(89), Some(75)),
                is_valid: (Some(true), Some(true)),
            },
            errors: Vec::new(),
        }
    }

    fn row<'a>(sections: &'a [DiffSection], label: &str) -> &'a DiffRow {
        sections
            .iter()
            .flat_map(|s| &s.rows)
            .find(|r| r.label == label)
            .unwrap()
    }

    #[test]
    fn eq_opt_str_trims_and_treats_empty_as_none() {
        let some = |s: &str| Some(s.to_string());
        assert!(eq_opt_str_trimmed(&some("  foo  "), &some("foo")));
        assert!(!eq_opt_str_trimmed(&some("foo"), &some("bar")));
        assert!(eq_opt_str_trimmed(&None, &None));
        assert!(eq_opt_str_trimmed(&None, &some("")));
        assert!(eq_opt_str_trimmed(&some("   "), &None));
        assert!(!eq_opt_str_trimmed(&some("foo"), &None));
    }

    #[test]
    fn eq_as_set_is_order_independent_trimmed_and_drops_empty() {
        let v = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(eq_as_set(&v(&["ns1", "ns2"]), &v(&["ns2", "ns1"])));
        assert!(eq_as_set(&v(&["ns1", "  ", " ns2 "]), &v(&["ns2", "ns1"])));
        assert!(!eq_as_set(&v(&["1.2.3.4"]), &v(&["1.2.3.5"])));
        assert!(eq_as_set(&v(&[]), &v(&[])));
    }

    #[test]
    fn sections_and_rows_keep_display_order() {
        let sections = build_diff_sections(&make_sample_diff());
        let titles: Vec<&str> = sections.iter().map(|s| s.title).collect();
        assert_eq!(titles, ["Registration", "DNS", "SSL"]);
        let labels = |i: usize| sections[i].rows.iter().map(|r| r.label).collect::<Vec<_>>();
        assert_eq!(
            labels(0),
            ["Registrar", "Organization", "Created", "Expires"]
        );
        assert_eq!(labels(1), ["Resolves", "A Records", "Nameservers"]);
        assert_eq!(
            labels(2),
            ["Issuer", "Valid Until", "Days Remaining", "Valid"]
        );
    }

    #[test]
    fn rows_compare_and_render_values() {
        let mut diff = make_sample_diff();
        diff.dns.a_records = (
            vec!["1.1.1.1".to_string(), "2.2.2.2".to_string()],
            vec!["3.3.3.3".to_string()],
        );
        let sections = build_diff_sections(&diff);
        assert!(row(&sections, "Nameservers").matches, "set equality");
        assert!(row(&sections, "Nameservers").list);
        assert!(!row(&sections, "Registrar").matches);
        let resolves = row(&sections, "Resolves");
        assert!(resolves.matches);
        assert_eq!(resolves.a_values, ["yes"]);
        assert_eq!(row(&sections, "Organization").a_values, ["—"]);
        let a = row(&sections, "A Records");
        assert_eq!((a.a_values.len(), a.b_values.len()), (2, 1));
    }
}
