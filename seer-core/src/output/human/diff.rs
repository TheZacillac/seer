use super::*;

impl HumanFormatter {
    pub(super) fn format_diff(&self, diff: &crate::diff::DomainDiff) -> String {
        let mut output = Vec::new();

        output.push(self.header(&format!(
            "Diff: {} vs {}",
            sanitize_display(&diff.domain_a),
            sanitize_display(&diff.domain_b)
        )));

        let domain_a = sanitize_display(&diff.domain_a);
        let domain_b = sanitize_display(&diff.domain_b);
        let sections = build_diff_sections(diff);
        let col_width = compute_column_width(&sections, &domain_a, &domain_b);

        // Label gutter width: max of all field labels (not section titles).
        let label_width = sections
            .iter()
            .flat_map(|s| s.rows.iter().map(|r| r.label.chars().count()))
            .max()
            .unwrap_or(0);

        // Indents and gutters
        let label_indent = "    "; // 4 spaces inside section
        let section_indent = "  "; // 2 spaces before section title
        let marker_gutter_width = 2; // "= " or "≠ "
                                     // Between label cell and marker: 2 spaces (inter-column gap).
                                     // Marker cell: "= " or "≠ " = 2 chars.
                                     // Total left pad before value column A = label_indent + label_width + 2 + 2.
        let header_left_pad = label_indent.chars().count() + label_width + 2 + marker_gutter_width;

        // Column header block
        let header_line = format!(
            "{}{}   {}",
            " ".repeat(header_left_pad),
            self.label(&pad_right(&domain_a, col_width)),
            self.label(&domain_b)
        );
        let rule_a: String = "─".repeat(domain_a.chars().count());
        let rule_b: String = "─".repeat(domain_b.chars().count());
        let rule_line = format!(
            "{}{}   {}",
            " ".repeat(header_left_pad),
            self.label(&pad_right(&rule_a, col_width)),
            self.label(&rule_b)
        );
        output.push(String::new());
        output.push(header_line);
        output.push(rule_line);

        for section in &sections {
            output.push(String::new());
            output.push(format!("{}{}", section_indent, self.label(section.title)));

            for row in &section.rows {
                // Wrap each value column independently.
                let mut a_lines: Vec<String> = row
                    .a_values
                    .iter()
                    .flat_map(|v| wrap_cell(&sanitize_display(v), col_width))
                    .collect();
                let mut b_lines: Vec<String> = row
                    .b_values
                    .iter()
                    .flat_map(|v| wrap_cell(&sanitize_display(v), col_width))
                    .collect();

                // Pad the shorter list with blank lines so rows align.
                let rows_needed = a_lines.len().max(b_lines.len()).max(1);
                while a_lines.len() < rows_needed {
                    a_lines.push(String::new());
                }
                while b_lines.len() < rows_needed {
                    b_lines.push(String::new());
                }

                let marker_glyph = if row.matches { "=" } else { "≠" };
                let color = |s: &str| -> String {
                    if row.matches {
                        self.success(s)
                    } else {
                        self.error(s)
                    }
                };

                for (i, (a, b)) in a_lines.iter().zip(b_lines.iter()).enumerate() {
                    let label_cell = if i == 0 {
                        format!("{}{}", label_indent, pad_right(row.label, label_width))
                    } else {
                        format!("{}{}", label_indent, " ".repeat(label_width))
                    };
                    let marker_cell = if i == 0 {
                        format!("{} ", color(marker_glyph))
                    } else {
                        "  ".to_string()
                    };
                    let color_value = |s: &str, raw: &str| -> String {
                        if raw.trim() == EMPTY_PLACEHOLDER {
                            self.dim(s)
                        } else {
                            color(s)
                        }
                    };
                    let a_cell = color_value(&pad_right(a, col_width), a);
                    let b_cell = color_value(b, b);
                    output.push(format!(
                        "{}  {}{}   {}",
                        self.label(&label_cell),
                        marker_cell,
                        a_cell,
                        b_cell
                    ));
                }
            }
        }

        output.join("\n")
    }
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
    let mut an: Vec<String> = a
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let mut bn: Vec<String> = b
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    an.sort();
    bn.sort();
    an == bn
}

/// Wraps `text` into lines no wider than `max_width` display chars.
/// Breaks at the last ASCII whitespace within the window when possible;
/// otherwise hard-breaks at the cap. Widths are measured in `chars().count()`
/// which is correct for ASCII and a reasonable fallback for other inputs.
fn wrap_cell(text: &str, max_width: usize) -> Vec<String> {
    let width = max_width.max(1);
    if text.is_empty() {
        return vec![String::new()];
    }

    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return vec![text.to_string()];
    }

    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let remaining = chars.len() - i;
        if remaining <= width {
            out.push(chars[i..].iter().collect());
            break;
        }
        // Search for last whitespace in chars[i .. i+width]
        let window_end = i + width;
        let break_at = (i..window_end).rev().find(|&k| chars[k].is_whitespace());
        match break_at {
            Some(k) if k > i => {
                out.push(chars[i..k].iter().collect());
                i = k + 1; // skip the whitespace itself
            }
            _ => {
                // No whitespace in window (or whitespace at index i): hard break.
                out.push(chars[i..window_end].iter().collect());
                i = window_end;
            }
        }
    }

    out
}

/// One labeled row in the rendered diff table. `a_values` / `b_values` each
/// hold one item per rendered line — scalars are single-element; multi-value
/// fields (A records, nameservers) hold one entry per item.
struct DiffRow {
    label: &'static str,
    a_values: Vec<String>,
    b_values: Vec<String>,
    matches: bool,
}

struct DiffSection {
    title: &'static str,
    rows: Vec<DiffRow>,
}

/// The placeholder rendered for `None` or empty values.
const EMPTY_PLACEHOLDER: &str = "—";

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
    match o {
        Some(true) => "yes".to_string(),
        Some(false) => "no".to_string(),
        None => EMPTY_PLACEHOLDER.to_string(),
    }
}

fn bool_as_str(b: bool) -> String {
    if b {
        "yes".to_string()
    } else {
        "no".to_string()
    }
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

fn build_diff_sections(diff: &crate::diff::DomainDiff) -> Vec<DiffSection> {
    let reg = &diff.registration;
    let dns = &diff.dns;
    let ssl = &diff.ssl;

    let registration = DiffSection {
        title: "Registration",
        rows: vec![
            DiffRow {
                label: "Registrar",
                a_values: vec![opt_or_placeholder(&reg.registrar.0)],
                b_values: vec![opt_or_placeholder(&reg.registrar.1)],
                matches: eq_opt_str_trimmed(&reg.registrar.0, &reg.registrar.1),
            },
            DiffRow {
                label: "Organization",
                a_values: vec![opt_or_placeholder(&reg.organization.0)],
                b_values: vec![opt_or_placeholder(&reg.organization.1)],
                matches: eq_opt_str_trimmed(&reg.organization.0, &reg.organization.1),
            },
            DiffRow {
                label: "Created",
                a_values: vec![opt_or_placeholder(&reg.created.0)],
                b_values: vec![opt_or_placeholder(&reg.created.1)],
                matches: eq_opt_str_trimmed(&reg.created.0, &reg.created.1),
            },
            DiffRow {
                label: "Expires",
                a_values: vec![opt_or_placeholder(&reg.expires.0)],
                b_values: vec![opt_or_placeholder(&reg.expires.1)],
                matches: eq_opt_str_trimmed(&reg.expires.0, &reg.expires.1),
            },
        ],
    };

    let dns_section = DiffSection {
        title: "DNS",
        rows: vec![
            DiffRow {
                label: "Resolves",
                a_values: vec![bool_as_str(dns.resolves.0)],
                b_values: vec![bool_as_str(dns.resolves.1)],
                matches: dns.resolves.0 == dns.resolves.1,
            },
            DiffRow {
                label: "A Records",
                a_values: list_or_placeholder(&dns.a_records.0),
                b_values: list_or_placeholder(&dns.a_records.1),
                matches: eq_as_set(&dns.a_records.0, &dns.a_records.1),
            },
            DiffRow {
                label: "Nameservers",
                a_values: list_or_placeholder(&dns.nameservers.0),
                b_values: list_or_placeholder(&dns.nameservers.1),
                matches: eq_as_set(&dns.nameservers.0, &dns.nameservers.1),
            },
        ],
    };

    let ssl_section = DiffSection {
        title: "SSL",
        rows: vec![
            DiffRow {
                label: "Issuer",
                a_values: vec![opt_or_placeholder(&ssl.issuer.0)],
                b_values: vec![opt_or_placeholder(&ssl.issuer.1)],
                matches: eq_opt_str_trimmed(&ssl.issuer.0, &ssl.issuer.1),
            },
            DiffRow {
                label: "Valid Until",
                a_values: vec![opt_or_placeholder(&ssl.valid_until.0)],
                b_values: vec![opt_or_placeholder(&ssl.valid_until.1)],
                matches: eq_opt_str_trimmed(&ssl.valid_until.0, &ssl.valid_until.1),
            },
            DiffRow {
                label: "Days Remaining",
                a_values: vec![opt_i64_or_placeholder(&ssl.days_remaining.0)],
                b_values: vec![opt_i64_or_placeholder(&ssl.days_remaining.1)],
                matches: ssl.days_remaining.0 == ssl.days_remaining.1,
            },
            DiffRow {
                label: "Valid",
                a_values: vec![opt_bool_or_placeholder(&ssl.is_valid.0)],
                b_values: vec![opt_bool_or_placeholder(&ssl.is_valid.1)],
                matches: ssl.is_valid.0 == ssl.is_valid.1,
            },
        ],
    };

    vec![registration, dns_section, ssl_section]
}

/// Hard cap on a single value column (applies before wrapping).
const DIFF_COLUMN_CAP: usize = 40;

/// Computes the shared width for both value columns: the widest item across
/// every row of every section plus the two domain-header lengths, capped at
/// `DIFF_COLUMN_CAP`.
fn compute_column_width(sections: &[DiffSection], domain_a: &str, domain_b: &str) -> usize {
    let mut widest = domain_a.chars().count().max(domain_b.chars().count());
    for section in sections {
        for row in &section.rows {
            for v in row.a_values.iter().chain(row.b_values.iter()) {
                widest = widest.max(v.chars().count());
            }
        }
    }
    widest.clamp(1, DIFF_COLUMN_CAP)
}

/// Right-pads `text` with spaces to `width` display chars. Never truncates.
fn pad_right(text: &str, width: usize) -> String {
    let have = text.chars().count();
    if have >= width {
        text.to_string()
    } else {
        format!("{}{}", text, " ".repeat(width - have))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::{DnsDiff, DomainDiff, RegistrationDiff, SslDiff};

    #[test]
    fn eq_opt_str_trims_whitespace() {
        assert!(eq_opt_str_trimmed(
            &Some("  foo  ".to_string()),
            &Some("foo".to_string())
        ));
        assert!(!eq_opt_str_trimmed(
            &Some("foo".to_string()),
            &Some("bar".to_string())
        ));
    }

    #[test]
    fn eq_opt_str_both_none_matches() {
        assert!(eq_opt_str_trimmed(&None, &None));
    }

    #[test]
    fn eq_opt_str_empty_string_is_none() {
        assert!(eq_opt_str_trimmed(&None, &Some("".to_string())));
        assert!(eq_opt_str_trimmed(&Some("   ".to_string()), &None));
    }

    #[test]
    fn eq_opt_str_some_vs_none_differs() {
        assert!(!eq_opt_str_trimmed(&Some("foo".to_string()), &None));
    }

    #[test]
    fn eq_as_set_order_independent() {
        let a = vec!["ns1".to_string(), "ns2".to_string()];
        let b = vec!["ns2".to_string(), "ns1".to_string()];
        assert!(eq_as_set(&a, &b));
    }

    #[test]
    fn eq_as_set_trims_and_drops_empty() {
        let a = vec!["ns1".to_string(), "  ".to_string(), " ns2 ".to_string()];
        let b = vec!["ns2".to_string(), "ns1".to_string()];
        assert!(eq_as_set(&a, &b));
    }

    #[test]
    fn eq_as_set_different_contents() {
        let a = vec!["1.2.3.4".to_string()];
        let b = vec!["1.2.3.5".to_string()];
        assert!(!eq_as_set(&a, &b));
    }

    #[test]
    fn eq_as_set_both_empty_matches() {
        let a: Vec<String> = vec![];
        let b: Vec<String> = vec![];
        assert!(eq_as_set(&a, &b));
    }

    #[test]
    fn wrap_cell_short_returns_single_line() {
        assert_eq!(wrap_cell("hello", 10), vec!["hello".to_string()]);
    }

    #[test]
    fn wrap_cell_wraps_at_word_boundary() {
        let out = wrap_cell("the quick brown fox", 10);
        assert_eq!(out, vec!["the quick".to_string(), "brown fox".to_string()]);
    }

    #[test]
    fn wrap_cell_hard_breaks_when_no_whitespace() {
        // A long nameserver with no break points must hard-break at the cap.
        let out = wrap_cell("a.very.long.nameserver.example", 10);
        assert_eq!(
            out,
            vec![
                "a.very.lon".to_string(),
                "g.nameserv".to_string(),
                "er.example".to_string(),
            ]
        );
    }

    #[test]
    fn wrap_cell_exact_width_no_wrap() {
        assert_eq!(wrap_cell("1234567890", 10), vec!["1234567890".to_string()]);
    }

    #[test]
    fn wrap_cell_empty_input_returns_one_empty_line() {
        assert_eq!(wrap_cell("", 10), vec!["".to_string()]);
    }

    #[test]
    fn wrap_cell_zero_width_treated_as_one() {
        // Defensive: never loop forever on width 0. Caller must not pass 0, but
        // we clamp to 1 to be safe.
        let out = wrap_cell("abc", 0);
        assert_eq!(out, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    }

    fn make_sample_diff() -> DomainDiff {
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
                resolves: (true, true),
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
        }
    }

    #[test]
    fn build_diff_sections_produces_three_sections() {
        let diff = make_sample_diff();
        let sections = build_diff_sections(&diff);
        assert_eq!(sections.len(), 3);
        assert_eq!(sections[0].title, "Registration");
        assert_eq!(sections[1].title, "DNS");
        assert_eq!(sections[2].title, "SSL");
    }

    #[test]
    fn build_diff_sections_marks_nameservers_as_match_when_sets_equal() {
        let diff = make_sample_diff();
        let sections = build_diff_sections(&diff);
        let dns = &sections[1];
        let ns_row = dns.rows.iter().find(|r| r.label == "Nameservers").unwrap();
        assert!(ns_row.matches, "reversed-order nameservers should match");
    }

    #[test]
    fn build_diff_sections_marks_registrar_differ() {
        let diff = make_sample_diff();
        let sections = build_diff_sections(&diff);
        let reg = &sections[0];
        let row = reg.rows.iter().find(|r| r.label == "Registrar").unwrap();
        assert!(!row.matches);
    }

    #[test]
    fn build_diff_sections_marks_resolves_match_when_both_true() {
        let diff = make_sample_diff();
        let sections = build_diff_sections(&diff);
        let dns = &sections[1];
        let row = dns.rows.iter().find(|r| r.label == "Resolves").unwrap();
        assert!(row.matches);
        assert_eq!(row.a_values, vec!["yes".to_string()]);
        assert_eq!(row.b_values, vec!["yes".to_string()]);
    }

    #[test]
    fn build_diff_sections_renders_none_as_em_dash() {
        let diff = make_sample_diff();
        let sections = build_diff_sections(&diff);
        let reg = &sections[0];
        let row = reg.rows.iter().find(|r| r.label == "Organization").unwrap();
        assert_eq!(row.a_values, vec!["—".to_string()]);
    }

    #[test]
    fn build_diff_sections_a_records_one_item_per_row() {
        let mut diff = make_sample_diff();
        diff.dns.a_records = (
            vec!["1.1.1.1".to_string(), "2.2.2.2".to_string()],
            vec!["3.3.3.3".to_string()],
        );
        let sections = build_diff_sections(&diff);
        let dns = &sections[1];
        let row = dns.rows.iter().find(|r| r.label == "A Records").unwrap();
        assert_eq!(row.a_values.len(), 2);
        assert_eq!(row.b_values.len(), 1);
    }

    #[test]
    fn build_diff_sections_preserves_field_order() {
        let diff = make_sample_diff();
        let sections = build_diff_sections(&diff);
        let labels: Vec<&str> = sections[0].rows.iter().map(|r| r.label).collect();
        assert_eq!(
            labels,
            vec!["Registrar", "Organization", "Created", "Expires"]
        );
        let dns_labels: Vec<&str> = sections[1].rows.iter().map(|r| r.label).collect();
        assert_eq!(dns_labels, vec!["Resolves", "A Records", "Nameservers"]);
        let ssl_labels: Vec<&str> = sections[2].rows.iter().map(|r| r.label).collect();
        assert_eq!(
            ssl_labels,
            vec!["Issuer", "Valid Until", "Days Remaining", "Valid"]
        );
    }

    #[test]
    fn compute_column_width_uses_widest_value_across_sections() {
        let sections = vec![DiffSection {
            title: "Registration",
            rows: vec![
                DiffRow {
                    label: "Registrar",
                    a_values: vec!["IANA".to_string()],
                    b_values: vec!["MarkMonitor".to_string()],
                    matches: false,
                },
                DiffRow {
                    label: "Organization",
                    a_values: vec!["—".to_string()],
                    b_values: vec!["Google LLC".to_string()],
                    matches: false,
                },
            ],
        }];
        // Widest item is "MarkMonitor" (11).
        assert_eq!(compute_column_width(&sections, "a.com", "b.com"), 11);
    }

    #[test]
    fn compute_column_width_respects_domain_width() {
        let sections = vec![DiffSection {
            title: "Registration",
            rows: vec![DiffRow {
                label: "Registrar",
                a_values: vec!["x".to_string()],
                b_values: vec!["y".to_string()],
                matches: false,
            }],
        }];
        // Domain "very-long-domain.example" is wider than any value.
        let w = compute_column_width(&sections, "very-long-domain.example", "b.com");
        assert_eq!(w, "very-long-domain.example".chars().count());
    }

    #[test]
    fn compute_column_width_caps_at_40() {
        let long_value = "x".repeat(100);
        let sections = vec![DiffSection {
            title: "Registration",
            rows: vec![DiffRow {
                label: "Registrar",
                a_values: vec![long_value],
                b_values: vec!["y".to_string()],
                matches: false,
            }],
        }];
        assert_eq!(compute_column_width(&sections, "a.com", "b.com"), 40);
    }

    #[test]
    fn compute_column_width_minimum_sensible_default() {
        // Even with tiny inputs, width should not be zero.
        let sections = vec![DiffSection {
            title: "Registration",
            rows: vec![DiffRow {
                label: "X",
                a_values: vec!["a".to_string()],
                b_values: vec!["b".to_string()],
                matches: true,
            }],
        }];
        let w = compute_column_width(&sections, "a", "b");
        assert!(w >= 1);
    }

    fn diff_formatter() -> HumanFormatter {
        HumanFormatter::new().without_colors()
    }

    #[test]
    fn format_diff_shows_column_headers_with_domain_names() {
        let f = diff_formatter();
        let out = f.format_diff(&make_sample_diff());
        assert!(
            out.contains("example.com"),
            "missing domain_a in output:\n{}",
            out
        );
        assert!(
            out.contains("google.com"),
            "missing domain_b in output:\n{}",
            out
        );
        // A row indicating the header underline (Unicode box-drawing dash).
        assert!(out.contains("──"), "missing header underline:\n{}", out);
    }

    #[test]
    fn format_diff_marks_differing_rows_with_neq() {
        let f = diff_formatter();
        let out = f.format_diff(&make_sample_diff());
        // Registrar differs: IANA vs MarkMonitor.
        let registrar_line = out
            .lines()
            .find(|l| l.contains("Registrar"))
            .expect("registrar line missing");
        assert!(
            registrar_line.contains("≠"),
            "registrar row should be marked differ: {}",
            registrar_line
        );
    }

    #[test]
    fn format_diff_marks_matching_rows_with_eq() {
        let f = diff_formatter();
        let out = f.format_diff(&make_sample_diff());
        // Resolves matches (both true).
        let resolves_line = out
            .lines()
            .find(|l| l.contains("Resolves"))
            .expect("resolves line missing");
        assert!(
            resolves_line.contains('='),
            "resolves row should be marked match: {}",
            resolves_line
        );
        assert!(!resolves_line.contains('≠'));
    }

    #[test]
    fn format_diff_nameservers_reversed_order_is_match() {
        // make_sample_diff has reversed nameservers.
        let f = diff_formatter();
        let out = f.format_diff(&make_sample_diff());
        let ns_line = out
            .lines()
            .find(|l| l.contains("Nameservers"))
            .expect("nameservers line missing");
        assert!(
            ns_line.contains('=') && !ns_line.contains('≠'),
            "nameservers row should match (set equality): {}",
            ns_line
        );
    }

    #[test]
    fn format_diff_organization_none_renders_em_dash() {
        let f = diff_formatter();
        let out = f.format_diff(&make_sample_diff());
        let org_line = out
            .lines()
            .find(|l| l.contains("Organization"))
            .expect("organization line missing");
        assert!(org_line.contains("—"), "expected em dash: {}", org_line);
    }

    #[test]
    fn format_diff_multi_value_a_records_one_per_line() {
        let mut diff = make_sample_diff();
        diff.dns.a_records = (
            vec!["1.1.1.1".to_string(), "2.2.2.2".to_string()],
            vec!["3.3.3.3".to_string(), "4.4.4.4".to_string()],
        );
        let f = diff_formatter();
        let out = f.format_diff(&diff);
        assert!(out.contains("1.1.1.1"), "missing 1.1.1.1:\n{}", out);
        assert!(out.contains("2.2.2.2"), "missing 2.2.2.2:\n{}", out);
        assert!(out.contains("3.3.3.3"), "missing 3.3.3.3:\n{}", out);
        assert!(out.contains("4.4.4.4"), "missing 4.4.4.4:\n{}", out);
        // The label only appears on the first row of the field.
        let a_records_label_count = out.matches("A Records").count();
        assert_eq!(
            a_records_label_count, 1,
            "A Records label should appear exactly once:\n{}",
            out
        );
    }

    #[test]
    fn format_diff_wraps_long_scalar_values() {
        let mut diff = make_sample_diff();
        let long = "a".repeat(60);
        diff.ssl.issuer = (Some(long.clone()), Some("short".to_string()));
        let f = diff_formatter();
        let out = f.format_diff(&diff);
        // The 60-char value should not appear on any single line in full.
        for line in out.lines() {
            assert!(
                !line.contains(&long),
                "unwrapped 60-char value on one line: {}",
                line
            );
        }
        // But the characters as a whole should still be present.
        let chars_present = out.matches('a').count();
        assert!(
            chars_present >= 60,
            "wrapped value should preserve all chars, got {}",
            chars_present
        );
    }

    #[test]
    fn format_diff_plain_mode_contains_marker_glyphs() {
        let out = diff_formatter().format_diff(&make_sample_diff());
        assert!(out.contains('='), "plain mode missing =");
        assert!(out.contains('≠'), "plain mode missing ≠");
        assert!(out.contains('─'), "plain mode missing header rule ─");
    }

    #[test]
    fn format_diff_all_matching_has_no_neq() {
        let diff = DomainDiff {
            domain_a: "a.com".to_string(),
            domain_b: "a.com".to_string(),
            registration: RegistrationDiff {
                registrar: (Some("X".to_string()), Some("X".to_string())),
                organization: (Some("Org".to_string()), Some("Org".to_string())),
                created: (Some("2020".to_string()), Some("2020".to_string())),
                expires: (Some("2030".to_string()), Some("2030".to_string())),
            },
            dns: DnsDiff {
                a_records: (vec!["1.1.1.1".to_string()], vec!["1.1.1.1".to_string()]),
                nameservers: (vec!["ns".to_string()], vec!["ns".to_string()]),
                resolves: (true, true),
            },
            ssl: SslDiff {
                issuer: (Some("I".to_string()), Some("I".to_string())),
                valid_until: (Some("2030".to_string()), Some("2030".to_string())),
                days_remaining: (Some(10), Some(10)),
                is_valid: (Some(true), Some(true)),
            },
        };
        let out = diff_formatter().format_diff(&diff);
        assert!(
            !out.contains('≠'),
            "all-match diff should have no ≠:\n{}",
            out
        );
    }

    #[test]
    fn format_diff_all_differing_has_no_eq() {
        let diff = DomainDiff {
            domain_a: "a.com".to_string(),
            domain_b: "b.com".to_string(),
            registration: RegistrationDiff {
                registrar: (Some("X".to_string()), Some("Y".to_string())),
                organization: (Some("OrgX".to_string()), Some("OrgY".to_string())),
                created: (Some("2020".to_string()), Some("2021".to_string())),
                expires: (Some("2030".to_string()), Some("2031".to_string())),
            },
            dns: DnsDiff {
                a_records: (vec!["1.1.1.1".to_string()], vec!["2.2.2.2".to_string()]),
                nameservers: (vec!["nsa".to_string()], vec!["nsb".to_string()]),
                resolves: (true, false),
            },
            ssl: SslDiff {
                issuer: (Some("IA".to_string()), Some("IB".to_string())),
                valid_until: (Some("2030".to_string()), Some("2031".to_string())),
                days_remaining: (Some(10), Some(20)),
                is_valid: (Some(true), Some(false)),
            },
        };
        let out = diff_formatter().format_diff(&diff);
        // Every field differs. Match marker must not appear on any row.
        // We exclude the rule-line `─` and any spaces; only search within
        // lines that contain a field label (start with four spaces).
        for line in out.lines() {
            if line.starts_with("    ") && line.len() > 10 {
                assert!(
                    !line.contains('='),
                    "all-differing diff should have no = on field rows: {}",
                    line
                );
            }
        }
    }

    #[test]
    fn format_diff_uneven_list_lengths_pad_shorter_side() {
        let mut diff = make_sample_diff();
        diff.dns.nameservers = (
            vec!["ns1".to_string(), "ns2".to_string(), "ns3".to_string()],
            vec!["only".to_string()],
        );
        let out = diff_formatter().format_diff(&diff);
        // All three left-side nameservers render.
        assert!(out.contains("ns1"), "ns1 missing:\n{}", out);
        assert!(out.contains("ns2"), "ns2 missing:\n{}", out);
        assert!(out.contains("ns3"), "ns3 missing:\n{}", out);
        // Right side only has one value, "only".
        assert!(out.contains("only"), "right-side 'only' missing:\n{}", out);
        // The "only" string must appear exactly once — it should not be
        // mistakenly duplicated onto padding rows.
        assert_eq!(
            out.matches("only").count(),
            1,
            "right-side value must appear exactly once:\n{}",
            out
        );
    }

    #[test]
    fn format_diff_em_dash_is_dim_not_row_color() {
        // Colored formatter — we need to see the ANSI escape codes.
        // Force color output even in non-TTY test environments.
        colored::control::set_override(true);
        let f = HumanFormatter::new();
        let out = f.format_diff(&make_sample_diff());
        colored::control::unset_override();

        // In make_sample_diff, Organization is (None, Some("Google LLC")) →
        // differ row. The row-level red color for differ rows is the bright-red
        // ANSI code `\x1b[91m`. The dim em-dash cell should NOT appear inside
        // that code.
        //
        // We look for the Organization line and assert that the em-dash in it
        // is NOT wrapped in bright-red — i.e. the substring "\x1b[91m—" should
        // not appear. The em-dash should instead appear wrapped in the dim
        // (bright-black, `\x1b[90m`) code.
        let org_line = out
            .lines()
            .find(|l| l.contains("Organization"))
            .expect("organization line missing");
        assert!(
            !org_line.contains("\x1b[91m—"),
            "em-dash should not be red on a differ row: {:?}",
            org_line
        );
        assert!(
            org_line.contains("\x1b[90m"),
            "em-dash should be dim (bright-black ANSI): {:?}",
            org_line
        );
    }
}
