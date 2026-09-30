//! DNS Compare tab renderer — shows A vs B nameserver record comparison.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;
use seer_core::output::sanitize_line;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{or_dash, panel};

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, data: &LensData) {
    let LensData::Compare(c) = data else {
        return;
    };

    // Name the compared domain: `:compare` can target a domain other than the
    // session's, and the title is the only place that says which.
    let title = format!(
        "compare · {} · A {} vs B {}",
        c.domain, c.server_a.nameserver, c.server_b.nameserver
    );
    let inner = panel::render(f, area, theme, &title, theme.sky, false);

    // Layout: summary line + hint + table
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(inner);

    // Summary line
    let (summary_text, summary_color) = if c.matches {
        ("● identical".to_string(), theme.green)
    } else if c.status_matches() && c.chain_matches() {
        let n = c.only_in_a.len() + c.only_in_b.len();
        (format!("≠ {n} difference(s)"), theme.yellow)
    } else {
        (format!("≠ {}", sanitize_line(&c.summary())), theme.yellow)
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            summary_text,
            Style::default().fg(summary_color),
        ))),
        chunks[0],
    );

    // Hint line
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("a ", Style::default().fg(theme.overlay0)),
            Span::styled("cycle A  ", Style::default().fg(theme.subtext)),
            Span::styled("b ", Style::default().fg(theme.overlay0)),
            Span::styled("cycle B", Style::default().fg(theme.subtext)),
        ])),
        chunks[1],
    );

    // Build comparison rows from both servers' records.
    // We collect all unique record values across both, then show per-row match status.
    let mut all_values: Vec<String> = {
        let mut v: std::collections::HashSet<String> = std::collections::HashSet::new();
        for r in c.server_a.records.iter().chain(&c.server_b.records) {
            v.insert(sanitize_line(&r.format_short()));
        }
        let mut sorted: Vec<String> = v.into_iter().collect();
        sorted.sort();
        sorted
    };

    // If there are no records at all, show placeholder rows for any errors.
    if all_values.is_empty() {
        all_values.push("—".to_string());
    }

    let values_a: std::collections::HashSet<String> = c
        .server_a
        .records
        .iter()
        .map(|r| sanitize_line(&r.format_short()))
        .collect();
    let values_b: std::collections::HashSet<String> = c
        .server_b
        .records
        .iter()
        .map(|r| sanitize_line(&r.format_short()))
        .collect();

    let header = Row::new(["●", "RECORD", "A", "B"]).style(
        Style::default()
            .fg(theme.overlay0)
            .add_modifier(Modifier::DIM),
    );

    // The response code and CNAME chain lead: two servers can agree on the
    // records yet differ there (NXDOMAIN vs NODATA, another CDN target).
    let status = |s: &seer_core::dns::ServerResult| or_dash(s.status_label());
    let chain = |s: &seer_core::dns::ServerResult| {
        let hops: Vec<String> = s.cname_chain.iter().map(|r| r.format_short()).collect();
        or_dash((!hops.is_empty()).then(|| sanitize_line(&hops.join(" → "))))
    };
    let differs = |same: bool| {
        let (dot, color) = if same {
            ("=", theme.text)
        } else {
            ("≠", theme.yellow)
        };
        (dot.to_string(), Style::default().fg(color))
    };
    let mut head_rows = Vec::new();
    let (dot, style) = differs(c.status_matches());
    head_rows.push(
        Row::new(vec![
            dot,
            "status".into(),
            status(&c.server_a),
            status(&c.server_b),
        ])
        .style(style),
    );
    if !c.server_a.cname_chain.is_empty() || !c.server_b.cname_chain.is_empty() {
        let (dot, style) = differs(c.chain_matches());
        head_rows.push(
            Row::new(vec![
                dot,
                "CNAME".into(),
                chain(&c.server_a),
                chain(&c.server_b),
            ])
            .style(style),
        );
    }

    let rows: Vec<Row> = all_values
        .iter()
        .map(|val| {
            let in_a = values_a.contains(val);
            let in_b = values_b.contains(val);
            let (dot, row_color) = match (in_a, in_b) {
                (true, true) => ("=", theme.text),
                (true, false) => ("A", theme.yellow),
                (false, true) => ("B", theme.yellow),
                (false, false) => ("-", theme.overlay0),
            };
            Row::new(vec![
                dot.to_string(),
                c.record_type.to_string(),
                or_dash(in_a.then_some(val)),
                or_dash(in_b.then_some(val)),
            ])
            .style(Style::default().fg(row_color))
        })
        .collect();

    // Error rows if either server had a query error
    let mut error_rows: Vec<Row> = Vec::new();
    if let Some(ref e) = c.server_a.error {
        error_rows.push(
            Row::new(vec![
                "!".to_string(),
                "error".to_string(),
                sanitize_line(e),
                "—".to_string(),
            ])
            .style(Style::default().fg(theme.red)),
        );
    }
    if let Some(ref e) = c.server_b.error {
        error_rows.push(
            Row::new(vec![
                "!".to_string(),
                "error".to_string(),
                "—".to_string(),
                sanitize_line(e),
            ])
            .style(Style::default().fg(theme.red)),
        );
    }

    let all_rows: Vec<Row> = head_rows
        .into_iter()
        .chain(rows)
        .chain(error_rows)
        .collect();

    let table = Table::new(
        all_rows,
        [
            Constraint::Length(2),
            Constraint::Length(8),
            Constraint::Percentage(44),
            Constraint::Percentage(44),
        ],
    )
    .header(header)
    .column_spacing(1);

    f.render_widget(table, chunks[2]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::test_util::render_text;
    use seer_core::dns::{DnsComparison, DnsStatus, RecordData, RecordType, ServerResult};
    use seer_core::DnsRecord;

    fn make_record(ip: &str) -> DnsRecord {
        DnsRecord {
            name: "x.com".into(),
            record_type: RecordType::A,
            ttl: 300,
            data: RecordData::A { address: ip.into() },
        }
    }

    fn comparison_fixture(matches: bool) -> DnsComparison {
        let ip = "1.2.3.4";
        DnsComparison {
            domain: "x.com".into(),
            record_type: RecordType::A,
            server_a: ServerResult {
                nameserver: "8.8.8.8".into(),
                status: Some(DnsStatus::NoError),
                cname_chain: vec![],
                records: vec![make_record(ip)],
                error: None,
            },
            server_b: ServerResult {
                nameserver: "1.1.1.1".into(),
                status: Some(DnsStatus::NoError),
                cname_chain: vec![],
                records: if matches {
                    vec![make_record(ip)]
                } else {
                    vec![make_record("5.6.7.8")]
                },
                error: None,
            },
            matches,
            only_in_a: if matches { vec![] } else { vec![ip.into()] },
            only_in_b: if matches {
                vec![]
            } else {
                vec!["5.6.7.8".into()]
            },
            common: if matches { vec![ip.into()] } else { vec![] },
        }
    }

    #[test]
    fn renders_resolver_ips() {
        let theme = Theme::frappe();
        let data = LensData::Compare(Box::new(comparison_fixture(true)));
        let text = render_text(90, 14, |f| render(f, f.area(), &theme, &data));
        assert!(text.contains("8.8.8.8"), "A resolver IP should appear");
        assert!(text.contains("1.1.1.1"), "B resolver IP should appear");
        assert!(
            text.contains("compare · x.com ·"),
            "title must name the compared domain"
        );
    }

    #[test]
    fn renders_identical_summary_for_matching() {
        let theme = Theme::frappe();
        let data = LensData::Compare(Box::new(comparison_fixture(true)));
        let text = render_text(90, 14, |f| render(f, f.area(), &theme, &data));
        assert!(
            text.contains("identical"),
            "matching result should show 'identical'"
        );
    }

    #[test]
    fn renders_record_ip_in_table() {
        let theme = Theme::frappe();
        let data = LensData::Compare(Box::new(comparison_fixture(true)));
        let text = render_text(90, 14, |f| render(f, f.area(), &theme, &data));
        assert!(text.contains("1.2.3.4"), "record IP should appear in table");
    }

    #[test]
    fn renders_difference_summary() {
        let theme = Theme::frappe();
        let data = LensData::Compare(Box::new(comparison_fixture(false)));
        let text = render_text(90, 14, |f| render(f, f.area(), &theme, &data));
        assert!(
            text.contains("difference"),
            "non-matching should show 'difference(s)'"
        );
    }

    /// A negative-answer difference has no differing records to count, so
    /// the summary names the two outcomes instead of "0 difference(s)".
    #[test]
    fn renders_status_difference() {
        let theme = Theme::frappe();
        let mut c = comparison_fixture(true);
        c.matches = false;
        c.common.clear();
        c.server_a.records.clear();
        c.server_b.records.clear();
        c.server_a.status = Some(DnsStatus::NxDomain);
        let data = LensData::Compare(Box::new(c));
        let text = render_text(90, 14, |f| render(f, f.area(), &theme, &data));
        assert!(
            text.contains("Responses differ: NXDOMAIN vs NODATA"),
            "{text}"
        );
        assert!(!text.contains("0 difference"), "{text}");
    }
}
