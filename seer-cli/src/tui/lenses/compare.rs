//! DNS Compare tab renderer — shows A vs B nameserver record comparison.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::panel;

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, data: &LensData) {
    let LensData::Compare(c) = data else {
        return;
    };

    let title = format!(
        "compare · A {} vs B {}",
        c.server_a.nameserver, c.server_b.nameserver
    );
    let block = panel::block(theme, &title, theme.sky, false);
    let inner = block.inner(area);
    f.render_widget(block, area);

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
    } else {
        let n = c.only_in_a.len() + c.only_in_b.len();
        (format!("≠ {n} difference(s)"), theme.yellow)
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
        for r in &c.server_a.records {
            v.insert(r.format_short());
        }
        for r in &c.server_b.records {
            v.insert(r.format_short());
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
        .map(|r| r.format_short())
        .collect();
    let values_b: std::collections::HashSet<String> = c
        .server_b
        .records
        .iter()
        .map(|r| r.format_short())
        .collect();

    let header = Row::new(["●", "RECORD", "A", "B"]).style(
        Style::default()
            .fg(theme.overlay0)
            .add_modifier(Modifier::DIM),
    );

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
                if in_a { val.clone() } else { "—".to_string() },
                if in_b { val.clone() } else { "—".to_string() },
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
                e.clone(),
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
                e.clone(),
            ])
            .style(Style::default().fg(theme.red)),
        );
    }

    let all_rows: Vec<Row> = rows.into_iter().chain(error_rows).collect();

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
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use seer_core::dns::{DnsComparison, RecordData, RecordType, ServerResult};
    use seer_core::DnsRecord;

    fn buf_text(buf: &ratatui::buffer::Buffer) -> String {
        let a = buf.area();
        let mut s = String::new();
        for y in 0..a.height {
            for x in 0..a.width {
                s.push_str(buf[(x, y)].symbol());
            }
        }
        s
    }

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
                records: vec![make_record(ip)],
                error: None,
            },
            server_b: ServerResult {
                nameserver: "1.1.1.1".into(),
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
        let backend = TestBackend::new(90, 14);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data))
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(text.contains("8.8.8.8"), "A resolver IP should appear");
        assert!(text.contains("1.1.1.1"), "B resolver IP should appear");
    }

    #[test]
    fn renders_identical_summary_for_matching() {
        let theme = Theme::frappe();
        let data = LensData::Compare(Box::new(comparison_fixture(true)));
        let backend = TestBackend::new(90, 14);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data))
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(
            text.contains("identical"),
            "matching result should show 'identical'"
        );
    }

    #[test]
    fn renders_record_ip_in_table() {
        let theme = Theme::frappe();
        let data = LensData::Compare(Box::new(comparison_fixture(true)));
        let backend = TestBackend::new(90, 14);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data))
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(text.contains("1.2.3.4"), "record IP should appear in table");
    }

    #[test]
    fn renders_difference_summary() {
        let theme = Theme::frappe();
        let data = LensData::Compare(Box::new(comparison_fixture(false)));
        let backend = TestBackend::new(90, 14);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data))
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(
            text.contains("difference"),
            "non-matching should show 'difference(s)'"
        );
    }
}
