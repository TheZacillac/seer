//! DNSSEC tab renderer — state header + KV summary + DS records table.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{kv, panel};

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, data: &LensData) {
    let LensData::Dnssec(r) = data else {
        return;
    };

    let status_color = if r.chain_valid || r.status == "signed" {
        theme.green
    } else if r.status == "partial" || r.status == "misconfigured" {
        theme.yellow
    } else {
        theme.red
    };

    let block = panel::block(theme, "DNSSEC", status_color, false);
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Split: status header + kv + issues + DS table
    let has_ds = !r.ds_records.is_empty();
    let constraints = if has_ds {
        vec![
            Constraint::Length(1),
            Constraint::Length(7),
            Constraint::Length(2),
            Constraint::Min(0),
        ]
    } else {
        vec![
            Constraint::Length(1),
            Constraint::Length(7),
            Constraint::Min(0),
        ]
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    // Status header
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            r.status.to_uppercase(),
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        ))),
        chunks[0],
    );

    // KV summary
    let rows: Vec<(String, String)> = vec![
        ("enabled".into(), r.enabled.to_string()),
        ("status".into(), r.status.clone()),
        ("chain valid".into(), r.chain_valid.to_string()),
        ("DS records".into(), r.ds_records.len().to_string()),
        ("DNSKEY records".into(), r.dnskey_records.len().to_string()),
    ];
    kv::render(f, chunks[1], theme, status_color, &rows);

    // Issues line
    if !r.issues.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                r.issues.join("  ·  "),
                Style::default().fg(theme.yellow),
            ))),
            chunks[2],
        );
    }

    // DS records table
    if has_ds {
        let ds_area = chunks[chunks.len() - 1];
        let block2 = panel::block(theme, "DS Records", theme.overlay0, false);
        let inner2 = block2.inner(ds_area);
        f.render_widget(block2, ds_area);

        let header = Row::new(["KEY TAG", "ALGORITHM", "DIGEST TYPE", "MATCHED"])
            .style(Style::default().fg(theme.overlay0));
        let ds_rows = r.ds_records.iter().map(|ds| {
            let matched = if ds.matched_key { "✓" } else { "✗" };
            Row::new(vec![
                ds.key_tag.to_string(),
                ds.algorithm_name.clone(),
                ds.digest_type_name.clone(),
                matched.to_string(),
            ])
            .style(Style::default().fg(theme.text))
        });
        let table = Table::new(
            ds_rows,
            [
                Constraint::Length(10),
                Constraint::Percentage(35),
                Constraint::Percentage(35),
                Constraint::Length(8),
            ],
        )
        .header(header)
        .column_spacing(1);
        f.render_widget(table, inner2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use seer_core::DnssecReport;

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

    #[test]
    fn renders_status_field() {
        let theme = Theme::frappe();
        let data = LensData::Dnssec(Box::new(DnssecReport {
            domain: "x".into(),
            enabled: true,
            has_ds_records: true,
            has_dnskey_records: true,
            ds_records: vec![],
            dnskey_records: vec![],
            issues: vec![],
            status: "signed".into(),
            chain_valid: true,
        }));
        let backend = TestBackend::new(70, 14);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data))
            .unwrap();
        assert!(buf_text(terminal.backend().buffer()).contains("signed"));
    }
}
