//! Bulk lens — multi-domain batch runner with streaming results + CSV export.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::app::SPIN;
use crate::tui::panes::bulk::{op_domain, BulkState, OPS, SAMPLES};
use crate::tui::theme::Theme;
use crate::tui::widgets::{dot, gauge, panel};

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, bulk: &BulkState) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(0)])
        .split(area);

    // ── top panel: op chips + source + gauge + hints ─────────────────────────
    let top_title = format!("Bulk  ·  {}", bulk.op());
    let top_block = panel::block(theme, &top_title, theme.mauve, false);
    let top_inner = top_block.inner(rows[0]);
    f.render_widget(top_block, rows[0]);

    // Op chip row — highlight the selected op
    let op_chips: Line = {
        let mut spans = Vec::new();
        for (i, &op) in OPS.iter().enumerate() {
            if i > 0 {
                spans.push(Span::raw(" "));
            }
            let (fg, bg) = if i == bulk.op_idx {
                (theme.base, theme.mauve)
            } else {
                (theme.subtext, theme.surface0)
            };
            spans.push(Span::styled(
                format!(" {op} "),
                Style::default().fg(fg).bg(bg),
            ));
        }
        Line::from(spans)
    };

    // Source + count label
    let sample_count = SAMPLES[bulk.source_idx].1.len();
    let source_line = Line::from(vec![
        Span::styled("source: ", Style::default().fg(theme.overlay0)),
        Span::styled(bulk.source_name(), Style::default().fg(theme.sky)),
        Span::styled(
            format!("  ({sample_count} domains)"),
            Style::default().fg(theme.overlay0),
        ),
    ]);

    // Progress gauge: use bulk.total when set (file loads or explicit run).
    // Falls back to rows.len() so the gauge is never stuck at 0%.
    let denom = if bulk.total > 0 {
        bulk.total
    } else {
        bulk.rows.len().max(1)
    };
    let ratio = bulk.rows.len() as f64 / denom as f64;
    let gauge_label = format!("{}/{} done", bulk.rows.len(), denom);
    let gauge_line = gauge::line(ratio, 24, theme.mauve, Some(&gauge_label));

    // Running status
    let spin_text = if bulk.running {
        format!("  {} running…", SPIN[0])
    } else if !bulk.rows.is_empty() {
        "  done".to_string()
    } else {
        "  idle".to_string()
    };
    let status_fg = if bulk.running {
        theme.mauve
    } else if !bulk.rows.is_empty() {
        theme.green
    } else {
        theme.overlay0
    };
    let status_line = Line::from(vec![Span::styled(
        spin_text,
        Style::default().fg(status_fg),
    )]);

    // Hints
    let hints = "o op  ·  t source  ·  r run  ·  f file  ·  e export";
    let hints_line = Line::from(Span::styled(hints, Style::default().fg(theme.overlay0)));

    // Optional note (e.g. file error)
    let mut lines = vec![op_chips, source_line, gauge_line, status_line, hints_line];
    if let Some(note) = &bulk.note {
        lines.push(Line::from(Span::styled(
            note.as_str(),
            Style::default().fg(theme.red),
        )));
    }

    f.render_widget(Paragraph::new(lines), top_inner);

    // ── bottom panel: results table ──────────────────────────────────────────
    let results_title = format!("Results  ·  seer bulk {}", bulk.op());
    let results_block = panel::block(theme, &results_title, theme.mauve, false);
    let results_inner = results_block.inner(rows[1]);
    f.render_widget(results_block, rows[1]);

    if bulk.rows.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(vec![Span::styled(
                "no results — press r to run a sample or f to load a file",
                Style::default()
                    .fg(theme.overlay0)
                    .add_modifier(Modifier::ITALIC),
            )])),
            results_inner,
        );
        return;
    }

    let header = Row::new(["DOMAIN", "RESULT", "⚑"]).style(Style::default().fg(theme.overlay0));

    let body = bulk.rows.iter().map(|r| {
        let domain = op_domain(&r.operation).to_string();
        let result_text = if r.success {
            "ok".to_string()
        } else {
            r.error.as_deref().unwrap_or("failed").to_string()
        };
        let flag = if r.success {
            dot::line(theme, "ok", "●")
        } else {
            dot::line(theme, "fail", "●")
        };
        Row::new(vec![
            Line::from(domain),
            Line::from(Span::styled(
                result_text,
                Style::default().fg(if r.success { theme.green } else { theme.red }),
            )),
            flag,
        ])
        .style(Style::default().fg(theme.text))
    });

    let table = Table::new(
        body,
        [
            Constraint::Percentage(45),
            Constraint::Percentage(45),
            Constraint::Length(4),
        ],
    )
    .header(header)
    .column_spacing(1);

    f.render_widget(table, results_inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use seer_core::bulk::{BulkOperation, BulkResult};

    fn buf_text(terminal: &Terminal<TestBackend>) -> String {
        let area = terminal.backend().buffer().area();
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                s.push_str(terminal.backend().buffer()[(x, y)].symbol());
            }
        }
        s
    }

    fn make_result(domain: &str, success: bool) -> BulkResult {
        BulkResult {
            operation: BulkOperation::Lookup {
                domain: domain.to_string(),
            },
            success,
            data: None,
            error: if success {
                None
            } else {
                Some("timeout".into())
            },
            duration_ms: 42,
        }
    }

    #[test]
    fn renders_domain_in_results_table() {
        let theme = Theme::frappe();
        let mut bulk = BulkState::default();
        bulk.rows.push(make_result("rust-lang.org", true));

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &bulk))
            .unwrap();
        let text = buf_text(&terminal);
        assert!(
            text.contains("rust-lang.org"),
            "rendered buffer should contain the domain"
        );
    }

    #[test]
    fn renders_idle_placeholder_when_empty() {
        let theme = Theme::frappe();
        let bulk = BulkState::default();

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &bulk))
            .unwrap();
        let text = buf_text(&terminal);
        assert!(
            text.contains("no results"),
            "empty state should show 'no results' placeholder"
        );
    }

    #[test]
    fn renders_op_chips_row() {
        let theme = Theme::frappe();
        let bulk = BulkState::default();

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &bulk))
            .unwrap();
        let text = buf_text(&terminal);
        assert!(text.contains("lookup"), "op chips should show 'lookup'");
        assert!(text.contains("status"), "op chips should show 'status'");
    }
}
