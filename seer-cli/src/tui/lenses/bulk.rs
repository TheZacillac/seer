//! Bulk lens — multi-domain batch runner with streaming results + CSV export.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::app::SPIN;
use crate::tui::panes::bulk::{op_domain, BulkState, OPS};
use crate::tui::theme::Theme;
use crate::tui::widgets::{dot, gauge, panel, scroll_to};

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, bulk: &BulkState, editing: Option<&str>) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Min(0)])
        .split(area);

    // ── top panel: op chips + domains + gauge + hints ────────────────────────
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

    // Domains line — show edit cursor when field is active, preview otherwise
    let domains_line = if let Some(buf) = editing {
        Line::from(vec![
            Span::styled("domains: ", Style::default().fg(theme.overlay0)),
            Span::styled(format!("{buf}▏"), Style::default().fg(theme.text)),
        ])
    } else {
        let parsed = crate::tui::panes::bulk::parse_domains_input(&bulk.domains);
        if parsed.is_empty() {
            Line::from(Span::styled(
                "domains: none — press d to enter",
                Style::default().fg(theme.overlay0),
            ))
        } else {
            let preview = parsed
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            let more = if parsed.len() > 3 { ", …" } else { "" };
            Line::from(vec![
                Span::styled("domains: ", Style::default().fg(theme.overlay0)),
                Span::styled(parsed.len().to_string(), Style::default().fg(theme.sky)),
                Span::styled(
                    format!(" · {preview}{more}"),
                    Style::default().fg(theme.overlay0),
                ),
            ])
        }
    };

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

    // Running status + ok/failed tally
    let (ok, failed) = bulk.tally();
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
    let mut status_spans = vec![Span::styled(spin_text, Style::default().fg(status_fg))];
    if !bulk.rows.is_empty() {
        status_spans.push(Span::styled(
            format!("  ·  {ok} ok"),
            Style::default().fg(theme.green),
        ));
        if failed > 0 {
            status_spans.push(Span::styled(
                format!("  ·  {failed} failed"),
                Style::default().fg(theme.red),
            ));
        }
    }
    let status_line = Line::from(status_spans);

    // Hints
    let hints = "d domains · o op · r run · x stop · j/k select · v detail · f file · e export";
    let hints_line = Line::from(Span::styled(hints, Style::default().fg(theme.overlay0)));

    // Optional note (e.g. file error)
    let mut lines = vec![op_chips, domains_line, gauge_line, status_line, hints_line];
    if let Some(note) = &bulk.note {
        lines.push(Line::from(Span::styled(
            note.as_str(),
            Style::default().fg(theme.red),
        )));
    }

    f.render_widget(Paragraph::new(lines), top_inner);

    // ── bottom panel: results table (+ optional detail panel) ────────────────
    let selected = bulk.effective_selected();

    // When the detail panel is open and a row is selected, split the bottom
    // area into the results table (top) and a detail panel (bottom).
    let (table_area, detail_area) = if bulk.detail && selected.is_some() {
        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(9)])
            .split(rows[1]);
        (split[0], Some(split[1]))
    } else {
        (rows[1], None)
    };

    let results_title = format!("Results  ·  seer bulk {}", bulk.op());
    let results_block = panel::block(theme, &results_title, theme.mauve, false);
    let results_inner = results_block.inner(table_area);
    f.render_widget(results_block, table_area);

    if bulk.rows.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(vec![Span::styled(
                "enter domains (d) or load a file (f), then r to run",
                Style::default()
                    .fg(theme.overlay0)
                    .add_modifier(Modifier::ITALIC),
            )])),
            results_inner,
        );
        return;
    }

    let header = Row::new(["DOMAIN", "RESULT", "⚑"]).style(Style::default().fg(theme.overlay0));

    let body = bulk.rows.iter().enumerate().map(|(i, r)| {
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
        // Highlight the selected row so j/k navigation is visible.
        let row_style = if Some(i) == selected {
            Style::default().fg(theme.text).bg(theme.surface0)
        } else {
            Style::default().fg(theme.text)
        };
        Row::new(vec![
            Line::from(domain),
            Line::from(Span::styled(
                result_text,
                Style::default().fg(if r.success { theme.green } else { theme.red }),
            )),
            flag,
        ])
        .style(row_style)
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

    // Keep the selected row in view. While streaming with no manual selection,
    // `effective_selected` is the tail, so newest rows stay pinned; once the
    // user moves the selection it follows their choice instead.
    let mut state = scroll_to(selected);
    f.render_stateful_widget(table, results_inner, &mut state);

    // ── detail panel for the selected row ────────────────────────────────────
    if let (Some(area), Some(idx)) = (detail_area, selected) {
        if let Some(row) = bulk.rows.get(idx) {
            let detail_block = panel::block(theme, "Detail", theme.sky, false);
            let detail_inner = detail_block.inner(area);
            f.render_widget(detail_block, area);
            f.render_widget(
                Paragraph::new(detail_lines(theme, row))
                    .wrap(ratatui::widgets::Wrap { trim: false }),
                detail_inner,
            );
        }
    }
}

/// Build the detail view lines for a single result: a header row of facts plus
/// the error or a pretty-printed JSON dump of the returned data.
fn detail_lines<'a>(theme: &Theme, r: &seer_core::bulk::BulkResult) -> Vec<Line<'a>> {
    let domain = op_domain(&r.operation).to_string();
    let status = if r.success { "ok" } else { "failed" };
    let status_fg = if r.success { theme.green } else { theme.red };

    let mut lines = vec![Line::from(vec![
        Span::styled(domain, Style::default().fg(theme.text)),
        Span::styled("  ·  ", Style::default().fg(theme.overlay0)),
        Span::styled(status, Style::default().fg(status_fg)),
        Span::styled(
            format!("  ·  {} ms", r.duration_ms),
            Style::default().fg(theme.overlay0),
        ),
    ])];

    if let Some(err) = &r.error {
        lines.push(Line::from(Span::styled(
            err.clone(),
            Style::default().fg(theme.red),
        )));
    }

    match &r.data {
        Some(data) => match serde_json::to_string_pretty(data) {
            Ok(json) => {
                for l in json.lines() {
                    lines.push(Line::from(Span::styled(
                        l.to_string(),
                        Style::default().fg(theme.subtext),
                    )));
                }
            }
            Err(_) => lines.push(Line::from(Span::styled(
                "(could not render data)",
                Style::default().fg(theme.overlay0),
            ))),
        },
        None if r.error.is_none() => lines.push(Line::from(Span::styled(
            "(no data)",
            Style::default().fg(theme.overlay0),
        ))),
        None => {}
    }

    lines
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
            .draw(|f| render(f, f.area(), &theme, &bulk, None))
            .unwrap();
        let text = buf_text(&terminal);
        assert!(
            text.contains("rust-lang.org"),
            "rendered buffer should contain the domain"
        );
    }

    #[test]
    fn streaming_rows_keep_the_newest_in_view() {
        let theme = Theme::frappe();
        let mut bulk = BulkState::default();
        // More rows than fit in a short terminal; the newest (last) row must
        // stay visible as results stream in.
        for i in 0..50 {
            bulk.rows.push(make_result(&format!("d{i}.com"), true));
        }
        let backend = TestBackend::new(80, 14);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &bulk, None))
            .unwrap();
        let text = buf_text(&terminal);
        assert!(
            text.contains("d49.com"),
            "the newest streamed row should be pinned in view"
        );
    }

    #[test]
    fn renders_idle_placeholder_when_empty() {
        let theme = Theme::frappe();
        let bulk = BulkState::default();

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &bulk, None))
            .unwrap();
        let text = buf_text(&terminal);
        assert!(
            text.contains("enter domains"),
            "empty state should show 'enter domains' placeholder"
        );
    }

    #[test]
    fn renders_op_chips_row() {
        let theme = Theme::frappe();
        let bulk = BulkState::default();

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &bulk, None))
            .unwrap();
        let text = buf_text(&terminal);
        assert!(text.contains("lookup"), "op chips should show 'lookup'");
        assert!(text.contains("status"), "op chips should show 'status'");
    }

    #[test]
    fn empty_state_prompts_for_domains() {
        let theme = Theme::frappe();
        let bulk = BulkState::default();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &bulk, None))
            .unwrap();
        let text = buf_text(&terminal);
        assert!(text.contains("press d to enter"), "prompts for domains");
        assert!(text.contains("d domains"), "shows the new hint row");
    }

    #[test]
    fn shows_ok_failed_summary() {
        let theme = Theme::frappe();
        let mut bulk = BulkState::default();
        bulk.rows.push(make_result("ok.com", true));
        bulk.rows.push(make_result("bad.com", false));
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &bulk, None))
            .unwrap();
        let text = buf_text(&terminal);
        assert!(text.contains("1 ok"), "summary should report ok count");
        assert!(text.contains("1 failed"), "summary should report failures");
    }

    #[test]
    fn detail_panel_shows_error_for_selected_row() {
        let theme = Theme::frappe();
        let mut bulk = BulkState::default();
        bulk.rows.push(make_result("bad.com", false)); // error: "timeout"
        bulk.selected = Some(0);
        bulk.detail = true;
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &bulk, None))
            .unwrap();
        let text = buf_text(&terminal);
        assert!(text.contains("Detail"), "detail panel header should render");
        assert!(
            text.contains("timeout"),
            "detail panel should show the row error"
        );
    }
}
