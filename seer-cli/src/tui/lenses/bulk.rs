//! Bulk lens — multi-domain batch runner with streaming results + CSV export.
use ratatui::layout::Constraint;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Row;

use seer_core::output::sanitize_line;

use crate::ops::BULK_OPS;
use crate::tui::app::SPIN;
use crate::tui::line_editor::LineEditor;
use crate::tui::panes::bulk::BulkState;
use crate::tui::theme::Theme;
use crate::tui::widgets::page::{Block, Page, TableBlock};
use crate::tui::widgets::{dot, gauge};

/// The batch runner: op chips, the domains, progress and hints, then the
/// results panel and, when open (`v`), the selected row's detail panel.
pub fn page(theme: &Theme, bulk: &BulkState, editing: Option<&LineEditor>, spin: usize) -> Page {
    let top_title = format!("Bulk  ·  {}", bulk.op());

    // Op chip row — highlight the selected op
    let op_chips: Line = {
        let mut spans = Vec::new();
        for (i, &(op, _)) in BULK_OPS.iter().enumerate() {
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
            Span::styled(buf.with_caret("▏"), Style::default().fg(theme.text)),
        ])
    } else {
        match crate::tui::panes::bulk::parse_domains_input(&bulk.domains) {
            Ok(parsed) if parsed.is_empty() => Line::from(Span::styled(
                "domains: none — press d to enter",
                Style::default().fg(theme.overlay0),
            )),
            Err(e) => Line::from(vec![
                Span::styled("domains: ", Style::default().fg(theme.overlay0)),
                Span::styled(sanitize_line(&e), Style::default().fg(theme.red)),
            ]),
            Ok(parsed) => {
                let preview = sanitize_line(&parsed[..parsed.len().min(3)].join(", "));
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
    let gauge_line = gauge::line(theme, ratio, 24, theme.mauve, Some(&gauge_label));

    // Running status + ok/failed tally
    let (ok, failed) = bulk.tally();
    let spin_text = if bulk.running {
        format!("  {} running…", SPIN[spin % SPIN.len()])
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
    let hints =
        "d domains · o op · r run · x stop · j/k select · v detail (PgUp/PgDn) · f file · e export";
    let hints_line = Line::from(Span::styled(hints, Style::default().fg(theme.overlay0)));

    // Optional note (e.g. file error)
    let mut lines = vec![op_chips, domains_line, gauge_line, status_line, hints_line];
    if let Some(note) = &bulk.note {
        lines.push(Line::from(Span::styled(
            sanitize_line(note),
            Style::default().fg(theme.red),
        )));
    }

    let page = Page::new(top_title, theme.mauve)
        .push(Block::Lines(lines))
        .push(Block::Gap);

    // The op the rows were produced with — `o` only selects the NEXT run's op.
    let results = Page::new(
        format!("Results  ·  seer bulk {}", bulk.results_op()),
        theme.mauve,
    );
    if bulk.rows.is_empty() {
        return page.push(Block::Panel(results.push(Block::Lines(vec![Line::from(
            vec![Span::styled(
                "enter domains (d) or load a file (f), then r to run",
                Style::default()
                    .fg(theme.overlay0)
                    .add_modifier(Modifier::ITALIC),
            )],
        )]))));
    }

    let body = bulk
        .rows
        .iter()
        .map(|r| {
            let domain = sanitize_line(r.operation.domain());
            let result_text = if r.success {
                "ok".to_string()
            } else {
                sanitize_line(r.error.as_deref().unwrap_or("failed"))
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
        })
        .collect();
    // Keep the selected row in view. While streaming with no manual selection,
    // `effective_selected` is the tail, so newest rows stay pinned; once the
    // user moves the selection it follows their choice instead.
    let selected = bulk.effective_selected();
    let table = TableBlock::new(
        vec!["DOMAIN", "RESULT", "⚑"],
        vec![
            Constraint::Percentage(45),
            Constraint::Percentage(45),
            Constraint::Length(4),
        ],
        body,
    )
    .selected(selected);
    let page = page.push(Block::Panel(results.push(Block::Table(table))));

    // The detail panel for the selected row, scrolled with PgUp / PgDn.
    let detail = selected
        .filter(|_| bulk.detail)
        .and_then(|idx| bulk.rows.get(idx));
    match detail {
        Some(row) => page.push(Block::Panel(Page::new("Detail", theme.sky).push(
            Block::Scroll {
                lines: detail_lines(theme, row),
                offset: bulk.detail_scroll,
                unit: "lines",
            },
        ))),
        None => page,
    }
}

/// Build the detail view lines for a single result: a header row of facts plus
/// the error or a pretty-printed JSON dump of the returned data.
fn detail_lines(theme: &Theme, r: &seer_core::bulk::BulkResult) -> Vec<Line<'static>> {
    let domain = sanitize_line(r.operation.domain());
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
            sanitize_line(err),
            Style::default().fg(theme.red),
        )));
    }

    match &r.data {
        Some(data) => match serde_json::to_string_pretty(data) {
            Ok(json) => {
                // JSON escapes control characters, but a string can still
                // carry an escape-free terminal sequence (e.g. U+009B CSI).
                for l in json.lines() {
                    lines.push(Line::from(Span::styled(
                        sanitize_line(l),
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
    use crate::tui::widgets::page;

    /// Draw this lens's page as the TUI does.
    fn render(
        f: &mut ratatui::Frame,
        area: ratatui::layout::Rect,
        theme: &Theme,
        bulk: &BulkState,
        editing: Option<&LineEditor>,
        spin: usize,
    ) {
        page::draw(f, area, theme, page(theme, bulk, editing, spin), false);
    }
    use crate::tui::test_util::render_text;
    use seer_core::bulk::{BulkOperation, BulkResult};

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

        let text = render_text(80, 24, |f| render(f, f.area(), &theme, &bulk, None, 0));
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
        let text = render_text(80, 14, |f| render(f, f.area(), &theme, &bulk, None, 0));
        assert!(
            text.contains("d49.com"),
            "the newest streamed row should be pinned in view"
        );
    }

    #[test]
    fn spinner_animates_with_app_spin_index() {
        // Mirror of the follow-lens regression: the running spinner was
        // hardcoded to SPIN[0] and never animated (2026-07-11 review).
        let theme = Theme::frappe();
        let bulk = BulkState {
            running: true,
            ..Default::default()
        };

        let text = render_text(80, 24, |f| render(f, f.area(), &theme, &bulk, None, 3));
        assert!(
            text.contains(SPIN[3]),
            "spinner should render the current animation frame"
        );
    }

    #[test]
    fn renders_idle_placeholder_when_empty() {
        let theme = Theme::frappe();
        let bulk = BulkState::default();

        let text = render_text(80, 24, |f| render(f, f.area(), &theme, &bulk, None, 0));
        assert!(
            text.contains("enter domains"),
            "empty state should show 'enter domains' placeholder"
        );
    }

    #[test]
    fn renders_op_chips_row() {
        let theme = Theme::frappe();
        let bulk = BulkState::default();

        let text = render_text(80, 24, |f| render(f, f.area(), &theme, &bulk, None, 0));
        assert!(text.contains("lookup"), "op chips should show 'lookup'");
        assert!(text.contains("status"), "op chips should show 'status'");
    }

    #[test]
    fn empty_state_prompts_for_domains() {
        let theme = Theme::frappe();
        let bulk = BulkState::default();
        let text = render_text(80, 24, |f| render(f, f.area(), &theme, &bulk, None, 0));
        assert!(text.contains("press d to enter"), "prompts for domains");
        assert!(text.contains("d domains"), "shows the new hint row");
    }

    #[test]
    fn shows_ok_failed_summary() {
        let theme = Theme::frappe();
        let mut bulk = BulkState::default();
        bulk.rows.push(make_result("ok.com", true));
        bulk.rows.push(make_result("bad.com", false));
        let text = render_text(80, 24, |f| render(f, f.area(), &theme, &bulk, None, 0));
        assert!(text.contains("1 ok"), "summary should report ok count");
        assert!(text.contains("1 failed"), "summary should report failures");
    }

    #[test]
    fn results_title_names_the_runs_op_after_o_changes_selection() {
        let theme = Theme::frappe();
        let mut bulk = BulkState {
            run_op_idx: Some(0), // rows came from `lookup`
            op_idx: 1,           // `o` since selected `status`
            ..Default::default()
        };
        bulk.rows.push(make_result("a.com", true));
        let text = render_text(80, 24, |f| render(f, f.area(), &theme, &bulk, None, 0));
        assert!(text.contains("seer bulk lookup"), "got: {text}");
        assert!(!text.contains("seer bulk status"), "got: {text}");
    }

    #[test]
    fn domains_caret_renders_at_the_cursor() {
        let theme = Theme::frappe();
        let bulk = BulkState::default();
        let mut editor = LineEditor::from("a.com");
        editor.home();
        let text = render_text(80, 24, |f| {
            render(f, f.area(), &theme, &bulk, Some(&editor), 0);
        });
        assert!(text.contains("domains: ▏a.com"));
    }

    #[test]
    fn detail_panel_shows_error_for_selected_row() {
        let theme = Theme::frappe();
        let mut bulk = BulkState::default();
        bulk.rows.push(make_result("bad.com", false)); // error: "timeout"
        bulk.selected = Some(0);
        bulk.detail = true;
        let text = render_text(80, 24, |f| render(f, f.area(), &theme, &bulk, None, 0));
        assert!(text.contains("Detail"), "detail panel header should render");
        assert!(
            text.contains("timeout"),
            "detail panel should show the row error"
        );
    }
}
