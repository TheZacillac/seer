//! Follow lens — live DNS monitor: progress gauge + change log table.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::app::SPIN;
use crate::tui::panes::FollowState;
use crate::tui::theme::Theme;
use crate::tui::widgets::{dot, gauge, panel};

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, follow: &FollowState, spin: usize) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(0)])
        .split(area);

    // ── top panel: progress gauge + status ──────────────────────────────────
    let top_title = format!(
        "Follow  ·  {}s interval  ·  {} checks",
        follow.interval_secs, follow.count
    );
    let top_block = panel::block(theme, &top_title, theme.teal, false);
    let top_inner = top_block.inner(rows[0]);
    f.render_widget(top_block, rows[0]);

    let ratio = if follow.count > 0 {
        follow.log.len() as f64 / follow.count as f64
    } else {
        0.0
    };
    let gauge_label = format!("{}/{} done", follow.log.len(), follow.count);
    let gauge_line = gauge::line(ratio, 30, theme.teal, Some(&gauge_label));

    let spin_text = if follow.running {
        format!("  {} polling…", SPIN[spin % SPIN.len()])
    } else {
        "  idle".to_string()
    };
    let status_line = Line::from(vec![Span::styled(
        spin_text,
        Style::default().fg(if follow.running {
            theme.teal
        } else {
            theme.overlay0
        }),
    )]);

    let hints_line = Line::from(vec![Span::styled(
        "s start  ·  i interval  ·  n count  ·  x stop",
        Style::default().fg(theme.overlay0),
    )]);

    let top_para = Paragraph::new(vec![gauge_line, status_line, hints_line]);
    f.render_widget(top_para, top_inner);

    // ── bottom panel: change log table ──────────────────────────────────────
    let log_block = panel::block(theme, "Change Log", theme.teal, false);
    let log_inner = log_block.inner(rows[1]);
    f.render_widget(log_block, rows[1]);

    if follow.log.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(vec![Span::styled(
                "waiting for first check…",
                Style::default()
                    .fg(theme.overlay0)
                    .add_modifier(Modifier::ITALIC),
            )])),
            log_inner,
        );
        return;
    }

    let header =
        Row::new(["#", "TIME", "A RECORD", "Δ"]).style(Style::default().fg(theme.overlay0));

    let body = follow.log.iter().map(|it| {
        // An errored iteration (NXDOMAIN/timeout/resolver failure) has empty
        // records and changed=false; without inspecting it.error it would paint
        // identically to a healthy no-A-record check. Surface the failure.
        let (a_record, delta) = if !it.success() {
            let msg = it.error.as_deref().unwrap_or("error");
            (
                msg.chars().take(40).collect::<String>(),
                dot::line(theme, "fail", "ERROR"),
            )
        } else {
            let a = it
                .records
                .first()
                .map(|r| r.format_short())
                .unwrap_or_else(|| "—".into());
            let d = if it.changed {
                dot::line(theme, "warn", "CHANGED")
            } else {
                dot::line(theme, "ok", "—")
            };
            (a, d)
        };
        Row::new(vec![
            Line::from(it.iteration.to_string()),
            Line::from(it.timestamp.format("%H:%M:%S").to_string()),
            Line::from(a_record),
            delta,
        ])
        .style(Style::default().fg(theme.text))
    });

    let table = Table::new(
        body,
        [
            Constraint::Length(4),
            Constraint::Length(10),
            Constraint::Percentage(50),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .column_spacing(1);

    f.render_widget(table, log_inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use seer_core::dns::FollowIteration;

    fn make_iteration(iteration: usize, record_value: &str, changed: bool) -> FollowIteration {
        use seer_core::dns::{DnsRecord, RecordData};
        use seer_core::RecordType;

        let records = if record_value.is_empty() {
            vec![]
        } else {
            vec![DnsRecord {
                name: "example.com".into(),
                record_type: RecordType::A,
                ttl: 300,
                data: RecordData::A {
                    address: record_value.into(),
                },
            }]
        };

        FollowIteration {
            iteration,
            total_iterations: 5,
            timestamp: Utc::now(),
            records,
            changed,
            added: if changed {
                vec![record_value.into()]
            } else {
                vec![]
            },
            removed: vec![],
            error: None,
        }
    }

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

    #[test]
    fn renders_a_record_in_log() {
        let theme = Theme::frappe();
        let mut follow = FollowState::default();
        follow.push(make_iteration(1, "1.2.3.4", false));
        follow.push(make_iteration(2, "1.2.3.4", true));

        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &follow, 0))
            .unwrap();
        let text = buf_text(&terminal);
        assert!(
            text.contains("1.2.3.4"),
            "rendered buffer should contain A record IP"
        );
    }

    #[test]
    fn renders_error_iteration_as_failure_not_healthy() {
        // An errored iteration (empty records, changed=false) must NOT be
        // painted like a healthy no-record check; it should surface the error.
        let theme = Theme::frappe();
        let mut follow = FollowState::default();
        follow.push(FollowIteration {
            iteration: 1,
            total_iterations: 5,
            timestamp: Utc::now(),
            records: vec![],
            changed: false,
            added: vec![],
            removed: vec![],
            error: Some("NXDOMAIN".into()),
        });

        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &follow, 0))
            .unwrap();
        let text = buf_text(&terminal);
        assert!(
            text.contains("ERROR"),
            "errored iteration should render an ERROR marker"
        );
        assert!(
            text.contains("NXDOMAIN"),
            "errored iteration should surface the error message"
        );
    }

    #[test]
    fn spinner_animates_with_app_spin_index() {
        // The polling spinner was hardcoded to SPIN[0], so it froze on the
        // first frame for the whole run while every other loading indicator
        // in the TUI animates via app.spin (2026-07-11 review).
        let theme = Theme::frappe();
        let follow = FollowState {
            running: true,
            ..Default::default()
        };

        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &follow, 3))
            .unwrap();
        let text = buf_text(&terminal);
        assert!(
            text.contains(SPIN[3]),
            "spinner should render the current animation frame"
        );
    }

    #[test]
    fn renders_waiting_when_log_empty() {
        let theme = Theme::frappe();
        let follow = FollowState::default();

        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &follow, 0))
            .unwrap();
        let text = buf_text(&terminal);
        assert!(
            text.contains("waiting"),
            "empty log should show 'waiting' placeholder"
        );
    }
}
