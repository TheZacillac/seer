//! Propagation lens — summary gauge + resolver table.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{gauge, panel};

pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    data: &LensData,
    focused: bool,
    sel: usize,
) {
    let LensData::Prop(p) = data else { return };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    let top = panel::block(theme, "Propagation", theme.teal, false);
    let top_inner = top.inner(rows[0]);
    f.render_widget(top, rows[0]);
    let ratio = if p.servers_checked > 0 {
        p.servers_responding as f64 / p.servers_checked as f64
    } else {
        0.0
    };
    let label = format!("{}/{} resolved", p.servers_responding, p.servers_checked);
    f.render_widget(
        Paragraph::new(gauge::line(ratio, 30, theme.green, Some(&label))),
        top_inner,
    );

    let block = panel::block(theme, "Resolvers", theme.teal, focused);
    let inner = block.inner(rows[1]);
    f.render_widget(block, rows[1]);
    let header = Row::new(["RESOLVER", "PROVIDER", "REGION", "ANSWER", ""])
        .style(Style::default().fg(theme.overlay0));
    let body = p.results.iter().enumerate().map(|(i, sr)| {
        let answer = sr
            .records
            .first()
            .map(|r| r.format_short())
            .unwrap_or_else(|| "—".into());
        let state = if sr.success {
            format!("{}ms", sr.response_time_ms)
        } else {
            "fail".into()
        };
        let style = if focused && i == sel {
            Style::default().fg(theme.text).bg(theme.surface0)
        } else {
            Style::default().fg(theme.text)
        };
        Row::new(vec![
            sr.server.ip.clone(),
            sr.server.provider.clone(),
            sr.server.location.clone(),
            answer,
            state,
        ])
        .style(style)
    });
    let table = Table::new(
        body,
        [
            Constraint::Length(16),
            Constraint::Length(14),
            Constraint::Length(8),
            Constraint::Percentage(40),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .column_spacing(1);
    f.render_widget(table, inner);
}

// Verified to compile; exercised by the live smoke test.
