//! Propagation lens — summary gauge + resolver table.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{gauge, or_dash, panel, row_style, scroll_to};

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

    let top_inner = panel::render(f, rows[0], theme, "Propagation", theme.teal, false);
    let ratio = if p.servers_checked > 0 {
        p.servers_responding as f64 / p.servers_checked as f64
    } else {
        0.0
    };
    let label = format!("{}/{} resolved", p.servers_responding, p.servers_checked);
    f.render_widget(
        Paragraph::new(gauge::line(theme, ratio, 30, theme.green, Some(&label))),
        top_inner,
    );

    let inner = panel::render(f, rows[1], theme, "Resolvers", theme.teal, focused);
    let header = Row::new(["RESOLVER", "PROVIDER", "REGION", "ANSWER", ""])
        .style(Style::default().fg(theme.overlay0));
    let body = p.results.iter().enumerate().map(|(i, sr)| {
        let answer = or_dash(sr.records.first().map(|r| r.format_short()));
        let state = if sr.success {
            format!("{}ms", sr.response_time_ms)
        } else {
            "fail".into()
        };
        Row::new(vec![
            sr.server.ip.clone(),
            sr.server.provider.clone(),
            sr.server.location.clone(),
            answer,
            state,
        ])
        .style(row_style(theme, focused && i == sel))
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
    let mut state = scroll_to(focused.then_some(sel));
    f.render_stateful_widget(table, inner, &mut state);
}
