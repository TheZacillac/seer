//! Watchlist lens — selectable table of watched domains with health indicators.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{or_dash, panel, row_style, scroll_to};

pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    data: &LensData,
    focused: bool,
    sel: usize,
) {
    let LensData::Watch(w) = data else {
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    // Summary bar
    let summary_inner = panel::render(f, chunks[0], theme, "Watchlist", theme.yellow, false);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("{} domains", w.total),
                Style::default().fg(theme.text),
            ),
            Span::styled("  warnings: ", Style::default().fg(theme.overlay0)),
            Span::styled(w.warnings.to_string(), Style::default().fg(theme.yellow)),
            Span::styled("  critical: ", Style::default().fg(theme.overlay0)),
            Span::styled(w.critical.to_string(), Style::default().fg(theme.red)),
        ])),
        summary_inner,
    );

    // Results table
    let inner = panel::render(f, chunks[1], theme, "Domains", theme.yellow, focused);

    let header = Row::new(["DOMAIN", "EXPIRES(d)", "SSL(d)", "HTTP", "⚑"])
        .style(Style::default().fg(theme.overlay0));

    let rows = w.results.iter().enumerate().map(|(i, r)| {
        let expires = or_dash(r.domain_days_remaining);
        let ssl = or_dash(r.ssl_days_remaining);
        let http = or_dash(r.http_status);
        let issues_flag = if r.issues.is_empty() { "" } else { "!" };

        let expires_color = match r.domain_days_remaining {
            Some(d) if d < 14 => theme.red,
            Some(d) if d < 30 => theme.yellow,
            _ => theme.text,
        };
        let ssl_color = match r.ssl_days_remaining {
            Some(d) if d < 14 => theme.red,
            Some(d) if d < 30 => theme.yellow,
            _ => theme.text,
        };

        let base_style = row_style(theme, focused && i == sel);
        Row::new(vec![
            ratatui::text::Text::from(Span::styled(r.domain.clone(), base_style)),
            ratatui::text::Text::from(Span::styled(expires, Style::default().fg(expires_color))),
            ratatui::text::Text::from(Span::styled(ssl, Style::default().fg(ssl_color))),
            ratatui::text::Text::from(Span::styled(http, base_style)),
            ratatui::text::Text::from(Span::styled(issues_flag, Style::default().fg(theme.red))),
        ])
    });

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(40),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Length(3),
        ],
    )
    .header(header)
    .column_spacing(1);
    let mut state = scroll_to(focused.then_some(sel));
    f.render_stateful_widget(table, inner, &mut state);

    // Hint line
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "a add · d remove · ↵ open",
            Style::default().fg(theme.overlay0),
        ))),
        chunks[2],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::test_util::render_text;
    use chrono::Utc;
    use seer_core::{WatchReport, WatchResult};

    #[test]
    fn renders_watched_domain() {
        let theme = Theme::frappe();
        let data = LensData::Watch(Box::new(WatchReport {
            checked_at: Utc::now(),
            results: vec![WatchResult {
                domain: "x.com".into(),
                ssl_days_remaining: Some(90),
                domain_days_remaining: Some(180),
                registrar: Some("NameCheap".into()),
                http_status: Some(200),
                issues: vec![],
            }],
            total: 1,
            warnings: 0,
            critical: 0,
        }));
        let text = render_text(80, 14, |f| render(f, f.area(), &theme, &data, false, 0));
        assert!(text.contains("x.com"));
    }
}
