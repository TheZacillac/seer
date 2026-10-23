//! Watchlist lens — selectable table of watched domains with health indicators.
use ratatui::layout::Constraint;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Row;
use seer_core::output::sanitize_line;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::or_dash;
use crate::tui::widgets::page::{Block, Page, TableBlock};

/// Red under two weeks left, yellow under a month.
fn days_color(theme: &Theme, days: Option<i64>) -> ratatui::style::Color {
    match days {
        Some(d) if d < 14 => theme.red,
        Some(d) if d < 30 => theme.yellow,
        _ => theme.text,
    }
}

pub fn page(theme: &Theme, data: &LensData, focused: bool, sel: usize) -> Option<Page> {
    let LensData::Watch(w) = data else {
        return None;
    };

    let summary = Line::from(vec![
        Span::styled(
            format!("{} domains", w.total),
            Style::default().fg(theme.text),
        ),
        Span::styled("  warnings: ", Style::default().fg(theme.overlay0)),
        Span::styled(w.warnings.to_string(), Style::default().fg(theme.yellow)),
        Span::styled("  critical: ", Style::default().fg(theme.overlay0)),
        Span::styled(w.critical.to_string(), Style::default().fg(theme.red)),
    ]);

    let rows = w
        .results
        .iter()
        .map(|r| {
            let issues_flag = if r.issues.is_empty() { "" } else { "!" };
            Row::new(vec![
                Span::raw(sanitize_line(&r.domain)),
                Span::styled(
                    or_dash(r.domain_days_remaining),
                    Style::default().fg(days_color(theme, r.domain_days_remaining)),
                ),
                Span::styled(
                    or_dash(r.ssl_days_remaining),
                    Style::default().fg(days_color(theme, r.ssl_days_remaining)),
                ),
                Span::raw(or_dash(r.http_status)),
                Span::styled(issues_flag, Style::default().fg(theme.red)),
            ])
        })
        .collect();
    let table = TableBlock::new(
        vec!["DOMAIN", "EXPIRES(d)", "SSL(d)", "HTTP", "⚑"],
        vec![
            Constraint::Percentage(40),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Length(3),
        ],
        rows,
    )
    .selected(focused.then_some(sel));
    Some(
        Page::new("Watchlist", theme.yellow)
            .push(Block::Lines(vec![summary]))
            .push(Block::Gap)
            .push(Block::Table(table))
            .push(Block::Gap)
            .push(Block::Lines(vec![Line::from(Span::styled(
                "a add · d remove (press twice) · ↵ open",
                Style::default().fg(theme.overlay0),
            ))])),
    )
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
        data: &LensData,
        focused: bool,
        sel: usize,
    ) {
        if let Some(p) = page(theme, data, focused, sel) {
            page::draw(f, area, theme, p, focused);
        }
    }
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
