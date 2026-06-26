//! Watchlist lens — selectable table of watched domains with health indicators.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{panel, scroll_to};

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
    let summary_block = panel::block(theme, "Watchlist", theme.yellow, false);
    let summary_inner = summary_block.inner(chunks[0]);
    f.render_widget(summary_block, chunks[0]);
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
    let block = panel::block(theme, "Domains", theme.yellow, focused);
    let inner = block.inner(chunks[1]);
    f.render_widget(block, chunks[1]);

    let header = Row::new(["DOMAIN", "EXPIRES(d)", "SSL(d)", "HTTP", "⚑"])
        .style(Style::default().fg(theme.overlay0));

    let rows = w.results.iter().enumerate().map(|(i, r)| {
        let expires = r
            .domain_days_remaining
            .map(|d| d.to_string())
            .unwrap_or_else(|| "—".into());
        let ssl = r
            .ssl_days_remaining
            .map(|d| d.to_string())
            .unwrap_or_else(|| "—".into());
        let http = r
            .http_status
            .map(|c| c.to_string())
            .unwrap_or_else(|| "—".into());
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

        let base_style = if focused && i == sel {
            Style::default().fg(theme.text).bg(theme.surface0)
        } else {
            Style::default().fg(theme.text)
        };

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
    use chrono::Utc;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use seer_core::{WatchReport, WatchResult};

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
        let backend = TestBackend::new(80, 14);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data, false, 0))
            .unwrap();
        assert!(buf_text(terminal.backend().buffer()).contains("x.com"));
    }
}
