//! Overview lens — merged registration summary from the smart lookup.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{kv, panel};

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, data: &LensData) {
    let LensData::Overview(result) = data else {
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(0)])
        .split(area);

    let source = if result.is_available() {
        ("AVAILABLE", theme.green)
    } else if result.is_rdap() {
        ("RDAP", theme.mauve)
    } else {
        ("WHOIS", theme.peach)
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                result.domain_name().unwrap_or_default(),
                Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                source.0,
                Style::default().fg(source.1).add_modifier(Modifier::BOLD),
            ),
        ])),
        chunks[0],
    );

    let block = panel::block(theme, "Registration", theme.blue, false);
    let inner = block.inner(chunks[1]);
    f.render_widget(block, chunks[1]);

    let dash = || "—".to_string();
    let (expiry, registrar) = result.expiration_info();
    let rows: Vec<(String, String)> = vec![
        ("registrar".into(), registrar.unwrap_or_else(dash)),
        (
            "organization".into(),
            result.organization().unwrap_or_else(dash),
        ),
        (
            "expires".into(),
            expiry
                .map(|d| d.date_naive().to_string())
                .unwrap_or_else(dash),
        ),
        ("source".into(), source.0.to_string()),
    ];
    kv::render(f, inner, theme, theme.blue, &rows);
}

// Verified to compile; runtime rendering not yet exercised on a live terminal.
