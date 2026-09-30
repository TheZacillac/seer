//! Key/value rows with dotted leaders, like a WHOIS dump. Values are
//! sanitized here, so a row cannot skip the terminal guard.
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use seer_core::output::sanitize_line;

use crate::tui::theme::Theme;

/// Render rows of `(key, value)` with dotted leaders filling `area` width.
/// Values are remote data, so each passes `sanitize_line` (one line, no
/// terminal escapes).
pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    key_color: ratatui::style::Color,
    rows: &[(&str, String)],
) {
    let width = area.width as usize;
    let lines: Vec<Line> = rows
        .iter()
        .map(|(k, v)| {
            let v = sanitize_line(v);
            let used = k.chars().count() + v.chars().count() + 2;
            let dots = width.saturating_sub(used).max(1);
            Line::from(vec![
                Span::styled(*k, Style::default().fg(key_color)),
                Span::styled(
                    format!(" {} ", ".".repeat(dots)),
                    Style::default().fg(theme.surface1),
                ),
                Span::styled(v, Style::default().fg(theme.text)),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines), area);
}
