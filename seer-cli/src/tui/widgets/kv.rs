//! Key/value rows with dotted leaders, like a WHOIS dump.
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::tui::theme::Theme;

/// Render rows of `(key, value)` with dotted leaders filling `area` width.
pub fn render(f: &mut Frame, area: Rect, theme: &Theme, key_color: ratatui::style::Color, rows: &[(String, String)]) {
    let width = area.width as usize;
    let lines: Vec<Line> = rows
        .iter()
        .map(|(k, v)| {
            let used = k.chars().count() + v.chars().count() + 2;
            let dots = width.saturating_sub(used).max(1);
            Line::from(vec![
                Span::styled(k.clone(), Style::default().fg(key_color)),
                Span::styled(format!(" {} ", ".".repeat(dots)), Style::default().fg(theme.surface1)),
                Span::styled(v.clone(), Style::default().fg(theme.text)),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines), area);
}
