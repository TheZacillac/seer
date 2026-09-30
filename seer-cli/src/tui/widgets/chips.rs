//! A wrapped row of chips (small bordered labels).
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use seer_core::output::sanitize_line;

use crate::tui::theme::Theme;

/// One chip per item; items are remote data (certificate SANs), so each is
/// sanitized.
pub fn line<'a>(theme: &Theme, items: &[String]) -> Line<'a> {
    let mut spans = Vec::new();
    for (i, it) in items.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" "));
        }
        spans.push(Span::styled(
            format!(" {} ", sanitize_line(it)),
            Style::default().fg(theme.subtext).bg(theme.surface0),
        ));
    }
    Line::from(spans)
}
