//! Colored status dot + label.
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use seer_core::output::sanitize_line;

use crate::tui::theme::Theme;

/// `● label` colored by tone. `wait` uses a half-circle glyph. Labels often
/// quote remote data (certificate warnings, header advisories), so they are
/// sanitized.
pub fn line<'a>(theme: &Theme, tone: &str, label: impl Into<String>) -> Line<'a> {
    let glyph = if tone == "wait" { "◐ " } else { "● " };
    Line::from(vec![
        Span::styled(glyph, Style::default().fg(theme.tone(tone))),
        Span::styled(
            sanitize_line(&label.into()),
            Style::default().fg(theme.tone(tone)),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_line_has_two_spans() {
        let t = Theme::frappe();
        let l = line(&t, "ok", "HTTP 200");
        assert_eq!(l.spans.len(), 2);
        assert!(l.spans[1].content.contains("HTTP 200"));
    }
}
