//! A wrapped row of chips (small bordered labels).
use ratatui::style::Style;
use ratatui::text::{Line, Span};

use crate::tui::theme::Theme;

pub fn line<'a>(theme: &Theme, items: &[String]) -> Line<'a> {
    let mut spans = Vec::new();
    for (i, it) in items.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" "));
        }
        spans.push(Span::styled(
            format!(" {it} "),
            Style::default().fg(theme.subtext).bg(theme.surface0),
        ));
    }
    Line::from(spans)
}
