//! Block-char gauge: █ filled, ░ empty, like ratatui's Gauge but glyph-styled.
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

use crate::tui::theme::Theme;

/// Returns the number of filled cells for a ratio over `width`.
pub fn filled_cells(ratio: f64, width: u16) -> u16 {
    let r = ratio.clamp(0.0, 1.0);
    (r * width as f64).round() as u16
}

/// Build a styled gauge line: filled bar + empty bar + optional label.
/// Track and label colors come from `theme` (matching the dot/chips
/// convention) so the gauge stays readable under both Frappé and Latte.
pub fn line<'a>(
    theme: &Theme,
    ratio: f64,
    width: u16,
    color: Color,
    label: Option<&'a str>,
) -> Line<'a> {
    let f = filled_cells(ratio, width);
    let mut spans = vec![
        Span::styled("█".repeat(f as usize), Style::default().fg(color)),
        Span::styled(
            "░".repeat(width.saturating_sub(f) as usize),
            Style::default().fg(theme.surface1),
        ),
    ];
    if let Some(l) = label {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            l.to_string(),
            Style::default().fg(theme.subtext),
        ));
    }
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filled_cells_rounds_and_clamps() {
        assert_eq!(filled_cells(0.0, 30), 0);
        assert_eq!(filled_cells(1.0, 30), 30);
        assert_eq!(filled_cells(0.5, 30), 15);
        assert_eq!(filled_cells(2.0, 10), 10); // clamp
    }

    #[test]
    fn gauge_colors_follow_the_active_theme() {
        // Empty track and label must come from the active theme: these were
        // the TUI's only hardcoded Frappé colors, leaving gauge labels at
        // ~1.6:1 contrast (unreadable) under Latte.
        for theme in [Theme::frappe(), Theme::latte()] {
            let gauge = line(&theme, 0.5, 10, theme.green, Some("5/10"));
            // Spans: [filled, empty-track, spacer, label].
            assert_eq!(gauge.spans[1].style.fg, Some(theme.surface1), "track");
            assert_eq!(gauge.spans[3].style.fg, Some(theme.subtext), "label");
        }
    }
}
