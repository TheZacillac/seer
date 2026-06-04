//! Block-char gauge: █ filled, ░ empty, like ratatui's Gauge but glyph-styled.
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

/// Returns the number of filled cells for a ratio over `width`.
pub fn filled_cells(ratio: f64, width: u16) -> u16 {
    let r = ratio.clamp(0.0, 1.0);
    (r * width as f64).round() as u16
}

/// Build a styled gauge line: filled bar + empty bar + optional label.
pub fn line<'a>(ratio: f64, width: u16, color: Color, label: Option<&'a str>) -> Line<'a> {
    let f = filled_cells(ratio, width);
    let mut spans = vec![
        Span::styled("█".repeat(f as usize), Style::default().fg(color)),
        Span::styled(
            "░".repeat(width.saturating_sub(f) as usize),
            Style::default().fg(Color::Rgb(0x51, 0x57, 0x6d)),
        ),
    ];
    if let Some(l) = label {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            l.to_string(),
            Style::default().fg(Color::Rgb(0xb5, 0xbf, 0xe2)),
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
}
