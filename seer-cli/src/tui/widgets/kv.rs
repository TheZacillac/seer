//! Key/value rows, like a WHOIS dump: keys share a gutter, dotted leaders
//! run to it, and values wrap under the value column. Values are sanitized
//! here, so a row cannot skip the terminal guard.
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use seer_core::output::sanitize_line;

use crate::tui::theme::Theme;
use crate::tui::widgets::wrap_hard;

/// The value column for a block with these `keys`: two leader dots past the
/// longest key, at most half of `width` so values keep room.
pub fn gutter<'a>(keys: impl IntoIterator<Item = &'a str>, width: u16) -> usize {
    let longest = keys
        .into_iter()
        .map(|k| Span::raw(k).width())
        .max()
        .unwrap_or(0);
    (longest + 4).min(usize::from(width) / 2)
}

/// `key` and the `·` leaders that carry it to `gutter`.
pub fn leader(theme: &Theme, key: &str, key_color: Color, gutter: usize) -> [Span<'static>; 2] {
    let dots = gutter.saturating_sub(Span::raw(key).width() + 2).max(1);
    [
        Span::styled(key.to_string(), Style::default().fg(key_color)),
        Span::styled(
            format!(" {} ", "·".repeat(dots)),
            Style::default().fg(theme.surface1),
        ),
    ]
}

/// Rows of `(key, value)` as lines `width` wide: each key and its leaders,
/// then the value, wrapped under the value column. Values are remote data,
/// so each passes `sanitize_line` (no terminal escapes).
pub fn lines(
    theme: &Theme,
    key_color: Color,
    rows: &[(&str, String)],
    width: u16,
) -> Vec<Line<'static>> {
    let gutter = gutter(rows.iter().map(|(k, _)| *k), width);
    let value_w = u16::try_from(usize::from(width).saturating_sub(gutter)).unwrap_or(0);
    let mut out = Vec::new();
    for (k, v) in rows {
        let mut chunks = wrap_hard(&sanitize_line(v), value_w);
        if chunks.is_empty() {
            chunks.push(String::new());
        }
        for (i, chunk) in chunks.into_iter().enumerate() {
            let mut spans = if i == 0 {
                leader(theme, k, key_color, gutter).to_vec()
            } else {
                vec![Span::raw(" ".repeat(gutter))]
            };
            spans.push(Span::styled(chunk, Style::default().fg(theme.text)));
            out.push(Line::from(spans));
        }
    }
    out
}

/// Draw [`lines`] for `rows` into `area`.
pub fn render(f: &mut Frame, area: Rect, theme: &Theme, key_color: Color, rows: &[(&str, String)]) {
    f.render_widget(
        Paragraph::new(lines(theme, key_color, rows, area.width)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::test_util::render_lines;

    #[test]
    fn leaders_stop_at_a_shared_gutter() {
        let theme = Theme::frappe();
        let rows = [
            ("registrar", "IANA".to_string()),
            ("expires", "2027-08-13".to_string()),
        ];
        let s = render_lines(80, 2, |f| render(f, f.area(), &theme, theme.blue, &rows));
        let lines: Vec<&str> = s.lines().collect();
        assert!(lines[0].starts_with("registrar ·· IANA"), "{s}");
        assert!(lines[1].starts_with("expires ···· 2027-08-13"), "{s}");
    }

    #[test]
    fn long_values_wrap_under_the_value_column_sanitized() {
        let theme = Theme::frappe();
        let rows = [("ns", format!("{}\x1b[2J", "a".repeat(30)))];
        let got = lines(&theme, theme.blue, &rows, 20);
        assert!(got.len() > 1, "{got:?}");
        let text: String = got
            .iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.to_string()))
            .collect();
        assert!(!text.contains('\x1b'), "{text:?}");
    }
}
