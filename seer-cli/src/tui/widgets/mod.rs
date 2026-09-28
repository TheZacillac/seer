//! Small reusable TUI building blocks: `panel` (bordered block → inner
//! `Rect`), `kv` rows, `gauge`, status `dot` and `chips`, plus the shared
//! `or_dash` missing-value mark, `row_style` selection styling, and `stack`
//! and `wrap` for bands sized to their content before they are drawn.

pub mod chips;
pub mod dot;
pub mod gauge;
pub mod kv;
pub mod panel;

use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::Span;
use ratatui::widgets::TableState;

use crate::tui::theme::Theme;

/// `value` as text, or an em dash (the TUI's missing-value mark) when absent.
pub fn or_dash<T: ToString>(value: Option<T>) -> String {
    value.map_or_else(|| "—".to_string(), |v| v.to_string())
}

/// Style for one row of a selectable list: body text, on the `surface0`
/// selection band when `selected`.
///
/// Applied per row rather than via `Table::row_highlight_style`: ratatui clamps
/// an out-of-range selection to the last row, so a stale `sel` (e.g. while a
/// live `/` filter narrows the list) would highlight a row the App doesn't
/// consider selected.
pub fn row_style(theme: &Theme, selected: bool) -> Style {
    let style = Style::default().fg(theme.text);
    if selected {
        style.bg(theme.surface0)
    } else {
        style
    }
}

/// Build a `TableState` that keeps `selected` in view.
///
/// The list lenses render plain `Table`s, which (rendered non-statefully) never
/// scroll — a selection past the viewport edge becomes invisible. Rendering the
/// same table via `render_stateful_widget` with this state lets ratatui scroll
/// so the selected row stays on screen. The offset starts at 0 each frame;
/// ratatui recomputes it from `selected`, so no cross-frame state is needed.
/// Pass `None` (e.g. when a pane isn't focused) to leave the list at the top.
pub fn scroll_to(selected: Option<usize>) -> TableState {
    TableState::default().with_selected(selected)
}

/// Bands of the given `heights` stacked down `area` from its top, one blank
/// row apart. When they do not all fit, the band at `flex`, if any (a
/// scrolling table), gives up rows first, so the fixed bands after it — a
/// verdict, a note — stay whole; whatever still overflows is clipped at the
/// bottom.
pub fn stack(area: Rect, heights: &[u16], flex: Option<usize>) -> Vec<Rect> {
    let gaps = heights.len().saturating_sub(1);
    let total = heights.iter().map(|&h| usize::from(h)).sum::<usize>() + gaps;
    let excess = u16::try_from(total.saturating_sub(usize::from(area.height))).unwrap_or(u16::MAX);
    let mut y = area.y;
    heights
        .iter()
        .enumerate()
        .map(|(i, &height)| {
            let height = if flex == Some(i) {
                height.saturating_sub(excess)
            } else {
                height
            };
            let top = y.min(area.bottom());
            let height = height.min(area.bottom() - top);
            y = top.saturating_add(height).saturating_add(1);
            Rect {
                y: top,
                height,
                ..area
            }
        })
        .collect()
}

/// `text` split at spaces into lines at most `width` columns wide, filled
/// greedily. For a note whose area must be sized to it before it is drawn:
/// ratatui's own wrapping does not report how many lines it produced. A word
/// wider than the line gets a line of its own and is clipped when drawn.
pub fn wrap(text: &str, width: u16) -> Vec<String> {
    let width = usize::from(width);
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split(' ').filter(|w| !w.is_empty()) {
        if line.is_empty() {
            line.push_str(word);
        } else if Span::raw(line.as_str()).width() + 1 + Span::raw(word).width() <= width {
            line.push(' ');
            line.push_str(word);
        } else {
            lines.push(std::mem::replace(&mut line, word.to_string()));
        }
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_places_bands_top_down_one_row_apart() {
        let area = Rect::new(2, 5, 40, 20);
        let bands = stack(area, &[3, 1, 2], Some(0));
        let spans: Vec<(u16, u16)> = bands.iter().map(|r| (r.y, r.height)).collect();
        assert_eq!(spans, [(5, 3), (9, 1), (11, 2)]);
        assert!(bands.iter().all(|r| r.x == 2 && r.width == 40));
    }

    #[test]
    fn stack_shrinks_the_flex_band_so_the_rest_fit() {
        // 30 + 1 + 1 + 1 + 2 = 35 rows wanted in 10: the table keeps 5.
        let bands = stack(Rect::new(0, 0, 40, 10), &[30, 1, 2], Some(0));
        let spans: Vec<(u16, u16)> = bands.iter().map(|r| (r.y, r.height)).collect();
        assert_eq!(spans, [(0, 5), (6, 1), (8, 2)]);
        // Too little room even without the table: clipped, never past the area.
        let bands = stack(Rect::new(0, 0, 40, 3), &[4, 2, 2], Some(0));
        assert!(bands.iter().all(|r| r.bottom() <= 3), "{bands:?}");
        // With no flex band, the overflow is clipped at the bottom only.
        let bands = stack(Rect::new(0, 0, 40, 4), &[1, 3], None);
        let spans: Vec<(u16, u16)> = bands.iter().map(|r| (r.y, r.height)).collect();
        assert_eq!(spans, [(0, 1), (2, 2)]);
    }

    #[test]
    fn wrap_fills_lines_greedily_at_spaces() {
        assert_eq!(
            wrap("a random sibling resolves too", 12),
            ["a random", "sibling", "resolves too"]
        );
        assert_eq!(wrap("fits on one line", 40), ["fits on one line"]);
        assert!(wrap("", 10).is_empty());
        assert!(wrap("   ", 10).is_empty());
    }

    #[test]
    fn wrap_measures_display_width_and_keeps_long_words_whole() {
        // "—" is one column wide, so the phrase fits in 15 columns exactly.
        assert_eq!(wrap("resolves — this", 15), ["resolves — this"]);
        assert_eq!(
            wrap("see seer-probe-3f9a1c2e7b.seer.test now", 10),
            ["see", "seer-probe-3f9a1c2e7b.seer.test", "now"]
        );
    }
}
