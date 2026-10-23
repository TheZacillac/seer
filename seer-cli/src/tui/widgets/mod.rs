//! Small reusable TUI building blocks: `panel` (bordered block → inner
//! `Rect`), `kv` rows, `gauge`, status `dot` and `chips`, the selected-row
//! `inspector`, the `page` every lens is drawn through, plus the shared
//! `or_dash` missing-value mark, `row_style` selection styling, `scroll_to`,
//! and `wrap` / `wrap_hard` for text sized to its width before it is drawn.

pub mod chips;
pub mod dot;
pub mod gauge;
pub mod inspector;
pub mod kv;
pub mod page;
pub mod panel;

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

/// `text` split into lines at most `width` columns wide, breaking at the
/// last space that fits (the spaces at a break are dropped) and splitting a
/// run with no space mid-word. Unlike [`wrap`], the spacing inside a line is
/// kept: for values whose spacing is data (TXT records, header values).
/// A width of 0 is treated as 1.
pub fn wrap_hard(text: &str, width: u16) -> Vec<String> {
    let max = usize::from(width.max(1));
    let col = |s: &str| Span::raw(s).width();
    // Close `line` onto `lines`: trailing spaces dropped, blank lines skipped.
    fn push(lines: &mut Vec<String>, line: &mut String) {
        let kept = line.trim_end();
        if !kept.is_empty() {
            lines.push(kept.to_string());
        }
        line.clear();
    }
    let mut lines = Vec::new();
    let mut line = String::new();
    for c in text.chars() {
        let mut buf = [0u8; 4];
        let w = col(c.encode_utf8(&mut buf));
        if col(&line) + w > max && !line.is_empty() {
            if c == ' ' {
                push(&mut lines, &mut line);
                continue;
            }
            match line.rfind(' ') {
                // Carry the word after the last space onto the next line.
                Some(at) => {
                    let rest = line.split_off(at + 1);
                    push(&mut lines, &mut line);
                    line = rest;
                }
                None => push(&mut lines, &mut line),
            }
            // The carried word plus this character may still not fit.
            if col(&line) + w > max && !line.is_empty() {
                push(&mut lines, &mut line);
            }
        }
        // A continuation line does not start with the spaces it broke at.
        if !(line.is_empty() && c == ' ' && !lines.is_empty()) {
            line.push(c);
        }
    }
    push(&mut lines, &mut line);
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_hard_splits_words_wider_than_the_line() {
        assert_eq!(
            wrap_hard("v=DKIM1 abcdefghij", 4),
            ["v=DK", "IM1", "abcd", "efgh", "ij"]
        );
        assert_eq!(wrap_hard("fits", 10), ["fits"]);
        assert!(wrap_hard("", 5).is_empty());
        // Width 0 must not loop forever: treated as 1.
        assert_eq!(wrap_hard("ab", 0), ["a", "b"]);
    }

    /// The word carried to a new line plus a double-width character can
    /// still be too wide: it must break again, never overflow the width.
    #[test]
    fn wrap_hard_breaks_again_after_carrying_a_word() {
        let got = wrap_hard(" ab漢", 3);
        assert!(
            got.iter().all(|l| Span::raw(l.as_str()).width() <= 3),
            "{got:?}"
        );
        assert_eq!(got.concat(), "ab漢");
    }

    #[test]
    fn wrap_hard_keeps_the_spacing_inside_a_line() {
        // A value's own spacing is data (a TXT record, joined nameservers):
        // only the spaces a line breaks at are dropped.
        assert_eq!(wrap_hard("a  b", 10), ["a  b"]);
        assert_eq!(wrap_hard("v=spf1  -all", 7), ["v=spf1", "-all"]);
        assert!(wrap_hard("   ", 5).is_empty());
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
