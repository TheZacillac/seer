//! Small reusable TUI building blocks: `panel` (bordered block → inner
//! `Rect`), `kv` rows, `gauge`, status `dot` and `chips`, the selected-row
//! `inspector`, the `page` every lens is drawn through, the `function_list`
//! and `options` section widgets, plus the shared
//! `or_dash` missing-value mark, `row_style` selection styling, `scroll_to`,
//! and `wrap` / `wrap_hard` for text sized to its width before it is drawn.

pub mod chips;
pub mod dot;
pub mod function_list;
pub mod gauge;
pub mod inspector;
pub mod kv;
pub mod options;
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

/// `text` cut to at most `width` display columns, keeping the tail behind a
/// leading `…` — a typed value's end (the registrable part of a domain, the
/// caret) is what matters. Fits as-is when it already does.
pub fn fit_tail(text: &str, width: usize) -> String {
    if Span::raw(text).width() <= width {
        return text.to_string();
    }
    // Room for the `…` (one column) before the kept tail.
    let budget = width.saturating_sub(1);
    let mut kept = 0;
    let mut start = text.len();
    for (i, c) in text.char_indices().rev() {
        let w = Span::raw(c.to_string()).width();
        if kept + w > budget {
            break;
        }
        kept += w;
        start = i;
    }
    if width == 0 {
        return String::new();
    }
    format!("…{}", &text[start..])
}

/// An editor's text (`before` and `after` the cursor) with `caret` between
/// them, cut to at most `width` display columns with the caret always in
/// view. It shows the tail behind a leading `…` — as [`fit_tail`] does —
/// until the caret is left of that window; then the window starts at the
/// caret instead and a `…` marks the cut on the right. Fits as-is when it
/// already does. Both parts must be sanitized by the caller.
pub fn fit_caret(before: &str, after: &str, caret: &str, width: usize) -> String {
    let col = |s: &str| Span::raw(s).width();
    // One unit per char, the caret among them.
    let mut units: Vec<(String, usize)> = Vec::new();
    for c in before.chars() {
        let s = c.to_string();
        units.push((s.clone(), col(&s)));
    }
    let caret_at = units.len();
    units.push((caret.to_string(), col(caret)));
    for c in after.chars() {
        let s = c.to_string();
        units.push((s.clone(), col(&s)));
    }
    let joined =
        |range: &[(String, usize)]| range.iter().map(|(s, _)| s.as_str()).collect::<String>();
    if units.iter().map(|(_, w)| w).sum::<usize>() <= width {
        return joined(&units);
    }
    // Too narrow for a window with its cuts: the caret alone.
    if width < 3 {
        return if col(caret) <= width {
            caret.to_string()
        } else {
            String::new()
        };
    }
    // The tail window: as many trailing units as fit beside a leading `…`.
    let mut kept = 0;
    let mut tail = units.len();
    while tail > 0 && kept + units[tail - 1].1 < width {
        tail -= 1;
        kept += units[tail].1;
    }
    if caret_at >= tail {
        return format!("…{}", joined(&units[tail..]));
    }
    // The caret is left of the tail: start at it. A cut on the right is
    // certain here (everything from the caret on is wider than the window).
    let lead = usize::from(caret_at > 0);
    let budget = width.saturating_sub(lead + 1);
    let mut used = 0;
    let mut end = caret_at;
    while end < units.len() && used + units[end].1 <= budget {
        used += units[end].1;
        end += 1;
    }
    let head = if lead == 1 { "…" } else { "" };
    format!("{head}{}…", joined(&units[caret_at..end]))
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
    fn fit_tail_keeps_the_end_within_the_width() {
        assert_eq!(fit_tail("example.com", 11), "example.com");
        assert_eq!(fit_tail("abcdefghij", 5), "…ghij");
        assert_eq!(fit_tail("abc", 0), "");
        assert_eq!(fit_tail("abc", 1), "…");
        // A wide character is never split and the result never overflows:
        // 4 columns = `…` + one 2-column char (a second would need 5).
        let s = fit_tail("日本語", 4);
        assert_eq!(s, "…語");
        assert!(Span::raw(s.as_str()).width() <= 4);
        assert_eq!(fit_tail("日本語", 5), "…本語");
    }

    /// Width of the rendered window, and the caret still in it.
    fn caret_view(before: &str, after: &str, width: usize) -> String {
        let out = fit_caret(before, after, "▏", width);
        assert!(
            Span::raw(out.as_str()).width() <= width,
            "{out:?} > {width}"
        );
        assert!(out.contains('▏'), "caret out of view: {out:?}");
        out
    }

    #[test]
    fn fit_caret_shows_the_tail_while_the_caret_is_at_the_end() {
        assert_eq!(caret_view("example.com", "", 20), "example.com▏");
        // Same window `fit_tail` gives.
        assert_eq!(caret_view("abcdefghij", "", 6), "…ghij▏");
    }

    #[test]
    fn fit_caret_slides_to_keep_a_caret_left_of_the_tail_in_view() {
        // Home: the window starts at the caret, cut marked on the right.
        assert_eq!(caret_view("", "abcdefghij", 6), "▏abcd…");
        // In the middle: a cut on both sides.
        assert_eq!(caret_view("abcdef", "ghijkl", 6), "…▏ghi…");
        // Right of the tail's start it is the tail window again.
        assert_eq!(caret_view("abcdefghij", "kl", 8), "…ghij▏kl");
    }

    #[test]
    fn fit_caret_measures_display_width() {
        // Wide chars are never split and the window never overflows.
        assert_eq!(caret_view("日本語", "", 5), "…語▏");
        let home = caret_view("", "日本語日本語", 6);
        assert_eq!(home, "▏日本…");
        let mid = caret_view("日本語", "日本語", 7);
        assert!(mid.starts_with('…') && mid.ends_with('…'), "{mid:?}");
    }

    #[test]
    fn fit_caret_fits_as_is_and_survives_tiny_widths() {
        assert_eq!(fit_caret("ab", "cd", "▏", 5), "ab▏cd");
        assert_eq!(fit_caret("ab", "cd", "▏", 0), "");
        for w in 1..6 {
            let out = fit_caret("abc", "def", "▏", w);
            assert!(Span::raw(out.as_str()).width() <= w, "{out:?} at {w}");
        }
    }

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
