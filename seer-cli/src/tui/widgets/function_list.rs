//! The 2 Function section: every lens under its group header, the
//! selected one marked `▸` on a full-width band. Groups are a blank row
//! apart when the box is tall enough; a box too short for the list scrolls
//! to the selection and says how many functions lie beyond each edge.
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::Frame;

use crate::tui::action::Section;
use crate::tui::lenses::lenses;
use crate::tui::theme::Theme;
use crate::tui::widgets::{panel, row_style};

/// One row of the list; `function` is false for a header or a blank.
struct ListRow {
    line: Line<'static>,
    function: bool,
}

/// The list's rows and the row index of `selected` (a `LENSES` index).
/// `spaced` puts a blank row between groups.
fn rows(theme: &Theme, selected: usize, spaced: bool) -> (Vec<ListRow>, usize) {
    let mut out = Vec::new();
    let mut sel_row = 0;
    let mut group = "";
    for (i, l) in lenses().iter().enumerate() {
        if l.group != group {
            if spaced && !out.is_empty() {
                out.push(ListRow {
                    line: Line::default(),
                    function: false,
                });
            }
            group = l.group;
            out.push(ListRow {
                line: Line::from(Span::styled(
                    group,
                    Style::default()
                        .fg(theme.overlay0)
                        .add_modifier(Modifier::BOLD),
                )),
                function: false,
            });
        }
        let on = i == selected;
        if on {
            sel_row = out.len();
        }
        let mark = if on { "▸" } else { " " };
        out.push(ListRow {
            line: Line::from(vec![
                Span::styled(format!("{mark} "), Style::default().fg(theme.mauve)),
                Span::styled(format!("{} ", l.glyph), Style::default().fg(theme.lavender)),
                Span::raw(l.label),
            ])
            .style(row_style(theme, on)),
            function: true,
        });
    }
    (out, sel_row)
}

/// Rows the list wants with its groups spaced out, borders included.
pub fn wanted_height() -> u16 {
    let theme = Theme::frappe();
    u16::try_from(rows(&theme, 0, true).0.len() + 2).unwrap_or(u16::MAX)
}

/// The first row shown when `len` rows scroll in `height` to keep `sel`
/// in view, one row clear of the bottom edge so a mark there never
/// covers it.
fn window_top(len: usize, sel: usize, height: usize) -> usize {
    if len <= height {
        return 0;
    }
    sel.saturating_sub(height.saturating_sub(2))
        .min(len - height)
}

/// A `↑ n more` / `↓ n more` edge mark.
fn more(theme: &Theme, arrow: &str, n: usize) -> Line<'static> {
    Line::from(Span::styled(
        format!("  {arrow} {n} more"),
        Style::default().fg(theme.overlay0),
    ))
}

/// Draw the bordered list over `area`.
pub fn draw(f: &mut Frame, area: Rect, theme: &Theme, selected: usize, focused: bool) {
    let title = Section::Function.title("Function");
    let inner = panel::render(f, area, theme, &title, theme.mauve, focused);
    let h = usize::from(inner.height);
    let (mut list, mut sel_row) = rows(theme, selected, true);
    if list.len() > h {
        (list, sel_row) = rows(theme, selected, false);
    }
    let top = window_top(list.len(), sel_row, h);
    let end = (top + h).min(list.len());
    let functions = |rows: &[ListRow]| rows.iter().filter(|r| r.function).count();
    // An edge mark replaces the row it sits on, so that row counts as cut.
    // Three rows or fewer are all needed for the selection itself.
    let marks = h > 3;
    let above = if marks && top > 0 {
        functions(&list[..=top])
    } else {
        0
    };
    let below = if marks && end < list.len() {
        functions(&list[end - 1..])
    } else {
        0
    };
    for (y, (i, row)) in (inner.y..inner.bottom()).zip(list.into_iter().enumerate().skip(top)) {
        let line = if i == top && above > 0 {
            more(theme, "↑", above)
        } else if i + 1 == end && below > 0 {
            more(theme, "↓", below)
        } else {
            row.line
        };
        // A line drawn as its own widget carries its style across the row.
        f.render_widget(
            line,
            Rect {
                y,
                height: 1,
                ..inner
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::lenses::{lenses, LensKey};
    use crate::tui::test_util::{render_buffer, render_lines};
    use crate::tui::theme::Theme;
    use ratatui::text::Span;

    fn text(rows: &[ListRow]) -> Vec<String> {
        rows.iter()
            .map(|r| r.line.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect()
    }

    #[test]
    fn lists_every_function_under_its_group() {
        let t = Theme::frappe();
        let (rows, _) = rows(&t, 0, false);
        assert_eq!(
            rows.len(),
            lenses().len() + 4,
            "22 functions + 4 group headers"
        );
        assert_eq!(rows.iter().filter(|r| r.function).count(), lenses().len());
    }

    #[test]
    fn groups_appear_in_nav_order() {
        let t = Theme::frappe();
        let text = text(&rows(&t, 0, false).0);
        let at = |g: &str| text.iter().position(|r| r == g).expect(g);
        assert!(
            at("LOOKUP") < at("DNS") && at("DNS") < at("SECURITY") && at("SECURITY") < at("POWER")
        );
    }

    /// A glyph two columns wide pushes its label out of line.
    #[test]
    fn every_glyph_is_one_column_wide() {
        for l in lenses() {
            assert_eq!(Span::raw(l.glyph).width(), 1, "{}", l.label);
        }
    }

    #[test]
    fn a_tall_box_spaces_the_groups_and_shows_no_marks() {
        let t = Theme::frappe();
        let s = render_lines(24, wanted_height(), |f| draw(f, f.area(), &t, 0, true));
        let rows: Vec<&str> = s.lines().collect();
        let dns = rows
            .iter()
            .position(|r| r.trim_matches(['│', ' ']) == "DNS")
            .expect("DNS");
        assert_eq!(rows[dns - 1].trim_matches(['│', ' ']), "", "{s}");
        assert!(s.contains("History") && !s.contains("more"), "{s}");
    }

    #[test]
    fn a_short_box_packs_the_groups_and_counts_what_is_below() {
        let t = Theme::frappe();
        let s = render_lines(24, 10, |f| draw(f, f.area(), &t, 0, true));
        let rows: Vec<&str> = s.lines().collect();
        // 8 rows: LOOKUP, its 6 functions, then the mark over the DNS header.
        assert!(rows[7].contains("TLD Info"), "{s}");
        let hidden = lenses().len() - 6;
        assert!(rows[8].contains(&format!("↓ {hidden} more")), "{s}");
    }

    #[test]
    fn scrolls_to_keep_the_selection_visible() {
        let t = Theme::frappe();
        let s = render_lines(24, 10, |f| {
            draw(f, f.area(), &t, LensKey::History.index(), true);
        });
        assert!(s.contains("▸ ↺ History") && s.contains("↑"), "{s}");
        assert!(!s.contains("↓"), "the last function has nothing below: {s}");
    }

    /// Every selection stays in view at every height, marks included.
    #[test]
    fn a_mark_never_covers_the_selection() {
        let t = Theme::frappe();
        for h in 3..=wanted_height() {
            for (i, l) in lenses().iter().enumerate() {
                let s = render_lines(24, h, |f| draw(f, f.area(), &t, i, true));
                assert!(
                    s.contains(&format!("▸ {} {}", l.glyph, l.label)),
                    "{h}:\n{s}"
                );
            }
        }
    }

    #[test]
    fn the_selection_band_spans_the_row() {
        let t = Theme::frappe();
        let buf = render_buffer(24, 12, |f| draw(f, f.area(), &t, 0, true));
        // Row 2 is Overview (row 1 the LOOKUP header); column 20 is past its label.
        assert_eq!(buf[(20, 2)].bg, t.surface0);
        assert_ne!(buf[(20, 3)].bg, t.surface0);
    }
}
