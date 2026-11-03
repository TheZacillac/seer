//! The 2 Function section: every lens under its group header, the
//! selected one marked `▸`, scrolled so the selection stays in view.
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::tui::action::Section;
use crate::tui::lenses::lenses;
use crate::tui::theme::Theme;
use crate::tui::widgets::{panel, row_style};

/// The list's rows and the row index of `selected` (a `LENSES` index).
pub fn rows(theme: &Theme, selected: usize) -> (Vec<Line<'static>>, usize) {
    let mut out = Vec::new();
    let mut sel_row = 0;
    let mut group = "";
    for (i, l) in lenses().iter().enumerate() {
        if l.group != group {
            group = l.group;
            out.push(Line::from(Span::styled(
                group,
                Style::default()
                    .fg(theme.overlay0)
                    .add_modifier(Modifier::BOLD),
            )));
        }
        let on = i == selected;
        if on {
            sel_row = out.len();
        }
        let mark = if on { "▸" } else { " " };
        out.push(
            Line::from(vec![
                Span::styled(format!(" {mark} "), Style::default().fg(theme.mauve)),
                Span::styled(format!("{} ", l.glyph), Style::default().fg(theme.lavender)),
                Span::raw(l.label),
            ])
            .style(row_style(theme, on)),
        );
    }
    (out, sel_row)
}

/// Draw the bordered list over `area`.
pub fn draw(f: &mut Frame, area: Rect, theme: &Theme, selected: usize, focused: bool) {
    let title = Section::Function.title("Function");
    let inner = panel::render(f, area, theme, &title, theme.mauve, focused);
    let (lines, sel_row) = rows(theme, selected);
    let h = usize::from(inner.height.max(1));
    let top = (sel_row + 1).saturating_sub(h);
    let top = u16::try_from(top).unwrap_or(u16::MAX);
    f.render_widget(Paragraph::new(lines).scroll((top, 0)), inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::lenses::{lenses, LensKey};
    use crate::tui::test_util::render_lines;
    use crate::tui::theme::Theme;

    #[test]
    fn lists_every_function_under_its_group() {
        let t = Theme::frappe();
        let (rows, _) = rows(&t, 0);
        assert_eq!(
            rows.len(),
            lenses().len() + 4,
            "22 functions + 4 group headers"
        );
    }

    #[test]
    fn groups_appear_in_nav_order() {
        let t = Theme::frappe();
        let (rows, _) = rows(&t, 0);
        let text: Vec<String> = rows
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        let at = |g: &str| text.iter().position(|r| r == g).expect(g);
        assert!(
            at("LOOKUP") < at("DNS") && at("DNS") < at("SECURITY") && at("SECURITY") < at("POWER")
        );
    }

    #[test]
    fn scrolls_to_keep_the_selection_visible() {
        let t = Theme::frappe();
        let s = render_lines(24, 10, |f| {
            draw(f, f.area(), &t, LensKey::History.index(), true);
        });
        assert!(s.contains("History"), "{s}");
    }
}
