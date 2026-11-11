//! Bordered block with its title on the top border. Blocks merge their
//! borders with whatever they overlap, so sections laid out one cell over
//! each other share a single line with `┬ ┼ ┴` junctions. A shared line
//! cannot light up for one section, so focus shows on the title instead:
//! an inverted pill in the accent color.
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::merge::MergeStrategy;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Padding};
use ratatui::Frame;
use seer_core::output::sanitize_line;

use crate::tui::theme::Theme;

/// Columns a panel's border and padding take from its width.
pub const CHROME_W: u16 = 4;

/// Build a titled Block with one column of padding each side. `focused`
/// inverts the title. Titles often name remote data (a WHOIS server, a
/// subdomain source), so they are sanitized here.
fn block<'a>(theme: &Theme, title: &str, accent: Color, focused: bool) -> Block<'a> {
    let title_style = if focused {
        Style::default()
            .fg(theme.base)
            .bg(accent)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(accent)
    };
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        // Fuzzy: the rounded corners have no junction glyphs of their own.
        .merge_borders(MergeStrategy::Fuzzy)
        .border_style(Style::default().fg(theme.surface1))
        .padding(Padding::horizontal(1))
        .title(Line::from(Span::styled(
            format!(" {} ", sanitize_line(title)),
            title_style,
        )))
}

/// Draw a [`block`] over `area` and return the inner area for its content.
pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    title: &str,
    accent: Color,
    focused: bool,
) -> Rect {
    let block = block(theme, title, accent, focused);
    let inner = block.inner(area);
    f.render_widget(block, area);
    inner
}

/// A `── title ────` rule across `width`: the heading of a group of rows
/// inside a panel.
pub fn rule(theme: &Theme, title: &str, accent: Color, width: u16) -> Line<'static> {
    let title = format!(" {} ", sanitize_line(title));
    let line = Style::default().fg(theme.surface1);
    let used = 2 + Span::raw(title.as_str()).width();
    Line::from(vec![
        Span::styled("──", line),
        Span::styled(title, Style::default().fg(accent)),
        Span::styled("─".repeat(usize::from(width).saturating_sub(used)), line),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::test_util::{render_buffer, render_lines};

    #[test]
    fn panel_renders_title_in_border() {
        let theme = Theme::frappe();
        let s = render_lines(24, 4, |f| {
            let inner = render(f, f.area(), &theme, "Registration", theme.blue, false);
            assert_eq!(inner, Rect::new(2, 1, 24 - CHROME_W, 2));
        });
        assert!(s.starts_with("╭ Registration ─"), "{s}");
    }

    /// Focus is the title's inverted pill; the border keeps one color.
    #[test]
    fn focus_inverts_the_title_only() {
        let theme = Theme::frappe();
        let buf = |focused| {
            render_buffer(24, 4, |f| {
                render(f, f.area(), &theme, "T", theme.blue, focused);
            })
        };
        let (on, off) = (buf(true), buf(false));
        assert_eq!(on[(2, 0)].bg, theme.blue);
        assert_eq!(off[(2, 0)].fg, theme.blue);
        assert_eq!(on[(0, 0)].fg, off[(0, 0)].fg);
    }

    /// Panels one cell over each other share that line, with junctions.
    #[test]
    fn overlapping_panels_share_their_border() {
        let theme = Theme::frappe();
        let s = render_lines(20, 5, |f| {
            render(f, Rect::new(0, 0, 8, 3), &theme, "", theme.blue, false);
            render(f, Rect::new(7, 0, 13, 3), &theme, "", theme.blue, false);
            render(f, Rect::new(0, 2, 20, 3), &theme, "", theme.blue, false);
        });
        let rows: Vec<&str> = s.lines().collect();
        assert_eq!(rows[0].chars().nth(7), Some('┬'), "{s}");
        assert_eq!(rows[2].chars().nth(7), Some('┴'), "{s}");
        assert!(rows[2].starts_with('├') && rows[2].ends_with('┤'), "{s}");
    }

    #[test]
    fn a_rule_fills_the_width() {
        let theme = Theme::frappe();
        let r = rule(&theme, "Registry\x1b[2J", theme.blue, 20);
        assert_eq!(r.width(), 20);
        let text: String = r.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.starts_with("── Registry") && !text.contains('\x1b'),
            "{text}"
        );
    }
}
