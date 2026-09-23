//! Bordered block with the title embedded in the top border (┤ title ├), an
//! accent color, and a focus highlight — emulating ratatui's titled Block.
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders};

use crate::tui::theme::Theme;

/// Build a titled, accent-bordered Block. `focused` brightens the border.
pub fn block<'a>(
    theme: &Theme,
    title: &'a str,
    accent: ratatui::style::Color,
    focused: bool,
) -> Block<'a> {
    let border_color = if focused { accent } else { theme.surface1 };
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(border_color))
        .title(Line::from(vec![
            Span::styled("┤ ", Style::default().fg(theme.surface2)),
            Span::styled(title, Style::default().fg(accent)),
            Span::styled(" ├", Style::default().fg(theme.surface2)),
        ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::test_util::render_text;
    use ratatui::widgets::Paragraph;

    #[test]
    fn panel_renders_title_in_border() {
        let theme = Theme::frappe();
        let text = render_text(24, 4, |f| {
            let b = block(&theme, "Registration", theme.blue, true);
            f.render_widget(Paragraph::new("body").block(b), f.area());
        });
        assert!(text.contains("Registration"));
        assert!(text.contains('╭') || text.contains('┌'));
    }
}
