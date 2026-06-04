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
    use ratatui::backend::TestBackend;
    use ratatui::widgets::Paragraph;
    use ratatui::Terminal;

    fn buf_text(buf: &ratatui::buffer::Buffer) -> String {
        let area = buf.area();
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                s.push_str(buf[(x, y)].symbol());
            }
        }
        s
    }

    #[test]
    fn panel_renders_title_in_border() {
        let theme = Theme::frappe();
        let backend = TestBackend::new(24, 4);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                let b = block(&theme, "Registration", theme.blue, true);
                f.render_widget(Paragraph::new("body").block(b), f.area());
            })
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(text.contains("Registration"));
        assert!(text.contains('╭') || text.contains('┌'));
    }
}
