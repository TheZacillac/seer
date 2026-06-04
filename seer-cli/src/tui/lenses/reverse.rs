//! Reverse DNS lens — renders PTR records from `LensData::Reverse`.
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::panel;

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, data: &LensData) {
    let LensData::Reverse(records) = data else {
        return;
    };
    let block = panel::block(theme, "Reverse DNS · PTR", theme.sapphire, false);
    let inner = block.inner(area);
    f.render_widget(block, area);

    if records.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "no PTR records",
                Style::default()
                    .fg(theme.overlay0)
                    .add_modifier(Modifier::ITALIC),
            ))),
            inner,
        );
        return;
    }

    let header = Row::new(["IP", "PTR"]).style(Style::default().fg(theme.overlay0));
    let rows = records.iter().map(|r| {
        Row::new(vec![r.name.clone(), r.format_short()]).style(Style::default().fg(theme.text))
    });
    let table = Table::new(
        rows,
        [Constraint::Percentage(45), Constraint::Percentage(55)],
    )
    .header(header)
    .column_spacing(1);
    f.render_widget(table, inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use seer_core::dns::{RecordData, RecordType};
    use seer_core::DnsRecord;

    fn buf_text(buf: &ratatui::buffer::Buffer) -> String {
        let a = buf.area();
        let mut s = String::new();
        for y in 0..a.height {
            for x in 0..a.width {
                s.push_str(buf[(x, y)].symbol());
            }
        }
        s
    }

    #[test]
    fn renders_ptr_target() {
        let theme = Theme::frappe();
        let data = LensData::Reverse(vec![DnsRecord {
            name: "8.8.8.8".into(),
            record_type: RecordType::PTR,
            ttl: 300,
            data: RecordData::PTR {
                target: "dns.google".into(),
            },
        }]);
        let backend = TestBackend::new(70, 8);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data))
            .unwrap();
        assert!(buf_text(terminal.backend().buffer()).contains("dns.google"));
    }

    #[test]
    fn renders_empty_gracefully() {
        let theme = Theme::frappe();
        let data = LensData::Reverse(vec![]);
        let backend = TestBackend::new(60, 6);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data))
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(text.contains("no PTR records"));
    }
}
