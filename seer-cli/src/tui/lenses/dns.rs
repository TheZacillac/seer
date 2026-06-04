//! DNS Records lens (Records tab). DNSSEC/Compare tabs are placeholders.
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Row, Table};
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::lenses::placeholder;
use crate::tui::theme::Theme;
use crate::tui::widgets::panel;

pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    tab: usize,
    data: &LensData,
    focused: bool,
    sel: usize,
) {
    if tab != 0 {
        let label = if tab == 1 { "DNSSEC" } else { "Compare" };
        placeholder::render(f, area, theme, label);
        return;
    }
    let LensData::Dns(records) = data else { return };
    let block = panel::block(theme, "dig · records", theme.sky, focused);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let header =
        Row::new(["TYPE", "NAME", "DATA", "TTL"]).style(Style::default().fg(theme.overlay0));
    let rows = records.iter().enumerate().map(|(i, r)| {
        let style = if focused && i == sel {
            Style::default().fg(theme.text).bg(theme.surface0)
        } else {
            Style::default().fg(theme.text)
        };
        Row::new(vec![
            r.record_type.to_string(),
            r.name.clone(),
            r.format_short(),
            r.ttl.to_string(),
        ])
        .style(style)
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Percentage(35),
            Constraint::Percentage(45),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .column_spacing(1)
    .style(Style::default().add_modifier(Modifier::empty()));
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
    fn renders_an_a_record() {
        let theme = Theme::frappe();
        let data = LensData::Dns(vec![DnsRecord {
            name: "example.com".into(),
            record_type: RecordType::A,
            ttl: 300,
            data: RecordData::A {
                address: "93.184.215.14".into(),
            },
        }]);
        let backend = TestBackend::new(70, 8);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, 0, &data, false, 0))
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(text.contains("93.184.215.14"));
        assert!(text.contains("example.com"));
    }
}
