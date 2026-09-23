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
    use crate::tui::test_util::render_text;
    use seer_core::dns::{RecordData, RecordType};
    use seer_core::DnsRecord;

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
        let text = render_text(70, 8, |f| render(f, f.area(), &theme, &data));
        assert!(text.contains("dns.google"));
    }

    #[test]
    fn renders_empty_gracefully() {
        let theme = Theme::frappe();
        let data = LensData::Reverse(vec![]);
        let text = render_text(60, 6, |f| render(f, f.area(), &theme, &data));
        assert!(text.contains("no PTR records"));
    }
}
