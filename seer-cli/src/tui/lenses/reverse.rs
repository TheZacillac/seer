//! Reverse DNS lens — renders PTR records from `LensData::Reverse`.
use ratatui::layout::Constraint;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Row;
use seer_core::output::sanitize_line;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::page::{Block, Page, TableBlock};

pub fn page(theme: &Theme, data: &LensData) -> Option<Page> {
    let LensData::Reverse(records) = data else {
        return None;
    };
    let page = Page::new("Reverse DNS · PTR", theme.sapphire);
    if records.is_empty() {
        return Some(page.push(Block::Lines(vec![Line::from(Span::styled(
            "no PTR records",
            Style::default()
                .fg(theme.overlay0)
                .add_modifier(Modifier::ITALIC),
        ))])));
    }
    let rows = records
        .iter()
        .map(|r| {
            Row::new(vec![
                sanitize_line(&r.name),
                sanitize_line(&r.format_short()),
            ])
        })
        .collect();
    Some(page.push(Block::Table(TableBlock::new(
        vec!["IP", "PTR"],
        vec![Constraint::Percentage(45), Constraint::Percentage(55)],
        rows,
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::widgets::page;

    /// Draw this lens's page as the TUI does.
    fn render(f: &mut ratatui::Frame, area: ratatui::layout::Rect, theme: &Theme, data: &LensData) {
        page::draw(f, area, theme, page(theme, data).unwrap(), false);
    }
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
