//! DNS Records lens — Records tab (tab 0), DNSSEC tab (tab 1), Compare tab (tab 2).
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::lenses::{compare, dnssec};
use crate::tui::panes::Panes;
use crate::tui::theme::Theme;
use crate::tui::widgets::panel;

/// Nameserver labels matching `panes/dns.rs` NAMESERVERS order.
const NS_LABELS: &[&str] = &["system", "8.8.8.8", "1.1.1.1"];

#[allow(clippy::too_many_arguments)]
pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    tab: usize,
    data: &LensData,
    focused: bool,
    sel: usize,
    panes: &Panes,
) {
    if tab == 1 {
        dnssec::render(f, area, theme, data);
        return;
    }
    if tab == 2 {
        compare::render(f, area, theme, data);
        return;
    }

    // Tab 0: Records
    let LensData::Dns(records) = data else { return };
    let block = panel::block(theme, "dig · records", theme.sky, focused);
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Layout: nameserver chips (1 line) + hint (1 line) + table
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(inner);

    // Nameserver chip row
    let selected_ns = panes.dns.ns_idx;
    let mut ns_spans: Vec<Span> = Vec::new();
    for (i, label) in NS_LABELS.iter().enumerate() {
        if i > 0 {
            ns_spans.push(Span::raw(" "));
        }
        let style = if i == selected_ns {
            Style::default().fg(theme.base).bg(theme.sky)
        } else {
            Style::default().fg(theme.subtext).bg(theme.surface0)
        };
        ns_spans.push(Span::styled(format!(" {label} "), style));
    }
    f.render_widget(Paragraph::new(Line::from(ns_spans)), chunks[0]);

    // Hint line
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "s nameserver",
            Style::default().fg(theme.overlay0),
        ))),
        chunks[1],
    );

    // Records table
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
    f.render_widget(table, chunks[2]);
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

    fn a_record() -> DnsRecord {
        DnsRecord {
            name: "example.com".into(),
            record_type: RecordType::A,
            ttl: 300,
            data: RecordData::A {
                address: "93.184.215.14".into(),
            },
        }
    }

    #[test]
    fn renders_an_a_record() {
        let theme = Theme::frappe();
        let data = LensData::Dns(vec![a_record()]);
        let panes = Panes::default();
        let backend = TestBackend::new(70, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, 0, &data, false, 0, &panes))
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(text.contains("93.184.215.14"));
        assert!(text.contains("example.com"));
    }

    #[test]
    fn renders_nameserver_chip_row() {
        let theme = Theme::frappe();
        let data = LensData::Dns(vec![a_record()]);
        let panes = Panes::default();
        let backend = TestBackend::new(70, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, 0, &data, false, 0, &panes))
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(text.contains("system"), "chip row should show 'system'");
        assert!(text.contains("8.8.8.8"), "chip row should show '8.8.8.8'");
        assert!(text.contains("1.1.1.1"), "chip row should show '1.1.1.1'");
    }
}
