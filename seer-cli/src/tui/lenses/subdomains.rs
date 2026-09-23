//! Subdomains lens — selectable single-column table of CT-log subdomains.
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{panel, row_style, scroll_to};

pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    data: &LensData,
    focused: bool,
    sel: usize,
) {
    let LensData::Subdomains(s) = data else {
        return;
    };

    let title = format!("Subdomains · {} via {}", s.count, s.source);
    let inner = panel::render(f, area, theme, &title, theme.pink, focused);

    if s.subdomains.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "no subdomains found",
                Style::default()
                    .fg(theme.overlay0)
                    .add_modifier(Modifier::ITALIC),
            ))),
            inner,
        );
        return;
    }

    let header = Row::new(["HOST"]).style(Style::default().fg(theme.overlay0));

    let rows =
        s.subdomains.iter().enumerate().map(|(i, host)| {
            Row::new(vec![host.clone()]).style(row_style(theme, focused && i == sel))
        });

    let table = Table::new(rows, [Constraint::Percentage(100)])
        .header(header)
        .column_spacing(1);
    let mut state = scroll_to(focused.then_some(sel));
    f.render_stateful_widget(table, inner, &mut state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::test_util::render_text;
    use seer_core::SubdomainResult;

    #[test]
    fn renders_subdomain_rows() {
        let theme = Theme::frappe();
        let data = LensData::Subdomains(Box::new(SubdomainResult {
            domain: "example.com".into(),
            subdomains: vec!["www.example.com".into(), "api.example.com".into()],
            source: "crt.sh".into(),
            count: 2,
        }));
        let text = render_text(70, 10, |f| render(f, f.area(), &theme, &data, false, 0));
        assert!(text.contains("www.example.com"));
    }

    #[test]
    fn selecting_past_viewport_scrolls_last_row_into_view() {
        let theme = Theme::frappe();
        let hosts: Vec<String> = (0..60).map(|i| format!("h{i}.example.com")).collect();
        let data = LensData::Subdomains(Box::new(SubdomainResult {
            domain: "example.com".into(),
            subdomains: hosts,
            source: "crt.sh".into(),
            count: 60,
        }));
        // Short terminal can't fit 60 rows; without scrolling the last host
        // would never render even when selected.
        let text = render_text(60, 10, |f| render(f, f.area(), &theme, &data, true, 59));
        assert!(
            text.contains("h59.example.com"),
            "selecting the last row must scroll it into view"
        );
    }

    #[test]
    fn renders_empty_gracefully() {
        let theme = Theme::frappe();
        let data = LensData::Subdomains(Box::new(SubdomainResult {
            domain: "example.com".into(),
            subdomains: vec![],
            source: "crt.sh".into(),
            count: 0,
        }));
        let text = render_text(60, 6, |f| render(f, f.area(), &theme, &data, false, 0));
        assert!(text.contains("no subdomains found"));
    }
}
