//! Subdomains lens — selectable single-column table of CT-log subdomains.
use ratatui::layout::Constraint;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Row;
use seer_core::output::sanitize_line;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::page::{Block, Page, TableBlock};

pub fn page(theme: &Theme, data: &LensData, focused: bool, sel: usize) -> Option<Page> {
    let LensData::Subdomains(s) = data else {
        return None;
    };
    let page = Page::new(
        format!("Subdomains · {} via {}", s.count, s.source),
        theme.pink,
    );
    if s.subdomains.is_empty() {
        return Some(page.push(Block::Lines(vec![Line::from(Span::styled(
            "no subdomains found",
            Style::default()
                .fg(theme.overlay0)
                .add_modifier(Modifier::ITALIC),
        ))])));
    }
    let rows = s
        .subdomains
        .iter()
        .map(|host| Row::new(vec![sanitize_line(host)]))
        .collect();
    Some(
        page.push(Block::Table(
            TableBlock::new(vec!["HOST"], vec![Constraint::Percentage(100)], rows)
                .selected(focused.then_some(sel)),
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::widgets::page;

    /// Draw this lens's page as the TUI does.
    fn render(
        f: &mut ratatui::Frame,
        area: ratatui::layout::Rect,
        theme: &Theme,
        data: &LensData,
        focused: bool,
        sel: usize,
    ) {
        if let Some(p) = page(theme, data, focused, sel) {
            page::draw(f, area, theme, p, focused);
        }
    }
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
            truncated: false,
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
            truncated: false,
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
            truncated: false,
        }));
        let text = render_text(60, 6, |f| render(f, f.area(), &theme, &data, false, 0));
        assert!(text.contains("no subdomains found"));
    }
}
