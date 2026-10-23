//! Status lens — big HTTP code + composite health.
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use seer_core::output::sanitize_line;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::or_dash;
use crate::tui::widgets::page::{Block, Page};

pub fn page(theme: &Theme, data: &LensData) -> Option<Page> {
    let LensData::Status(s) = data else {
        return None;
    };
    let code = or_dash(s.http_status);
    let text = sanitize_line(s.http_status_text.as_deref().unwrap_or_default());
    let headline = Line::from(vec![
        Span::styled(
            format!("{code} "),
            Style::default()
                .fg(theme.green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(text, Style::default().fg(theme.subtext)),
    ]);

    let mut rows = vec![("title", or_dash(s.title.as_deref()))];
    if let Some(c) = &s.certificate {
        rows.push(("ssl issuer", c.issuer.clone()));
        rows.push(("ssl valid", format!("{}d", c.days_until_expiry)));
    }
    if let Some(e) = &s.domain_expiration {
        rows.push(("expires in", format!("{}d", e.days_until_expiry)));
    }
    if let Some(dns) = &s.dns_resolution {
        let resolves = if dns.resolves { "yes" } else { "no" };
        rows.push(("resolves", resolves.to_string()));
    }
    Some(
        Page::new("HTTP Health", theme.green)
            .push(Block::Lines(vec![headline]))
            .push(Block::Gap)
            .push(Block::Kv {
                key_color: theme.green,
                rows,
            }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::widgets::page;

    /// Draw this lens's page as the TUI does.
    fn render(f: &mut ratatui::Frame, area: ratatui::layout::Rect, theme: &Theme, data: &LensData) {
        if let Some(p) = page(theme, data) {
            page::draw(f, area, theme, p, false);
        }
    }
    use crate::tui::test_util::render_text;
    use seer_core::StatusResponse;

    #[test]
    fn renders_http_code() {
        let theme = Theme::frappe();
        let mut sr = StatusResponse::new("example.com".into());
        sr.http_status = Some(200);
        sr.http_status_text = Some("OK".into());
        let data = LensData::Status(Box::new(sr));
        let text = render_text(60, 8, |f| render(f, f.area(), &theme, &data));
        assert!(text.contains("200"));
    }
}
