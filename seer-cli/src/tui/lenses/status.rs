//! Status lens — big HTTP code + composite health.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{kv, panel};

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, data: &LensData) {
    let LensData::Status(s) = data else { return };
    let block = panel::block(theme, "HTTP Health", theme.green, false);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(0)])
        .split(inner);

    let code = s
        .http_status
        .map(|c| c.to_string())
        .unwrap_or_else(|| "—".into());
    let text = s.http_status_text.clone().unwrap_or_default();
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("{code} "),
                Style::default()
                    .fg(theme.green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(text, Style::default().fg(theme.subtext)),
        ])),
        chunks[0],
    );

    let mut rows: Vec<(String, String)> = Vec::new();
    rows.push((
        "title".into(),
        s.title.clone().unwrap_or_else(|| "—".into()),
    ));
    if let Some(c) = &s.certificate {
        rows.push(("ssl issuer".into(), c.issuer.clone()));
        rows.push(("ssl valid".into(), format!("{}d", c.days_until_expiry)));
    }
    if let Some(e) = &s.domain_expiration {
        rows.push(("expires in".into(), format!("{}d", e.days_until_expiry)));
    }
    if let Some(dns) = &s.dns_resolution {
        rows.push((
            "resolves".into(),
            if dns.resolves {
                "yes".into()
            } else {
                "no".into()
            },
        ));
    }
    kv::render(f, chunks[1], theme, theme.green, &rows);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use seer_core::StatusResponse;

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
    fn renders_http_code() {
        let theme = Theme::frappe();
        let mut sr = StatusResponse::new("example.com".into());
        sr.http_status = Some(200);
        sr.http_status_text = Some("OK".into());
        let data = LensData::Status(Box::new(sr));
        let backend = TestBackend::new(60, 8);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data))
            .unwrap();
        assert!(buf_text(terminal.backend().buffer()).contains("200"));
    }
}
