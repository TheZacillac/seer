//! SSL/Cert lens — certificate summary + SANs.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{chips, kv, panel};
use ratatui::widgets::Paragraph;

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, data: &LensData) {
    let LensData::Ssl(s) = data else { return };
    let block = panel::block(theme, "Certificate", theme.green, false);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(2)])
        .split(inner);

    let leaf = s.chain.first();
    let dash = || "—".to_string();
    let rows: Vec<(String, String)> = vec![
        ("domain".into(), s.domain.clone()),
        (
            "subject".into(),
            leaf.map(|c| c.subject.clone()).unwrap_or_else(dash),
        ),
        (
            "issuer".into(),
            leaf.map(|c| c.issuer.clone()).unwrap_or_else(dash),
        ),
        (
            "key".into(),
            leaf.and_then(|c| c.key_type.clone()).unwrap_or_else(dash),
        ),
        (
            "valid".into(),
            if s.is_valid {
                "yes".into()
            } else {
                "no".into()
            },
        ),
        ("expires in".into(), format!("{}d", s.days_until_expiry)),
    ];
    kv::render(f, chunks[0], theme, theme.green, &rows);
    f.render_widget(Paragraph::new(chips::line(theme, &s.san_names)), chunks[1]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use seer_core::SslReport;

    fn ssl_fixture() -> SslReport {
        SslReport {
            domain: "example.com".into(),
            chain: vec![],
            protocol_version: None,
            san_names: vec!["example.com".into(), "*.example.com".into()],
            is_valid: true,
            hostname_verified: true,
            days_until_expiry: 225,
            caa: None,
            warnings: vec![],
        }
    }

    #[test]
    fn renders_expiry_days() {
        let theme = Theme::frappe();
        let data = LensData::Ssl(Box::new(ssl_fixture()));
        let backend = TestBackend::new(60, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data))
            .unwrap();
        let a = terminal.backend().buffer().area();
        let mut s = String::new();
        for y in 0..a.height {
            for x in 0..a.width {
                s.push_str(terminal.backend().buffer()[(x, y)].symbol());
            }
        }
        assert!(s.contains("225"));
    }
}
