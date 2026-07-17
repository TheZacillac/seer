//! SSL/Cert lens — certificate summary, posture warnings + SANs.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::Line;
use ratatui::Frame;
use seer_core::CertWarningSeverity;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{chips, dot, kv, panel};
use ratatui::widgets::Paragraph;

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, data: &LensData) {
    let LensData::Ssl(s) = data else { return };
    let block = panel::block(theme, "Certificate", theme.green, false);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            // One line per posture warning (zero-height when clean).
            Constraint::Length(s.warnings.len() as u16),
            Constraint::Length(2),
        ])
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
        (
            "hostname".into(),
            if s.hostname_verified {
                "verified".into()
            } else {
                "MISMATCH".into()
            },
        ),
        ("expires in".into(), format!("{}d", s.days_until_expiry)),
    ];
    kv::render(f, chunks[0], theme, theme.green, &rows);
    if !s.warnings.is_empty() {
        let lines: Vec<Line> = s
            .warnings
            .iter()
            .map(|w| {
                let tone = match w.severity {
                    CertWarningSeverity::Critical => "fail",
                    CertWarningSeverity::Warning => "warn",
                };
                dot::line(theme, tone, w.message.clone())
            })
            .collect();
        f.render_widget(Paragraph::new(lines), chunks[1]);
    }
    f.render_widget(Paragraph::new(chips::line(theme, &s.san_names)), chunks[2]);
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

    fn render_to_text(data: &LensData, width: u16, height: u16) -> String {
        let theme = Theme::frappe();
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, data))
            .unwrap();
        let a = terminal.backend().buffer().area();
        let mut s = String::new();
        for y in 0..a.height {
            for x in 0..a.width {
                s.push_str(terminal.backend().buffer()[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }

    #[test]
    fn renders_expiry_days() {
        let data = LensData::Ssl(Box::new(ssl_fixture()));
        let s = render_to_text(&data, 60, 12);
        assert!(s.contains("225"));
    }

    #[test]
    fn renders_hostname_verification_state() {
        let data = LensData::Ssl(Box::new(ssl_fixture()));
        let s = render_to_text(&data, 60, 12);
        assert!(s.contains("hostname"), "got: {s}");
        assert!(s.contains("verified"), "got: {s}");

        let mut report = ssl_fixture();
        report.hostname_verified = false;
        let s = render_to_text(&LensData::Ssl(Box::new(report)), 60, 12);
        assert!(s.contains("MISMATCH"), "got: {s}");
    }

    #[test]
    fn renders_cert_warnings() {
        use seer_core::{CertWarning, CertWarningSeverity};
        let mut report = ssl_fixture();
        report.warnings = vec![
            CertWarning {
                severity: CertWarningSeverity::Critical,
                message: "weak RSA key (1024 bits)".into(),
            },
            CertWarning {
                severity: CertWarningSeverity::Warning,
                message: "certificate is self-signed".into(),
            },
        ];
        let s = render_to_text(&LensData::Ssl(Box::new(report)), 70, 16);
        assert!(s.contains("weak RSA key"), "got: {s}");
        assert!(s.contains("self-signed"), "got: {s}");
    }
}
