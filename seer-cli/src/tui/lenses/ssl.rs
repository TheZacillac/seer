//! SSL/Cert lens — certificate summary, posture warnings + SANs.
use ratatui::text::Line;
use seer_core::CertWarningSeverity;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::page::{Block, Page};
use crate::tui::widgets::{chips, dot, or_dash};

pub fn page(theme: &Theme, data: &LensData) -> Option<Page> {
    let LensData::Ssl(s) = data else {
        return None;
    };
    let leaf = s.chain.first();
    let valid = if s.is_valid { "yes" } else { "no" };
    let hostname = if s.hostname_verified {
        "verified"
    } else {
        "MISMATCH"
    };
    let rows = vec![
        ("domain", s.domain.clone()),
        ("subject", or_dash(leaf.map(|c| &c.subject))),
        ("issuer", or_dash(leaf.map(|c| &c.issuer))),
        ("key", or_dash(leaf.and_then(|c| c.key_type.as_deref()))),
        ("valid", valid.to_string()),
        ("hostname", hostname.to_string()),
        ("expires in", format!("{}d", s.days_until_expiry)),
    ];
    // One line per posture warning.
    let warnings: Vec<Line<'static>> = s
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
    Some(
        Page::new("Certificate", theme.green)
            .push(Block::Kv {
                key_color: theme.green,
                rows,
            })
            .push_if(!warnings.is_empty(), || Block::Lines(warnings))
            .push(Block::Gap)
            .push(Block::Lines(vec![chips::line(theme, &s.san_names)])),
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
    use crate::tui::test_util::render_lines;
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
        render_lines(width, height, |f| render(f, f.area(), &theme, data))
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
        use seer_core::{CertWarning, CertWarningKind, CertWarningSeverity};
        let mut report = ssl_fixture();
        report.warnings = vec![
            CertWarning {
                severity: CertWarningSeverity::Critical,
                kind: CertWarningKind::WeakKey,
                message: "weak RSA key (1024 bits)".into(),
            },
            CertWarning {
                severity: CertWarningSeverity::Warning,
                kind: CertWarningKind::SelfSigned,
                message: "certificate is self-signed".into(),
            },
        ];
        let s = render_to_text(&LensData::Ssl(Box::new(report)), 70, 16);
        assert!(s.contains("weak RSA key"), "got: {s}");
        assert!(s.contains("self-signed"), "got: {s}");
    }
}
