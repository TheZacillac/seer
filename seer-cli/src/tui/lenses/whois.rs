//! WHOIS lens — key/value dump.
use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::or_dash;
use crate::tui::widgets::page::{Block, Page};

pub fn page(theme: &Theme, data: &LensData) -> Option<Page> {
    let LensData::Whois(w) = data else {
        return None;
    };
    let rows = vec![
        ("domain", w.domain.clone()),
        ("registrar", or_dash(w.registrar.as_deref())),
        ("organization", or_dash(w.organization.as_deref())),
        ("created", or_dash(w.creation_date.map(|d| d.date_naive()))),
        ("updated", or_dash(w.updated_date.map(|d| d.date_naive()))),
        (
            "expires",
            or_dash(w.expiration_date.map(|d| d.date_naive())),
        ),
        ("dnssec", or_dash(w.dnssec.as_deref())),
        ("nameservers", w.nameservers.join("  ")),
        ("status", w.status.join(", ")),
    ];
    Some(
        Page::new(format!("WHOIS · {}", w.whois_server), theme.peach).push(Block::Kv {
            key_color: theme.peach,
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
        page::draw(f, area, theme, page(theme, data).unwrap(), false);
    }
    use crate::tui::test_util::render_lines;

    fn render_whois(fields: serde_json::Value) -> String {
        // WhoisResponse derives no Default; deserializing keeps the fixture to
        // the fields under test (absent Options default to None).
        let mut v = serde_json::json!({
            "domain": "example.com",
            "nameservers": ["a.iana-servers.net", "b.iana-servers.net"],
            "status": ["clientTransferProhibited"],
            "whois_server": "whois.verisign-grs.com"
        });
        v.as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        let data = LensData::Whois(Box::new(serde_json::from_value(v).unwrap()));
        let theme = Theme::frappe();
        render_lines(80, 12, |f| render(f, f.area(), &theme, &data))
    }

    #[test]
    fn renders_fields_and_dates() {
        let text = render_whois(serde_json::json!({
            "registrar": "Example Registrar",
            "creation_date": "1995-08-14T04:00:00Z",
            "expiration_date": "2030-08-13T04:00:00Z"
        }));
        assert!(
            text.contains("WHOIS · whois.verisign-grs.com"),
            "got: {text}"
        );
        assert!(text.contains("· Example Registrar"), "got: {text}");
        assert!(text.contains("· 1995-08-14 "), "date only: {text}");
        assert!(text.contains("· 2030-08-13 "), "date only: {text}");
        assert!(
            text.contains("a.iana-servers.net  b.iana-servers.net"),
            "got: {text}"
        );
    }

    #[test]
    fn missing_values_render_as_a_dash() {
        let text = render_whois(serde_json::json!({}));
        let row = |key: &str| {
            text.lines()
                .find(|l| l.contains(&format!("│{key} ·")))
                .unwrap_or_else(|| panic!("no {key} row: {text}"))
                .to_string()
        };
        for key in [
            "registrar",
            "organization",
            "created",
            "updated",
            "expires",
            "dnssec",
        ] {
            let row = row(key);
            assert!(
                row.trim_end_matches('│').trim_end().ends_with("· —"),
                "{key}: {text}"
            );
        }
    }
}
