//! RDAP lens — Domain, IP, and ASN tabs.
use ratatui::style::Style;
use ratatui::text::{Line, Span};

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::or_dash;
use crate::tui::widgets::page::{Block, Page};

/// The tab's object kind: its title and accent.
fn kind(theme: &Theme, tab: usize) -> (&'static str, ratatui::style::Color) {
    match tab {
        2 => ("RDAP Object · ASN", theme.lavender),
        1 => ("RDAP Object · IP", theme.blue),
        _ => ("RDAP Object · domain", theme.mauve),
    }
}

pub fn page(theme: &Theme, tab: usize, data: &LensData) -> Page {
    let (title, accent) = kind(theme, tab);
    let page = Page::new(title, accent);
    // No data: show a tab-appropriate hint so the pane isn't just blank.
    let LensData::Rdap(r) = data else {
        let hint = match tab {
            2 => "use :rdap AS<number>  (e.g. :rdap AS15169)",
            1 => "use :rdap <ip>  (e.g. :rdap 8.8.8.8)",
            _ => "enter a domain to look up",
        };
        return page.push(Block::Lines(vec![Line::from(Span::styled(
            hint,
            Style::default().fg(theme.subtext),
        ))]));
    };
    let rows = match tab {
        0 => {
            let delegation = r.secure_dns.as_ref().and_then(|s| s.delegation_signed);
            vec![
                ("handle", or_dash(r.handle.as_deref())),
                ("ldhName", or_dash(r.ldh_name.as_deref())),
                ("port43", or_dash(r.port43.as_deref())),
                ("registrar", or_dash(r.get_registrar())),
                ("delegationSigned", or_dash(delegation)),
                ("nameservers", r.nameserver_names().join("  ")),
                ("status", r.status.join(", ")),
            ]
        }
        1 => vec![
            ("handle", or_dash(r.handle.as_deref())),
            ("name", or_dash(r.name.as_deref())),
            ("startAddress", or_dash(r.start_address.as_deref())),
            ("endAddress", or_dash(r.end_address.as_deref())),
            ("ipVersion", or_dash(r.ip_version.as_deref())),
            ("country", or_dash(r.country.as_deref())),
            ("parentHandle", or_dash(r.parent_handle.as_deref())),
            ("status", r.status.join(", ")),
        ],
        _ => vec![
            ("handle", or_dash(r.handle.as_deref())),
            ("name", or_dash(r.name.as_deref())),
            ("startAutnum", or_dash(r.start_autnum)),
            ("endAutnum", or_dash(r.end_autnum)),
            ("country", or_dash(r.country.as_deref())),
            ("status", r.status.join(", ")),
        ],
    };
    page.push(Block::Kv {
        key_color: accent,
        rows,
    })
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
        tab: usize,
        data: &LensData,
    ) {
        page::draw(f, area, theme, page(theme, tab, data), false);
    }
    use crate::tui::test_util::render_text;

    fn rdap_fixture(handle: &str, name: &str) -> seer_core::RdapResponse {
        serde_json::from_value(serde_json::json!({
            "handle": handle,
            "name": name
        }))
        .unwrap()
    }

    #[test]
    fn renders_asn_tab_with_name() {
        let theme = Theme::frappe();
        let data = LensData::Rdap(Box::new(rdap_fixture("AS15169", "GOOGLE")));
        let text = render_text(70, 10, |f| render(f, f.area(), &theme, 2, &data));
        assert!(text.contains("GOOGLE"));
    }

    #[test]
    fn renders_ip_tab() {
        let theme = Theme::frappe();
        let r: seer_core::RdapResponse = serde_json::from_value(serde_json::json!({
            "handle": "NET-8-8-8-0-1",
            "startAddress": "8.8.8.0",
            "endAddress": "8.8.8.255",
            "ipVersion": "v4"
        }))
        .unwrap();
        let data = LensData::Rdap(Box::new(r));
        let text = render_text(70, 10, |f| render(f, f.area(), &theme, 1, &data));
        assert!(text.contains("8.8.8.0"));
    }
}
