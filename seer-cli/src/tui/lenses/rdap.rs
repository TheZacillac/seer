//! RDAP lens — Domain, IP, and ASN tabs.
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{kv, or_dash, panel};

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, tab: usize, data: &LensData) {
    // When there's no loaded RDAP data yet, show a tab-appropriate hint.
    if let LensData::Rdap(r) = data {
        match tab {
            0 => return render_domain(f, area, theme, r),
            1 => return render_ip(f, area, theme, r),
            _ => return render_asn(f, area, theme, r),
        }
    }

    // No data: show a hint so the pane isn't just blank.
    let hint_text = match tab {
        2 => "use :rdap AS<number>  (e.g. :rdap AS15169)",
        1 => "use :rdap <ip>  (e.g. :rdap 8.8.8.8)",
        _ => "enter a domain to look up",
    };
    let title = match tab {
        2 => "RDAP Object · ASN",
        1 => "RDAP Object · IP",
        _ => "RDAP Object · domain",
    };
    let accent = match tab {
        2 => theme.lavender,
        1 => theme.blue,
        _ => theme.mauve,
    };
    let inner = panel::render(f, area, theme, title, accent, false);
    f.render_widget(
        Paragraph::new(Line::from(vec![Span::styled(
            hint_text,
            Style::default().fg(theme.subtext),
        )])),
        inner,
    );
}

fn render_domain(f: &mut Frame, area: Rect, theme: &Theme, r: &seer_core::RdapResponse) {
    let inner = panel::render(f, area, theme, "RDAP Object · domain", theme.mauve, false);

    let delegation = r.secure_dns.as_ref().and_then(|s| s.delegation_signed);
    let rows = [
        ("handle", or_dash(r.handle.as_deref())),
        ("ldhName", or_dash(r.ldh_name.as_deref())),
        ("port43", or_dash(r.port43.as_deref())),
        ("registrar", or_dash(r.get_registrar())),
        ("delegationSigned", or_dash(delegation)),
        ("nameservers", r.nameserver_names().join("  ")),
        ("status", r.status.join(", ")),
    ];
    kv::render(f, inner, theme, theme.mauve, &rows);
}

fn render_ip(f: &mut Frame, area: Rect, theme: &Theme, r: &seer_core::RdapResponse) {
    let inner = panel::render(f, area, theme, "RDAP Object · IP", theme.blue, false);

    let rows = [
        ("handle", or_dash(r.handle.as_deref())),
        ("name", or_dash(r.name.as_deref())),
        ("startAddress", or_dash(r.start_address.as_deref())),
        ("endAddress", or_dash(r.end_address.as_deref())),
        ("ipVersion", or_dash(r.ip_version.as_deref())),
        ("country", or_dash(r.country.as_deref())),
        ("parentHandle", or_dash(r.parent_handle.as_deref())),
        ("status", r.status.join(", ")),
    ];
    kv::render(f, inner, theme, theme.blue, &rows);
}

fn render_asn(f: &mut Frame, area: Rect, theme: &Theme, r: &seer_core::RdapResponse) {
    let inner = panel::render(f, area, theme, "RDAP Object · ASN", theme.lavender, false);

    let rows = [
        ("handle", or_dash(r.handle.as_deref())),
        ("name", or_dash(r.name.as_deref())),
        ("startAutnum", or_dash(r.start_autnum)),
        ("endAutnum", or_dash(r.end_autnum)),
        ("country", or_dash(r.country.as_deref())),
        ("status", r.status.join(", ")),
    ];
    kv::render(f, inner, theme, theme.lavender, &rows);
}

#[cfg(test)]
mod tests {
    use super::*;
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
