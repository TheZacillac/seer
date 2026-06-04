//! RDAP lens — Domain, IP, and ASN tabs.
use ratatui::layout::Rect;
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{kv, panel};

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, tab: usize, data: &LensData) {
    let LensData::Rdap(r) = data else {
        return;
    };

    match tab {
        0 => render_domain(f, area, theme, r),
        1 => render_ip(f, area, theme, r),
        _ => render_asn(f, area, theme, r),
    }
}

fn render_domain(f: &mut Frame, area: Rect, theme: &Theme, r: &seer_core::RdapResponse) {
    let block = panel::block(theme, "RDAP Object · domain", theme.mauve, false);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let dash = || "—".to_string();
    let delegation = r
        .secure_dns
        .as_ref()
        .and_then(|s| s.delegation_signed)
        .map(|b| b.to_string())
        .unwrap_or_else(dash);
    let rows: Vec<(String, String)> = vec![
        ("handle".into(), r.handle.clone().unwrap_or_else(dash)),
        ("ldhName".into(), r.ldh_name.clone().unwrap_or_else(dash)),
        ("port43".into(), r.port43.clone().unwrap_or_else(dash)),
        ("registrar".into(), r.get_registrar().unwrap_or_else(dash)),
        ("delegationSigned".into(), delegation),
        ("nameservers".into(), r.nameserver_names().join("  ")),
        ("status".into(), r.status.join(", ")),
    ];
    kv::render(f, inner, theme, theme.mauve, &rows);
}

fn render_ip(f: &mut Frame, area: Rect, theme: &Theme, r: &seer_core::RdapResponse) {
    let block = panel::block(theme, "RDAP Object · IP", theme.blue, false);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let dash = || "—".to_string();
    let rows: Vec<(String, String)> = vec![
        ("handle".into(), r.handle.clone().unwrap_or_else(dash)),
        ("name".into(), r.name.clone().unwrap_or_else(dash)),
        (
            "startAddress".into(),
            r.start_address.clone().unwrap_or_else(dash),
        ),
        (
            "endAddress".into(),
            r.end_address.clone().unwrap_or_else(dash),
        ),
        (
            "ipVersion".into(),
            r.ip_version.clone().unwrap_or_else(dash),
        ),
        ("country".into(), r.country.clone().unwrap_or_else(dash)),
        (
            "parentHandle".into(),
            r.parent_handle.clone().unwrap_or_else(dash),
        ),
        ("status".into(), r.status.join(", ")),
    ];
    kv::render(f, inner, theme, theme.blue, &rows);
}

fn render_asn(f: &mut Frame, area: Rect, theme: &Theme, r: &seer_core::RdapResponse) {
    let block = panel::block(theme, "RDAP Object · ASN", theme.lavender, false);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let dash = || "—".to_string();
    let rows: Vec<(String, String)> = vec![
        ("handle".into(), r.handle.clone().unwrap_or_else(dash)),
        ("name".into(), r.name.clone().unwrap_or_else(dash)),
        (
            "startAutnum".into(),
            r.start_autnum.map(|n| n.to_string()).unwrap_or_else(dash),
        ),
        (
            "endAutnum".into(),
            r.end_autnum.map(|n| n.to_string()).unwrap_or_else(dash),
        ),
        ("country".into(), r.country.clone().unwrap_or_else(dash)),
        ("status".into(), r.status.join(", ")),
    ];
    kv::render(f, inner, theme, theme.lavender, &rows);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

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
        let backend = TestBackend::new(70, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, 2, &data))
            .unwrap();
        assert!(buf_text(terminal.backend().buffer()).contains("GOOGLE"));
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
        let backend = TestBackend::new(70, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, 1, &data))
            .unwrap();
        assert!(buf_text(terminal.backend().buffer()).contains("8.8.8.0"));
    }
}
