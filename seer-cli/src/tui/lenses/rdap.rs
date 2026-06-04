//! RDAP lens — Domain tab wired; IP/ASN tabs placeholder.
use ratatui::layout::Rect;
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::lenses::placeholder;
use crate::tui::theme::Theme;
use crate::tui::widgets::{kv, panel};

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, tab: usize, data: &LensData) {
    if tab != 0 {
        placeholder::render(
            f,
            area,
            theme,
            if tab == 1 {
                "RDAP · IP"
            } else {
                "RDAP · ASN"
            },
        );
        return;
    }
    let LensData::Rdap(r) = data else { return };
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

// No unit test for RDAP — RdapResponse is large to fixture. Verified to compile;
// runtime rendering not yet exercised on a live terminal.
