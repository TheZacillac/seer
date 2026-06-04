//! WHOIS lens — key/value dump.
use ratatui::layout::Rect;
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{kv, panel};

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, data: &LensData) {
    let LensData::Whois(w) = data else { return };
    let title = format!("WHOIS · {}", w.whois_server);
    let block = panel::block(theme, &title, theme.peach, false);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let dash = || "—".to_string();
    let rows: Vec<(String, String)> = vec![
        ("domain".into(), w.domain.clone()),
        ("registrar".into(), w.registrar.clone().unwrap_or_else(dash)),
        ("organization".into(), w.organization.clone().unwrap_or_else(dash)),
        ("created".into(), w.creation_date.map(|d| d.date_naive().to_string()).unwrap_or_else(dash)),
        ("updated".into(), w.updated_date.map(|d| d.date_naive().to_string()).unwrap_or_else(dash)),
        ("expires".into(), w.expiration_date.map(|d| d.date_naive().to_string()).unwrap_or_else(dash)),
        ("dnssec".into(), w.dnssec.clone().unwrap_or_else(dash)),
        ("nameservers".into(), w.nameservers.join("  ")),
        ("status".into(), w.status.join(", ")),
    ];
    kv::render(f, inner, theme, theme.peach, &rows);
}

// No unit test: WhoisResponse has ~25 fields and derives no Default, so a
// fixture is impractical. The WHOIS lens is covered by the live smoke test
// (Task 13) and verified to compile here.
