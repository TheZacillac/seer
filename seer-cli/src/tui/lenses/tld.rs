//! TLD Info lens — KV display of TLD registry data.
use ratatui::layout::Rect;
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{kv, panel};

pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    data: &LensData,
    _panes: &crate::tui::panes::Panes,
) {
    let LensData::Tld(t) = data else {
        return;
    };

    let block = panel::block(theme, "TLD Info", theme.maroon, false);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let dash = || "—".to_string();
    let rows: Vec<(String, String)> = vec![
        ("tld".into(), t.tld.clone()),
        ("type".into(), t.tld_type.clone()),
        ("whois".into(), t.whois_server.clone().unwrap_or_else(dash)),
        ("rdap".into(), t.rdap_url.clone().unwrap_or_else(dash)),
        (
            "registry".into(),
            t.registry_url.clone().unwrap_or_else(dash),
        ),
    ];
    kv::render(f, inner, theme, theme.maroon, &rows);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::panes::Panes;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use seer_core::TldInfo;

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
    fn renders_whois_server() {
        let theme = Theme::frappe();
        let data = LensData::Tld(Box::new(TldInfo {
            tld: ".com".into(),
            whois_server: Some("whois.verisign-grs.com".into()),
            rdap_url: None,
            registry_url: None,
            tld_type: "gTLD".into(),
        }));
        let panes = Panes::default();
        let backend = TestBackend::new(70, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data, &panes))
            .unwrap();
        assert!(buf_text(terminal.backend().buffer()).contains("whois.verisign-grs.com"));
    }
}
