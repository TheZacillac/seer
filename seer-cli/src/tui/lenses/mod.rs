//! Registry of the 18 lenses shown in the left nav, grouped LOOKUP / DNS /
//! SECURITY / POWER.

pub mod avail;
pub mod bulk;
pub mod compare;
pub mod diff;
pub mod dns;
pub mod dnssec;
pub mod follow;
pub mod headers;
pub mod history;
pub mod overview;
pub mod placeholder;
pub mod propagation;
pub mod rdap;
pub mod reverse;
pub mod ssl;
pub mod status;
pub mod subdomains;
pub mod takeover;
pub mod tld;
pub mod watch;
pub mod whois;

#[derive(Debug, Clone, Copy)]
pub struct Lens {
    pub key: &'static str,
    pub label: &'static str,
    pub glyph: &'static str,
    pub cmd: &'static str,
    pub group: &'static str,
    pub tabs: &'static [&'static str],
    pub implemented: bool,
}

const NO_TABS: &[&str] = &[];

pub fn lenses() -> &'static [Lens] {
    &[
        Lens {
            key: "overview",
            label: "Overview",
            glyph: "◈",
            cmd: "lookup",
            group: "LOOKUP",
            tabs: NO_TABS,
            implemented: true,
        },
        Lens {
            key: "whois",
            label: "WHOIS",
            glyph: "▤",
            cmd: "whois",
            group: "LOOKUP",
            tabs: NO_TABS,
            implemented: true,
        },
        Lens {
            key: "rdap",
            label: "RDAP",
            glyph: "▦",
            cmd: "rdap",
            group: "LOOKUP",
            tabs: &["Domain", "IP", "ASN"],
            implemented: true,
        },
        Lens {
            key: "reverse",
            label: "Reverse DNS",
            glyph: "↩",
            cmd: "reverse",
            group: "LOOKUP",
            tabs: NO_TABS,
            implemented: true,
        },
        Lens {
            key: "avail",
            label: "Availability",
            glyph: "◎",
            cmd: "avail",
            group: "LOOKUP",
            tabs: NO_TABS,
            implemented: true,
        },
        Lens {
            key: "tld",
            label: "TLD Info",
            glyph: "⊞",
            cmd: "tld",
            group: "LOOKUP",
            tabs: NO_TABS,
            implemented: true,
        },
        Lens {
            key: "dns",
            label: "DNS Records",
            glyph: "≣",
            cmd: "dig",
            group: "DNS",
            tabs: &["Records", "DNSSEC", "Compare"],
            implemented: true,
        },
        Lens {
            key: "propagation",
            label: "Propagation",
            glyph: "◐",
            cmd: "prop",
            group: "DNS",
            tabs: NO_TABS,
            implemented: true,
        },
        Lens {
            key: "follow",
            label: "Follow",
            glyph: "⟳",
            cmd: "follow",
            group: "DNS",
            tabs: NO_TABS,
            implemented: true,
        },
        Lens {
            key: "ssl",
            label: "SSL / Cert",
            glyph: "⛨",
            cmd: "ssl",
            group: "SECURITY",
            tabs: NO_TABS,
            implemented: true,
        },
        Lens {
            key: "status",
            label: "Status",
            glyph: "♥",
            cmd: "status",
            group: "SECURITY",
            tabs: NO_TABS,
            implemented: true,
        },
        Lens {
            key: "subdomains",
            label: "Subdomains",
            glyph: "⋔",
            cmd: "subdomains",
            group: "SECURITY",
            tabs: NO_TABS,
            implemented: true,
        },
        Lens {
            key: "headers",
            label: "HTTP Headers",
            glyph: "☰",
            cmd: "headers",
            group: "SECURITY",
            tabs: NO_TABS,
            implemented: true,
        },
        Lens {
            key: "takeover",
            label: "Takeover",
            glyph: "⚑",
            cmd: "takeover",
            group: "SECURITY",
            tabs: NO_TABS,
            implemented: true,
        },
        Lens {
            key: "diff",
            label: "Diff",
            glyph: "⇄",
            cmd: "diff",
            group: "POWER",
            tabs: NO_TABS,
            implemented: true,
        },
        Lens {
            key: "bulk",
            label: "Bulk",
            glyph: "⧉",
            cmd: "bulk",
            group: "POWER",
            tabs: NO_TABS,
            implemented: true,
        },
        Lens {
            key: "watch",
            label: "Watchlist",
            glyph: "★",
            cmd: "watch",
            group: "POWER",
            tabs: NO_TABS,
            implemented: true,
        },
        Lens {
            key: "history",
            label: "History",
            glyph: "↺",
            cmd: "history",
            group: "POWER",
            tabs: NO_TABS,
            implemented: true,
        },
    ]
}

/// Find a lens index by its `cmd` alias or `key`.
pub fn find_by_cmd_or_key(token: &str) -> Option<usize> {
    lenses()
        .iter()
        .position(|l| l.cmd == token || l.key == token)
}

/// Next/previous sub-tab index for a lens, wrapping. `forward = true` advances.
pub fn cycle_tab(lens: &Lens, current: usize, forward: bool) -> usize {
    let n = lens.tabs.len();
    if n == 0 {
        return 0;
    }
    if forward {
        (current + 1) % n
    } else {
        (current + n - 1) % n
    }
}

use ratatui::layout::Rect;
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::panes::Panes;
use crate::tui::theme::Theme;

/// Dispatch human-view rendering to the lens's renderer.
/// `panes` carries interactive component state; Phase-2 renderers may ignore it
/// (param prefixed `_panes` in those signatures to suppress clippy).
#[allow(clippy::too_many_arguments)]
pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    key: &str,
    tab: usize,
    data: &LensData,
    focused: bool,
    sel: usize,
    panes: &Panes,
) {
    match key {
        "overview" => overview::render(f, area, theme, data),
        "whois" => whois::render(f, area, theme, data),
        "rdap" => rdap::render(f, area, theme, tab, data),
        "dns" => dns::render(f, area, theme, tab, data, focused, sel, panes),
        "ssl" => ssl::render(f, area, theme, data),
        "status" => status::render(f, area, theme, data),
        "propagation" => propagation::render(f, area, theme, data, focused, sel),
        // Phase 2 renderers
        "reverse" => reverse::render(f, area, theme, data),
        "avail" => avail::render(f, area, theme, data),
        "watch" => watch::render(f, area, theme, data, focused, sel),
        "history" => history::render(f, area, theme, data, focused, sel),
        "subdomains" => subdomains::render(f, area, theme, data, focused, sel),
        "headers" => headers::render(f, area, theme, data),
        "takeover" => takeover::render(f, area, theme, data, focused, sel),
        // Pane-driven lenses ("follow", "bulk", "tld") are handled in
        // render.rs::main_pane before the state match — they render from
        // `app.panes` state and never reach this generic dispatch.
        other => placeholder::render(f, area, theme, other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_eighteen_lenses_in_four_groups() {
        let ls = lenses();
        assert_eq!(ls.len(), 18);
        assert_eq!(ls[0].key, "overview");
        assert_eq!(ls[0].group, "LOOKUP");
        let groups: Vec<&str> = ls.iter().map(|l| l.group).collect();
        let order = ["LOOKUP", "DNS", "SECURITY", "POWER"];
        let mut seen = vec![];
        for g in groups {
            if seen.last() != Some(&g) {
                seen.push(g);
            }
        }
        assert_eq!(seen, order);
    }

    #[test]
    fn all_lenses_are_implemented() {
        let implemented: Vec<&str> = lenses()
            .iter()
            .filter(|l| l.implemented)
            .map(|l| l.key)
            .collect();
        // All 18 lenses — Phase 1+2+3+4a+4b, plus headers/takeover.
        assert_eq!(
            implemented,
            vec![
                "overview",
                "whois",
                "rdap",
                "reverse",
                "avail",
                "tld",
                "dns",
                "propagation",
                "follow",
                "ssl",
                "status",
                "subdomains",
                "headers",
                "takeover",
                "diff",
                "bulk",
                "watch",
                "history"
            ]
        );
    }

    #[test]
    fn lens_keys_and_glyphs_are_unique() {
        // The nav renders glyph + label; a shared glyph makes two rows look
        // like the same lens at a glance (headers originally reused WHOIS's ▤).
        let mut keys: Vec<&str> = lenses().iter().map(|l| l.key).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(keys.len(), before, "duplicate lens key");

        let mut glyphs: Vec<&str> = lenses().iter().map(|l| l.glyph).collect();
        glyphs.sort_unstable();
        let before = glyphs.len();
        glyphs.dedup();
        assert_eq!(glyphs.len(), before, "duplicate lens glyph");

        let mut cmds: Vec<&str> = lenses().iter().map(|l| l.cmd).collect();
        cmds.sort_unstable();
        let before = cmds.len();
        cmds.dedup();
        assert_eq!(cmds.len(), before, "duplicate lens cmd alias");
    }

    #[test]
    fn find_by_command_resolves_aliases() {
        assert_eq!(
            find_by_cmd_or_key("dig").map(|i| lenses()[i].key),
            Some("dns")
        );
        assert_eq!(
            find_by_cmd_or_key("whois").map(|i| lenses()[i].key),
            Some("whois")
        );
        assert_eq!(
            find_by_cmd_or_key("prop").map(|i| lenses()[i].key),
            Some("propagation")
        );
        assert_eq!(
            find_by_cmd_or_key("headers").map(|i| lenses()[i].key),
            Some("headers")
        );
        assert_eq!(
            find_by_cmd_or_key("takeover").map(|i| lenses()[i].key),
            Some("takeover")
        );
        assert_eq!(find_by_cmd_or_key("nope"), None);
    }

    #[test]
    fn cycle_tab_wraps_in_both_directions() {
        let rdap = lenses().iter().position(|l| l.key == "rdap").unwrap();
        assert_eq!(cycle_tab(&lenses()[rdap], 0, true), 1);
        assert_eq!(cycle_tab(&lenses()[rdap], 2, true), 0);
        assert_eq!(cycle_tab(&lenses()[rdap], 0, false), 2);
    }
}
