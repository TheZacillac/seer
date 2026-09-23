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
}

/// A tab-less lens whose `:` command is its key; `.cmd()` / `.tabs()` override.
const fn lens(
    key: &'static str,
    label: &'static str,
    glyph: &'static str,
    group: &'static str,
) -> Lens {
    Lens {
        key,
        label,
        glyph,
        cmd: key,
        group,
        tabs: &[],
    }
}

impl Lens {
    /// `:` command alias, for lenses whose command differs from their key.
    const fn cmd(self, cmd: &'static str) -> Self {
        Self { cmd, ..self }
    }

    /// Sub-tabs, cycled with `[` / `]`.
    const fn tabs(self, tabs: &'static [&'static str]) -> Self {
        Self { tabs, ..self }
    }
}

/// Nav order; lenses sharing a group must be contiguous (the nav prints a
/// group header whenever the group changes).
static LENSES: &[Lens] = &[
    lens("overview", "Overview", "◈", "LOOKUP").cmd("lookup"),
    lens("whois", "WHOIS", "▤", "LOOKUP"),
    lens("rdap", "RDAP", "▦", "LOOKUP").tabs(&["Domain", "IP", "ASN"]),
    lens("reverse", "Reverse DNS", "↩", "LOOKUP"),
    lens("avail", "Availability", "◎", "LOOKUP"),
    lens("tld", "TLD Info", "⊞", "LOOKUP"),
    lens("dns", "DNS Records", "≣", "DNS")
        .cmd("dig")
        .tabs(&["Records", "DNSSEC", "Compare"]),
    lens("propagation", "Propagation", "◐", "DNS").cmd("prop"),
    lens("follow", "Follow", "⟳", "DNS"),
    lens("ssl", "SSL / Cert", "⛨", "SECURITY"),
    lens("status", "Status", "♥", "SECURITY"),
    lens("subdomains", "Subdomains", "⋔", "SECURITY"),
    lens("headers", "HTTP Headers", "☰", "SECURITY"),
    lens("takeover", "Takeover", "⚑", "SECURITY"),
    lens("diff", "Diff", "⇄", "POWER"),
    lens("bulk", "Bulk", "⧉", "POWER"),
    lens("watch", "Watchlist", "★", "POWER"),
    lens("history", "History", "↺", "POWER"),
];

pub fn lenses() -> &'static [Lens] {
    LENSES
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
/// `filter` is the active `/`-filter, for renderers that filter by reference
/// (History); other row lenses receive already-filtered `data`.
#[allow(clippy::too_many_arguments)]
pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    key: &str,
    tab: usize,
    data: &LensData,
    filter: &str,
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
        "history" => history::render(f, area, theme, data, filter, focused, sel),
        "subdomains" => subdomains::render(f, area, theme, data, focused, sel),
        "headers" => headers::render(f, area, theme, data),
        "takeover" => takeover::render(f, area, theme, data, focused, sel),
        // Pane-driven lenses render from `app.panes` state in
        // render.rs::main_pane, before the state match, so they never reach
        // this generic dispatch.
        "follow" | "diff" | "bulk" | "tld" => {}
        other => debug_assert!(false, "lens {other:?} has no renderer"),
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
    fn registry_lists_lenses_in_nav_order() {
        let keys: Vec<&str> = lenses().iter().map(|l| l.key).collect();
        assert_eq!(
            keys,
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
    fn lens_keys_labels_glyphs_and_cmds_are_unique() {
        // The nav renders glyph + label; a shared glyph makes two rows look
        // like the same lens at a glance (headers originally reused WHOIS's ▤).
        let assert_unique = |what: &str, field: fn(&Lens) -> &'static str| {
            let mut values: Vec<&str> = lenses().iter().map(field).collect();
            values.sort_unstable();
            let before = values.len();
            values.dedup();
            assert_eq!(values.len(), before, "duplicate lens {what}");
        };
        assert_unique("key", |l| l.key);
        assert_unique("label", |l| l.label);
        assert_unique("glyph", |l| l.glyph);
        assert_unique("cmd alias", |l| l.cmd);
    }

    #[test]
    fn lens_fields_have_the_expected_shape() {
        // `lens()` takes its strings positionally; these shapes catch a
        // transposed argument (e.g. key ⇄ label) that uniqueness would miss.
        for l in lenses() {
            assert!(l.key.bytes().all(|b| b.is_ascii_lowercase()), "{l:?}");
            assert!(l.cmd.bytes().all(|b| b.is_ascii_lowercase()), "{l:?}");
            assert!(
                l.label.starts_with(|c: char| c.is_ascii_uppercase()),
                "{l:?}"
            );
            assert_eq!(l.glyph.chars().count(), 1, "{l:?}");
        }
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

    #[test]
    fn every_registered_lens_has_a_render_arm() {
        // Handed another lens's payload, a renderer skips it or draws its
        // empty state, so only a key missing from `render`'s match can panic
        // here, via its debug_assert.
        let theme = Theme::frappe();
        let data = LensData::History(vec![]);
        let panes = Panes::default();
        for l in lenses() {
            crate::tui::test_util::render_buffer(80, 24, |f| {
                render(f, f.area(), &theme, l.key, 0, &data, "", false, 0, &panes);
            });
        }
    }
}
