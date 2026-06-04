//! Registry of the 16 lenses shown in the left nav, grouped LOOKUP / DNS /
//! SECURITY / POWER. Only 7 are wired this pass (`implemented = true`).

pub mod overview;
pub mod whois;
pub mod rdap;
pub mod dns;
pub mod ssl;
pub mod status;
pub mod propagation;
pub mod placeholder;

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
        Lens { key: "overview", label: "Overview", glyph: "◈", cmd: "lookup", group: "LOOKUP", tabs: NO_TABS, implemented: true },
        Lens { key: "whois", label: "WHOIS", glyph: "▤", cmd: "whois", group: "LOOKUP", tabs: NO_TABS, implemented: true },
        Lens { key: "rdap", label: "RDAP", glyph: "▦", cmd: "rdap", group: "LOOKUP", tabs: &["Domain", "IP", "ASN"], implemented: true },
        Lens { key: "reverse", label: "Reverse DNS", glyph: "↩", cmd: "reverse", group: "LOOKUP", tabs: NO_TABS, implemented: false },
        Lens { key: "avail", label: "Availability", glyph: "◎", cmd: "avail", group: "LOOKUP", tabs: NO_TABS, implemented: false },
        Lens { key: "tld", label: "TLD Info", glyph: "⊞", cmd: "tld", group: "LOOKUP", tabs: NO_TABS, implemented: false },
        Lens { key: "dns", label: "DNS Records", glyph: "≣", cmd: "dig", group: "DNS", tabs: &["Records", "DNSSEC", "Compare"], implemented: true },
        Lens { key: "propagation", label: "Propagation", glyph: "◐", cmd: "prop", group: "DNS", tabs: NO_TABS, implemented: true },
        Lens { key: "follow", label: "Follow", glyph: "⟳", cmd: "follow", group: "DNS", tabs: NO_TABS, implemented: false },
        Lens { key: "ssl", label: "SSL / Cert", glyph: "⛨", cmd: "ssl", group: "SECURITY", tabs: NO_TABS, implemented: true },
        Lens { key: "status", label: "Status", glyph: "♥", cmd: "status", group: "SECURITY", tabs: NO_TABS, implemented: true },
        Lens { key: "subdomains", label: "Subdomains", glyph: "⋔", cmd: "subdomains", group: "SECURITY", tabs: NO_TABS, implemented: false },
        Lens { key: "diff", label: "Diff", glyph: "⇄", cmd: "diff", group: "POWER", tabs: NO_TABS, implemented: false },
        Lens { key: "bulk", label: "Bulk", glyph: "⧉", cmd: "bulk", group: "POWER", tabs: NO_TABS, implemented: false },
        Lens { key: "watch", label: "Watchlist", glyph: "★", cmd: "watch", group: "POWER", tabs: NO_TABS, implemented: false },
        Lens { key: "history", label: "History", glyph: "↺", cmd: "history", group: "POWER", tabs: NO_TABS, implemented: false },
    ]
}

/// Find a lens index by its `cmd` alias or `key`.
pub fn find_by_cmd_or_key(token: &str) -> Option<usize> {
    lenses().iter().position(|l| l.cmd == token || l.key == token)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_sixteen_lenses_in_four_groups() {
        let ls = lenses();
        assert_eq!(ls.len(), 16);
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
    fn seven_core_lenses_are_implemented() {
        let implemented: Vec<&str> = lenses()
            .iter()
            .filter(|l| l.implemented)
            .map(|l| l.key)
            .collect();
        assert_eq!(
            implemented,
            vec!["overview", "whois", "rdap", "dns", "propagation", "ssl", "status"]
        );
    }

    #[test]
    fn find_by_command_resolves_aliases() {
        assert_eq!(find_by_cmd_or_key("dig").map(|i| lenses()[i].key), Some("dns"));
        assert_eq!(find_by_cmd_or_key("whois").map(|i| lenses()[i].key), Some("whois"));
        assert_eq!(find_by_cmd_or_key("prop").map(|i| lenses()[i].key), Some("propagation"));
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
