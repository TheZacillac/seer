//! Registry of the 18 lenses shown in the left nav, grouped LOOKUP / DNS /
//! SECURITY / POWER. Each `LENSES` entry also carries the lens's behaviour
//! flags — `interactive` (↵ focuses it without rows), `filter` (which tabs
//! take `/`) and `heavy` (an active scan, run only on request) — so `App`
//! reads them here instead of keeping its own lists of keys.

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
pub mod trace;
pub mod watch;
pub mod whois;

/// A lens's identity. Every lens-keyed table (per-lens state, fetch
/// generations, filters, the renderer and pane dispatch) is keyed by this
/// enum rather than a string, so a misspelt or unregistered key cannot
/// compile, and a new lens is a non-exhaustive-match error wherever it
/// needs handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LensKey {
    Overview,
    Whois,
    Rdap,
    Reverse,
    Avail,
    Tld,
    Dns,
    Propagation,
    Follow,
    Ssl,
    Status,
    Subdomains,
    Headers,
    Takeover,
    Diff,
    Bulk,
    Watch,
    History,
}

impl LensKey {
    /// The key's name: also the lens's `:` command unless `.cmd()` overrides it.
    pub const fn as_str(self) -> &'static str {
        match self {
            LensKey::Overview => "overview",
            LensKey::Whois => "whois",
            LensKey::Rdap => "rdap",
            LensKey::Reverse => "reverse",
            LensKey::Avail => "avail",
            LensKey::Tld => "tld",
            LensKey::Dns => "dns",
            LensKey::Propagation => "propagation",
            LensKey::Follow => "follow",
            LensKey::Ssl => "ssl",
            LensKey::Status => "status",
            LensKey::Subdomains => "subdomains",
            LensKey::Headers => "headers",
            LensKey::Takeover => "takeover",
            LensKey::Diff => "diff",
            LensKey::Bulk => "bulk",
            LensKey::Watch => "watch",
            LensKey::History => "history",
        }
    }

    /// Whether the lens draws from its `panes` state rather than a fetched
    /// result (render.rs `main_pane`), the same in every output format — so
    /// it has no raw view.
    pub const fn renders_from_panes(self) -> bool {
        matches!(
            self,
            LensKey::Follow | LensKey::Diff | LensKey::Bulk | LensKey::Tld
        )
    }

    /// This key's position in the nav.
    pub fn index(self) -> usize {
        LENSES
            .iter()
            .position(|l| l.key == self)
            .expect("every LensKey is registered (registry_lists_every_key_once)")
    }
}

/// Lets tests and lookups compare a key with its name.
impl PartialEq<&str> for LensKey {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

/// Which of a lens's sub-tabs accept the in-lens `/`-filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    None,
    /// Every tab (or the lens has none).
    All,
    /// Only this tab lists rows.
    Tab(usize),
}

#[derive(Debug, Clone, Copy)]
pub struct Lens {
    pub key: LensKey,
    pub label: &'static str,
    pub glyph: &'static str,
    pub cmd: &'static str,
    pub group: &'static str,
    pub tabs: &'static [&'static str],
    /// ↵ focuses the pane even with no rows: its controls work without data.
    pub interactive: bool,
    /// Where `/` filters the loaded rows.
    pub filter: Filter,
    /// An active scan (CT-log queries, HTTP probes across many hosts): it
    /// runs only on request (↵ or its `:` command), never on navigation.
    pub heavy: bool,
}

/// A tab-less, non-interactive lens whose `:` command is its key; the
/// builder methods below override the rest.
const fn lens(key: LensKey, label: &'static str, glyph: &'static str, group: &'static str) -> Lens {
    Lens {
        key,
        label,
        glyph,
        cmd: key.as_str(),
        group,
        tabs: &[],
        interactive: false,
        filter: Filter::None,
        heavy: false,
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

    const fn interactive(self) -> Self {
        Self {
            interactive: true,
            ..self
        }
    }

    const fn filter(self, filter: Filter) -> Self {
        Self { filter, ..self }
    }

    const fn heavy(self) -> Self {
        Self {
            heavy: true,
            ..self
        }
    }

    /// Whether sub-`tab` accepts the in-lens `/`-filter.
    pub fn filterable(&self, tab: usize) -> bool {
        match self.filter {
            Filter::None => false,
            Filter::All => true,
            Filter::Tab(t) => t == tab,
        }
    }
}

/// Nav order; lenses sharing a group must be contiguous (the nav prints a
/// group header whenever the group changes).
static LENSES: &[Lens] = &[
    lens(LensKey::Overview, "Overview", "◈", "LOOKUP").cmd("lookup"),
    lens(LensKey::Whois, "WHOIS", "▤", "LOOKUP"),
    lens(LensKey::Rdap, "RDAP", "▦", "LOOKUP")
        .tabs(&["Domain", "IP", "ASN"])
        .interactive(),
    lens(LensKey::Reverse, "Reverse DNS", "↩", "LOOKUP"),
    lens(LensKey::Avail, "Availability", "◎", "LOOKUP"),
    lens(LensKey::Tld, "TLD Info", "⊞", "LOOKUP").interactive(),
    lens(LensKey::Dns, "DNS Records", "≣", "DNS")
        .cmd("dig")
        .tabs(&["Records", "DNSSEC", "Compare", "Trace"])
        .interactive()
        .filter(Filter::Tab(0)),
    lens(LensKey::Propagation, "Propagation", "◐", "DNS")
        .cmd("prop")
        .filter(Filter::All),
    lens(LensKey::Follow, "Follow", "⟳", "DNS").interactive(),
    lens(LensKey::Ssl, "SSL / Cert", "⛨", "SECURITY"),
    lens(LensKey::Status, "Status", "♥", "SECURITY"),
    lens(LensKey::Subdomains, "Subdomains", "⋔", "SECURITY")
        .filter(Filter::All)
        .heavy(),
    lens(LensKey::Headers, "HTTP Headers", "☰", "SECURITY"),
    lens(LensKey::Takeover, "Takeover", "⚑", "SECURITY")
        .filter(Filter::All)
        .heavy(),
    lens(LensKey::Diff, "Diff", "⇄", "POWER").interactive(),
    lens(LensKey::Bulk, "Bulk", "⧉", "POWER").interactive(),
    // An empty watchlist has no rows, yet `a` (add) is the pane's point.
    lens(LensKey::Watch, "Watchlist", "★", "POWER").interactive(),
    lens(LensKey::History, "History", "↺", "POWER").filter(Filter::All),
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
/// (History, DNS Records); other row lenses receive already-filtered `data`.
#[allow(clippy::too_many_arguments)]
pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    key: LensKey,
    tab: usize,
    data: &LensData,
    filter: &str,
    focused: bool,
    sel: usize,
    panes: &Panes,
) {
    match key {
        LensKey::Overview => overview::render(f, area, theme, data),
        LensKey::Whois => whois::render(f, area, theme, data),
        LensKey::Rdap => rdap::render(f, area, theme, tab, data),
        LensKey::Dns => dns::render(f, area, theme, tab, data, filter, focused, sel, panes),
        LensKey::Ssl => ssl::render(f, area, theme, data),
        LensKey::Status => status::render(f, area, theme, data),
        LensKey::Propagation => propagation::render(f, area, theme, data, focused, sel),
        LensKey::Reverse => reverse::render(f, area, theme, data),
        LensKey::Avail => avail::render(f, area, theme, data),
        LensKey::Watch => watch::render(f, area, theme, data, focused, sel),
        LensKey::History => history::render(f, area, theme, data, filter, focused, sel),
        LensKey::Subdomains => subdomains::render(f, area, theme, data, focused, sel),
        LensKey::Headers => headers::render(f, area, theme, data),
        LensKey::Takeover => takeover::render(f, area, theme, data, focused, sel),
        // Pane-driven lenses render from `app.panes` state in
        // render.rs::main_pane, before the state match, so they never reach
        // this generic dispatch.
        LensKey::Follow | LensKey::Diff | LensKey::Bulk | LensKey::Tld => {}
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
        let keys: Vec<&str> = lenses().iter().map(|l| l.key.as_str()).collect();
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
    fn registry_lists_every_key_once() {
        // `LensKey::index` relies on this; a key missing from LENSES would
        // panic the first time anything looked it up.
        let mut keys: Vec<&str> = lenses().iter().map(|l| l.key.as_str()).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), lenses().len(), "duplicate key");
        for (i, l) in lenses().iter().enumerate() {
            assert_eq!(l.key.index(), i);
            assert_eq!(find_by_cmd_or_key(l.key.as_str()), Some(i), "{l:?}");
        }
    }

    #[test]
    fn behaviour_flags_live_in_the_registry() {
        let flagged = |pick: fn(&Lens) -> bool| -> Vec<&str> {
            lenses()
                .iter()
                .filter(|l| pick(l))
                .map(|l| l.key.as_str())
                .collect()
        };
        assert_eq!(flagged(|l| l.heavy), ["subdomains", "takeover"]);
        assert_eq!(
            flagged(|l| l.interactive),
            ["rdap", "tld", "dns", "follow", "diff", "bulk", "watch"]
        );
        assert_eq!(
            flagged(|l| l.filterable(0)),
            ["dns", "propagation", "subdomains", "takeover", "history"]
        );
        // Of the DNS lens's tabs only Records lists rows.
        assert!(!LENSES[LensKey::Dns.index()].filterable(1));
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
        assert_unique("key", |l| l.key.as_str());
        assert_unique("label", |l| l.label);
        assert_unique("glyph", |l| l.glyph);
        assert_unique("cmd alias", |l| l.cmd);
    }

    #[test]
    fn lens_fields_have_the_expected_shape() {
        // `lens()` takes its strings positionally; these shapes catch a
        // transposed argument (e.g. key ⇄ label) that uniqueness would miss.
        for l in lenses() {
            assert!(
                l.key.as_str().bytes().all(|b| b.is_ascii_lowercase()),
                "{l:?}"
            );
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
            find_by_cmd_or_key("dig").map(|i| lenses()[i].key.as_str()),
            Some("dns")
        );
        assert_eq!(
            find_by_cmd_or_key("whois").map(|i| lenses()[i].key.as_str()),
            Some("whois")
        );
        assert_eq!(
            find_by_cmd_or_key("prop").map(|i| lenses()[i].key.as_str()),
            Some("propagation")
        );
        assert_eq!(
            find_by_cmd_or_key("headers").map(|i| lenses()[i].key.as_str()),
            Some("headers")
        );
        assert_eq!(
            find_by_cmd_or_key("takeover").map(|i| lenses()[i].key.as_str()),
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
