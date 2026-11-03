//! Registry of the 22 lenses shown in the Function list, grouped LOOKUP / DNS /
//! SECURITY / POWER. Each `LENSES` entry also carries the lens's behaviour
//! flags — `interactive` (↵ focuses it without rows), `filter` (`/` filters
//! its rows), `heavy` (an active scan, run only on request) and `options` (its
//! Options-section fields, see `options.rs`) — so `App` reads them here
//! instead of keeping its own lists of keys, and its `keys`: the Details-section
//! action keys the status bar and `?` overlay list for it.

pub mod audit;
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

use crossterm::event::KeyCode;

use crate::tui::options::{self, OptSpec};

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
    Dnssec,
    Compare,
    Trace,
    Propagation,
    Follow,
    Ssl,
    Status,
    Subdomains,
    Headers,
    Audit,
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
            LensKey::Dnssec => "dnssec",
            LensKey::Compare => "compare",
            LensKey::Trace => "trace",
            LensKey::Propagation => "propagation",
            LensKey::Follow => "follow",
            LensKey::Ssl => "ssl",
            LensKey::Status => "status",
            LensKey::Subdomains => "subdomains",
            LensKey::Headers => "headers",
            LensKey::Audit => "audit",
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

/// A key a lens's pane handles, for the status bar and `?` overlay. `code`
/// is what the pane matches (the dead-hint test sends it) and what the hint
/// shows.
#[derive(Debug, Clone, Copy)]
pub struct KeyHint {
    pub code: KeyCode,
    pub what: &'static str,
}

const fn hint(code: KeyCode, what: &'static str) -> KeyHint {
    KeyHint { code, what }
}

impl KeyHint {
    /// The key as the hint shows it: `↵` for Enter, else the character.
    pub fn label(&self) -> String {
        match self.code {
            KeyCode::Enter => "↵".to_string(),
            KeyCode::Char(c) => c.to_string(),
            other => format!("{other:?}"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Lens {
    pub key: LensKey,
    pub label: &'static str,
    pub glyph: &'static str,
    pub cmd: &'static str,
    pub group: &'static str,
    /// The Options box's fields (see `options.rs`); empty collapses the box.
    pub options: &'static [OptSpec],
    /// ↵ focuses the pane even with no rows: its controls work without data.
    pub interactive: bool,
    /// `/` filters the loaded rows.
    pub filter: bool,
    /// An active scan (CT-log queries, HTTP probes across many hosts): it
    /// runs only on request (↵ or its `:` command), never on navigation.
    pub heavy: bool,
    /// Pane keys beyond the global ones, shown in the status bar while
    /// focused and in `?`.
    pub keys: &'static [KeyHint],
}

/// A non-interactive lens whose `:` command is its key; the
/// builder methods below override the rest.
const fn lens(key: LensKey, label: &'static str, glyph: &'static str, group: &'static str) -> Lens {
    Lens {
        key,
        label,
        glyph,
        cmd: key.as_str(),
        group,
        options: &[],
        interactive: false,
        filter: false,
        heavy: false,
        keys: &[],
    }
}

impl Lens {
    /// `:` command alias, for lenses whose command differs from their key.
    const fn cmd(self, cmd: &'static str) -> Self {
        Self { cmd, ..self }
    }

    const fn options(self, options: &'static [OptSpec]) -> Self {
        Self { options, ..self }
    }

    const fn interactive(self) -> Self {
        Self {
            interactive: true,
            ..self
        }
    }

    const fn filter(self) -> Self {
        Self {
            filter: true,
            ..self
        }
    }

    const fn heavy(self) -> Self {
        Self {
            heavy: true,
            ..self
        }
    }

    const fn keys(self, keys: &'static [KeyHint]) -> Self {
        Self { keys, ..self }
    }

    /// Whether `/` filters this lens's rows.
    pub fn filterable(&self) -> bool {
        self.filter
    }
}

/// Nav order; lenses sharing a group must be contiguous (the nav prints a
/// group header whenever the group changes).
static LENSES: &[Lens] = &[
    lens(LensKey::Overview, "Overview", "◈", "LOOKUP").cmd("lookup"),
    lens(LensKey::Whois, "WHOIS", "▤", "LOOKUP"),
    lens(LensKey::Rdap, "RDAP", "▦", "LOOKUP").options(options::RDAP),
    lens(LensKey::Reverse, "Reverse DNS", "↩", "LOOKUP"),
    lens(LensKey::Avail, "Availability", "◎", "LOOKUP"),
    lens(LensKey::Tld, "TLD Info", "⊞", "LOOKUP")
        .interactive()
        .keys(&[hint(KeyCode::Enter, "load")]),
    lens(LensKey::Dns, "Records", "≣", "DNS")
        .cmd("dig")
        .filter()
        .options(options::RECORDS),
    lens(LensKey::Dnssec, "DNSSEC", "◑", "DNS"),
    lens(LensKey::Compare, "Compare", "≍", "DNS").options(options::COMPARE),
    lens(LensKey::Trace, "Trace", "⇶", "DNS").options(options::TRACE),
    lens(LensKey::Propagation, "Propagation", "◐", "DNS")
        .cmd("prop")
        .filter(),
    lens(LensKey::Follow, "Follow", "⟳", "DNS")
        .interactive()
        .options(options::FOLLOW)
        .keys(&[
            hint(KeyCode::Enter, "start"),
            hint(KeyCode::Char('x'), "stop"),
        ]),
    lens(LensKey::Ssl, "SSL / Cert", "⛨", "SECURITY"),
    lens(LensKey::Status, "Status", "♥", "SECURITY"),
    lens(LensKey::Subdomains, "Subdomains", "⋔", "SECURITY")
        .filter()
        .heavy(),
    lens(LensKey::Headers, "HTTP Headers", "☰", "SECURITY"),
    lens(LensKey::Audit, "Audit", "◉", "SECURITY").heavy(),
    lens(LensKey::Takeover, "Takeover", "⚑", "SECURITY")
        .filter()
        .heavy(),
    lens(LensKey::Diff, "Diff", "⇄", "POWER").options(options::DIFF),
    lens(LensKey::Bulk, "Bulk", "⧉", "POWER")
        .interactive()
        .options(options::BULK)
        .keys(&[
            hint(KeyCode::Enter, "run · detail"),
            hint(KeyCode::Char('v'), "detail"),
            hint(KeyCode::Char('x'), "cancel"),
            hint(KeyCode::Char('e'), "export"),
        ]),
    // An empty watchlist has no rows, yet `a` (add) is the pane's point.
    lens(LensKey::Watch, "Watchlist", "★", "POWER")
        .interactive()
        .keys(&[
            hint(KeyCode::Char('a'), "add"),
            hint(KeyCode::Char('d'), "remove"),
            hint(KeyCode::Enter, "open"),
        ]),
    lens(LensKey::History, "History", "↺", "POWER")
        .filter()
        .keys(&[
            hint(KeyCode::Enter, "replay"),
            hint(KeyCode::Char('c'), "clear"),
        ]),
];

pub fn lenses() -> &'static [Lens] {
    LENSES
}

/// Lenses matching `query` for the `Space` switcher, best first, at most
/// eight: a label prefix, then a `:` command prefix, then a substring of
/// either, then the query's letters in order within the label — ignoring
/// case, ties in nav order. An empty query lists the first eight.
pub fn switch_matches(query: &str) -> Vec<usize> {
    const SHOWN: usize = 8;
    let q = query.trim().to_lowercase();
    let score = |l: &Lens| -> Option<u8> {
        let label = l.label.to_lowercase();
        if label.starts_with(&q) {
            return Some(0);
        }
        if l.cmd.starts_with(&q) {
            return Some(1);
        }
        if label.contains(&q) || l.cmd.contains(&q) {
            return Some(2);
        }
        let mut rest = label.chars().filter(|c| c.is_alphanumeric());
        q.chars().all(|c| rest.any(|l| l == c)).then_some(3)
    };
    let mut ranked: Vec<(u8, usize)> = LENSES
        .iter()
        .enumerate()
        .filter_map(|(i, l)| score(l).map(|s| (s, i)))
        .collect();
    ranked.sort();
    ranked.into_iter().take(SHOWN).map(|(_, i)| i).collect()
}

/// The first lens of the group after (`forward`) or before the one `from`
/// is in, wrapping at either end. Backward from inside a group goes to the
/// previous group's start, like `{` in an editor.
pub fn group_start(from: usize, forward: bool) -> usize {
    let starts: Vec<usize> = (0..LENSES.len())
        .filter(|&i| i == 0 || LENSES[i - 1].group != LENSES[i].group)
        .collect();
    let current = starts.iter().rposition(|&s| s <= from).unwrap_or(0);
    let n = starts.len();
    let next = if forward {
        (current + 1) % n
    } else {
        (current + n - 1) % n
    };
    starts[next]
}

/// Find a lens index by its `cmd` alias or `key`.
pub fn find_by_cmd_or_key(token: &str) -> Option<usize> {
    lenses()
        .iter()
        .position(|l| l.cmd == token || l.key == token)
}

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::page::Page;

/// The lens's human-view page for `data`, if it renders one. `render.rs`
/// draws it as the Details section.
/// `rdap_query` is the RDAP lens's Query choice (its label only).
/// `filter` is the active `/`-filter, for renderers that filter by reference
/// (History, DNS Records); other row lenses receive already-filtered `data`.
pub fn page(
    theme: &Theme,
    key: LensKey,
    rdap_query: usize,
    data: &LensData,
    filter: &str,
    focused: bool,
    sel: usize,
) -> Option<Page> {
    match key {
        LensKey::Overview => overview::page(theme, data),
        LensKey::Whois => whois::page(theme, data),
        LensKey::Rdap => Some(rdap::page(theme, rdap_query, data)),
        LensKey::Ssl => ssl::page(theme, data),
        LensKey::Status => status::page(theme, data),
        LensKey::Reverse => reverse::page(theme, data),
        LensKey::Avail => avail::page(theme, data),
        LensKey::Propagation => propagation::page(theme, data, focused, sel),
        LensKey::Watch => watch::page(theme, data, focused, sel),
        LensKey::History => history::page(theme, data, filter, focused, sel),
        LensKey::Subdomains => subdomains::page(theme, data, focused, sel),
        LensKey::Headers => headers::page(theme, data, focused, sel),
        LensKey::Audit => audit::page(theme, data, focused, sel),
        LensKey::Takeover => takeover::page(theme, data, focused, sel),
        LensKey::Dns => dns::page(theme, data, filter, focused, sel),
        LensKey::Dnssec => dnssec::page(theme, data),
        LensKey::Compare => compare::page(theme, data),
        LensKey::Trace => trace::page(theme, data, focused, sel),
        // Pane-driven lenses render from `app.panes` state in
        // render.rs::main_pane, before the state match, so they never reach
        // this dispatch.
        LensKey::Follow | LensKey::Diff | LensKey::Bulk | LensKey::Tld => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_ids_are_unique_per_lens() {
        for lens in lenses() {
            let mut ids: Vec<_> = lens.options.iter().map(|s| s.id).collect();
            let n = ids.len();
            ids.sort_by_key(|id| format!("{id:?}"));
            ids.dedup();
            assert_eq!(ids.len(), n, "{} declares an option twice", lens.label);
        }
    }

    #[test]
    fn hint_labels_come_from_their_key_code() {
        assert_eq!(hint(KeyCode::Char('s'), "start").label(), "s");
        assert_eq!(hint(KeyCode::Enter, "open").label(), "↵");
    }

    #[test]
    fn switcher_ranks_label_prefix_then_command_then_substring_then_subsequence() {
        let first = |q: &str| switch_matches(q).first().map(|&i| lenses()[i].key);
        assert_eq!(first("tra"), Some(LensKey::Trace));
        assert_eq!(first("dig"), Some(LensKey::Dns), "command prefix");
        assert_eq!(first("cert"), Some(LensKey::Ssl), "substring of SSL / Cert");
        assert_eq!(first("hdrs"), Some(LensKey::Headers), "subsequence");
        assert_eq!(first("TRA"), Some(LensKey::Trace), "case-insensitive");
        assert!(switch_matches("zzzz").is_empty());
        assert_eq!(switch_matches("").len(), 8);
    }

    #[test]
    fn group_start_steps_between_groups_and_wraps() {
        let dns = LensKey::Dns.index();
        let ssl = LensKey::Ssl.index();
        let diff = LensKey::Diff.index();
        assert_eq!(group_start(0, true), dns);
        assert_eq!(group_start(dns + 1, true), ssl);
        assert_eq!(group_start(diff, true), 0, "wraps past POWER to LOOKUP");
        assert_eq!(group_start(0, false), diff, "wraps back to POWER");
        assert_eq!(
            group_start(dns + 1, false),
            0,
            "mid-group goes to the previous group's start"
        );
    }

    #[test]
    fn registry_has_twenty_two_lenses_in_four_groups() {
        let ls = lenses();
        assert_eq!(ls.len(), 22);
        let dns: Vec<&str> = ls
            .iter()
            .filter(|l| l.group == "DNS")
            .map(|l| l.label)
            .collect();
        assert_eq!(
            dns,
            [
                "Records",
                "DNSSEC",
                "Compare",
                "Trace",
                "Propagation",
                "Follow"
            ]
        );
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
                "dnssec",
                "compare",
                "trace",
                "propagation",
                "follow",
                "ssl",
                "status",
                "subdomains",
                "headers",
                "audit",
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
        assert_eq!(flagged(|l| l.heavy), ["subdomains", "audit", "takeover"]);
        assert_eq!(
            flagged(|l| l.interactive),
            ["tld", "follow", "bulk", "watch"]
        );
        assert_eq!(
            flagged(|l| l.filterable()),
            ["dns", "propagation", "subdomains", "takeover", "history"]
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
    fn every_registered_lens_has_a_page_arm() {
        // Handed another lens's payload, a renderer skips it or draws its
        // empty state, so only a key missing from `page`'s match can panic
        // here, via its debug_assert.
        let theme = Theme::frappe();
        let data = LensData::History(vec![]);
        for l in lenses() {
            let _ = page(&theme, l.key, 0, &data, "", false, 0);
        }
    }
}
