//! Pure application state for the TUI. No ratatui imports — `render.rs` reads
//! this. `update(Msg) -> Vec<Action>` is the single state transition. Focus is
//! one of four `Section`s; option values live in `options`, and `default_req`
//! is the only place they become a request. `↵` in Function runs what waits
//! for it (heavy lenses, Follow, Bulk) and retries a failed lookup; a cycled
//! option supersedes the lens's stale result at once and fetches after the
//! `REFETCH_TICKS` debounce.

use std::collections::HashMap;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use seer_core::output::OutputFormat;
use seer_core::RecordType;

use crate::tui::action::{
    Action, EditTarget, FetchReq, InputMode, LensData, LensKey, LensState, Msg, Section,
};
use crate::tui::command::{self, CmdOutcome};
use crate::tui::event::{self, KeyAction};
use crate::tui::lenses;
use crate::tui::options::{OptId, OptSpec, Options};
use crate::tui::panes::{PaneOutcome, Panes};
use crate::tui::theme::Theme;

/// Number of 100ms ticks a toast lives for (~2.2s).
const TOAST_TICKS: u32 = 22;
/// Rows a PgUp/PgDn moves the raw view.
const PAGE_ROWS: u16 = 10;
/// Ticks a cycled option waits before re-running (300 ms), so holding ← →
/// fetches only the settled value.
const REFETCH_TICKS: u32 = 3;
/// Spinner frames (braille), matching the mockup.
pub const SPIN: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

#[derive(Debug, Clone)]
pub struct Toast {
    pub tone: String,
    pub msg: String,
    ticks_left: u32,
}

/// A destructive key press waiting for its confirming second press.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Confirm {
    /// History `c`: empties the whole store, whatever the filter shows.
    ClearHistory,
    /// Watchlist `d` on this domain.
    Unwatch(String),
}

pub struct App {
    pub lens: usize,
    pub section: Section,
    /// The Options section's selected field, an index into `visible_options`.
    pub opt_cursor: usize,
    /// The option whose last typed value was refused, drawn marked until a
    /// value commits or the lens changes.
    pub opt_error: Option<OptId>,
    pub sel: usize,
    pub format: OutputFormat,
    pub domain: Option<String>,
    pub input_mode: InputMode,
    pub help: bool,
    pub should_quit: bool,
    pub spin: usize,
    pub toast: Option<Toast>,
    pub panes: Panes,
    /// Every lens's option values; `default_req` turns them into requests.
    pub options: Options,
    /// First line of the raw (non-human) view shown at the top of its panel.
    pub raw_scroll: u16,
    /// Active color theme (Frappé by default). Private so swaps go through
    /// `set_theme_by_name`, keeping `theme.name` canonical.
    theme: Theme,
    states: HashMap<LensKey, LensState>,
    startup: Vec<Action>,
    /// Per-lens generation counter; stale results carry a lower gen and are dropped.
    fetch_gen: HashMap<LensKey, u64>,
    /// Lenses whose generation moved on since the last `update`: their
    /// in-flight fetch is superseded, so `update` emits a `CancelFetch` for it.
    superseded: Vec<LensKey>,
    /// Committed in-lens `/`-filter per lens (subdomains/history/propagation).
    lens_filter: HashMap<LensKey, String>,
    /// The request each lens's cached state was last fetched for. The state
    /// cache is keyed by lens only, so this is what tells `fetch_current` that
    /// a cached result belongs to another option value or an ad-hoc target
    /// (`:rdap AS15169`, `:compare other.com …`) and must not be re-served.
    last_req: HashMap<LensKey, FetchReq>,
    /// A destructive action armed by its first key press, with the ticks
    /// left before it lapses (the toast asking for the second press lives
    /// as long).
    confirm: Option<(Confirm, u32)>,
    /// Whether the frame changed since it was last drawn (see `take_redraw`).
    redraw: bool,
    /// Ticks left before a cycled option re-runs the lens (debounce).
    refetch_in: Option<u32>,
}

impl App {
    /// A fresh session. It always opens on the rendered (human) view: the
    /// config's `output_format` is the CLI's default, and `r` toggles raw.
    pub fn new(domain: Option<String>) -> Self {
        let mut app = Self {
            lens: 0,
            section: Section::Function,
            opt_cursor: 0,
            opt_error: None,
            sel: 0,
            format: OutputFormat::Human,
            domain: None,
            input_mode: InputMode::Normal,
            help: false,
            should_quit: false,
            spin: 0,
            toast: None,
            panes: Panes::default(),
            options: Options::default(),
            raw_scroll: 0,
            theme: Theme::frappe(),
            states: HashMap::new(),
            startup: Vec::new(),
            fetch_gen: HashMap::new(),
            superseded: Vec::new(),
            lens_filter: HashMap::new(),
            last_req: HashMap::new(),
            confirm: None,
            redraw: true,
            refetch_in: None,
        };
        if let Some(d) = domain {
            let actions = match app.target_or_toast(&d) {
                Some(target) => app.set_domain_and_fetch(target),
                None => vec![],
            };
            app.startup.extend(actions);
        }
        if app.domain.is_none() {
            app.set_section(Section::Domain);
        }
        app
    }

    /// Drain the actions queued at construction (initial lookup).
    pub fn take_startup_actions(&mut self) -> Vec<Action> {
        // Nothing was in flight to cancel yet.
        self.superseded.clear();
        std::mem::take(&mut self.startup)
    }

    /// Whether the frame must be redrawn, clearing the flag. Anything but a
    /// tick changes what is shown (input, data, a resize); a tick only does
    /// while something animates or when it expires the toast.
    pub fn take_redraw(&mut self) -> bool {
        std::mem::take(&mut self.redraw)
    }

    /// Whether the current frame animates with the tick (a spinner, or a
    /// debounced re-run about to start one).
    fn animating(&self) -> bool {
        self.refetch_in.is_some()
            || matches!(self.state_of(self.lens), LensState::Loading)
            || self.stream_running(self.current_lens().key)
    }

    /// Whether `key`'s streaming run (Follow or Bulk) is in progress.
    fn stream_running(&self, key: LensKey) -> bool {
        match key {
            LensKey::Follow => self.panes.follow.running,
            LensKey::Bulk => self.panes.bulk.running,
            _ => false,
        }
    }

    /// The active theme — `mod.rs` passes this to `render::view` each frame.
    pub fn theme(&self) -> &Theme {
        &self.theme
    }

    /// Swap the active theme by name ("frappe" | "latte", case-insensitive;
    /// see `Theme::from_name`). Unknown names leave the current theme in
    /// place and return false. Shared seam: used by the `:theme` command and
    /// by config wiring in `mod.rs`.
    pub fn set_theme_by_name(&mut self, name: &str) -> bool {
        match Theme::from_name(name) {
            Some(t) => {
                self.theme = t;
                true
            }
            None => false,
        }
    }

    pub fn current_lens(&self) -> &'static lenses::Lens {
        &lenses::lenses()[self.lens]
    }

    pub fn state_of(&self, lens: usize) -> &LensState {
        self.states
            .get(&lenses::lenses()[lens].key)
            .unwrap_or(&LensState::Idle)
    }

    pub fn set_toast(&mut self, tone: &str, msg: &str) {
        self.toast = Some(Toast {
            tone: tone.to_string(),
            msg: msg.to_string(),
            ticks_left: TOAST_TICKS,
        });
    }

    /// Show lens `i` with its first row selected and the Function section
    /// focused. Every lens change goes through here, so no path can carry
    /// the previous lens's selection, option cursor or pending debounce over.
    fn goto_lens(&mut self, i: usize) {
        self.drop_debounce_placeholder();
        self.lens = i;
        self.sel = 0;
        self.raw_scroll = 0;
        self.section = Section::Function;
        self.opt_cursor = 0;
        self.opt_error = None;
        self.refetch_in = None;
    }

    /// The current lens's option fields that show now.
    pub fn visible_options(&self) -> Vec<&'static OptSpec> {
        self.options.visible(self.current_lens().key)
    }

    /// Focus `section`. Domain is a live text field, so focusing it opens
    /// the target editor on the current domain.
    pub fn set_section(&mut self, section: Section) {
        // Leaving Domain any way but a commit closes its editor unapplied.
        if section != Section::Domain
            && matches!(
                self.input_mode,
                InputMode::Field {
                    target: EditTarget::Target,
                    ..
                }
            )
        {
            self.input_mode = InputMode::Normal;
        }
        if section == Section::Domain {
            self.input_mode = InputMode::Field {
                target: EditTarget::Target,
                buf: self.domain.clone().unwrap_or_default().into(),
            };
        }
        if section == Section::Options {
            let last = self.visible_options().len().saturating_sub(1);
            self.opt_cursor = self.opt_cursor.min(last);
        }
        self.section = section;
    }

    /// The section one step away in Tab order, skipping Options when the
    /// lens has none.
    fn next_section(&self, forward: bool) -> Section {
        let all = Section::ALL;
        let mut i = all.iter().position(|s| *s == self.section).unwrap_or(1);
        loop {
            i = if forward {
                (i + 1) % all.len()
            } else {
                (i + all.len() - 1) % all.len()
            };
            if all[i] != Section::Options || !self.visible_options().is_empty() {
                return all[i];
            }
        }
    }

    /// An option changed: re-run the lens now (`debounce` false: a typed
    /// commit) or after `REFETCH_TICKS` (`debounce` true: a cycled value,
    /// so holding ← → fetches only the settled one). Heavy and streaming
    /// lenses only drop their stale result; they run on `↵`.
    fn option_changed(&mut self, debounce: bool) -> Vec<Action> {
        self.opt_error = None;
        if debounce {
            self.supersede_stale_result();
            self.refetch_in = Some(REFETCH_TICKS);
            return vec![];
        }
        self.refetch_in = None;
        self.clear_debounce_placeholder(self.current_lens().key);
        self.fetch_with_current(false)
    }

    /// A cycled option no longer matches the request the current lens's
    /// result (or in-flight fetch) belongs to: supersede it now, so that
    /// result cannot land under the new label while the debounce waits.
    /// The lens shows Loading until the settled value's fetch goes out
    /// (`expire_debounce`); a lens with no request for the new value just
    /// drops the old result. Heavy lenses keep their staging.
    fn supersede_stale_result(&mut self) {
        let lens = self.current_lens();
        let key = lens.key;
        let (Some(domain), false) = (self.domain.clone(), lens.heavy) else {
            return;
        };
        let Some(prev) = self.last_req.get(&key) else {
            return;
        };
        let want = self.default_req(key, &domain);
        let stale = match &want {
            Some(w) => w != prev,
            None => !self.cache_fits_options(prev),
        };
        if !stale {
            return;
        }
        self.bump_fetch_gen(key);
        self.last_req.remove(&key);
        if want.is_some() {
            // The placeholder `expire_debounce` replaces with the fetch.
            self.states.insert(key, LensState::Loading);
        } else {
            self.states.remove(&key);
        }
    }

    /// Drop `key`'s Loading state when it is the debounce placeholder:
    /// nothing is in flight for it (its request was superseded and has not
    /// been re-issued), so it would never be replaced.
    fn clear_debounce_placeholder(&mut self, key: LensKey) {
        if matches!(self.states.get(&key), Some(LensState::Loading))
            && !self.last_req.contains_key(&key)
        {
            self.states.remove(&key);
        }
    }

    /// The debounce ran out: fetch the settled value.
    fn expire_debounce(&mut self) -> Vec<Action> {
        self.refetch_in = None;
        self.clear_debounce_placeholder(self.current_lens().key);
        self.fetch_with_current(false)
    }

    /// Leaving the lens mid-debounce: its placeholder would never be
    /// replaced, so drop it (a revisit fetches afresh).
    fn drop_debounce_placeholder(&mut self) {
        if self.refetch_in.take().is_some() {
            self.clear_debounce_placeholder(self.current_lens().key);
        }
    }

    /// Increment and return the generation counter for a lens, superseding
    /// its in-flight fetch.
    fn bump_fetch_gen(&mut self, key: LensKey) -> u64 {
        let g = self.fetch_gen.entry(key).or_insert(0);
        *g += 1;
        if !self.superseded.contains(&key) {
            self.superseded.push(key);
        }
        *g
    }

    /// Build a `Fetch` action with a fresh generation for staleness detection.
    /// Every dispatch marks its lens Loading (so explicit requests show a
    /// spinner instead of the lens's idle hint) and records the request the
    /// lens's state will belong to.
    fn fetch_action(&mut self, req: FetchReq) -> Action {
        let key = req.lens_key();
        let gen = self.bump_fetch_gen(key);
        self.states.insert(key, LensState::Loading);
        self.last_req.insert(key, req.clone());
        Action::Fetch { req, gen }
    }

    /// What the in-flight/last fetch for `lens` is querying (for the loading
    /// indicator), if a request was recorded.
    pub fn pending_target(&self, lens: usize) -> Option<String> {
        self.last_req
            .get(&lenses::lenses()[lens].key)
            .map(FetchReq::target)
    }

    /// The active in-lens filter for the current lens: the live edit buffer
    /// while the filter field is open, else the committed filter (empty if
    /// none). Used by both the renderer and `row_count`, so the visible rows
    /// and the selection index space always agree.
    pub fn active_filter(&self) -> String {
        if let InputMode::Field {
            target: EditTarget::LensFilter,
            buf,
        } = &self.input_mode
        {
            return buf.as_str().to_string();
        }
        self.lens_filter
            .get(&self.current_lens().key)
            .cloned()
            .unwrap_or_default()
    }

    /// Number of selectable rows in the current lens's loaded data.
    pub fn row_count(&self) -> usize {
        let LensState::Loaded(data) = self.state_of(self.lens) else {
            return 0;
        };
        // Count the filtered rows so selection stays within the visible subset.
        let filter = self.active_filter();
        let filtered = crate::tui::filter::apply(data, &filter);
        let data = filtered.as_ref().unwrap_or(data);
        match data {
            // Filtered by reference, so the verdict still sees every answer.
            LensData::Dig(r) => crate::tui::filter::dig_rows(r, &filter).count(),
            // One selectable row per delegation hop.
            LensData::Trace(t) => t.hops.len(),
            LensData::Prop(p) => p.results.len(),
            LensData::Reverse(r) => r.len(),
            LensData::Watch(w) => w.results.len(),
            // Filtered by reference (entries are too heavy to clone per frame).
            LensData::History(e) => crate::tui::filter::history_rows(e, &filter).count(),
            LensData::Subdomains(s) => s.subdomains.len(),
            // Only reported (non-safe) hosts are listed, so the selection
            // index space is the findings vec, not hosts_checked.
            LensData::Takeover(t) => t.findings.len(),
            // One selectable row per finding.
            LensData::Audit(a) => a.findings.len(),
            // One selectable row per graded header.
            LensData::Headers(h) => h.headers.len(),
            _ => 0,
        }
    }

    /// Whether the main pane shows the raw (serialized) view: a non-human
    /// format over a lens with loaded data. Pane-driven lenses render from
    /// their pane state in every format, so they have no raw view.
    pub fn raw_view(&self) -> bool {
        self.format != OutputFormat::Human
            && !self.current_lens().key.renders_from_panes()
            && matches!(self.state_of(self.lens), LensState::Loaded(_))
    }

    /// The raw view's line count, for clamping its scroll.
    fn raw_line_count(&self) -> usize {
        match self.state_of(self.lens) {
            LensState::Loaded(data) => crate::payload::serialize(data, self.format).lines().count(),
            _ => 0,
        }
    }

    /// Scroll the raw view by `delta` lines, clamped to its last line.
    fn scroll_raw(&mut self, delta: i32) {
        let last = self.raw_line_count().saturating_sub(1);
        let last = u16::try_from(last).unwrap_or(u16::MAX);
        let next = i32::from(self.raw_scroll) + delta;
        self.raw_scroll = u16::try_from(next.max(0)).unwrap_or(u16::MAX).min(last);
    }

    /// Validate a typed or pasted target: an IP literal (canonical form, for
    /// the Reverse and RDAP lenses) or a host / DNS query name, normalized by
    /// core. An invalid one is refused with a toast (`None`), leaving the
    /// session target as it was.
    fn target_or_toast(&mut self, raw: &str) -> Option<String> {
        let raw = raw.trim();
        if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
            return Some(ip.to_string());
        }
        match seer_core::validation::normalize_query_name(raw) {
            Ok(target) => Some(target),
            Err(e) => {
                let msg = seer_core::output::sanitize_line(&e.to_string());
                self.set_toast("fail", &msg);
                None
            }
        }
    }

    /// Record the (validated) target and fetch the current lens for it — an
    /// explicit request, so a heavy lens runs too.
    ///
    /// Targets are normalized as hosts, keeping a leading `www.`: the DNS,
    /// Trace, SSL, Status, Headers, Propagation and Follow lenses ask about
    /// that exact name, as the CLI does, while WHOIS, RDAP, availability and
    /// the other registration lookups drop `www.` in core themselves.
    fn set_domain_and_fetch(&mut self, target: String) -> Vec<Action> {
        self.set_domain_and_fetch_with(target, true)
    }

    /// `set_domain_and_fetch`, where `explicit` false lets a heavy lens
    /// wait for ↵ (a domain edit re-runs the function it sits on).
    fn set_domain_and_fetch_with(&mut self, target: String, explicit: bool) -> Vec<Action> {
        let mut actions = Vec::new();
        // A new target invalidates every cached lens.
        if self.domain.as_deref() != Some(target.as_str()) {
            self.states.clear();
            self.last_req.clear();
            self.refetch_in = None;
            // `:diff a b` / `:compare d …` overrides follow the session target
            // only until it changes; the new target becomes domain A again.
            self.panes.diff.a.clear();
            self.panes.compare.domain = None;
            // Supersede EVERY lens's fetch, not just the current one's (which
            // fetch_current bumps below): an in-flight fetch on another lens,
            // started under the old domain, would otherwise still match its
            // unchanged gen and land as the new domain's data — and keep
            // probing the old target meanwhile.
            let keys: Vec<LensKey> = self.fetch_gen.keys().copied().collect();
            for key in keys {
                self.bump_fetch_gen(key);
            }
            // A new target invalidates any per-lens filters too.
            self.lens_filter.clear();
            // The resolved IP is derived from the OLD domain's DNS/Status
            // results; clearing it prevents the RDAP IP query from looking up
            // the previous domain's address under the new domain.
            self.panes.dns.resolved_ip = None;
            // The Follow lens tracks this domain; cancel any in-flight run —
            // the generation bump below only drops its UI callbacks, while
            // StopFollow makes run_loop signal the background DNS loop itself,
            // which would otherwise keep polling the old domain. (The Bulk
            // pane operates on its own independent domain list, so it is
            // intentionally left alone.)
            if self.panes.follow.running {
                actions.push(Action::StopFollow);
            }
            self.panes.follow.reset_for_new_domain();
        }
        self.domain = Some(target);
        self.sel = 0;
        actions.extend(self.fetch_current(explicit));
        actions
    }

    /// Queue a fetch for the current lens at the current domain, marking it
    /// Loading. Returns None if there's nothing to fetch — including a heavy
    /// lens reached by navigation (`explicit` false): it waits for ↵. History
    /// and Watch do not require a target domain.
    fn fetch_current(&mut self, explicit: bool) -> Option<Action> {
        let lens = self.current_lens();
        let key = lens.key;
        // History reflects on-disk state that lookups mutate behind its back;
        // always re-read it rather than serving a cached (possibly empty) view.
        if key == LensKey::History {
            self.states.remove(&key);
        }
        // Most lenses need a target; History/Watch are global views.
        let want = match self.domain.clone() {
            Some(domain) => self.default_req(key, &domain),
            None => match key {
                LensKey::History => Some(FetchReq::History),
                LensKey::Watch => Some(FetchReq::Watch),
                _ => None,
            },
        };
        // Cached (or in flight) for the current domain → revisiting is
        // instant, unless the cache answers another request than the one
        // the options now make (Type, Server… changed; `:rdap other.org`
        // or `:compare other.com …` while a session domain is set). With
        // no default request (`want` is None) an ad-hoc result stays,
        // unless it contradicts an option (the RDAP Query).
        if matches!(
            self.states.get(&key),
            Some(LensState::Loaded(_) | LensState::Loading)
        ) {
            let stale = self.last_req.get(&key).is_some_and(|prev| match &want {
                Some(w) => w != prev,
                None => !self.cache_fits_options(prev),
            });
            if !stale {
                return None;
            }
            // Drop the mismatched state, and invalidate any in-flight fetch
            // for it even when no replacement request follows (e.g. the RDAP
            // domain query with no session domain).
            self.states.remove(&key);
            self.last_req.remove(&key);
            self.bump_fetch_gen(key);
        }
        if lens.heavy && !explicit {
            return None;
        }
        want.map(|req| self.fetch_action(req))
    }

    /// Whether a cached request still matches the options that pick what a
    /// lens shows: only the RDAP Query (Domain / IP / ASN) does today.
    fn cache_fits_options(&self, prev: &FetchReq) -> bool {
        let kind = match prev {
            FetchReq::RdapDomain(_) => 0,
            FetchReq::RdapIp(_) => 1,
            FetchReq::RdapAsn(_) => 2,
            _ => return true,
        };
        self.options.choice(LensKey::Rdap, OptId::RdapQuery) == Some(kind)
    }

    /// The request lens `key` makes at `domain` with its current options —
    /// the one place option values become a fetch. `None` when the lens has
    /// nothing to fetch by itself (RDAP IP without a resolved address, ASN,
    /// Diff without a second domain, the streaming Follow and Bulk).
    fn default_req(&self, key: LensKey, domain: &str) -> Option<FetchReq> {
        let d = domain.to_string();
        let o = &self.options;
        Some(match key {
            LensKey::Overview => FetchReq::Overview(d),
            LensKey::Whois => FetchReq::Whois(d),
            LensKey::Rdap => match o.choice(key, OptId::RdapQuery)? {
                0 => FetchReq::RdapDomain(d),
                // Only an address a DNS/Status result resolved, never the
                // domain string itself.
                1 => FetchReq::RdapIp(self.panes.dns.resolved_ip.clone()?),
                _ => return None, // ASN needs `:rdap AS…`
            },
            LensKey::Dns => FetchReq::Dns {
                domain: d,
                record_type: o.record_type(key)?,
                nameserver: o.server(key, OptId::Server)?,
            },
            LensKey::Dnssec => FetchReq::Dnssec(d),
            LensKey::Compare => FetchReq::Compare {
                domain: self.panes.compare.effective_domain(Some(domain))?,
                record_type: RecordType::A,
                a: o.server(key, OptId::ServerA)??,
                b: o.server(key, OptId::ServerB)??,
            },
            LensKey::Trace => FetchReq::Trace {
                domain: d,
                record_type: o.record_type(key)?,
            },
            LensKey::Ssl => FetchReq::Ssl(d),
            LensKey::Status => FetchReq::Status(d),
            LensKey::Propagation => FetchReq::Prop(d),
            LensKey::Reverse => FetchReq::Reverse(d),
            LensKey::Avail => FetchReq::Avail(d),
            LensKey::Tld => FetchReq::Tld(self.panes.tld.current()),
            LensKey::Diff => {
                let b = o.text(key, OptId::SecondDomain)?;
                if b.is_empty() {
                    return None;
                }
                FetchReq::Diff {
                    a: self.panes.diff.effective_a(Some(domain))?,
                    b,
                }
            }
            LensKey::Watch => FetchReq::Watch,
            LensKey::History => FetchReq::History,
            LensKey::Subdomains => FetchReq::Subdomains(d),
            LensKey::Headers => FetchReq::Headers(d),
            LensKey::Audit => FetchReq::Audit(d),
            LensKey::Takeover => FetchReq::Takeover(d),
            LensKey::Follow | LensKey::Bulk => return None, // streaming — started explicitly
        })
    }

    /// Populate `panes.dns.resolved_ip` from DNS or Status results so the RDAP
    /// IP query can auto-fetch without an explicit `:rdap <ip>` command. A dig
    /// answer's A records sit past any CNAME chain, under the chain's end.
    fn extract_resolved_ip_if_needed(&mut self, data: &LensData) {
        match data {
            LensData::Dig(result) => {
                let ip = result.records().find_map(|r| {
                    if let seer_core::dns::RecordData::A { address } = &r.data {
                        Some(address.clone())
                    } else {
                        None
                    }
                });
                if ip.is_some() {
                    self.panes.dns.resolved_ip = ip;
                }
            }
            LensData::Status(s) => {
                let ip = s
                    .dns_resolution
                    .as_ref()
                    .and_then(|d| d.a_records.first().cloned());
                if ip.is_some() {
                    self.panes.dns.resolved_ip = ip;
                }
            }
            _ => {}
        }
    }

    /// The single state transition. Cancels for superseded fetches lead the
    /// returned actions, so they can never abort a fetch this same step
    /// started for the lens.
    pub fn update(&mut self, msg: Msg) -> Vec<Action> {
        let tick = matches!(msg, Msg::Tick);
        let animating = tick && self.animating();
        let had_toast = self.toast.is_some();
        let actions = self.step(msg);
        if !tick || animating || had_toast != self.toast.is_some() {
            self.redraw = true;
        }
        let mut out: Vec<Action> = self.superseded.drain(..).map(Action::CancelFetch).collect();
        out.extend(actions);
        out
    }

    fn step(&mut self, msg: Msg) -> Vec<Action> {
        match msg {
            Msg::Tick => {
                self.spin = (self.spin + 1) % SPIN.len();
                if let Some(t) = &mut self.toast {
                    t.ticks_left = t.ticks_left.saturating_sub(1);
                    if t.ticks_left == 0 {
                        self.toast = None;
                    }
                }
                if let Some((_, ticks)) = &mut self.confirm {
                    *ticks = ticks.saturating_sub(1);
                    if *ticks == 0 {
                        self.confirm = None;
                    }
                }
                if let Some(ticks) = &mut self.refetch_in {
                    *ticks = ticks.saturating_sub(1);
                    if *ticks == 0 {
                        return self.expire_debounce();
                    }
                }
                vec![]
            }
            Msg::Data { lens, gen, result } => {
                // Drop stale results — only store if the generation matches.
                let current_gen = self.fetch_gen.get(&lens).copied().unwrap_or(0);
                if current_gen == gen {
                    let new_state = match result {
                        Ok(data) => {
                            // Side-effect: extract resolved IP from DNS/Status results.
                            self.extract_resolved_ip_if_needed(&data);
                            LensState::Loaded(data)
                        }
                        Err(e) => LensState::Error(e),
                    };
                    self.states.insert(lens, new_state);
                    // A refresh can return fewer rows (e.g. after `watch
                    // remove` of the last row); keep the selection on a
                    // real row so the highlight and row actions agree.
                    if lens == self.current_lens().key {
                        self.sel = self.sel.min(self.row_count().saturating_sub(1));
                        self.raw_scroll = 0;
                    }
                }
                vec![]
            }
            Msg::CopyResult { ok, label } => {
                if ok {
                    self.set_toast("ok", &format!("copied {label}"));
                } else {
                    // The failure label carries the handler's message (e.g.
                    // clipboard unavailable), so it is shown verbatim. Non-copy
                    // side effects (CSV writes, bulk file loads) use Msg::Toast.
                    self.set_toast("fail", &label);
                }
                vec![]
            }
            Msg::Toast { tone, msg } => {
                self.set_toast(tone, &msg);
                vec![]
            }
            Msg::FollowStep { gen, it } => {
                // Drop steps from a superseded run.
                if gen == self.panes.follow.gen {
                    self.panes.follow.push(*it);
                }
                vec![]
            }
            Msg::FollowDone { gen } => {
                if gen == self.panes.follow.gen {
                    self.panes.follow.running = false;
                }
                vec![]
            }
            Msg::BulkStep { gen, result } => {
                // Drop results from a superseded run.
                if gen == self.panes.bulk.gen {
                    self.panes.bulk.push(*result);
                }
                vec![]
            }
            Msg::BulkDone { gen } => {
                if gen == self.panes.bulk.gen {
                    self.panes.bulk.running = false;
                }
                vec![]
            }
            // Only Press events — ignoring Repeat/Release avoids double-input on
            // Windows legacy consoles. (Held-key auto-repeat is not relied upon.)
            Msg::Input(Event::Key(key)) if key.kind == KeyEventKind::Press => self.on_key(key),
            Msg::Input(Event::Paste(s)) => {
                // Bracketed paste lands here as one string. Every input is a
                // single-line editor, so line breaks, tabs and any other
                // control character become spaces (a pasted multi-line
                // domain list stays one space-separated line) rather than
                // landing in a buffer that is echoed to the terminal.
                let s: String = s
                    .chars()
                    .map(|c| if c.is_control() { ' ' } else { c })
                    .collect();
                match &mut self.input_mode {
                    InputMode::Field { buf, .. } => buf.insert_str(&s),
                    InputMode::Command(buf) => buf.insert_str(&s),
                    InputMode::Normal => {}
                }
                vec![]
            }
            Msg::Input(_) => vec![],
        }
    }

    fn on_key(&mut self, key: KeyEvent) -> Vec<Action> {
        // Mode-specific capture takes precedence.
        match std::mem::take(&mut self.input_mode) {
            InputMode::Command(buf) => return self.on_command_key(key, buf),
            InputMode::Field { target, buf } => return self.on_field_key(key, target, buf),
            InputMode::Normal => {}
        }
        // Only the confirming key, pressed next, completes an armed
        // destructive action; any other key disarms it.
        let confirm = self.confirm.take().map(|(c, _)| c);
        // Normal-mode bindings are bare keys, and the pane handlers / keymap
        // match on `key.code` alone — so Ctrl/Alt chords must stop here. In
        // raw mode Ctrl-C arrives as `Char('c') + CONTROL`: unfiltered, a
        // reflexive Ctrl-C on History wiped it (`c`), Ctrl-D removed a watched
        // domain, Ctrl-R/Ctrl-E started/exported a bulk run. Ctrl-C gets the
        // same quit hint as `q`; every other chord is ignored. (SHIFT is not
        // a chord — `G` must still work — and neither is AltGr.)
        if event::is_chord(&key) {
            let ctrl_c =
                key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
            if ctrl_c {
                return self.on_normal_action(KeyAction::QuitHint);
            }
            return vec![];
        }
        if self.help {
            if matches!(
                key.code,
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q')
            ) {
                self.help = false;
            }
            return vec![];
        }
        // The raw view scrolls: PgUp/PgDn anywhere, j/k/↑/↓ in Details.
        if self.raw_view() {
            let details = self.section == Section::Details;
            let delta = match key.code {
                KeyCode::PageDown => Some(i32::from(PAGE_ROWS)),
                KeyCode::PageUp => Some(-i32::from(PAGE_ROWS)),
                KeyCode::Char('j') | KeyCode::Down if details => Some(1),
                KeyCode::Char('k') | KeyCode::Up if details => Some(-1),
                _ => None,
            };
            if let Some(delta) = delta {
                self.scroll_raw(delta);
                return vec![];
            }
        }
        if self.section == Section::Options {
            if let Some(actions) = self.on_options_key(key) {
                return actions;
            }
        }
        // Delegate to pane component when Details is focused.
        if let Some(actions) = self.handle_pane_key(key, confirm) {
            return actions;
        }
        // `/` opens the in-lens filter when a filterable result lens is in
        // Details; elsewhere it stays the domain-edit shortcut.
        let lens = self.current_lens();
        if key.code == KeyCode::Char('/')
            && self.section == Section::Details
            && lens.filterable()
            && matches!(self.state_of(self.lens), LensState::Loaded(_))
        {
            let cur = self.lens_filter.get(&lens.key).cloned().unwrap_or_default();
            self.input_mode = InputMode::Field {
                target: EditTarget::LensFilter,
                buf: cur.into(),
            };
            return vec![];
        }
        let Some(ka) = event::map(key) else {
            return vec![];
        };
        self.on_normal_action(ka)
    }

    fn on_command_key(
        &mut self,
        key: KeyEvent,
        mut buf: crate::tui::line_editor::LineEditor,
    ) -> Vec<Action> {
        use crate::tui::line_editor::EditOutcome;
        match buf.handle_key(key) {
            EditOutcome::Cancel => vec![],
            EditOutcome::Submit => self.exec_command(buf.as_str()),
            EditOutcome::Continue => {
                self.input_mode = InputMode::Command(buf);
                vec![]
            }
        }
    }

    fn on_field_key(
        &mut self,
        key: KeyEvent,
        target: EditTarget,
        mut buf: crate::tui::line_editor::LineEditor,
    ) -> Vec<Action> {
        use crate::tui::line_editor::EditOutcome;
        // The Domain section is a field: Tab / Shift-Tab commit it and move on.
        if target == EditTarget::Target && matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
            // Pick the next section while still on Domain: committing moves
            // focus to Function, which would shift the step by one.
            let next = self.next_section(key.code == KeyCode::Tab);
            let actions = self.apply_field(target, buf.as_str().trim().to_string());
            // A refused domain keeps the editor open: stay on Domain.
            if self.section != Section::Domain {
                self.set_section(next);
            }
            return actions;
        }
        match buf.handle_key(key) {
            EditOutcome::Cancel => {
                match target {
                    EditTarget::Target => self.section = Section::Function,
                    EditTarget::Option(_) => self.opt_error = None,
                    _ => {}
                }
                vec![]
            }
            EditOutcome::Submit => self.apply_field(target, buf.as_str().trim().to_string()),
            EditOutcome::Continue => {
                self.input_mode = InputMode::Field { target, buf };
                vec![]
            }
        }
    }

    fn apply_field(&mut self, target: EditTarget, value: String) -> Vec<Action> {
        match target {
            EditTarget::Target => {
                if value.is_empty() {
                    self.section = Section::Function;
                    return vec![];
                }
                let Some(target) = self.target_or_toast(&value) else {
                    // Refused: keep the editor open on the typed text, as a
                    // refused option value stays.
                    self.section = Section::Domain;
                    self.input_mode = InputMode::Field {
                        target: EditTarget::Target,
                        buf: value.into(),
                    };
                    return vec![];
                };
                self.section = Section::Function;
                // An unchanged domain only moves focus: no re-run, and the
                // selection stays.
                if self.domain.as_deref() == Some(target.as_str()) {
                    // …unless the function failed: committing retries it.
                    if matches!(self.state_of(self.lens), LensState::Error(_)) {
                        return self.fetch_with_current(false);
                    }
                    return vec![];
                }
                // Re-run the current function, not Overview. Not explicit:
                // a heavy lens still waits for ↵.
                self.set_domain_and_fetch_with(target, false)
            }
            EditTarget::Option(id) => {
                let key = self.current_lens().key;
                match self.options.commit_text(key, id, &value) {
                    Ok(true) => self.option_changed(false),
                    Ok(false) => {
                        self.opt_error = None;
                        vec![]
                    }
                    Err(msg) => {
                        // Refused: keep the editor open on the typed text,
                        // as Domain does, so it can be corrected.
                        self.opt_error = Some(id);
                        self.set_toast("fail", &msg);
                        self.input_mode = InputMode::Field {
                            target,
                            buf: value.into(),
                        };
                        vec![]
                    }
                }
            }
            EditTarget::Switcher => match lenses::switch_matches(&value).first() {
                Some(&i) => self.nav_to(i),
                None => {
                    let msg = format!("no lens matches “{value}”");
                    self.set_toast("warn", &seer_core::output::sanitize_line(&msg));
                    vec![]
                }
            },
            EditTarget::LensFilter => {
                // Commit the filter for the current lens; empty clears it.
                let key = self.current_lens().key;
                if value.is_empty() {
                    self.lens_filter.remove(&key);
                } else {
                    self.lens_filter.insert(key, value);
                }
                self.sel = 0;
                vec![]
            }
            EditTarget::WatchAdd => {
                if value.is_empty() {
                    return vec![];
                }
                vec![self.watch_mutate(Some(value), None)]
            }
            EditTarget::TldFilter => {
                // Commit the filter, then load details for the first match so the
                // detail panel reflects the new selection without an extra ↵.
                self.panes.tld.set_filter(value);
                let cur = self.panes.tld.current();
                if cur.is_empty() {
                    self.states.remove(&LensKey::Tld);
                    vec![]
                } else {
                    vec![self.fetch_action(FetchReq::Tld(cur))]
                }
            }
        }
    }

    /// A watchlist edit: the lens shows Loading until the refresh that
    /// follows the edit lands under the generation bumped here (see mod.rs).
    fn watch_mutate(&mut self, add: Option<String>, remove: Option<String>) -> Action {
        let gen = self.bump_fetch_gen(LensKey::Watch);
        self.states.insert(LensKey::Watch, LensState::Loading);
        Action::WatchMutate { add, remove, gen }
    }

    fn handle_pane_key(&mut self, key: KeyEvent, confirm: Option<Confirm>) -> Option<Vec<Action>> {
        if self.section != Section::Details {
            return None;
        }
        let lens_key = self.current_lens().key;
        // Watch and history actions need App state (selected row, loaded
        // data), so they are handled here; unhandled keys fall through to
        // normal nav.
        match lens_key {
            LensKey::Watch => return self.handle_watch_key(key, confirm),
            LensKey::History => return self.handle_history_key(key, confirm),
            _ => {}
        }
        let domain = self.domain.clone();
        let outcome = self
            .panes
            .handle_key(lens_key, key, domain.as_deref(), &self.options)?;
        Some(self.apply_pane_outcome(outcome))
    }

    /// Arm `action` for a confirming second press of the same key, telling
    /// the user what it will do.
    fn arm(&mut self, action: Confirm, msg: &str) {
        self.set_toast("warn", msg);
        self.confirm = Some((action, TOAST_TICKS));
    }

    /// Watch lens key handling (App-side — needs selected row + loaded data).
    /// Returns `Some(actions)` for consumed keys, `None` to fall through.
    fn handle_watch_key(&mut self, key: KeyEvent, confirm: Option<Confirm>) -> Option<Vec<Action>> {
        match key.code {
            KeyCode::Char('a') => {
                self.input_mode = InputMode::Field {
                    target: EditTarget::WatchAdd,
                    buf: crate::tui::line_editor::LineEditor::new(),
                };
                Some(vec![])
            }
            // Removing asks for a second `d` first.
            KeyCode::Char('d') => {
                let domain = self.selected_watch_domain()?;
                let armed = Confirm::Unwatch(domain.clone());
                if confirm.as_ref() == Some(&armed) {
                    return Some(vec![self.watch_mutate(None, Some(domain))]);
                }
                let msg = format!("press d again to stop watching {domain}");
                self.arm(armed, &seer_core::output::sanitize_line(&msg));
                Some(vec![])
            }
            KeyCode::Enter => {
                let domain = self.selected_watch_domain()?;
                Some(self.open_overview(&domain))
            }
            _ => None,
        }
    }

    /// History lens key handling (App-side).
    fn handle_history_key(
        &mut self,
        key: KeyEvent,
        confirm: Option<Confirm>,
    ) -> Option<Vec<Action>> {
        match key.code {
            KeyCode::Enter => {
                let domain = self.selected_history_domain()?;
                Some(self.open_overview(&domain))
            }
            // Clearing asks for a second `c` first, and says it empties the
            // whole store: a `/`-filter narrows the view, not the clear.
            KeyCode::Char('c') => {
                if confirm == Some(Confirm::ClearHistory) {
                    let gen = self.bump_fetch_gen(LensKey::History);
                    self.states.insert(LensKey::History, LensState::Loading);
                    return Some(vec![Action::HistoryClear { gen }]);
                }
                let total = match self.state_of(self.lens) {
                    LensState::Loaded(LensData::History(entries)) => entries.len(),
                    _ => 0,
                };
                let msg = format!("press c again to delete ALL {total} history entries");
                self.arm(Confirm::ClearHistory, &msg);
                Some(vec![])
            }
            _ => None,
        }
    }

    /// Replay a stored domain (a watch or history row) on the Overview.
    fn open_overview(&mut self, domain: &str) -> Vec<Action> {
        let Some(target) = self.target_or_toast(domain) else {
            return vec![];
        };
        self.goto_lens(0);
        self.set_domain_and_fetch(target)
    }

    /// Returns the domain of the currently selected watchlist row, if available.
    fn selected_watch_domain(&self) -> Option<String> {
        if let LensState::Loaded(LensData::Watch(w)) = self.state_of(self.lens) {
            w.results.get(self.sel).map(|r| r.domain.clone())
        } else {
            None
        }
    }

    /// Returns the domain of the currently selected history entry, if available.
    /// `sel` indexes the FILTERED view (`row_count` counts filtered rows), so
    /// the active `/`-filter must be applied before indexing.
    fn selected_history_domain(&self) -> Option<String> {
        let LensState::Loaded(data) = self.state_of(self.lens) else {
            return None;
        };
        if let LensData::History(entries) = data {
            crate::tui::filter::history_rows(entries, &self.active_filter())
                .nth(self.sel)
                .map(|e| e.domain.clone())
        } else {
            None
        }
    }

    fn apply_pane_outcome(&mut self, outcome: PaneOutcome) -> Vec<Action> {
        match outcome {
            PaneOutcome::None => vec![],
            // `fetch_action` marks the lens Loading (spinner, not idle hint).
            PaneOutcome::Fetch(req) => vec![self.fetch_action(req)],
            PaneOutcome::Action(a) => vec![a],
            PaneOutcome::EditField(target) => {
                let cur = match target {
                    EditTarget::TldFilter => self.panes.tld.filter.clone(),
                    _ => String::new(),
                };
                self.input_mode = InputMode::Field {
                    target,
                    buf: cur.into(),
                };
                vec![]
            }
            PaneOutcome::Toast { tone, msg } => {
                self.set_toast(tone, &msg);
                vec![]
            }
        }
    }

    fn exec_command(&mut self, line: &str) -> Vec<Action> {
        match command::parse(line) {
            CmdOutcome::Noop => vec![],
            CmdOutcome::Quit => {
                self.should_quit = true;
                vec![Action::Quit]
            }
            CmdOutcome::Help => {
                self.help = true;
                vec![]
            }
            CmdOutcome::Copy => self.copy_action(),
            CmdOutcome::SetFormat(f) => {
                self.format = f.parse().unwrap_or(OutputFormat::Human);
                self.raw_scroll = 0;
                self.set_toast("ok", &format!("output → {f}"));
                vec![]
            }
            CmdOutcome::BadFormat => {
                self.set_toast("fail", "formats: human · json · yaml · markdown");
                vec![]
            }
            CmdOutcome::SetTheme(name) => {
                if self.set_theme_by_name(&name) {
                    let msg = format!("theme → {}", self.theme.name);
                    self.set_toast("ok", &msg);
                } else {
                    // Parser validates names, but stay robust if they drift.
                    self.bad_theme_toast();
                }
                vec![]
            }
            CmdOutcome::BadTheme => {
                self.bad_theme_toast();
                vec![]
            }
            CmdOutcome::Lens { lens, target } => {
                // Smart :rdap <target>: route to the right RDAP query based on target type.
                if lens == "rdap" {
                    if let Some(t) = target {
                        return self.rdap_command(&t);
                    }
                }
                // `:tld <tld>` selects the TLD switcher slot rather than treating
                // the argument as a domain — using `fetch_with` here would clobber
                // the session domain with e.g. ".io".
                if lens == "tld" {
                    if let Some(t) = target {
                        return self.tld_command(&t);
                    }
                }
                let Some(i) = lenses::find_by_cmd_or_key(&lens) else {
                    return vec![];
                };
                // Validate first: a refused target leaves the view unchanged.
                let target = match target {
                    Some(t) => match self.target_or_toast(&t) {
                        Some(target) => Some(target),
                        None => return vec![],
                    },
                    None => None,
                };
                self.goto_lens(i);
                match target {
                    Some(target) => self.set_domain_and_fetch(target),
                    // A command is an explicit request: a heavy lens runs.
                    None => self.fetch_with_current(true),
                }
            }
            CmdOutcome::Lookup(d) => {
                let Some(target) = self.target_or_toast(&d) else {
                    return vec![];
                };
                self.goto_lens(0);
                self.set_domain_and_fetch(target)
            }
            CmdOutcome::Diff { a, b } => {
                // The options' commit-time checks come first: a refused B
                // leaves the view and the stored options unchanged.
                if !self.commit_command_options(LensKey::Diff, &[(OptId::SecondDomain, &b)]) {
                    return vec![];
                }
                let b = self
                    .options
                    .text(LensKey::Diff, OptId::SecondDomain)
                    .unwrap_or(b);
                self.goto_lens(LensKey::Diff.index());
                // A is the command's until the session target changes.
                self.panes.diff.a = a.clone();
                vec![self.fetch_action(FetchReq::Diff { a, b })]
            }
            CmdOutcome::Compare { domain, a, b } => {
                if !self.commit_command_options(
                    LensKey::Compare,
                    &[(OptId::ServerA, &a), (OptId::ServerB, &b)],
                ) {
                    return vec![];
                }
                self.goto_lens(LensKey::Compare.index());
                // The domain is the command's until the session target
                // changes; the resolvers are the options just committed.
                self.panes.compare.domain = Some(domain.clone());
                vec![self.fetch_action(FetchReq::Compare {
                    domain,
                    record_type: RecordType::A,
                    a,
                    b,
                })]
            }
            CmdOutcome::Dig {
                domain,
                record_type,
                server,
                trace,
            } => {
                let Some(target) = self.target_or_toast(&domain) else {
                    return vec![];
                };
                if let Some(server) = &server {
                    if !self.commit_command_options(LensKey::Dns, &[(OptId::Server, server)]) {
                        return vec![];
                    }
                }
                // `+trace` opens the Trace lens, anything else Records.
                let lens = if trace { LensKey::Trace } else { LensKey::Dns };
                self.goto_lens(lens.index());
                // The lens's request reads its options, so the cache check
                // refetches when only the type or server changed.
                self.options.set_record_type(lens, record_type);
                self.set_domain_and_fetch(target)
            }
            CmdOutcome::WatchMutate { add, remove } => {
                self.goto_lens(LensKey::Watch.index());
                vec![self.watch_mutate(add, remove)]
            }
            CmdOutcome::Invalid(msg) => {
                self.set_toast("fail", &msg);
                vec![]
            }
            CmdOutcome::Unknown(c) => {
                self.set_toast("fail", &format!("unknown command: {c}"));
                vec![]
            }
        }
    }

    /// Write a `:` command's option values through the same commit-time
    /// checks the Options box applies. All of them are checked before any
    /// is stored; on a refusal it toasts, changes nothing and returns false.
    fn commit_command_options(&mut self, key: LensKey, values: &[(OptId, &str)]) -> bool {
        let mut scratch = Options::default();
        for &(id, raw) in values {
            if let Err(msg) = scratch.commit_text(key, id, raw) {
                self.set_toast("fail", &msg);
                return false;
            }
        }
        for &(id, raw) in values {
            // Checked above, so this only stores.
            let _ = self.options.commit_text(key, id, raw);
        }
        true
    }

    /// Handle `:rdap <target>` — sets the RDAP Query option from
    /// whether the target looks like an IP address, an ASN, or a domain name.
    fn rdap_command(&mut self, target: &str) -> Vec<Action> {
        self.goto_lens(LensKey::Rdap.index());

        // IP address?
        if target.parse::<std::net::IpAddr>().is_ok() {
            self.options.set_choice(LensKey::Rdap, OptId::RdapQuery, 1);
            return vec![self.fetch_action(FetchReq::RdapIp(target.to_string()))];
        }

        // ASN? Match AS15169, as15169, or bare 15169.
        if let Some(asn) = parse_asn(target) {
            self.options.set_choice(LensKey::Rdap, OptId::RdapQuery, 2);
            return vec![self.fetch_action(FetchReq::RdapAsn(asn))];
        }

        // Default: domain lookup.
        self.options.set_choice(LensKey::Rdap, OptId::RdapQuery, 0);
        vec![self.fetch_action(FetchReq::RdapDomain(target.to_string()))]
    }

    /// Handle `:tld <tld>` — select the requested TLD slot in the switcher and
    /// fetch its info WITHOUT touching the global session domain. If the TLD is
    /// not one of the known slots, show an error toast and change nothing.
    fn tld_command(&mut self, tld: &str) -> Vec<Action> {
        if !self.panes.tld.select(tld) {
            self.set_toast("fail", &format!("unknown tld: {tld}"));
            return vec![];
        }
        self.goto_lens(LensKey::Tld.index());
        // `fetch_action` replaces any cached TLD state with Loading.
        vec![self.fetch_action(FetchReq::Tld(self.panes.tld.current()))]
    }

    /// Standard `:theme` error, naming the valid themes (mirrors BadFormat).
    fn bad_theme_toast(&mut self) {
        let msg = format!("themes: {}", Theme::NAMES.join(" · "));
        self.set_toast("fail", &msg);
    }

    /// Fetch the current lens at the existing domain (if any). `explicit`:
    /// the user asked for it (↵, a command), so a heavy lens runs too.
    fn fetch_with_current(&mut self, explicit: bool) -> Vec<Action> {
        self.fetch_current(explicit).into_iter().collect()
    }

    /// Navigate to lens `i`: its cached result, or its default fetch (never
    /// a heavy lens's — that waits for ↵).
    fn nav_to(&mut self, i: usize) -> Vec<Action> {
        self.goto_lens(i);
        self.fetch_with_current(false)
    }

    fn on_normal_action(&mut self, ka: KeyAction) -> Vec<Action> {
        let n_lenses = lenses::lenses().len();
        match ka {
            KeyAction::Down => {
                if self.section == Section::Function {
                    return self.nav_to((self.lens + 1) % n_lenses);
                }
                let max = self.row_count().saturating_sub(1);
                self.sel = (self.sel + 1).min(max);
                vec![]
            }
            KeyAction::Up => {
                if self.section == Section::Function {
                    return self.nav_to((self.lens + n_lenses - 1) % n_lenses);
                }
                self.sel = self.sel.saturating_sub(1);
                vec![]
            }
            KeyAction::Top => {
                if self.section == Section::Function {
                    return self.nav_to(0);
                }
                self.sel = 0;
                vec![]
            }
            KeyAction::Bottom => {
                if self.section == Section::Function {
                    return self.nav_to(n_lenses - 1);
                }
                self.sel = self.row_count().saturating_sub(1);
                vec![]
            }
            KeyAction::NextGroup => self.nav_to(lenses::group_start(self.lens, true)),
            KeyAction::PrevGroup => self.nav_to(lenses::group_start(self.lens, false)),
            KeyAction::NextSection => {
                let next = self.next_section(true);
                self.set_section(next);
                vec![]
            }
            KeyAction::PrevSection => {
                let next = self.next_section(false);
                self.set_section(next);
                vec![]
            }
            KeyAction::JumpSection(i) => {
                let Some(&section) = Section::ALL.get(i) else {
                    return vec![];
                };
                if section == Section::Options && self.visible_options().is_empty() {
                    let msg = format!("no options for {}", self.current_lens().label);
                    self.set_toast("info", &msg);
                    return vec![];
                }
                self.set_section(section);
                vec![]
            }
            KeyAction::EnterPane => {
                let lens = self.current_lens();
                // ↵ runs a heavy lens that has not run for this target yet
                // (or failed): navigation leaves it waiting for this.
                if lens.heavy
                    && self.domain.is_some()
                    && matches!(
                        self.state_of(self.lens),
                        LensState::Idle | LensState::Error(_)
                    )
                {
                    self.states.remove(&lens.key);
                    return self.fetch_with_current(true);
                }
                if self.section != Section::Function {
                    return vec![];
                }
                // ↵ retries a failed lookup, whatever the lens.
                if matches!(self.state_of(self.lens), LensState::Error(_)) {
                    let actions = self.fetch_with_current(true);
                    if !actions.is_empty() {
                        return actions;
                    }
                }
                // Follow and Bulk start from here; if they cannot (no
                // domain, no inputs), Options is where to supply them. A run
                // in progress is refused where focus is.
                if matches!(lens.key, LensKey::Follow | LensKey::Bulk) {
                    let running = self.stream_running(lens.key);
                    return match self.start_run(lens.key) {
                        Some(PaneOutcome::Action(a)) => vec![a],
                        refused if running => {
                            refused.map_or_else(Vec::new, |o| self.apply_pane_outcome(o))
                        }
                        refused => {
                            self.set_section(Section::Options);
                            refused.map_or_else(Vec::new, |o| self.apply_pane_outcome(o))
                        }
                    };
                }
                // Options first; else Details. Interactive lenses focus even
                // with no rows: their in-pane controls work without loaded
                // data. The raw view focuses to scroll with j/k.
                if !self.visible_options().is_empty() {
                    self.set_section(Section::Options);
                } else if self.row_count() > 0 || lens.interactive || self.raw_view() {
                    self.set_section(Section::Details);
                }
                vec![]
            }
            KeyAction::Back => {
                self.section = Section::Function;
                vec![]
            }
            KeyAction::ToggleRaw => {
                self.raw_scroll = 0;
                self.format = if self.format == OutputFormat::Human {
                    self.set_toast("info", "raw output → json (:set output yaml|markdown)");
                    OutputFormat::Json
                } else {
                    self.set_toast("ok", "human view");
                    OutputFormat::Human
                };
                vec![]
            }
            KeyAction::Copy => self.copy_action(),
            KeyAction::EditDomain => {
                self.set_section(Section::Domain);
                vec![]
            }
            KeyAction::Command => {
                self.input_mode = InputMode::Command(crate::tui::line_editor::LineEditor::new());
                vec![]
            }
            KeyAction::Switcher => {
                self.input_mode = InputMode::Field {
                    target: EditTarget::Switcher,
                    buf: crate::tui::line_editor::LineEditor::new(),
                };
                vec![]
            }
            KeyAction::Help => {
                self.help = true;
                vec![]
            }
            KeyAction::QuitHint => {
                self.set_toast("info", "type :q to quit");
                vec![]
            }
        }
    }

    /// Options-section keys: move between fields, step a value, or `↵` to
    /// type one (Text / Number / Nameserver) or run (Follow, Bulk, heavy
    /// lenses) / go to Details. `None` lets global keys through.
    fn on_options_key(&mut self, key: KeyEvent) -> Option<Vec<Action>> {
        let specs = self.visible_options();
        let spec = *specs.get(self.opt_cursor)?;
        let lens = self.current_lens();
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.opt_cursor = (self.opt_cursor + 1).min(specs.len() - 1);
                Some(vec![])
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.opt_cursor = self.opt_cursor.saturating_sub(1);
                Some(vec![])
            }
            KeyCode::Char('l') | KeyCode::Right | KeyCode::Char('h') | KeyCode::Left => {
                let forward = matches!(key.code, KeyCode::Char('l') | KeyCode::Right);
                if self.options.cycle(lens.key, spec.id, forward) {
                    // A Source change can hide the field under the cursor.
                    let last = self.visible_options().len().saturating_sub(1);
                    self.opt_cursor = self.opt_cursor.min(last);
                    return Some(self.option_changed(true));
                }
                Some(vec![])
            }
            KeyCode::Enter if spec.is_typed() => {
                let (value, placeholder) = self.options.display(lens.key, spec);
                let buf = if placeholder || value == "system" {
                    String::new()
                } else {
                    value
                };
                self.input_mode = InputMode::Field {
                    target: EditTarget::Option(spec.id),
                    buf: buf.into(),
                };
                Some(vec![])
            }
            KeyCode::Enter => Some(self.submit_options()),
            _ => None,
        }
    }

    /// `↵` on a chosen (not typed) field: start Follow / Bulk, run a heavy
    /// lens, else look at the result.
    fn submit_options(&mut self) -> Vec<Action> {
        let key = self.current_lens().key;
        if let Some(outcome) = self.start_run(key) {
            return self.apply_pane_outcome(outcome);
        }
        if self.current_lens().heavy {
            self.states.remove(&key);
            return self.fetch_with_current(true);
        }
        self.set_section(Section::Details);
        vec![]
    }

    /// Start the streaming run for `key` from its options: the one path
    /// `↵` takes from Function and from Options. `None` for a lens that
    /// does not stream; a refusal (no domain, nothing to run over) comes
    /// back as a toast outcome.
    fn start_run(&mut self, key: LensKey) -> Option<PaneOutcome> {
        match key {
            LensKey::Follow => {
                let Some(domain) = self.domain.clone() else {
                    return Some(PaneOutcome::Toast {
                        tone: "info",
                        msg: "enter a domain first (1)".to_string(),
                    });
                };
                let (count, secs) = self.options.follow_run()?;
                Some(self.panes.follow.start(&domain, count, secs))
            }
            LensKey::Bulk => {
                let (op, input) = self.options.bulk_run()?;
                Some(self.panes.bulk.start(op, input))
            }
            _ => None,
        }
    }

    /// Build a Copy action from the current lens's loaded output.
    fn copy_action(&mut self) -> Vec<Action> {
        let label = self.current_lens().label;
        // History has no serialized form (the shared payload serializer
        // yields a placeholder string), so copying would put that placeholder
        // on the clipboard and still report success.
        if self.current_lens().key == LensKey::History {
            self.set_toast(
                "info",
                "history can't be copied — ↵ replays an entry, then y copies it",
            );
            return vec![];
        }
        match self.state_of(self.lens) {
            LensState::Loaded(data) => {
                let fmt = if self.format == OutputFormat::Human {
                    OutputFormat::Markdown
                } else {
                    self.format
                };
                let text = crate::payload::serialize(data, fmt);
                vec![Action::Copy {
                    text,
                    label: format!("{label} as {fmt:?}").to_lowercase(),
                }]
            }
            _ => {
                self.set_toast("fail", "nothing to copy yet");
                vec![]
            }
        }
    }
}

/// Parse an ASN from `AS15169` / `as15169` / bare `15169`. Only a
/// case-insensitive `AS` prefix is stripped, so domain-ish tokens such as
/// `ab64496` or `apple123` are not mistaken for ASNs.
fn parse_asn(target: &str) -> Option<u32> {
    let digits = match target.get(..2) {
        Some(prefix) if prefix.eq_ignore_ascii_case("as") => &target[2..],
        _ => target,
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

    fn key(app: &mut App, code: KeyCode) -> Vec<Action> {
        app.update(Msg::Input(Event::Key(KeyEvent::new(
            code,
            KeyModifiers::NONE,
        ))))
    }

    /// A NOERROR dig result with no answers.
    fn empty_dig() -> LensData {
        LensData::Dig(Box::new(crate::payload::fixtures::dig(
            RecordType::A,
            vec![],
        )))
    }

    /// A session with no target that is already past the Domain field, for
    /// tests about other sections (a fresh no-domain app starts typing).
    fn idle_app() -> App {
        let mut app = App::new(None);
        app.set_section(Section::Function);
        app
    }

    #[test]
    fn startup_section_depends_on_the_target() {
        let app = App::new(None);
        assert_eq!(app.section, Section::Domain);
        assert!(matches!(
            app.input_mode,
            InputMode::Field {
                target: EditTarget::Target,
                ..
            }
        ));
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        assert_eq!(app.section, Section::Function);
    }

    #[test]
    fn tab_cycles_sections_and_skips_empty_options() {
        let mut app = app_on_lens(Some("example.com"), "whois");
        app.set_section(Section::Function);
        key(&mut app, KeyCode::Tab);
        assert_eq!(app.section, Section::Details, "WHOIS has no options");
        key(&mut app, KeyCode::Tab);
        assert_eq!(app.section, Section::Domain);
        key(&mut app, KeyCode::Tab); // commits the unchanged domain
        assert_eq!(app.section, Section::Function);
        app.lens = LensKey::Dns.index();
        key(&mut app, KeyCode::Tab);
        assert_eq!(app.section, Section::Options);
        key(&mut app, KeyCode::BackTab);
        assert_eq!(app.section, Section::Function);
    }

    #[test]
    fn digits_jump_to_sections() {
        let mut app = app_on_lens(Some("example.com"), "dns");
        app.set_section(Section::Function);
        key(&mut app, KeyCode::Char('4'));
        assert_eq!(app.section, Section::Details);
        key(&mut app, KeyCode::Char('3'));
        assert_eq!(app.section, Section::Options);
        key(&mut app, KeyCode::Char('2'));
        assert_eq!(app.section, Section::Function);
        app.lens = LensKey::Whois.index();
        key(&mut app, KeyCode::Char('3'));
        assert_eq!(app.section, Section::Function, "no options to go to");
        assert!(matches!(&app.toast, Some(t) if t.msg.contains("no options")));
        key(&mut app, KeyCode::Char('1'));
        assert_eq!(app.section, Section::Domain);
    }

    // Review Focus 1.
    #[test]
    fn domain_field_keeps_section_and_letter_keys_as_text() {
        let mut app = App::new(None);
        for c in "123.rj/q".chars() {
            key(&mut app, KeyCode::Char(c));
        }
        assert_eq!(app.section, Section::Domain);
        assert!(matches!(
            &app.input_mode,
            InputMode::Field { target: EditTarget::Target, buf } if buf.as_str() == "123.rj/q"
        ));
        assert_eq!(app.format, OutputFormat::Human, "r did not toggle raw");
    }

    #[test]
    fn committing_the_domain_reruns_the_current_function() {
        let mut app = App::new(None);
        app.lens = LensKey::Dns.index();
        for c in "example.com".chars() {
            key(&mut app, KeyCode::Char(c));
        }
        let actions = key(&mut app, KeyCode::Enter);
        assert_eq!(app.section, Section::Function);
        assert_eq!(app.current_lens().key, LensKey::Dns, "stays on Records");
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Fetch {
                req: FetchReq::Dns { .. },
                ..
            }
        )));
        // Esc reverts an edit.
        key(&mut app, KeyCode::Char('1'));
        key(&mut app, KeyCode::Char('x'));
        key(&mut app, KeyCode::Esc);
        assert_eq!(app.domain.as_deref(), Some("example.com"));
        assert_eq!(app.section, Section::Function);
    }

    #[test]
    fn cycling_an_option_reruns_after_the_debounce() {
        let mut app = app_on_lens(Some("example.com"), "dns");
        app.set_section(Section::Options);
        assert!(key(&mut app, KeyCode::Right)
            .iter()
            .all(|a| !matches!(a, Action::Fetch { .. })));
        key(&mut app, KeyCode::Right);
        assert_eq!(
            app.options.record_type(LensKey::Dns),
            Some(RecordType::CNAME)
        );
        let mut fetches = vec![];
        for _ in 0..REFETCH_TICKS {
            fetches.extend(app.update(Msg::Tick));
        }
        let reqs: Vec<_> = fetches
            .iter()
            .filter_map(|a| match a {
                Action::Fetch { req, .. } => Some(req.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(reqs.len(), 1, "one fetch for the burst: {reqs:?}");
        assert!(matches!(
            &reqs[0],
            FetchReq::Dns {
                record_type: RecordType::CNAME,
                ..
            }
        ));
    }

    #[test]
    fn typed_options_commit_now_or_are_refused() {
        let mut app = app_on_lens(Some("example.com"), "dns");
        app.set_section(Section::Options);
        key(&mut app, KeyCode::Down); // Server
        key(&mut app, KeyCode::Enter);
        assert!(matches!(
            app.input_mode,
            InputMode::Field {
                target: EditTarget::Option(OptId::Server),
                ..
            }
        ));
        for c in "9.9.9.9".chars() {
            key(&mut app, KeyCode::Char(c));
        }
        let actions = key(&mut app, KeyCode::Enter);
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch { req: FetchReq::Dns { nameserver: Some(ns), .. }, .. } if ns == "9.9.9.9"
            )),
            "got {actions:?}"
        );
        key(&mut app, KeyCode::Enter);
        for c in " bad!".chars() {
            key(&mut app, KeyCode::Char(c));
        }
        let actions = key(&mut app, KeyCode::Enter);
        assert!(!actions.iter().any(|a| matches!(a, Action::Fetch { .. })));
        assert_eq!(app.opt_error, Some(OptId::Server));
        assert!(matches!(&app.toast, Some(t) if t.tone == "fail"));
    }

    #[test]
    fn bulk_options_never_start_a_run_until_enter() {
        // Bulk: editing options never starts a run; ↵ on a choice does.
        let mut app = app_on_lens(Some("example.com"), "bulk");
        app.set_section(Section::Options);
        app.options
            .set_text(LensKey::Bulk, OptId::BulkDomains, "a.com".into());
        assert!(key(&mut app, KeyCode::Right).is_empty()); // Op → status
        for _ in 0..REFETCH_TICKS {
            assert!(app
                .update(Msg::Tick)
                .iter()
                .all(|a| !matches!(a, Action::StartBulk(_))));
        }
        let actions = key(&mut app, KeyCode::Enter);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::StartBulk(p) if p.op == "status")));
    }

    #[test]
    fn follow_options_never_start_a_run_until_enter() {
        let mut app = app_on_lens(Some("example.com"), "follow");
        app.set_section(Section::Options);
        let is_run = |a: &Action| matches!(a, Action::StartFollow(_) | Action::Fetch { .. });
        assert!(key(&mut app, KeyCode::Right).is_empty()); // Interval 30 → 35
        for _ in 0..REFETCH_TICKS * 2 {
            assert!(!app.update(Msg::Tick).iter().any(is_run), "ticks never run");
        }
        // ↵ on a typed Options field edits it; it does not start a run.
        let actions = key(&mut app, KeyCode::Enter);
        assert!(actions.is_empty());
        assert!(matches!(
            app.input_mode,
            InputMode::Field {
                target: EditTarget::Option(OptId::Interval),
                ..
            }
        ));
        key(&mut app, KeyCode::Esc);
        // ↵ from Details starts it, as does ↵ from Function (below).
        let actions = key(&mut app, KeyCode::Char('4'));
        assert!(actions.is_empty());
        let actions = key(&mut app, KeyCode::Enter);
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::StartFollow(p) if p.interval_secs == 35 && p.iterations == 20
            )),
            "got {actions:?}"
        );
    }

    #[test]
    fn enter_in_function_starts_follow_with_the_options() {
        let mut app = app_on_lens(Some("example.com"), "follow");
        app.options
            .commit_text(LensKey::Follow, OptId::Count, "5")
            .unwrap();
        let actions = key(&mut app, KeyCode::Enter);
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::StartFollow(p) if p.iterations == 5 && p.interval_secs == 30
            )),
            "got {actions:?}"
        );
        assert_eq!(
            app.section,
            Section::Function,
            "the run is watched in Details"
        );
        assert!(app.panes.follow.running);
    }

    #[test]
    fn enter_never_restarts_a_running_follow_or_bulk() {
        // A stray ↵ must not wipe a long run's results, from any section.
        for section in [Section::Function, Section::Options, Section::Details] {
            let mut app = app_on_lens(Some("example.com"), "follow");
            key(&mut app, KeyCode::Enter);
            let gen = app.panes.follow.gen;
            app.set_section(section);
            let actions = key(&mut app, KeyCode::Enter);
            assert!(
                !actions.iter().any(|a| matches!(a, Action::StartFollow(_))),
                "follow restarted from {section:?}: {actions:?}"
            );
            assert_eq!(app.panes.follow.gen, gen, "{section:?}");
            assert!(app.panes.follow.running, "{section:?}");
            assert_eq!(app.section, section, "a refusal keeps focus");
            // In Options, ↵ on Follow's numeric fields opens their editor.
            if section != Section::Options {
                assert!(
                    matches!(&app.toast, Some(t) if t.msg.contains("running")),
                    "{section:?}: {:?}",
                    app.toast
                );
            }

            let mut app = app_on_lens(None, "bulk");
            app.options
                .set_text(LensKey::Bulk, OptId::BulkDomains, "a.com".into());
            key(&mut app, KeyCode::Enter);
            assert!(app.panes.bulk.running);
            let gen = app.panes.bulk.gen;
            app.set_section(section);
            let actions = key(&mut app, KeyCode::Enter);
            assert!(
                !actions.iter().any(|a| matches!(a, Action::StartBulk(_))),
                "bulk restarted from {section:?}: {actions:?}"
            );
            assert_eq!(app.panes.bulk.gen, gen, "{section:?}");
            assert_eq!(app.section, section, "a refusal keeps focus");
            assert!(
                matches!(&app.toast, Some(t) if t.msg.contains("running")),
                "{section:?}: {:?}",
                app.toast
            );
        }
    }

    #[test]
    fn enter_in_function_on_follow_without_a_domain_lands_in_options() {
        let mut app = app_on_lens(None, "follow");
        let actions = key(&mut app, KeyCode::Enter);
        assert!(!actions.iter().any(|a| matches!(a, Action::StartFollow(_))));
        assert_eq!(app.section, Section::Options);
        assert!(
            matches!(&app.toast, Some(t) if t.msg.contains("domain")),
            "{:?}",
            app.toast
        );
        assert!(!app.panes.follow.running);
    }

    #[test]
    fn enter_in_function_starts_bulk_or_lands_in_options_with_the_toast() {
        let mut app = app_on_lens(Some("example.com"), "bulk");
        // Nothing to run over yet: refused, Options gets the focus.
        let actions = key(&mut app, KeyCode::Enter);
        assert!(!actions.iter().any(|a| matches!(a, Action::StartBulk(_))));
        assert_eq!(app.section, Section::Options);
        assert!(
            matches!(&app.toast, Some(t) if t.msg.contains("Options")),
            "{:?}",
            app.toast
        );
        // With a Source input set, ↵ in Function runs it.
        app.options
            .commit_text(LensKey::Bulk, OptId::BulkDomains, "a.com b.com")
            .unwrap();
        app.set_section(Section::Function);
        let actions = key(&mut app, KeyCode::Enter);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::StartBulk(p) if p.domains == ["a.com", "b.com"])),
            "got {actions:?}"
        );
        assert_eq!(app.section, Section::Function);
    }

    #[test]
    fn enter_in_function_retries_any_failed_lookup() {
        for lens in ["whois", "dns", "ssl"] {
            let mut app = app_on_lens(Some("example.com"), lens);
            let key_ = app.current_lens().key;
            app.states
                .insert(key_, LensState::Error("timed out".into()));
            let actions = key(&mut app, KeyCode::Enter);
            assert!(
                actions.iter().any(|a| matches!(a, Action::Fetch { .. })),
                "{lens}: {actions:?}"
            );
            assert!(
                matches!(app.state_of(app.lens), LensState::Loading),
                "{lens}"
            );
            assert_eq!(app.section, Section::Function, "{lens}: stays put");
        }
    }

    #[test]
    fn committing_an_unchanged_domain_retries_a_failed_lookup() {
        let mut app = app_on_lens(Some("example.com"), "whois");
        app.states
            .insert(LensKey::Whois, LensState::Error("timed out".into()));
        key(&mut app, KeyCode::Char('1'));
        let actions = key(&mut app, KeyCode::Enter);
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch { req: FetchReq::Whois(d), .. } if d == "example.com"
            )),
            "got {actions:?}"
        );
        assert_eq!(app.section, Section::Function);
        // A healthy lens still only moves focus.
        let mut app = app_on_lens(Some("example.com"), "whois");
        app.states.insert(LensKey::Whois, LensState::Loading);
        key(&mut app, KeyCode::Char('1'));
        assert!(key(&mut app, KeyCode::Enter).is_empty());
    }

    #[test]
    fn heavy_lenses_stage_on_navigation_and_run_on_enter() {
        for lens in ["subdomains", "audit", "takeover"] {
            let mut app = app_on_lens(Some("example.com"), lens);
            assert!(app.current_lens().heavy);
            // Staging rule: a non-explicit fetch (domain commit, option
            // change) leaves the lens waiting.
            assert!(app.fetch_with_current(false).is_empty(), "{lens}");
            assert!(matches!(app.state_of(app.lens), LensState::Idle));
            // ↵ in Function runs it.
            let actions = key(&mut app, KeyCode::Enter);
            assert!(
                actions.iter().any(|a| matches!(a, Action::Fetch { .. })),
                "{lens}: {actions:?}"
            );
        }
    }

    #[test]
    fn committing_a_domain_does_not_run_a_heavy_lens() {
        let mut app = app_on_lens(Some("example.com"), "subdomains");
        app.set_section(Section::Domain);
        app.input_mode = InputMode::Field {
            target: EditTarget::Target,
            buf: "other.com".into(),
        };
        let actions = key(&mut app, KeyCode::Enter);
        assert_eq!(app.domain.as_deref(), Some("other.com"));
        assert!(!actions.iter().any(|a| matches!(a, Action::Fetch { .. })));
        assert!(matches!(app.state_of(app.lens), LensState::Idle));
        let actions = key(&mut app, KeyCode::Enter);
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch { req: FetchReq::Subdomains(d), .. } if d == "other.com"
            )),
            "got {actions:?}"
        );
    }

    #[test]
    fn a_refused_domain_keeps_the_editor_open_with_the_typed_text() {
        for leave in [KeyCode::Enter, KeyCode::Tab] {
            let mut app = app_on_lens(Some("example.com"), "whois");
            key(&mut app, KeyCode::Char('/'));
            for c in " bad!".chars() {
                key(&mut app, KeyCode::Char(c));
            }
            let actions = key(&mut app, leave);
            assert!(actions.is_empty(), "{actions:?}");
            assert_eq!(app.section, Section::Domain, "{leave:?}");
            assert!(matches!(
                &app.input_mode,
                InputMode::Field { target: EditTarget::Target, buf } if buf.as_str() == "example.com bad!"
            ));
            assert!(matches!(&app.toast, Some(t) if t.tone == "fail"));
            assert_eq!(app.domain.as_deref(), Some("example.com"));
        }
    }

    #[test]
    fn an_unchanged_domain_only_moves_focus() {
        let mut app = app_on_lens(Some("example.com"), "whois");
        app.set_section(Section::Details);
        app.sel = 3;
        key(&mut app, KeyCode::Tab); // Domain
        assert_eq!(app.section, Section::Domain);
        let actions = key(&mut app, KeyCode::Tab); // commits the same domain
        assert_eq!(app.section, Section::Function);
        assert!(!actions.iter().any(|a| matches!(a, Action::Fetch { .. })));
        assert_eq!(app.sel, 3, "selection survives");
        // ↵ on the unchanged domain likewise.
        key(&mut app, KeyCode::Char('1'));
        let actions = key(&mut app, KeyCode::Enter);
        assert!(actions.is_empty(), "{actions:?}");
        assert_eq!((app.section, app.sel), (Section::Function, 3));
    }

    #[test]
    fn a_refused_option_keeps_its_editor_open_and_marked_until_fixed_or_esc() {
        let mut app = app_on_lens(Some("example.com"), "dns");
        app.set_section(Section::Options);
        key(&mut app, KeyCode::Down); // Server
        key(&mut app, KeyCode::Enter);
        for c in "9.9.9.9 bad!".chars() {
            key(&mut app, KeyCode::Char(c));
        }
        let actions = key(&mut app, KeyCode::Enter);
        assert!(!actions.iter().any(|a| matches!(a, Action::Fetch { .. })));
        assert_eq!(app.opt_error, Some(OptId::Server));
        assert!(matches!(&app.toast, Some(t) if t.tone == "fail"));
        // The editor is still open on what was typed, as Domain's is.
        assert!(matches!(
            &app.input_mode,
            InputMode::Field { target: EditTarget::Option(OptId::Server), buf }
                if buf.as_str() == "9.9.9.9 bad!"
        ));
        assert_eq!(app.options.server(LensKey::Dns, OptId::Server), Some(None));
        // Fixing the text and committing applies it and clears the mark.
        for _ in 0..5 {
            key(&mut app, KeyCode::Backspace); // " bad!"
        }
        let actions = key(&mut app, KeyCode::Enter);
        assert_eq!(app.opt_error, None);
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch { req: FetchReq::Dns { nameserver: Some(ns), .. }, .. } if ns == "9.9.9.9"
            )),
            "got {actions:?}"
        );
        // Esc on a refused editor closes it and clears the mark.
        key(&mut app, KeyCode::Enter);
        key(&mut app, KeyCode::Char(' ')); // whitespace is refused
        key(&mut app, KeyCode::Char('x'));
        key(&mut app, KeyCode::Enter);
        assert_eq!(app.opt_error, Some(OptId::Server));
        key(&mut app, KeyCode::Esc);
        assert_eq!(app.opt_error, None);
        assert!(matches!(app.input_mode, InputMode::Normal));
        // Committing an unchanged value clears a stale mark too.
        app.opt_error = Some(OptId::Server);
        key(&mut app, KeyCode::Enter);
        key(&mut app, KeyCode::Enter);
        assert_eq!(app.opt_error, None);
    }

    #[test]
    fn a_source_change_keeps_the_option_cursor_on_a_visible_field() {
        let mut app = app_on_lens(None, "bulk");
        app.set_section(Section::Options);
        key(&mut app, KeyCode::Down); // Source
        key(&mut app, KeyCode::Right); // → file: Domains gives way to File
        let specs = app.visible_options();
        assert_eq!(specs[2].id, OptId::BulkFile);
        assert!(app.opt_cursor < specs.len());
        // Entering Options clamps a cursor left past the end.
        app.opt_cursor = 9;
        app.set_section(Section::Function);
        app.set_section(Section::Options);
        assert_eq!(app.opt_cursor, 2);
    }

    #[test]
    fn a_lens_change_cancels_a_pending_debounce() {
        let mut app = app_on_lens(Some("example.com"), "dns");
        app.set_section(Section::Options);
        key(&mut app, KeyCode::Right);
        key(&mut app, KeyCode::Esc);
        key(&mut app, KeyCode::Char('j')); // another lens
        assert_ne!(app.current_lens().key, LensKey::Dns);
        for _ in 0..REFETCH_TICKS * 2 {
            let actions = app.update(Msg::Tick);
            assert!(!actions.iter().any(|a| matches!(a, Action::Fetch { .. })));
        }
    }

    #[test]
    fn a_second_cycle_restarts_the_debounce_countdown() {
        let mut app = app_on_lens(Some("example.com"), "dns");
        app.set_section(Section::Options);
        let fetches = |app: &mut App| {
            app.update(Msg::Tick)
                .iter()
                .filter(|a| matches!(a, Action::Fetch { .. }))
                .count()
        };
        key(&mut app, KeyCode::Right);
        assert_eq!(fetches(&mut app), 0);
        assert_eq!(fetches(&mut app), 0);
        key(&mut app, KeyCode::Right); // restarts at 3
        assert_eq!(fetches(&mut app), 0, "the first press's deadline passed");
        assert_eq!(fetches(&mut app), 0);
        assert_eq!(fetches(&mut app), 1);
        assert_eq!(fetches(&mut app), 0, "once");
    }

    #[test]
    fn a_domain_change_drops_a_pending_debounce() {
        let mut app = app_on_lens(Some("example.com"), "dns");
        app.set_section(Section::Options);
        key(&mut app, KeyCode::Right);
        let actions = app.set_domain_and_fetch_with("other.com".into(), false);
        assert_eq!(
            actions
                .iter()
                .filter(|a| matches!(a, Action::Fetch { .. }))
                .count(),
            1
        );
        for _ in 0..REFETCH_TICKS * 2 {
            let actions = app.update(Msg::Tick);
            assert!(!actions.iter().any(|a| matches!(a, Action::Fetch { .. })));
        }
    }

    // Review Focus 2.
    #[test]
    fn paste_goes_into_the_open_option_editor() {
        let mut app = app_on_lens(Some("example.com"), "diff");
        app.set_section(Section::Options);
        key(&mut app, KeyCode::Enter);
        app.update(Msg::Input(Event::Paste("other\n.org".into())));
        assert!(matches!(
            &app.input_mode,
            InputMode::Field { target: EditTarget::Option(OptId::SecondDomain), buf } if buf.as_str() == "other .org"
        ));
        assert_eq!(app.domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn a_cycled_option_drops_the_old_result_at_once_and_fetches_after_the_debounce() {
        let mut app = app_on_lens(Some("example.com"), "dns");
        let first = app.fetch_with_current(true);
        let old_gen = fetch_gen_of(&first);
        app.set_section(Section::Options);
        let actions = key(&mut app, KeyCode::Right); // A → AAAA
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::CancelFetch(LensKey::Dns))),
            "the in-flight fetch is cancelled now: {actions:?}"
        );
        assert!(!has_fetch(&actions), "the new fetch waits for the debounce");
        assert!(matches!(app.state_of(app.lens), LensState::Loading));
        // The old value's result lands inside the debounce window.
        app.update(Msg::Data {
            lens: LensKey::Dns,
            gen: old_gen,
            result: Ok(empty_dig()),
        });
        assert!(
            matches!(app.state_of(app.lens), LensState::Loading),
            "the A result must not show under the new Type"
        );
        // Exactly one fetch goes out once the value has settled.
        let mut fetches = vec![];
        for _ in 0..REFETCH_TICKS * 2 {
            fetches.extend(
                app.update(Msg::Tick)
                    .into_iter()
                    .filter(|a| matches!(a, Action::Fetch { .. })),
            );
        }
        assert_eq!(fetches.len(), 1, "{fetches:?}");
        assert!(matches!(
            &fetches[0],
            Action::Fetch {
                req: FetchReq::Dns {
                    record_type: RecordType::AAAA,
                    ..
                },
                ..
            }
        ));
        answer(&mut app, &fetches, LensKey::Dns, empty_dig());
        assert!(matches!(app.state_of(app.lens), LensState::Loaded(_)));
    }

    #[test]
    fn cycling_back_to_the_original_value_still_refetches() {
        let mut app = app_on_lens(Some("example.com"), "dns");
        let first = app.fetch_with_current(true);
        answer(&mut app, &first, LensKey::Dns, empty_dig());
        app.set_section(Section::Options);
        key(&mut app, KeyCode::Right); // → AAAA: result dropped, Loading
        key(&mut app, KeyCode::Left); // → A again, inside the debounce
        let mut fetches = 0;
        for _ in 0..REFETCH_TICKS * 2 {
            fetches += app
                .update(Msg::Tick)
                .iter()
                .filter(|a| matches!(a, Action::Fetch { .. }))
                .count();
        }
        assert_eq!(
            fetches, 1,
            "no lens is left on a spinner with nothing in flight"
        );
    }

    #[test]
    fn leaving_a_lens_mid_debounce_leaves_no_stuck_spinner() {
        let mut app = app_on_lens(Some("example.com"), "dns");
        let first = app.fetch_with_current(true);
        answer(&mut app, &first, LensKey::Dns, empty_dig());
        app.set_section(Section::Options);
        key(&mut app, KeyCode::Right);
        let _ = app.nav_to(LensKey::Whois.index());
        let back = app.nav_to(LensKey::Dns.index());
        assert!(has_fetch(&back), "a revisit fetches afresh: {back:?}");
    }

    #[test]
    fn a_refused_compare_server_changes_nothing() {
        // (A bare word like `junk` is a valid hostname to core, so the
        // refusal here is an unsupported scheme.)
        let mut app = app_on_lens(Some("example.com"), "whois");
        let actions = app.exec_command("compare other.com ftp://ns.example 1.1.1.1");
        assert!(actions.is_empty(), "{actions:?}");
        assert!(matches!(&app.toast, Some(t) if t.tone == "fail"));
        assert_eq!(app.current_lens().key, LensKey::Whois, "no lens switch");
        assert_eq!(
            app.options.server(LensKey::Compare, OptId::ServerA),
            Some(Some("8.8.8.8".into())),
            "neither server was stored"
        );
        assert!(app.panes.compare.domain.is_none());
        // Valid servers are stored and queried.
        let actions = app.exec_command("compare other.com 9.9.9.9 1.1.1.1");
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch { req: FetchReq::Compare { a, .. }, .. } if a == "9.9.9.9"
            )),
            "got {actions:?}"
        );
        assert_eq!(
            app.options.server(LensKey::Compare, OptId::ServerA),
            Some(Some("9.9.9.9".into()))
        );
    }

    #[test]
    fn a_refused_dig_server_changes_nothing() {
        let mut app = app_on_lens(Some("example.com"), "whois");
        let actions = app.exec_command("dig @ftp://ns.example example.com MX");
        assert!(actions.is_empty(), "{actions:?}");
        assert!(matches!(&app.toast, Some(t) if t.tone == "fail"));
        assert_eq!(app.current_lens().key, LensKey::Whois);
        assert_eq!(app.options.record_type(LensKey::Dns), Some(RecordType::A));
    }

    #[test]
    fn diff_command_normalizes_its_second_domain_like_the_option() {
        let mut app = app_on_lens(Some("example.com"), "whois");
        let actions = app.exec_command("diff a.com B.COM");
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch { req: FetchReq::Diff { b, .. }, .. } if b == "b.com"
            )),
            "got {actions:?}"
        );
        assert_eq!(
            app.options
                .text(LensKey::Diff, OptId::SecondDomain)
                .as_deref(),
            Some("b.com")
        );
        // A refused B leaves the view alone.
        let mut app = app_on_lens(Some("example.com"), "whois");
        let actions = app.exec_command("diff a.com b!d");
        assert!(actions.is_empty(), "{actions:?}");
        assert_eq!(app.current_lens().key, LensKey::Whois);
        assert!(matches!(&app.toast, Some(t) if t.tone == "fail"));
    }

    // Review Focus 3.
    #[test]
    fn an_option_change_supersedes_the_inflight_fetch() {
        let mut app = app_on_lens(Some("example.com"), "dns");
        let first = app.fetch_with_current(true);
        let old_gen = fetch_gen_of(&first);
        app.set_section(Section::Options);
        key(&mut app, KeyCode::Right);
        for _ in 0..REFETCH_TICKS {
            app.update(Msg::Tick);
        }
        app.update(Msg::Data {
            lens: LensKey::Dns,
            gen: old_gen,
            result: Ok(empty_dig()),
        });
        assert!(
            matches!(app.state_of(app.lens), LensState::Loading),
            "stale A result dropped"
        );
    }

    #[test]
    fn the_option_cursor_stays_on_a_visible_field() {
        let mut app = app_on_lens(None, "bulk");
        app.set_section(Section::Options);
        key(&mut app, KeyCode::Down);
        key(&mut app, KeyCode::Down); // Domains (3rd field)
        assert_eq!(app.opt_cursor, 2);
        key(&mut app, KeyCode::Down);
        assert_eq!(app.opt_cursor, 2, "clamped to the last field");
    }

    #[test]
    fn esc_leaves_options_for_function() {
        let mut app = app_on_lens(Some("example.com"), "rdap");
        app.set_section(Section::Options);
        key(&mut app, KeyCode::Esc);
        assert_eq!(app.section, Section::Function);
    }

    #[test]
    fn headers_rows_are_selectable() {
        let mut app = idle_app();
        app.lens = LensKey::Headers.index();
        let finding = |header: &str| seer_core::HeaderFinding {
            header: header.into(),
            present: true,
            value: None,
            verdict: seer_core::HeaderVerdict::Present,
            note: None,
        };
        let report = seer_core::HeaderReport {
            domain: "example.com".into(),
            url: "https://example.com/".into(),
            status: 200,
            redirects: 0,
            grade: "C".into(),
            score: 65,
            headers: vec![
                finding("strict-transport-security"),
                finding("x-frame-options"),
            ],
            cookies: vec![],
            disclosures: vec![],
            notes: vec![],
        };
        app.states.insert(
            LensKey::Headers,
            LensState::Loaded(LensData::Headers(Box::new(report))),
        );
        assert_eq!(app.row_count(), 2);
    }

    /// Every key a lens advertises is consumed by its pane (no dead hints).
    #[test]
    fn every_lens_key_hint_is_handled() {
        for lens in lenses::lenses() {
            for hint in lens.keys {
                let mut app = App::new(Some("example.com".into()));
                app.lens = lens.key.index();
                app.set_section(Section::Details);
                match lens.key {
                    LensKey::Watch => {
                        app.states
                            .insert(LensKey::Watch, make_watch_state("example.com"));
                    }
                    LensKey::History => {
                        app.states
                            .insert(LensKey::History, make_history_state("old.com"));
                    }
                    _ => {}
                }
                // Bulk's ↵ starts a run only once it has something to run.
                app.options
                    .set_text(LensKey::Bulk, OptId::BulkDomains, "a.com".into());
                let ev = KeyEvent::new(hint.code, KeyModifiers::NONE);
                assert!(
                    app.handle_pane_key(ev, None).is_some(),
                    "{} hint {:?} ({}) is not handled",
                    lens.label,
                    hint.label(),
                    hint.what
                );
            }
        }
    }

    #[test]
    fn brace_jumps_to_the_next_group_through_nav_to() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        app.set_section(Section::Details);
        key(&mut app, KeyCode::Char('}'));
        assert_eq!(app.lens, LensKey::Dns.index());
        assert_eq!(app.section, Section::Function);
        key(&mut app, KeyCode::Char('{'));
        assert_eq!(app.lens, 0);
    }

    #[test]
    fn dns_tools_are_lenses_with_their_own_fetch() {
        for (key, want) in [
            (LensKey::Dnssec, "Dnssec"),
            (LensKey::Compare, "Compare"),
            (LensKey::Trace, "Trace"),
        ] {
            let mut app = App::new(Some("example.com".into()));
            let _ = app.take_startup_actions();
            let actions = app.nav_to(key.index());
            assert!(
                actions.iter().any(|a| matches!(
                    a,
                    Action::Fetch { req, .. } if format!("{req:?}").starts_with(want)
                )),
                "{key:?}: {actions:?}"
            );
        }
    }

    #[test]
    fn dig_trace_opens_the_trace_lens() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        app.exec_command("dig example.com +trace");
        assert_eq!(app.current_lens().key, LensKey::Trace);
        app.exec_command("compare example.com 1.1.1.1 8.8.8.8");
        assert_eq!(app.current_lens().key, LensKey::Compare);
        app.exec_command("dig example.com");
        assert_eq!(app.current_lens().key, LensKey::Dns);
    }

    #[test]
    fn new_starts_on_overview_in_the_domain_field() {
        let app = App::new(None);
        assert_eq!(app.lens, 0);
        assert_eq!(app.section, Section::Domain);
        assert!(!app.should_quit);
    }

    #[test]
    fn startup_with_domain_emits_overview_fetch() {
        let mut app = App::new(Some("example.com".into()));
        let actions = app.take_startup_actions();
        assert!(matches!(
            actions.as_slice(),
            [Action::Fetch {
                req: FetchReq::Overview(_),
                ..
            }]
        ));
    }

    #[test]
    fn space_opens_the_switcher_and_enter_goes_to_the_best_match() {
        let mut app = idle_app();
        app.set_section(Section::Details);
        key(&mut app, KeyCode::Char(' '));
        for c in "j1{/".chars() {
            key(&mut app, KeyCode::Char(c));
        }
        assert_eq!(app.lens, 0, "keys typed into the switcher never navigate");
        for _ in 0..4 {
            key(&mut app, KeyCode::Backspace);
        }
        for c in "tra".chars() {
            key(&mut app, KeyCode::Char(c));
        }
        key(&mut app, KeyCode::Enter);
        assert_eq!(app.current_lens().key, LensKey::Trace);
        // No match: stay put and say so.
        key(&mut app, KeyCode::Char(' '));
        for c in "zzzz".chars() {
            key(&mut app, KeyCode::Char(c));
        }
        key(&mut app, KeyCode::Enter);
        assert_eq!(app.current_lens().key, LensKey::Trace);
        assert!(matches!(&app.toast, Some(t) if t.msg.contains("no lens matches")));
    }

    #[test]
    fn data_message_keyed_by_lens_string_stores_state() {
        let mut app = idle_app();
        // gen 0 matches the initial fetch_gen (entry absent → 0), so result is stored.
        app.update(Msg::Data {
            lens: LensKey::Dns,
            gen: 0,
            result: Ok(empty_dig()),
        });
        let dns_idx = lenses::find_by_cmd_or_key("dns").unwrap();
        assert!(matches!(app.state_of(dns_idx), LensState::Loaded(_)));
    }

    #[test]
    fn r_toggles_raw_format() {
        let mut app = idle_app();
        assert_eq!(app.format, OutputFormat::Human);
        key(&mut app, KeyCode::Char('r'));
        assert_eq!(app.format, OutputFormat::Json);
    }

    #[test]
    fn tick_clears_expired_toast() {
        let mut app = idle_app();
        app.set_toast("ok", "hi");
        for _ in 0..40 {
            app.update(Msg::Tick);
        }
        assert!(app.toast.is_none());
    }

    // ---- Watch lens action tests ----

    fn make_watch_state_data(domain: &str) -> LensData {
        use chrono::DateTime;
        let checked_at = DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap();
        LensData::Watch(Box::new(seer_core::WatchReport {
            checked_at,
            results: vec![seer_core::WatchResult {
                domain: domain.to_string(),
                ssl_days_remaining: None,
                domain_days_remaining: None,
                registrar: None,
                http_status: None,
                issues: vec![],
            }],
            total: 1,
            warnings: 0,
            critical: 0,
        }))
    }

    fn make_watch_state(domain: &str) -> LensState {
        LensState::Loaded(make_watch_state_data(domain))
    }

    fn make_history_entry(domain: &str) -> seer_core::HistoryEntry {
        use chrono::DateTime;
        use seer_core::{HistoryEntry, LookupResult, WhoisResponse};
        let timestamp = DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap();
        let whois = WhoisResponse {
            domain: domain.to_string(),
            ..Default::default()
        };
        HistoryEntry {
            domain: domain.to_string(),
            timestamp,
            result: LookupResult::Whois {
                data: whois,
                rdap_error: None,
                rdap_fallback: None,
                dns_nameservers: None,
            },
        }
    }

    fn make_history_state(domain: &str) -> LensState {
        LensState::Loaded(LensData::History(vec![make_history_entry(domain)]))
    }

    fn watch_lens_idx() -> usize {
        lenses::find_by_cmd_or_key("watch").unwrap()
    }

    fn history_lens_idx() -> usize {
        lenses::find_by_cmd_or_key("history").unwrap()
    }

    fn app_on_watch_with_domain(domain: &str) -> App {
        let mut app = idle_app();
        let idx = watch_lens_idx();
        app.lens = idx;
        app.set_section(Section::Details);
        app.sel = 0;
        app.states
            .insert(lenses::lenses()[idx].key, make_watch_state(domain));
        app
    }

    #[test]
    fn watch_d_emits_watch_mutate_remove() {
        let mut app = app_on_watch_with_domain("example.com");
        // The first `d` only asks; the second removes.
        let actions = key(&mut app, KeyCode::Char('d'));
        assert!(actions.is_empty(), "{actions:?}");
        assert!(matches!(&app.toast, Some(t) if t.msg.contains("press d again")));
        let actions = key(&mut app, KeyCode::Char('d'));
        assert!(matches!(app.state_of(watch_lens_idx()), LensState::Loading));
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::WatchMutate {
                    add: None,
                    remove: Some(domain),
                    ..
                } if domain == "example.com"
            )),
            "expected WatchMutate{{remove: Some(example.com)}}, got {actions:?}",
        );
    }

    #[test]
    fn watch_a_enters_field_watch_add() {
        let mut app = app_on_watch_with_domain("example.com");
        key(&mut app, KeyCode::Char('a'));
        assert!(
            matches!(
                app.input_mode,
                InputMode::Field {
                    target: EditTarget::WatchAdd,
                    ..
                }
            ),
            "expected Field{{WatchAdd}}, got {:?}",
            app.input_mode
        );
    }

    #[test]
    fn watch_enter_switches_to_overview() {
        let mut app = app_on_watch_with_domain("example.com");
        let actions = key(&mut app, KeyCode::Enter);
        assert_eq!(app.lens, 0, "should switch to overview lens");
        assert_eq!(app.section, Section::Function);
        // Should emit a fetch for the selected domain
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch {
                    req: FetchReq::Overview(_),
                    ..
                }
            )),
            "expected Fetch(Overview), got {actions:?}",
        );
    }

    // ---- History lens action tests ----

    #[test]
    fn history_c_emits_history_clear() {
        let mut app = idle_app();
        let idx = history_lens_idx();
        app.lens = idx;
        app.set_section(Section::Details);
        app.states
            .insert(lenses::lenses()[idx].key, make_history_state("old.com"));
        let actions = key(&mut app, KeyCode::Char('c'));
        assert!(actions.is_empty(), "the first c only asks: {actions:?}");
        assert!(matches!(&app.toast, Some(t) if t.msg.contains("ALL 1 history")));
        let actions = key(&mut app, KeyCode::Char('c'));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::HistoryClear { .. })),
            "expected HistoryClear, got {actions:?}",
        );
    }

    /// A destructive key needs its confirming press next, within the toast
    /// window: another key or the window lapsing disarms it.
    #[test]
    fn destructive_keys_need_a_prompt_second_press() {
        let mut app = idle_app();
        app.lens = history_lens_idx();
        app.set_section(Section::Details);
        app.states
            .insert(LensKey::History, make_history_state("old.com"));
        // Filtered to nothing, `c` still says it clears everything.
        app.lens_filter.insert(LensKey::History, "zzz".into());
        key(&mut app, KeyCode::Char('c'));
        assert!(matches!(&app.toast, Some(t) if t.msg.contains("ALL 1")));
        key(&mut app, KeyCode::Char('j'));
        let actions = key(&mut app, KeyCode::Char('c'));
        assert!(actions.is_empty(), "another key in between disarms");
        for _ in 0..=TOAST_TICKS {
            app.update(Msg::Tick);
        }
        let actions = key(&mut app, KeyCode::Char('c'));
        assert!(actions.is_empty(), "a lapsed confirmation disarms");

        // Watchlist: the confirmation is for the row it was armed on.
        let mut app = app_on_watch_with_domain("a.com");
        key(&mut app, KeyCode::Char('d'));
        app.states.insert(LensKey::Watch, make_watch_state("b.com"));
        let actions = key(&mut app, KeyCode::Char('d'));
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::WatchMutate { .. })),
            "a second d on another row re-asks: {actions:?}"
        );
    }

    #[test]
    fn history_enter_switches_to_overview() {
        let mut app = idle_app();
        let idx = history_lens_idx();
        app.lens = idx;
        app.set_section(Section::Details);
        app.sel = 0;
        app.states
            .insert(lenses::lenses()[idx].key, make_history_state("old.com"));
        let actions = key(&mut app, KeyCode::Enter);
        assert_eq!(app.lens, 0, "should switch to overview lens");
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch {
                    req: FetchReq::Overview(_),
                    ..
                }
            )),
            "expected Fetch(Overview), got {actions:?}",
        );
    }

    // ---- Generation guard tests ----

    #[test]
    fn stale_data_msg_is_dropped() {
        let mut app = idle_app();
        let dns_idx = lenses::find_by_cmd_or_key("dns").unwrap();
        // Bump gen to 1 by simulating a fetch (domain set → fetch triggered).
        app.domain = Some("example.com".into());
        app.fetch_gen.insert(lenses::lenses()[dns_idx].key, 1);
        // Send a stale result with gen 0.
        app.update(Msg::Data {
            lens: LensKey::Dns,
            gen: 0,
            result: Ok(empty_dig()),
        });
        // Lens should remain Idle — stale result was dropped.
        assert!(
            matches!(app.state_of(dns_idx), LensState::Idle),
            "stale gen-0 result must be dropped when current gen is 1",
        );
    }

    #[test]
    fn current_gen_data_msg_is_stored() {
        let mut app = idle_app();
        let dns_idx = lenses::find_by_cmd_or_key("dns").unwrap();
        app.fetch_gen.insert(lenses::lenses()[dns_idx].key, 2);
        app.update(Msg::Data {
            lens: LensKey::Dns,
            gen: 2,
            result: Ok(empty_dig()),
        });
        assert!(
            matches!(app.state_of(dns_idx), LensState::Loaded(_)),
            "matching gen must be stored",
        );
    }

    #[test]
    fn follow_step_dropped_on_stale_gen() {
        use chrono::Utc;
        let mut app = idle_app();
        // panes.follow.gen starts at 0; send a step with gen 5 (old run).
        app.panes.follow.gen = 3;
        let it = seer_core::dns::FollowIteration {
            iteration: 1,
            total_iterations: 5,
            timestamp: Utc::now(),
            records: vec![],
            changed: false,
            added: vec![],
            removed: vec![],
            error: None,
        };
        app.update(Msg::FollowStep {
            gen: 5,
            it: Box::new(it),
        });
        assert!(
            app.panes.follow.log.is_empty(),
            "stale follow step must be dropped"
        );
    }

    #[test]
    fn follow_step_accepted_on_matching_gen() {
        use chrono::Utc;
        let mut app = idle_app();
        app.panes.follow.gen = 7;
        let it = seer_core::dns::FollowIteration {
            iteration: 1,
            total_iterations: 5,
            timestamp: Utc::now(),
            records: vec![],
            changed: false,
            added: vec![],
            removed: vec![],
            error: None,
        };
        app.update(Msg::FollowStep {
            gen: 7,
            it: Box::new(it),
        });
        assert_eq!(
            app.panes.follow.log.len(),
            1,
            "matching gen follow step must be accepted"
        );
    }

    #[test]
    fn switching_domain_resets_follow_pane_and_drops_stale_steps() {
        use chrono::Utc;
        let make_iter = || seer_core::dns::FollowIteration {
            iteration: 1,
            total_iterations: 5,
            timestamp: Utc::now(),
            records: vec![],
            changed: false,
            added: vec![],
            removed: vec![],
            error: None,
        };

        let mut app = idle_app();
        // Establish an in-flight follow run on the first domain.
        let _ = app.set_domain_and_fetch("a.com".into());
        app.panes.follow.gen = 1;
        app.panes.follow.running = true;
        app.update(Msg::FollowStep {
            gen: 1,
            it: Box::new(make_iter()),
        });
        assert_eq!(
            app.panes.follow.log.len(),
            1,
            "precondition: one logged step"
        );

        // Switch the target domain — the follow pane must be invalidated AND
        // the in-flight background run cancelled. Without StopFollow the old
        // domain's DNS loop kept polling invisibly for up to 10 minutes; the
        // generation guard only drops its UI updates (2026-07-11 review).
        let actions = app.set_domain_and_fetch("b.com".into());
        assert!(
            actions.iter().any(|a| matches!(a, Action::StopFollow)),
            "domain switch with a live follow run must emit StopFollow"
        );
        assert!(
            app.panes.follow.gen > 1,
            "gen must advance so the old run's callbacks are superseded"
        );
        assert!(!app.panes.follow.running, "running flag must clear");
        assert!(
            app.panes.follow.log.is_empty(),
            "old domain's results must be cleared from the pane"
        );

        // A late callback from the old (a.com) run must now be dropped.
        app.update(Msg::FollowStep {
            gen: 1,
            it: Box::new(make_iter()),
        });
        assert!(
            app.panes.follow.log.is_empty(),
            "stale step from the previous domain must be dropped"
        );
    }

    #[test]
    fn rdap_command_ip_routes_to_the_ip_query() {
        let mut app = idle_app();
        let actions = app.rdap_command("8.8.8.8");
        assert_eq!(
            app.options.choice(LensKey::Rdap, OptId::RdapQuery),
            Some(1),
            ":rdap <ip> must select the IP query"
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch {
                    req: FetchReq::RdapIp(_),
                    ..
                }
            )),
            "expected Fetch(RdapIp), got {actions:?}",
        );
    }

    #[test]
    fn rdap_command_asn_routes_to_the_asn_query() {
        let mut app = idle_app();
        let actions = app.rdap_command("AS15169");
        assert_eq!(
            app.options.choice(LensKey::Rdap, OptId::RdapQuery),
            Some(2),
            ":rdap AS<n> must select the ASN query"
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch {
                    req: FetchReq::RdapAsn(15169),
                    ..
                }
            )),
            "expected Fetch(RdapAsn(15169)), got {actions:?}",
        );
    }

    #[test]
    fn rdap_command_domain_routes_to_the_domain_query() {
        let mut app = idle_app();
        let actions = app.rdap_command("example.com");
        assert_eq!(
            app.options.choice(LensKey::Rdap, OptId::RdapQuery),
            Some(0),
            ":rdap <domain> must select the domain query"
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch {
                    req: FetchReq::RdapDomain(_),
                    ..
                }
            )),
            "expected Fetch(RdapDomain), got {actions:?}",
        );
    }

    #[test]
    fn headers_command_selects_lens_and_fetches_the_domain() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        let actions = app.exec_command("headers");
        let idx = lenses::find_by_cmd_or_key("headers").unwrap();
        assert_eq!(app.lens, idx, ":headers must switch to the headers lens");
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch { req: FetchReq::Headers(d), .. } if d == "example.com"
            )),
            "expected Fetch(Headers(example.com)), got {actions:?}",
        );
    }

    #[test]
    fn audit_command_selects_lens_and_fetches_the_domain() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        let actions = app.exec_command("audit");
        let idx = lenses::find_by_cmd_or_key("audit").unwrap();
        assert_eq!(app.lens, idx, ":audit must switch to the audit lens");
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch { req: FetchReq::Audit(d), .. } if d == "example.com"
            )),
            "expected Fetch(Audit(example.com)), got {actions:?}",
        );
    }

    #[test]
    fn takeover_command_selects_lens_and_fetches_the_domain() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        let actions = app.exec_command("takeover");
        let idx = lenses::find_by_cmd_or_key("takeover").unwrap();
        assert_eq!(app.lens, idx, ":takeover must switch to the takeover lens");
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch { req: FetchReq::Takeover(d), .. } if d == "example.com"
            )),
            "expected Fetch(Takeover(example.com)), got {actions:?}",
        );
    }

    #[test]
    fn audit_row_count_is_one_row_per_finding() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        app.lens = LensKey::Audit.index();
        let mut report = seer_core::AuditReport {
            domain: "example.com".into(),
            host: "example.com".into(),
            overall: None,
            categories: vec![],
            findings: vec![],
            runs: vec![],
            complete: true,
            fail_under: None,
            passed: true,
        };
        report.findings = (0..3)
            .map(|_| seer_core::audit::Finding {
                id: "web.headers.missing",
                category: seer_core::audit::Category::Web,
                severity: seer_core::audit::Severity::Low,
                host: "example.com".into(),
                title: "t".into(),
                evidence: None,
                remediation: None,
            })
            .collect();
        app.states.insert(
            LensKey::Audit,
            LensState::Loaded(LensData::Audit(Box::new(report))),
        );
        assert_eq!(app.row_count(), 3);
    }

    #[test]
    fn takeover_row_count_uses_reported_findings_not_hosts_checked() {
        use seer_core::{TakeoverFinding, TakeoverReport, TakeoverVerdict};
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        app.lens = lenses::find_by_cmd_or_key("takeover").unwrap();
        let report = TakeoverReport {
            domain: "example.com".into(),
            // 40 hosts scanned, but only 2 are actionable and listed — the
            // selection index space must follow the table, not the scan.
            hosts_checked: 40,
            hosts_skipped: 0,
            vulnerable: 1,
            potential: 1,
            inconclusive: 0,
            findings: vec![
                TakeoverFinding {
                    host: "a.example.com".into(),
                    verdict: TakeoverVerdict::Vulnerable,
                    provider: None,
                    cname: None,
                    addresses: vec![],
                    evidence: None,
                    http_status: None,
                    probe_note: None,
                },
                TakeoverFinding {
                    host: "b.example.com".into(),
                    verdict: TakeoverVerdict::Potential,
                    provider: None,
                    cname: None,
                    addresses: vec![],
                    evidence: None,
                    http_status: None,
                    probe_note: None,
                },
            ],
            notes: vec![],
        };
        app.states.insert(
            LensKey::Takeover,
            LensState::Loaded(LensData::Takeover(Box::new(report))),
        );
        assert_eq!(app.row_count(), 2);
    }

    #[test]
    fn tld_command_selects_slot_without_clobbering_domain() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        let actions = app.exec_command("tld .io");
        let tld_idx = lenses::find_by_cmd_or_key("tld").unwrap();
        assert_eq!(app.lens, tld_idx, ":tld must switch to the tld lens");
        // The session domain must NOT be overwritten by ".io".
        assert_eq!(app.domain.as_deref(), Some("example.com"));
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch { req: FetchReq::Tld(t), .. } if t == ".io"
            )),
            "expected Fetch(Tld(.io)), got {actions:?}",
        );
    }

    #[test]
    fn tld_command_unknown_tld_errors_and_keeps_domain() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        let actions = app.exec_command("tld .zzz");
        assert!(actions.is_empty(), "unknown tld should emit no fetch");
        assert_eq!(app.domain.as_deref(), Some("example.com"));
        assert!(
            matches!(&app.toast, Some(t) if t.tone == "fail"),
            "unknown tld should set a fail toast",
        );
    }

    #[test]
    fn watch_mutate_refresh_uses_current_gen() {
        // Loading the watch lens bumps fetch_gen["watch"]; the mutation must
        // refresh with the SAME (current) gen so the Data is not dropped.
        let mut app = app_on_watch_with_domain("example.com");
        // Simulate the lens having been fetched once (gen → 1).
        app.fetch_gen
            .insert(lenses::lenses()[watch_lens_idx()].key, 1);
        key(&mut app, KeyCode::Char('d'));
        let actions = key(&mut app, KeyCode::Char('d'));
        let gen = actions.iter().find_map(|a| match a {
            Action::WatchMutate { gen, .. } => Some(*gen),
            _ => None,
        });
        assert_eq!(gen, Some(2), "mutation must carry a freshly-bumped gen");
        // A Data refresh at that gen must be accepted (not dropped as stale).
        app.update(Msg::Data {
            lens: LensKey::Watch,
            gen: 2,
            result: Ok(make_watch_state_data("kept.com")),
        });
        assert!(
            matches!(app.state_of(watch_lens_idx()), LensState::Loaded(LensData::Watch(w)) if w.results[0].domain == "kept.com"),
            "gen-correct watch refresh must replace the cached view",
        );
    }

    #[test]
    fn refresh_with_fewer_rows_clamps_the_selection() {
        let mut app = app_on_watch_with_domain("a.com");
        let LensState::Loaded(LensData::Watch(mut report)) = make_watch_state("a.com") else {
            unreachable!()
        };
        let row = report.results[0].clone();
        report.results = ["a.com", "b.com", "c.com"]
            .iter()
            .map(|d| seer_core::WatchResult {
                domain: d.to_string(),
                ..row.clone()
            })
            .collect();
        app.states
            .insert(LensKey::Watch, LensState::Loaded(LensData::Watch(report)));
        app.sel = 2; // "c.com", the last row
        app.fetch_gen.insert(LensKey::Watch, 1);
        // The refresh after removing "c.com" returns one row.
        app.update(Msg::Data {
            lens: LensKey::Watch,
            gen: 1,
            result: Ok(make_watch_state_data("a.com")),
        });
        assert_eq!(app.sel, 0, "selection must move onto the remaining row");
        assert_eq!(app.selected_watch_domain().as_deref(), Some("a.com"));
    }

    #[test]
    fn enter_pane_allowed_for_bulk_lens_empty() {
        let mut app = idle_app();
        let bulk_idx = lenses::find_by_cmd_or_key("bulk").unwrap();
        app.lens = bulk_idx;
        assert_eq!(app.row_count(), 0, "no rows");
        // Enter maps to KeyAction::EnterPane from the Function section.
        key(&mut app, KeyCode::Enter);
        assert_eq!(
            app.section,
            Section::Options,
            "bulk lens should allow EnterPane even with 0 rows",
        );
    }

    #[test]
    fn history_always_refetches_even_when_loaded() {
        let mut app = idle_app();
        app.domain = Some("example.com".into());
        let hidx = history_lens_idx();
        app.lens = hidx;
        // First entry → a History fetch is issued.
        let a1 = app.fetch_current(false);
        assert!(
            matches!(
                a1,
                Some(Action::Fetch {
                    req: FetchReq::History,
                    ..
                })
            ),
            "first visit should fetch history, got {a1:?}",
        );
        // Simulate the result arriving.
        app.states.insert(
            lenses::lenses()[hidx].key,
            LensState::Loaded(LensData::History(vec![])),
        );
        // Second entry → cache is dropped, so it fetches again (fresh disk read).
        let a2 = app.fetch_current(false);
        assert!(
            matches!(
                a2,
                Some(Action::Fetch {
                    req: FetchReq::History,
                    ..
                })
            ),
            "history must always refetch even when already Loaded, got {a2:?}",
        );
    }

    #[test]
    fn history_fetches_without_a_domain() {
        let mut app = idle_app(); // no target domain
        app.lens = history_lens_idx();
        let a = app.fetch_current(false);
        assert!(
            matches!(
                a,
                Some(Action::Fetch {
                    req: FetchReq::History,
                    ..
                })
            ),
            "history should load with no domain set, got {a:?}",
        );
    }

    #[test]
    fn paste_appends_into_active_field() {
        let mut app = idle_app();
        app.input_mode = InputMode::Field {
            target: EditTarget::WatchAdd,
            buf: "a.com ".into(),
        };
        app.update(Msg::Input(Event::Paste("b.com c.com".into())));
        assert!(
            matches!(&app.input_mode, InputMode::Field { buf, .. } if buf.as_str() == "a.com b.com c.com"),
            "paste should append to the field buffer, got {:?}",
            app.input_mode
        );
    }

    #[test]
    fn lens_filter_live_buffer_wins_then_commits_and_clears() {
        let mut app = idle_app();
        // While the filter field is open, the live edit buffer is the active filter.
        app.input_mode = InputMode::Field {
            target: EditTarget::LensFilter,
            buf: "api".into(),
        };
        assert_eq!(app.active_filter(), "api");

        // Committing stores it for the current lens.
        let _ = app.apply_field(EditTarget::LensFilter, "api".to_string());
        app.input_mode = InputMode::Normal;
        assert_eq!(app.active_filter(), "api");

        // Committing an empty value clears the filter.
        let _ = app.apply_field(EditTarget::LensFilter, String::new());
        assert_eq!(app.active_filter(), "");
    }

    #[test]
    fn domain_switch_invalidates_other_lenses_inflight_fetches() {
        let mut app = idle_app();
        let _ = app.set_domain_and_fetch("a.com".into());
        // Simulate an in-flight DNS fetch for a.com on a non-current lens.
        let dns_idx = lenses::find_by_cmd_or_key("dns").unwrap();
        let dns_key = lenses::lenses()[dns_idx].key;
        app.fetch_gen.insert(dns_key, 1);
        app.states.insert(dns_key, LensState::Loading);
        // Switch domains, then let the old domain's result land late.
        let _ = app.set_domain_and_fetch("b.com".into());
        app.update(Msg::Data {
            lens: LensKey::Dns,
            gen: 1,
            result: Ok(empty_dig()),
        });
        assert!(
            !matches!(app.state_of(dns_idx), LensState::Loaded(_)),
            "a late result fetched under the old domain must not be stored as the new domain's data",
        );
    }

    #[test]
    fn history_enter_with_filter_pivots_to_filtered_selection() {
        let mut app = idle_app();
        let idx = history_lens_idx();
        app.lens = idx;
        app.set_section(Section::Details);
        app.states.insert(
            lenses::lenses()[idx].key,
            LensState::Loaded(LensData::History(vec![
                make_history_entry("alpha.com"),
                make_history_entry("beta.com"),
            ])),
        );
        // Commit a `/`-filter matching only the second entry; sel 0 now points
        // at beta.com in the filtered view.
        let _ = app.apply_field(EditTarget::LensFilter, "beta".into());
        let actions = key(&mut app, KeyCode::Enter);
        assert_eq!(
            app.domain.as_deref(),
            Some("beta.com"),
            "Enter must resolve the selection against the filtered view, not the unfiltered list",
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch {
                    req: FetchReq::Overview(d),
                    ..
                } if d == "beta.com"
            )),
            "expected Fetch(Overview(beta.com)), got {actions:?}",
        );
    }

    // ---- Theme tests ----

    #[test]
    fn theme_command_swaps_live_theme() {
        let mut app = idle_app();
        assert_eq!(app.theme().name, "frappe", "Frappé must be the default");
        let frappe_base = app.theme().base;
        let actions = app.exec_command("theme latte");
        assert!(actions.is_empty(), ":theme must not emit actions");
        assert_eq!(app.theme().name, "latte");
        assert_ne!(
            app.theme().base,
            frappe_base,
            "latte must actually change the base color"
        );
        assert_eq!(app.theme().base, Theme::latte().base);
        assert_eq!(app.theme().text, Theme::latte().text);
        assert!(
            matches!(&app.toast, Some(t) if t.tone == "ok" && t.msg.contains("latte")),
            "expected ok toast naming latte, got {:?}",
            app.toast
        );
    }

    #[test]
    fn unknown_theme_errors_and_keeps_current_theme() {
        let mut app = idle_app();
        let _ = app.exec_command("theme latte");
        let actions = app.exec_command("theme mocha");
        assert!(actions.is_empty());
        assert_eq!(
            app.theme().name,
            "latte",
            "an unknown theme must not change the active theme"
        );
        assert!(
            matches!(
                &app.toast,
                Some(t) if t.tone == "fail" && t.msg.contains("frappe") && t.msg.contains("latte")
            ),
            "error toast must name the valid themes, got {:?}",
            app.toast
        );
        // Bare `:theme` gets the same error.
        let _ = app.exec_command("theme");
        assert!(matches!(&app.toast, Some(t) if t.tone == "fail"));
        assert_eq!(app.theme().name, "latte");
    }

    #[test]
    fn set_theme_by_name_seam_round_trips() {
        let mut app = idle_app();
        assert!(app.set_theme_by_name("latte"));
        assert_eq!(app.theme().name, "latte");
        assert!(app.set_theme_by_name("Frappé"), "accented alias must work");
        assert_eq!(app.theme().name, "frappe");
        assert!(!app.set_theme_by_name("nord"));
        assert_eq!(app.theme().name, "frappe", "failed swap keeps old theme");
    }

    // ---- Review-fix regressions ----

    fn chord(app: &mut App, code: KeyCode, mods: KeyModifiers) -> Vec<Action> {
        app.update(Msg::Input(Event::Key(KeyEvent::new(code, mods))))
    }

    fn app_on_lens(domain: Option<&str>, lens: &str) -> App {
        let mut app = App::new(domain.map(str::to_string));
        let _ = app.take_startup_actions();
        app.set_section(Section::Function);
        app.lens = lenses::find_by_cmd_or_key(lens).unwrap();
        app
    }

    #[test]
    fn ctrl_c_on_history_pane_shows_quit_hint_instead_of_clearing() {
        let mut app = app_on_lens(None, "history");
        app.set_section(Section::Details);
        app.states
            .insert(LensKey::History, make_history_state("old.com"));
        let actions = chord(&mut app, KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::HistoryClear { .. })),
            "Ctrl-C must never clear history, got {actions:?}"
        );
        assert!(
            matches!(&app.toast, Some(t) if t.msg.contains(":q")),
            "Ctrl-C should show the same quit hint as `q`, got {:?}",
            app.toast
        );
    }

    #[test]
    fn ctrl_and_alt_chords_never_reach_pane_handlers() {
        // Watch: Ctrl-D must not remove the selected domain.
        let mut app = app_on_watch_with_domain("example.com");
        let actions = chord(&mut app, KeyCode::Char('d'), KeyModifiers::CONTROL);
        assert!(actions.is_empty(), "Ctrl-D on watch: {actions:?}");

        // Bulk: Ctrl-↵ must not start a run, Alt-E must not overwrite the CSV.
        let mut app = app_on_lens(None, "bulk");
        app.set_section(Section::Details);
        app.options
            .set_text(LensKey::Bulk, OptId::BulkDomains, "a.com".into());
        let actions = chord(&mut app, KeyCode::Enter, KeyModifiers::CONTROL);
        assert!(actions.is_empty() && !app.panes.bulk.running, "{actions:?}");
        app.panes.bulk.rows.push(seer_core::bulk::BulkResult {
            operation: seer_core::bulk::BulkOperation::Lookup {
                domain: "a.com".into(),
            },
            success: true,
            data: None,
            error: None,
            duration_ms: 1,
        });
        let actions = chord(&mut app, KeyCode::Char('e'), KeyModifiers::ALT);
        assert!(actions.is_empty(), "Alt-E on bulk: {actions:?}");

        // Follow: Ctrl-↵ must not start a run.
        let mut app = app_on_lens(Some("example.com"), "follow");
        app.set_section(Section::Details);
        let actions = chord(&mut app, KeyCode::Enter, KeyModifiers::CONTROL);
        assert!(
            actions.is_empty() && !app.panes.follow.running,
            "{actions:?}"
        );
    }

    #[test]
    fn shift_and_altgr_keys_keep_working_in_normal_mode() {
        // `G` arrives with SHIFT; it must still jump to the last lens.
        let mut app = idle_app();
        chord(&mut app, KeyCode::Char('G'), KeyModifiers::SHIFT);
        assert_eq!(app.lens, lenses::lenses().len() - 1);
        // `}` typed with AltGr (CONTROL|ALT on Windows) still jumps a group.
        let mut app = app_on_lens(None, "rdap");
        let next = lenses::group_start(app.lens, true);
        chord(
            &mut app,
            KeyCode::Char('}'),
            KeyModifiers::CONTROL | KeyModifiers::ALT,
        );
        assert_eq!(app.lens, next);
    }

    #[test]
    fn rdap_asn_cache_is_not_served_for_the_domain_query() {
        let rdap = |app: &mut App, gen| {
            let r: seer_core::RdapResponse = serde_json::from_str("{}").unwrap();
            app.update(Msg::Data {
                lens: LensKey::Rdap,
                gen,
                result: Ok(LensData::Rdap(Box::new(r))),
            });
        };
        let gen_of = |actions: &[Action]| {
            actions.iter().find_map(|a| match a {
                Action::Fetch { gen, .. } => Some(*gen),
                _ => None,
            })
        };

        // With a session domain: back on the Domain query the lens refetches
        // the domain object.
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        let asn = app.exec_command("rdap AS15169");
        rdap(&mut app, gen_of(&asn).unwrap());
        app.options.set_choice(LensKey::Rdap, OptId::RdapQuery, 0);
        let back = app.fetch_with_current(false);
        assert!(
            back.iter().any(|a| matches!(
                a,
                Action::Fetch { req: FetchReq::RdapDomain(d), .. } if d == "example.com"
            )),
            "expected RdapDomain refetch, got {back:?}"
        );

        // Without one: nothing to refetch, but the ASN object must not render
        // as the Domain query's data.
        let mut app = idle_app();
        let asn = app.exec_command("rdap AS15169");
        rdap(&mut app, gen_of(&asn).unwrap());
        app.options.set_choice(LensKey::Rdap, OptId::RdapQuery, 0);
        let _ = app.fetch_with_current(false);
        let idx = lenses::find_by_cmd_or_key("rdap").unwrap();
        assert!(
            matches!(app.state_of(idx), LensState::Idle),
            "stale ASN object served for the Domain query"
        );
    }

    #[test]
    fn watch_subcommands_do_not_clobber_the_session_domain() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        let actions = app.exec_command("watch add example.org");
        assert_eq!(app.domain.as_deref(), Some("example.com"));
        assert_eq!(app.lens, watch_lens_idx());
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::WatchMutate { add: Some(d), remove: None, .. } if d == "example.org"
            )),
            "got {actions:?}"
        );

        for line in ["history clear", "bulk file.txt", "watch frob"] {
            app.toast = None;
            let actions = app.exec_command(line);
            assert!(actions.is_empty(), "{line}: {actions:?}");
            assert_eq!(app.domain.as_deref(), Some("example.com"), "{line}");
            assert!(matches!(&app.toast, Some(t) if t.tone == "fail"), "{line}");
        }
    }

    #[test]
    fn explicit_requests_mark_the_lens_loading() {
        let mut app = idle_app();
        let _ = app.rdap_command("8.8.8.8");
        let idx = lenses::find_by_cmd_or_key("rdap").unwrap();
        assert!(
            matches!(app.state_of(idx), LensState::Loading),
            "`:rdap <ip>` must show a spinner, not the idle hint"
        );
        assert_eq!(app.pending_target(idx).as_deref(), Some("8.8.8.8"));

        let _ = app.exec_command("diff a.com b.com");
        let idx = lenses::find_by_cmd_or_key("diff").unwrap();
        assert!(matches!(app.state_of(idx), LensState::Loading));
    }

    #[test]
    fn diff_command_domain_a_drives_the_pane_rerun() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        let _ = app.exec_command("diff a.com b.com");
        assert_eq!(app.panes.diff.a, "a.com");
        assert!(
            matches!(
                app.default_req(LensKey::Diff, "example.com"),
                Some(FetchReq::Diff { a, b }) if a == "a.com" && b == "b.com"
            ),
            "the lens's request must be a.com ⇄ b.com"
        );
        // A new session target resets A to follow it again.
        let _ = app.set_domain_and_fetch("new.com".into());
        assert!(app.panes.diff.a.is_empty());
    }

    #[test]
    fn dig_command_carries_the_record_type() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        let actions = app.exec_command("dig example.com MX");
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch {
                    req: FetchReq::Dns {
                        record_type: RecordType::MX,
                        ..
                    },
                    ..
                }
            )),
            "got {actions:?}"
        );
        let actions = app.exec_command("dig example.com BOGUS");
        assert!(actions.is_empty());
        assert!(matches!(&app.toast, Some(t) if t.tone == "fail" && t.msg.contains("BOGUS")));
    }

    #[test]
    fn side_effect_toasts_are_shown_verbatim() {
        let mut app = idle_app();
        app.update(Msg::Toast {
            tone: "ok",
            msg: "wrote seer-bulk-lookup.csv".into(),
        });
        assert!(
            matches!(&app.toast, Some(t) if t.msg == "wrote seer-bulk-lookup.csv"),
            "was \"copied wrote …\", got {:?}",
            app.toast
        );
    }

    #[test]
    fn enter_focuses_an_empty_watchlist_so_add_is_reachable() {
        let mut app = app_on_lens(None, "watch");
        app.states.insert(
            LensKey::Watch,
            LensState::Loaded(LensData::Watch(Box::new(seer_core::WatchReport {
                checked_at: chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap(),
                results: vec![],
                total: 0,
                warnings: 0,
                critical: 0,
            }))),
        );
        key(&mut app, KeyCode::Enter);
        assert_eq!(app.section, Section::Details);
        key(&mut app, KeyCode::Char('a'));
        assert!(matches!(
            app.input_mode,
            InputMode::Field {
                target: EditTarget::WatchAdd,
                ..
            }
        ));
    }

    #[test]
    fn rdap_asn_detection_only_strips_an_as_prefix() {
        assert_eq!(parse_asn("AS15169"), Some(15169));
        assert_eq!(parse_asn("as15169"), Some(15169));
        assert_eq!(parse_asn("15169"), Some(15169));
        assert_eq!(parse_asn("ab64496"), None);
        assert_eq!(parse_asn("apple123"), None);
        assert_eq!(parse_asn("AS"), None);
        let mut app = idle_app();
        let actions = app.rdap_command("apple123");
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch { req: FetchReq::RdapDomain(d), .. } if d == "apple123"
            )),
            "got {actions:?}"
        );
    }

    #[test]
    fn copy_refuses_history_instead_of_copying_a_placeholder() {
        let mut app = app_on_lens(None, "history");
        app.states
            .insert(LensKey::History, make_history_state("old.com"));
        let actions = key(&mut app, KeyCode::Char('y'));
        assert!(
            !actions.iter().any(|a| matches!(a, Action::Copy { .. })),
            "got {actions:?}"
        );
        assert!(matches!(&app.toast, Some(t) if t.tone != "ok"));
    }

    #[test]
    fn history_filter_counts_by_reference() {
        let mut app = app_on_lens(None, "history");
        let data = LensData::History(vec![
            make_history_entry("alpha.com"),
            make_history_entry("beta.com"),
        ]);
        // History is never deep-cloned by the generic filter...
        assert!(crate::tui::filter::apply(&data, "beta").is_none());
        app.states.insert(LensKey::History, LensState::Loaded(data));
        let _ = app.apply_field(EditTarget::LensFilter, "beta".into());
        // ...yet the visible-row count still reflects the filter.
        assert_eq!(app.row_count(), 1);
    }

    #[test]
    fn paste_appends_into_command_buffer() {
        let mut app = idle_app();
        app.input_mode = InputMode::Command("look".into());
        app.update(Msg::Input(Event::Paste("up x.com".into())));
        assert!(
            matches!(&app.input_mode, InputMode::Command(buf) if buf.as_str() == "lookup x.com"),
            "paste should append to the command buffer, got {:?}",
            app.input_mode
        );
    }

    // ---- DNS lens: dig results, filter, trace ----

    /// A dig result for `www.seer.test` A: one CNAME hop, then `n` addresses.
    fn chained_dig(n: u8) -> LensData {
        use crate::payload::fixtures;
        let mut answers = vec![fixtures::cname("www.seer.test", "edge.cdn.test.")];
        answers.extend((1..=n).map(|i| fixtures::a("edge.cdn.test", &format!("192.0.2.{i}"))));
        LensData::Dig(Box::new(fixtures::dig(RecordType::A, answers)))
    }

    /// The DNS lens on `example.com`, its Records fetch answered with `data`.
    fn dns_app_with(data: LensData) -> App {
        let mut app = app_on_lens(Some("example.com"), "dns");
        let actions = app.fetch_with_current(false);
        let Some(Action::Fetch { gen, .. }) = actions.first() else {
            panic!("expected a Records fetch, got {actions:?}");
        };
        app.update(Msg::Data {
            lens: LensKey::Dns,
            gen: *gen,
            result: Ok(data),
        });
        app
    }

    fn fetch_gen_of(actions: &[Action]) -> u64 {
        actions
            .iter()
            .find_map(|a| match a {
                Action::Fetch { gen, .. } => Some(*gen),
                _ => None,
            })
            .expect("a fetch")
    }

    #[test]
    fn dig_rows_are_the_selectable_answers_chain_included() {
        let app = dns_app_with(chained_dig(2));
        assert!(matches!(
            app.state_of(app.lens),
            LensState::Loaded(LensData::Dig(_))
        ));
        assert_eq!(app.row_count(), 3, "the CNAME hop and both addresses");
    }

    #[test]
    fn a_dig_answer_resolves_the_ip_past_the_cname_chain() {
        let app = dns_app_with(chained_dig(2));
        assert_eq!(app.panes.dns.resolved_ip.as_deref(), Some("192.0.2.1"));
        // A negative answer has none to offer.
        let app = dns_app_with(LensData::Dig(Box::new(
            crate::payload::fixtures::dig_status(RecordType::A, seer_core::DnsStatus::NxDomain),
        )));
        assert_eq!(app.panes.dns.resolved_ip, None);
    }

    #[test]
    fn selection_is_clamped_when_a_refetch_returns_fewer_answers() {
        let mut app = dns_app_with(chained_dig(4));
        app.set_section(Section::Details);
        key(&mut app, KeyCode::Char('G'));
        assert_eq!(app.sel, 4);
        // Another nameserver re-queries the lens; its answer is shorter.
        assert!(app.options.cycle(LensKey::Dns, OptId::Server, true));
        let actions = app.fetch_with_current(false);
        let gen = fetch_gen_of(&actions);
        app.update(Msg::Data {
            lens: LensKey::Dns,
            gen,
            result: Ok(chained_dig(1)),
        });
        assert_eq!(app.row_count(), 2);
        assert_eq!(app.sel, 1, "back on the last real row");
    }

    #[test]
    fn slash_filters_the_dns_records_rows() {
        let mut app = dns_app_with(chained_dig(3));
        app.set_section(Section::Details);
        key(&mut app, KeyCode::Char('/'));
        assert!(matches!(
            app.input_mode,
            InputMode::Field {
                target: EditTarget::LensFilter,
                ..
            }
        ));
        for c in "192.0.2.3".chars() {
            key(&mut app, KeyCode::Char(c));
        }
        assert_eq!(app.row_count(), 1, "the live buffer filters as you type");
        key(&mut app, KeyCode::Enter);
        assert_eq!(app.active_filter(), "192.0.2.3");
        assert_eq!(app.row_count(), 1);
        assert_eq!(app.sel, 0);
        // The filter belongs to Records: DNSSEC shows none, and it is still
        // there on the way back.
        app.nav_to(LensKey::Dnssec.index());
        assert_eq!(app.active_filter(), "");
        app.nav_to(LensKey::Dns.index());
        assert_eq!(app.active_filter(), "192.0.2.3");
    }

    #[test]
    fn trace_results_load_with_one_row_per_hop() {
        let mut app = app_on_lens(Some("example.com"), "dns");
        let actions = app.nav_to(LensKey::Trace.index());
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch {
                    req: FetchReq::Trace { domain, .. },
                    ..
                } if domain == "example.com"
            )),
            "got {actions:?}"
        );
        let trace = crate::payload::fixtures::trace(vec![], None);
        app.update(Msg::Data {
            lens: LensKey::Trace,
            gen: fetch_gen_of(&actions),
            result: Ok(LensData::Trace(Box::new(trace))),
        });
        assert!(matches!(
            app.state_of(app.lens),
            LensState::Loaded(LensData::Trace(_))
        ));
        assert_eq!(app.row_count(), 2, "one row per hop");
    }

    #[test]
    fn dig_command_selects_the_nameserver_and_the_trace_lens() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        let actions = app.exec_command("dig @9.9.9.9 AAAA example.org");
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch {
                    req: FetchReq::Dns {
                        domain,
                        record_type: RecordType::AAAA,
                        nameserver: Some(ns),
                    },
                    ..
                } if domain == "example.org" && ns == "9.9.9.9"
            )),
            "got {actions:?}"
        );

        let actions = app.exec_command("dig example.org https +trace");
        assert_eq!(app.current_lens().key, LensKey::Trace);
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch {
                    req: FetchReq::Trace {
                        record_type: RecordType::HTTPS,
                        ..
                    },
                    ..
                }
            )),
            "got {actions:?}"
        );

        let actions = app.exec_command("dig example.org A MX");
        assert!(actions.is_empty());
        assert!(
            matches!(&app.toast, Some(t) if t.tone == "fail" && t.msg.contains("one record type"))
        );
    }

    /// `:dig` asks about the name as typed, like `seer dig`: a `www.` host
    /// has records of its own (usually a CNAME), so the target keeps it.
    #[test]
    fn dig_queries_a_www_host_as_typed() {
        let mut app = idle_app();
        let actions = app.exec_command("dig www.seer.test");
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch {
                    req: FetchReq::Dns { domain, .. },
                    ..
                } if domain == "www.seer.test"
            )),
            "got {actions:?}"
        );
        let actions = app.exec_command("dig WWW.Seer.test. +trace");
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch {
                    req: FetchReq::Trace { domain, .. },
                    ..
                } if domain == "www.seer.test"
            )),
            "got {actions:?}"
        );
        // Still one canonical target: the same host spelled another way is
        // not a new one.
        assert_eq!(app.domain.as_deref(), Some("www.seer.test"));
    }

    /// A Records `/`-filter stays with Records: `:dig +trace` and
    /// `:compare` land on lenses without one, and it is there on return.
    #[test]
    fn dig_and_compare_leave_the_records_filter_on_records() {
        for command in [
            "dig example.com +trace",
            "compare example.com 8.8.8.8 1.1.1.1",
        ] {
            let mut app = dns_app_with(chained_dig(3));
            app.lens_filter.insert(LensKey::Dns, "192.0.2.3".into());
            app.exec_command(command);
            assert_ne!(app.current_lens().key, LensKey::Dns, "{command}");
            assert_eq!(app.active_filter(), "", "{command}");
            app.exec_command("dig example.com");
            assert_eq!(app.active_filter(), "192.0.2.3", "{command}");
        }
    }

    #[test]
    fn copy_and_raw_view_serialize_the_dig_result() {
        let mut app = dns_app_with(chained_dig(1));
        let actions = key(&mut app, KeyCode::Char('y'));
        let Some(Action::Copy { text, label }) = actions.first() else {
            panic!("expected a copy, got {actions:?}");
        };
        assert!(
            text.starts_with("## DNS A Records: www.seer.test"),
            "{text}"
        );
        assert!(label.contains("markdown"), "{label}");

        app.format = OutputFormat::Json;
        let actions = key(&mut app, KeyCode::Char('y'));
        let Some(Action::Copy { text, .. }) = actions.first() else {
            panic!("expected a copy, got {actions:?}");
        };
        let value: serde_json::Value = serde_json::from_str(text).expect("one JSON object");
        assert_eq!(value["status"], "NOERROR");
        assert_eq!(value["answers"][1]["name"], "edge.cdn.test");
    }

    fn has_fetch(actions: &[Action]) -> bool {
        actions.iter().any(|a| matches!(a, Action::Fetch { .. }))
    }

    /// Navigating onto Subdomains or Takeover used to start a CT-log query
    /// (and, for Takeover, HTTP probes) on every pass through the nav.
    #[test]
    fn heavy_lenses_wait_for_enter_instead_of_scanning_on_nav() {
        for lens in [LensKey::Subdomains, LensKey::Takeover] {
            let mut app = App::new(Some("example.com".into()));
            let _ = app.take_startup_actions();
            // Walk the nav down onto the heavy lens.
            let mut landed = vec![];
            while app.current_lens().key != lens {
                landed = key(&mut app, KeyCode::Char('j'));
            }
            assert!(
                !has_fetch(&landed),
                "{lens:?} must not auto-run: {landed:?}"
            );
            assert!(matches!(app.state_of(app.lens), LensState::Idle));
            // ↵ runs it, without leaving the nav.
            let actions = key(&mut app, KeyCode::Enter);
            assert!(has_fetch(&actions), "{lens:?}: {actions:?}");
            assert!(matches!(app.state_of(app.lens), LensState::Loading));
            // Once run, revisiting serves the cache rather than re-running.
            key(&mut app, KeyCode::Char('k'));
            assert!(!has_fetch(&key(&mut app, KeyCode::Char('j'))));
        }
        // A command is an explicit request: it runs at once.
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        app.input_mode = InputMode::Command("subdomains".into());
        assert!(has_fetch(&key(&mut app, KeyCode::Enter)));
    }

    /// A new target, option or request supersedes a lens's fetch: the cancel
    /// comes before any new fetch, so it cannot abort the replacement.
    #[test]
    fn superseded_fetches_are_cancelled_before_their_replacement() {
        let mut app = App::new(Some("a.com".into()));
        let _ = app.take_startup_actions();
        key(&mut app, KeyCode::Char('j')); // WHOIS in flight too
        assert_eq!(app.current_lens().key, LensKey::Whois);
        let actions = app.update(Msg::Input(Event::Paste(String::new())));
        assert!(actions.is_empty(), "a no-op update cancels nothing");
        app.input_mode = InputMode::Field {
            target: EditTarget::Target,
            buf: "b.com".into(),
        };
        let actions = key(&mut app, KeyCode::Enter);
        assert_eq!(app.domain.as_deref(), Some("b.com"));
        let first_fetch = actions
            .iter()
            .position(|a| matches!(a, Action::Fetch { .. }))
            .expect("the new target fetches");
        for lens in [LensKey::Overview, LensKey::Whois] {
            let cancel = actions
                .iter()
                .position(|a| matches!(a, Action::CancelFetch(k) if *k == lens))
                .unwrap_or_else(|| panic!("{lens:?} not cancelled: {actions:?}"));
            assert!(cancel < first_fetch, "{actions:?}");
        }
        // An option change supersedes the old request's fetch.
        app.nav_to(LensKey::Rdap.index()); // RDAP, domain query in flight
        app.options.set_choice(LensKey::Rdap, OptId::RdapQuery, 2);
        key(&mut app, KeyCode::Char('j'));
        let actions = key(&mut app, KeyCode::Char('k'));
        assert!(matches!(
            actions.first(),
            Some(Action::CancelFetch(LensKey::Rdap))
        ));
    }

    /// `g`/`G` in the nav (and replaying a watch/history row, and the `/`
    /// target) land on the first row, and serve the cached Overview rather
    /// than refetching it (an Overview refetch records history again).
    #[test]
    fn every_lens_change_resets_selection() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        app.update(Msg::Data {
            lens: LensKey::Overview,
            gen: 1,
            result: Ok(empty_dig()),
        });
        assert!(matches!(app.state_of(0), LensState::Loaded(_)));
        // Onto RDAP with a stale selection, then back with `g`.
        app.lens = LensKey::Rdap.index();
        app.sel = 4;
        let actions = key(&mut app, KeyCode::Char('g'));
        assert_eq!((app.lens, app.sel), (0, 0));
        assert!(
            !has_fetch(&actions),
            "the cached Overview is served: {actions:?}"
        );
        // `G` likewise resets the selection.
        app.sel = 4;
        key(&mut app, KeyCode::Char('G'));
        assert_eq!(app.sel, 0);
        // A new `/` target re-runs the lens it is on, from its first row.
        app.lens = LensKey::Rdap.index();
        app.sel = 4;
        key(&mut app, KeyCode::Char('/'));
        app.input_mode = InputMode::Field {
            target: EditTarget::Target,
            buf: "other.com".into(),
        };
        key(&mut app, KeyCode::Enter);
        assert_eq!((app.lens, app.sel), (LensKey::Rdap.index(), 0));
    }

    /// An invalid target used to become the session domain lowercased as
    /// typed; it is refused, and the previous target stays.
    #[test]
    fn invalid_targets_are_refused_and_ip_literals_accepted() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        key(&mut app, KeyCode::Char('/'));
        app.input_mode = InputMode::Field {
            target: EditTarget::Target,
            buf: "not a domain!".into(),
        };
        let actions = key(&mut app, KeyCode::Enter);
        assert!(actions.is_empty(), "{actions:?}");
        assert_eq!(app.domain.as_deref(), Some("example.com"));
        assert!(matches!(&app.toast, Some(t) if t.tone == "fail"));

        // `:reverse 2001:db8::1` — an IPv6 literal is a valid target.
        key(&mut app, KeyCode::Char(':'));
        app.input_mode = InputMode::Command("reverse 2001:DB8::1".into());
        let actions = key(&mut app, KeyCode::Enter);
        assert_eq!(app.domain.as_deref(), Some("2001:db8::1"));
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Fetch { req: FetchReq::Reverse(ip), .. } if ip == "2001:db8::1"
        )));
        // A wildcard query name is valid for `:dig`.
        app.input_mode = InputMode::Command("dig *.example.com".into());
        key(&mut app, KeyCode::Enter);
        assert_eq!(app.domain.as_deref(), Some("*.example.com"));
    }

    #[test]
    fn pasted_control_characters_become_spaces() {
        let mut app = idle_app();
        key(&mut app, KeyCode::Char('/'));
        app.update(Msg::Input(Event::Paste(
            "a.com\r\nb.com\tc\u{1b}[2J".into(),
        )));
        let InputMode::Field { buf, .. } = &app.input_mode else {
            panic!("field closed");
        };
        assert_eq!(buf.as_str(), "a.com  b.com c [2J");
    }

    /// An idle tick used to redraw the whole frame ten times a second.
    #[test]
    fn idle_ticks_do_not_redraw() {
        let mut app = idle_app();
        assert!(app.take_redraw(), "the first frame");
        app.update(Msg::Tick);
        assert!(!app.take_redraw(), "nothing animates");
        key(&mut app, KeyCode::Char('j'));
        assert!(app.take_redraw(), "input changes the frame");
        // A toast redraws when it appears and when it expires, not between.
        app.set_toast("ok", "hi");
        for _ in 0..TOAST_TICKS - 1 {
            app.update(Msg::Tick);
            assert!(!app.take_redraw());
        }
        app.update(Msg::Tick);
        assert!(app.toast.is_none());
        assert!(app.take_redraw(), "the expired toast must be cleared");
        // A loading lens animates its spinner.
        app.states
            .insert(app.current_lens().key, LensState::Loading);
        app.update(Msg::Tick);
        assert!(app.take_redraw());
    }

    /// The CLI's `output_format = "json"` used to open the TUI in the raw
    /// view on every lens.
    #[test]
    fn a_session_opens_on_the_rendered_view() {
        assert_eq!(App::new(None).format, OutputFormat::Human);
    }

    #[test]
    fn the_raw_view_scrolls_and_resets_on_lens_change() {
        let mut app = idle_app();
        app.lens = LensKey::Dns.index();
        app.update(Msg::Data {
            lens: LensKey::Dns,
            gen: 0,
            result: Ok(chained_dig(3)),
        });
        key(&mut app, KeyCode::Char('r'));
        assert!(app.raw_view());
        let lines = app.raw_line_count() as u16;
        assert!(lines > PAGE_ROWS, "fixture too short: {lines}");
        key(&mut app, KeyCode::PageDown);
        assert_eq!(app.raw_scroll, PAGE_ROWS);
        // j/k scroll once the raw view is focused (Details).
        key(&mut app, KeyCode::Char('4'));
        assert_eq!(app.section, Section::Details);
        key(&mut app, KeyCode::Char('j'));
        assert_eq!(app.raw_scroll, PAGE_ROWS + 1);
        key(&mut app, KeyCode::Char('k'));
        key(&mut app, KeyCode::PageUp);
        key(&mut app, KeyCode::PageUp);
        assert_eq!(app.raw_scroll, 0, "clamped at the top");
        for _ in 0..(lines / PAGE_ROWS + 3) {
            key(&mut app, KeyCode::PageDown);
        }
        assert_eq!(app.raw_scroll, lines - 1, "clamped at the last line");
        key(&mut app, KeyCode::Esc);
        key(&mut app, KeyCode::Char('j'));
        assert_eq!(app.raw_scroll, 0, "another lens starts at its top");
    }

    // ---- Options drive every request ----

    /// Every declared option, changed from its default, changes what its
    /// lens fetches or starts — so no field in the Options box is dead.
    #[test]
    fn every_option_changes_its_lens_request() {
        use crate::tui::options::OptKind;
        for lens in lenses::lenses() {
            for spec in lens.options {
                let mut app = App::new(Some("example.com".into()));
                let _ = app.take_startup_actions();
                app.panes.dns.resolved_ip = Some("192.0.2.1".into());
                app.options
                    .set_text(LensKey::Diff, OptId::SecondDomain, "example.org".into());
                app.options
                    .set_text(LensKey::Bulk, OptId::BulkDomains, "a.com b.com".into());
                app.options
                    .set_text(LensKey::Bulk, OptId::BulkFile, "list.txt".into());
                // File is read only when Source names it.
                if spec.id == OptId::BulkFile {
                    app.options.set_choice(LensKey::Bulk, OptId::BulkSource, 1);
                }
                let before = run_signature(&mut app, lens.key);
                match spec.kind {
                    OptKind::Text { .. } => {
                        let alt = if spec.id == OptId::BulkDomains {
                            "c.com"
                        } else {
                            "other.org"
                        };
                        app.options.commit_text(lens.key, spec.id, alt).unwrap();
                    }
                    _ => assert!(app.options.cycle(lens.key, spec.id, true)),
                }
                let after = run_signature(&mut app, lens.key);
                assert_ne!(before, after, "{} option {:?} is dead", lens.label, spec.id);
            }
        }
    }

    /// What a lens would fetch or start now, as text, for comparison.
    fn run_signature(app: &mut App, key: LensKey) -> String {
        match key {
            LensKey::Follow => format!("{:?}", app.options.follow_run()),
            LensKey::Bulk => format!("{:?}", app.options.bulk_run()),
            _ => format!("{:?}", app.default_req(key, "example.com")),
        }
    }

    #[test]
    fn records_and_trace_keep_their_own_record_type() {
        let mut app = app_on_lens(Some("example.com"), "dns");
        app.options.set_record_type(LensKey::Dns, RecordType::MX);
        let actions = app.nav_to(LensKey::Trace.index());
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch {
                    req: FetchReq::Trace {
                        record_type: RecordType::A,
                        ..
                    },
                    ..
                }
            )),
            "got {actions:?}"
        );
    }

    #[test]
    fn an_rdap_query_change_drops_the_cached_result() {
        let mut app = app_on_lens(Some("example.com"), "rdap");
        // Any loaded payload stands in for the domain result: only the
        // request it was fetched for matters to the cache check.
        app.states
            .insert(LensKey::Rdap, LensState::Loaded(empty_dig()));
        app.last_req
            .insert(LensKey::Rdap, FetchReq::RdapDomain("example.com".into()));
        app.options.set_choice(LensKey::Rdap, OptId::RdapQuery, 2); // ASN: no default req
        let actions = app.fetch_with_current(false);
        assert!(actions.is_empty());
        assert!(
            matches!(app.state_of(app.lens), LensState::Idle),
            "domain result not re-served"
        );
    }

    #[test]
    fn commands_write_the_options() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        app.exec_command("dig @9.9.9.9 AAAA example.org");
        assert_eq!(
            app.options.record_type(LensKey::Dns),
            Some(RecordType::AAAA)
        );
        assert_eq!(
            app.options.server(LensKey::Dns, OptId::Server),
            Some(Some("9.9.9.9".into()))
        );
        app.exec_command("dig example.org https +trace");
        assert_eq!(
            app.options.record_type(LensKey::Trace),
            Some(RecordType::HTTPS)
        );
        app.exec_command("compare other.com 9.9.9.9 8.8.4.4");
        assert_eq!(
            app.options.server(LensKey::Compare, OptId::ServerB),
            Some(Some("8.8.4.4".into()))
        );
        app.exec_command("diff a.com b.com");
        assert_eq!(
            app.options.text(LensKey::Diff, OptId::SecondDomain),
            Some("b.com".into())
        );
        app.exec_command("rdap AS15169");
        assert_eq!(app.options.choice(LensKey::Rdap, OptId::RdapQuery), Some(2));
    }

    // Review Focus 5.
    #[test]
    fn a_new_domain_keeps_options_but_resets_command_overrides() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        app.options.set_record_type(LensKey::Dns, RecordType::MX);
        app.exec_command("compare other.com 9.9.9.9 8.8.4.4");
        let _ = app.set_domain_and_fetch("new.com".into());
        assert_eq!(app.options.record_type(LensKey::Dns), Some(RecordType::MX));
        assert!(app.panes.compare.domain.is_none());
        assert!(matches!(
            app.default_req(LensKey::Compare, "new.com"),
            Some(FetchReq::Compare { domain, .. }) if domain == "new.com"
        ));
    }

    #[test]
    fn follow_and_bulk_start_from_their_options() {
        let mut app = app_on_lens(Some("example.com"), "follow");
        app.options
            .commit_text(LensKey::Follow, OptId::Count, "5")
            .unwrap();
        let out = app.panes.handle_key(
            LensKey::Follow,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            Some("example.com"),
            &app.options,
        );
        assert!(
            matches!(
                out,
                Some(PaneOutcome::Action(Action::StartFollow(ref p))) if p.iterations == 5 && p.interval_secs == 30
            ),
            "got {out:?}"
        );

        // Bulk: Op and Domains come from the options.
        let mut app = app_on_lens(Some("example.com"), "bulk");
        assert!(app.options.cycle(LensKey::Bulk, OptId::BulkOp, true));
        app.options
            .commit_text(LensKey::Bulk, OptId::BulkDomains, "a.com b.com")
            .unwrap();
        let out = app.panes.handle_key(
            LensKey::Bulk,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            Some("example.com"),
            &app.options,
        );
        assert!(
            matches!(
                out,
                Some(PaneOutcome::Action(Action::StartBulk(ref p)))
                    if p.op == "status" && p.domains == ["a.com", "b.com"]
            ),
            "got {out:?}"
        );
    }

    /// Answers `fetch`'s request the way the event loop would.
    fn answer(app: &mut App, actions: &[Action], lens: LensKey, data: LensData) {
        app.update(Msg::Data {
            lens,
            gen: fetch_gen_of(actions),
            result: Ok(data),
        });
    }

    #[test]
    fn an_ad_hoc_diff_survives_leaving_and_returning() {
        let mut app = idle_app();
        let actions = app.exec_command("diff a.com b.com");
        answer(&mut app, &actions, LensKey::Diff, empty_dig());
        assert!(matches!(
            app.state_of(LensKey::Diff.index()),
            LensState::Loaded(_)
        ));
        let _ = app.nav_to(LensKey::Whois.index());
        let back = app.nav_to(LensKey::Diff.index());
        assert!(!has_fetch(&back), "no refetch: {back:?}");
        assert!(matches!(
            app.state_of(LensKey::Diff.index()),
            LensState::Loaded(_)
        ));
    }

    #[test]
    fn an_rdap_ip_result_without_a_resolved_ip_survives_leaving_and_returning() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        let actions = app.exec_command("rdap 8.8.8.8");
        answer(&mut app, &actions, LensKey::Rdap, empty_dig());
        let _ = app.nav_to(LensKey::Whois.index());
        let back = app.nav_to(LensKey::Rdap.index());
        assert!(!has_fetch(&back), "no refetch: {back:?}");
        assert!(matches!(
            app.state_of(LensKey::Rdap.index()),
            LensState::Loaded(_)
        ));
    }
}
