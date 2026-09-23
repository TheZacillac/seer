//! Pure application state for the TUI. No ratatui imports — `render.rs` reads
//! this. `update(Msg) -> Vec<Action>` is the single state transition.

use std::collections::HashMap;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use seer_core::output::OutputFormat;
use seer_core::RecordType;

use crate::tui::action::{
    Action, EditTarget, FetchReq, Focus, InputMode, LensData, LensState, Msg,
};
use crate::tui::command::{self, CmdOutcome};
use crate::tui::event::{self, KeyAction};
use crate::tui::lenses;
use crate::tui::panes::{PaneOutcome, Panes};
use crate::tui::theme::Theme;

/// Number of 100ms ticks a toast lives for (~2.2s).
const TOAST_TICKS: u32 = 22;
/// Spinner frames (braille), matching the mockup.
pub const SPIN: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

#[derive(Debug, Clone)]
pub struct Toast {
    pub tone: String,
    pub msg: String,
    ticks_left: u32,
}

pub struct App {
    pub lens: usize,
    pub focus: Focus,
    pub tab: usize,
    pub sel: usize,
    pub format: OutputFormat,
    pub domain: Option<String>,
    pub input_mode: InputMode,
    pub help: bool,
    pub should_quit: bool,
    pub spin: usize,
    pub toast: Option<Toast>,
    pub panes: Panes,
    /// Active color theme (Frappé by default). Private so swaps go through
    /// `set_theme_by_name`, keeping `theme.name` canonical.
    theme: Theme,
    states: HashMap<&'static str, LensState>,
    startup: Vec<Action>,
    /// Per-lens generation counter; stale results carry a lower gen and are dropped.
    fetch_gen: HashMap<&'static str, u64>,
    /// Committed in-lens `/`-filter per lens key (subdomains/history/propagation).
    lens_filter: HashMap<&'static str, String>,
    /// The request each lens's cached state was last fetched for. The state
    /// cache is keyed by lens only, so this is what tells `fetch_current` that
    /// a cached result belongs to another sub-tab or an ad-hoc target
    /// (`:rdap AS15169`, `:compare other.com …`) and must not be re-served.
    last_req: HashMap<&'static str, FetchReq>,
}

impl App {
    pub fn new(domain: Option<String>) -> Self {
        let mut app = Self {
            lens: 0,
            focus: Focus::Nav,
            tab: 0,
            sel: 0,
            format: OutputFormat::Human,
            domain: None,
            input_mode: InputMode::Normal,
            help: false,
            should_quit: false,
            spin: 0,
            toast: None,
            panes: Panes::default(),
            theme: Theme::frappe(),
            states: HashMap::new(),
            startup: Vec::new(),
            fetch_gen: HashMap::new(),
            lens_filter: HashMap::new(),
            last_req: HashMap::new(),
        };
        if let Some(d) = domain {
            let actions = app.set_domain_and_fetch(&d);
            app.startup.extend(actions);
        }
        app
    }

    /// Seeds session defaults from the user config (`~/.seer/config.toml`).
    ///
    /// Pure: the caller (`mod.rs`) performs the file I/O and passes the loaded
    /// config in, keeping this `App` layer free of I/O. Currently seeds the
    /// output format used by the raw-output view; the DNS pane's nameserver is
    /// a fixed system/Google/Cloudflare picker and is intentionally left alone.
    pub fn apply_config(&mut self, config: &seer_core::SeerConfig) {
        self.format = config.output_format.parse().unwrap_or(OutputFormat::Human);
    }

    /// Drain the actions queued at construction (initial lookup).
    pub fn take_startup_actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.startup)
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
            .get(lenses::lenses()[lens].key)
            .unwrap_or(&LensState::Idle)
    }

    pub fn set_toast(&mut self, tone: &str, msg: &str) {
        self.toast = Some(Toast {
            tone: tone.to_string(),
            msg: msg.to_string(),
            ticks_left: TOAST_TICKS,
        });
    }

    /// Increment and return the generation counter for a lens key.
    fn bump_fetch_gen(&mut self, key: &'static str) -> u64 {
        let g = self.fetch_gen.entry(key).or_insert(0);
        *g += 1;
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
            .get(lenses::lenses()[lens].key)
            .map(FetchReq::target)
    }

    /// Number of selectable rows in the current lens's loaded data.
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
            .get(self.current_lens().key)
            .cloned()
            .unwrap_or_default()
    }

    pub fn row_count(&self) -> usize {
        let LensState::Loaded(data) = self.state_of(self.lens) else {
            return 0;
        };
        // Count the filtered rows so selection stays within the visible subset.
        let filter = self.active_filter();
        let filtered = crate::tui::filter::apply(data, &filter);
        let data = filtered.as_ref().unwrap_or(data);
        match data {
            LensData::Dns(r) => r.len(),
            LensData::Prop(p) => p.results.len(),
            LensData::Reverse(r) => r.len(),
            LensData::Watch(w) => w.results.len(),
            // Filtered by reference (entries are too heavy to clone per frame).
            LensData::History(e) => crate::tui::filter::history_rows(e, &filter).count(),
            LensData::Subdomains(s) => s.subdomains.len(),
            // Only reported (non-safe) hosts are listed, so the selection
            // index space is the findings vec, not hosts_checked.
            LensData::Takeover(t) => t.findings.len(),
            _ => 0,
        }
    }

    /// Normalize + record the domain and produce a Fetch for the current lens
    /// (if it has anything to fetch).
    fn set_domain_and_fetch(&mut self, raw: &str) -> Vec<Action> {
        let normalized = seer_core::normalize_domain(raw).unwrap_or_else(|_| raw.to_lowercase());
        let mut actions = Vec::new();
        // A new target invalidates every cached lens.
        if self.domain.as_deref() != Some(normalized.as_str()) {
            self.states.clear();
            self.last_req.clear();
            // `:diff a b` / `:compare d …` overrides follow the session target
            // only until it changes; the new target becomes domain A again.
            self.panes.diff.a.clear();
            self.panes.compare.domain = None;
            // Bump EVERY lens's generation, not just the current one's (which
            // fetch_current bumps below): an in-flight fetch on another lens,
            // started under the old domain, would otherwise still match its
            // unchanged gen and land as the new domain's data.
            for gen in self.fetch_gen.values_mut() {
                *gen += 1;
            }
            // A new target invalidates any per-lens filters too.
            self.lens_filter.clear();
            // The resolved IP is derived from the OLD domain's DNS/Status
            // results; clearing it prevents the RDAP "IP" tab from looking up
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
        self.domain = Some(normalized);
        self.sel = 0;
        actions.extend(self.fetch_current());
        actions
    }

    /// Queue a fetch for the current lens at the current domain, marking it
    /// Loading. Returns None if there's nothing to fetch. History and Watch do
    /// not require a target domain.
    fn fetch_current(&mut self) -> Option<Action> {
        let key = self.current_lens().key;
        // History reflects on-disk state that lookups mutate behind its back;
        // always re-read it rather than serving a cached (possibly empty) view.
        if key == "history" {
            self.states.remove(key);
        }
        // Most lenses need a target; History/Watch are global views.
        let want = match self.domain.clone() {
            Some(domain) => self.default_req(key, &domain),
            None => match key {
                "history" => Some(FetchReq::History),
                "watch" => Some(FetchReq::Watch),
                _ => None,
            },
        };
        // Cached (or in flight) for the current domain → revisiting is instant,
        // unless the cache was produced for another sub-tab or target: lens
        // switches reset the tab to 0, so e.g. a cached DNSSEC (tab 1) or
        // `:rdap AS…` (tab 2) result would otherwise render under tab 0.
        if matches!(
            self.states.get(key),
            Some(LensState::Loaded(_) | LensState::Loading)
        ) {
            let stale = self.last_req.get(key).is_some_and(|prev| {
                prev.tab() != self.tab || want.as_ref().is_some_and(|w| w != prev)
            });
            if !stale {
                return None;
            }
            // Drop the mismatched state, and invalidate any in-flight fetch
            // for it even when no replacement request follows (e.g. RDAP
            // domain tab with no session domain).
            self.states.remove(key);
            self.last_req.remove(key);
            self.bump_fetch_gen(key);
        }
        want.map(|req| self.fetch_action(req))
    }

    /// Default fetch request for a lens at `domain` (used by nav/number-jump).
    /// Interactive lenses with no single-domain default return None.
    fn default_req(&self, key: &str, domain: &str) -> Option<FetchReq> {
        let d = domain.to_string();
        Some(match key {
            "overview" => FetchReq::Overview(d),
            "whois" => FetchReq::Whois(d),
            "rdap" => match self.tab {
                0 => FetchReq::RdapDomain(d),
                // IP tab: only auto-fetch when a real IP has been resolved (from
                // a prior DNS/Status lookup). Without one, fall back to the idle
                // hint rather than firing RdapIp against a domain string.
                1 => FetchReq::RdapIp(self.panes.dns.resolved_ip.clone()?),
                _ => return None, // ASN needs explicit :rdap AS…
            },
            "dns" => match self.tab {
                1 => FetchReq::Dnssec(d),
                2 => FetchReq::Compare {
                    domain: self.panes.compare.domain.clone().unwrap_or(d),
                    record_type: RecordType::A,
                    a: self.panes.compare.a.clone(),
                    b: self.panes.compare.b.clone(),
                },
                _ => FetchReq::Dns {
                    domain: d,
                    record_type: self.panes.dns.record_type,
                    nameserver: self.panes.dns.nameserver(),
                },
            },
            "ssl" => FetchReq::Ssl(d),
            "status" => FetchReq::Status(d),
            "propagation" => FetchReq::Prop(d),
            "reverse" => FetchReq::Reverse(d),
            "avail" => FetchReq::Avail(d),
            "tld" => FetchReq::Tld(self.panes.tld.current()),
            "diff" => return None, // needs a second domain (DiffB field)
            "watch" => FetchReq::Watch,
            "history" => FetchReq::History,
            "subdomains" => FetchReq::Subdomains(d),
            "headers" => FetchReq::Headers(d),
            "takeover" => FetchReq::Takeover(d),
            "follow" | "bulk" => return None, // streaming — started explicitly
            _ => return None,
        })
    }

    /// After a sub-tab change, a tab-bearing lens needs the new tab's data
    /// (the per-lens cache is keyed by lens, not tab), so drop the cached state
    /// and re-fetch for the now-active tab.
    fn refetch_for_tab(&mut self) -> Vec<Action> {
        let lens = self.current_lens();
        if lens.tabs.is_empty() {
            return vec![];
        }
        let key = lens.key;
        self.states.remove(key);
        // Invalidate any in-flight fetch for the previous tab even when the
        // new tab has no default request (RDAP IP tab without a resolved IP,
        // ASN tab): no fetch_action follows to bump the gen there, and the
        // old tab's late result would otherwise render as this tab's data.
        self.bump_fetch_gen(key);
        self.fetch_with_current()
    }

    /// Populate `panes.dns.resolved_ip` from DNS or Status results so the RDAP
    /// IP tab can auto-fetch without an explicit `:rdap <ip>` command.
    fn extract_resolved_ip_if_needed(&mut self, data: &LensData) {
        match data {
            LensData::Dns(records) => {
                let ip = records.iter().find_map(|r| {
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

    pub fn update(&mut self, msg: Msg) -> Vec<Action> {
        match msg {
            Msg::Tick => {
                self.spin = (self.spin + 1) % SPIN.len();
                if let Some(t) = &mut self.toast {
                    t.ticks_left = t.ticks_left.saturating_sub(1);
                    if t.ticks_left == 0 {
                        self.toast = None;
                    }
                }
                vec![]
            }
            Msg::Data { lens, gen, result } => {
                // Resolve the string key back to a &'static str via the registry.
                if let Some(reg) = lenses::lenses().iter().find(|l| l.key == lens) {
                    // Drop stale results — only store if the generation matches.
                    let current_gen = self.fetch_gen.get(reg.key).copied().unwrap_or(0);
                    if current_gen == gen {
                        let new_state = match result {
                            Ok(data) => {
                                // Side-effect: extract resolved IP from DNS/Status results.
                                self.extract_resolved_ip_if_needed(&data);
                                LensState::Loaded(data)
                            }
                            Err(e) => LensState::Error(e),
                        };
                        self.states.insert(reg.key, new_state);
                        // A refresh can return fewer rows (e.g. after `watch
                        // remove` of the last row); keep the selection on a
                        // real row so the highlight and row actions agree.
                        if reg.key == self.current_lens().key {
                            self.sel = self.sel.min(self.row_count().saturating_sub(1));
                        }
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
                // Bracketed paste lands here as one string. Route it into whatever
                // text buffer is active so multi-line domain lists paste cleanly.
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
        // Delegate to pane component when pane-focused.
        if let Some(actions) = self.handle_pane_key(key) {
            return actions;
        }
        // `/` opens the in-lens filter when a filterable result lens is
        // pane-focused; when nav-focused it stays the domain-edit shortcut.
        if key.code == KeyCode::Char('/')
            && self.focus == Focus::Pane
            && crate::tui::filter::is_filterable(self.current_lens().key)
            && matches!(self.state_of(self.lens), LensState::Loaded(_))
        {
            let cur = self
                .lens_filter
                .get(self.current_lens().key)
                .cloned()
                .unwrap_or_default();
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
        match buf.handle_key(key) {
            EditOutcome::Cancel => vec![],
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
                    return vec![];
                }
                self.lens = 0;
                self.focus = Focus::Nav;
                self.set_domain_and_fetch(&value)
            }
            EditTarget::LensFilter => {
                // Commit the filter for the current lens; empty clears it.
                let key = self.current_lens().key;
                if value.is_empty() {
                    self.lens_filter.remove(key);
                } else {
                    self.lens_filter.insert(key, value);
                }
                self.sel = 0;
                vec![]
            }
            EditTarget::DiffB => {
                self.panes.diff.b = value.to_lowercase();
                match self.panes.diff.effective_a(self.domain.as_deref()) {
                    Some(a) if !self.panes.diff.b.is_empty() => {
                        let b = self.panes.diff.b.clone();
                        let action = self.fetch_action(FetchReq::Diff { a, b });
                        vec![action]
                    }
                    _ => vec![],
                }
            }
            EditTarget::WatchAdd => {
                if value.is_empty() {
                    return vec![];
                }
                let gen = self.bump_fetch_gen("watch");
                vec![Action::WatchMutate {
                    add: Some(value),
                    remove: None,
                    gen,
                }]
            }
            EditTarget::TldFilter => {
                // Commit the filter, then load details for the first match so the
                // detail panel reflects the new selection without an extra ↵.
                self.panes.tld.set_filter(value);
                let cur = self.panes.tld.current();
                if cur.is_empty() {
                    self.states.remove("tld");
                    vec![]
                } else {
                    vec![self.fetch_action(FetchReq::Tld(cur))]
                }
            }
            EditTarget::FollowInterval
            | EditTarget::FollowCount
            | EditTarget::BulkPath
            | EditTarget::BulkDomains => self.panes.apply_field(target, value, self.domain.clone()),
        }
    }

    fn handle_pane_key(&mut self, key: KeyEvent) -> Option<Vec<Action>> {
        if self.focus != Focus::Pane {
            return None;
        }
        let lens_key = self.current_lens().key;
        // Watch and history actions need App state (selected row, loaded data),
        // so they are handled here before generic pane delegation.
        if lens_key == "watch" {
            if let Some(actions) = self.handle_watch_key(key) {
                return Some(actions);
            }
            return None; // fall through to normal nav for unhandled keys
        }
        if lens_key == "history" {
            if let Some(actions) = self.handle_history_key(key) {
                return Some(actions);
            }
            return None;
        }
        let domain = self.domain.clone();
        let outcome = self
            .panes
            .handle_key(lens_key, self.tab, key, domain.as_deref())?;
        Some(self.apply_pane_outcome(outcome))
    }

    /// Watch lens key handling (App-side — needs selected row + loaded data).
    /// Returns `Some(actions)` for consumed keys, `None` to fall through.
    fn handle_watch_key(&mut self, key: KeyEvent) -> Option<Vec<Action>> {
        match key.code {
            KeyCode::Char('a') => {
                self.input_mode = InputMode::Field {
                    target: EditTarget::WatchAdd,
                    buf: crate::tui::line_editor::LineEditor::new(),
                };
                Some(vec![])
            }
            KeyCode::Char('d') => {
                let domain = self.selected_watch_domain()?;
                let gen = self.bump_fetch_gen("watch");
                Some(vec![Action::WatchMutate {
                    add: None,
                    remove: Some(domain),
                    gen,
                }])
            }
            KeyCode::Enter => {
                let domain = self.selected_watch_domain()?;
                self.lens = 0; // switch to Overview
                self.focus = Focus::Nav;
                Some(self.fetch_with(&domain))
            }
            _ => None,
        }
    }

    /// History lens key handling (App-side).
    fn handle_history_key(&mut self, key: KeyEvent) -> Option<Vec<Action>> {
        match key.code {
            KeyCode::Enter => {
                let domain = self.selected_history_domain()?;
                self.lens = 0;
                self.focus = Focus::Nav;
                Some(self.fetch_with(&domain))
            }
            KeyCode::Char('c') => {
                let gen = self.bump_fetch_gen("history");
                Some(vec![Action::HistoryClear { gen }])
            }
            _ => None,
        }
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
                let cur = self.panes.field_value(target);
                self.input_mode = InputMode::Field {
                    target,
                    buf: cur.into(),
                };
                vec![]
            }
            PaneOutcome::Toast { tone, msg } => {
                self.set_toast(tone, msg);
                vec![]
            }
        }
    }

    fn fetch_with(&mut self, domain: &str) -> Vec<Action> {
        self.set_domain_and_fetch(domain)
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
                // Smart :rdap <target>: route to the right RDAP sub-tab based on target type.
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
                if let Some(i) = lenses::find_by_cmd_or_key(&lens) {
                    self.lens = i;
                    self.sel = 0;
                    self.focus = Focus::Nav;
                    self.reset_tab();
                    if let Some(t) = target {
                        return self.fetch_with(&t);
                    }
                    return self.fetch_with_current();
                }
                vec![]
            }
            CmdOutcome::Lookup(d) => {
                self.lens = 0;
                self.reset_tab();
                self.fetch_with(&d)
            }
            CmdOutcome::Diff { a, b } => {
                if let Some(i) = lenses::find_by_cmd_or_key("diff") {
                    self.lens = i;
                    self.sel = 0;
                    self.focus = Focus::Nav;
                    self.reset_tab();
                }
                // Keep A too: the pane's labels and its ↵ re-run must use the
                // command's A, not the session domain.
                self.panes.diff.a = a.clone();
                self.panes.diff.b = b.clone();
                let action = self.fetch_action(FetchReq::Diff { a, b });
                vec![action]
            }
            CmdOutcome::Compare { domain, a, b } => {
                if let Some(i) = lenses::find_by_cmd_or_key("dns") {
                    self.lens = i;
                    self.tab = 2; // Compare tab
                    self.sel = 0;
                    self.focus = Focus::Nav;
                }
                // Remember the domain (so `a`/`b` re-runs stay on it) and keep
                // the cycling indices in sync with the given resolvers.
                self.panes.compare.domain = Some(domain.clone());
                self.panes.compare.set_servers(a.clone(), b.clone());
                let action = self.fetch_action(FetchReq::Compare {
                    domain,
                    record_type: RecordType::A,
                    a,
                    b,
                });
                vec![action]
            }
            CmdOutcome::Dig {
                domain,
                record_type,
            } => {
                if let Some(i) = lenses::find_by_cmd_or_key("dns") {
                    self.lens = i;
                    self.sel = 0;
                    self.focus = Focus::Nav;
                    self.reset_tab();
                }
                // The Records tab's default request reads the type, so the
                // cache check refetches when only the type changed.
                self.panes.dns.record_type = record_type;
                self.fetch_with(&domain)
            }
            CmdOutcome::WatchMutate { add, remove } => {
                if let Some(i) = lenses::find_by_cmd_or_key("watch") {
                    self.lens = i;
                    self.sel = 0;
                    self.focus = Focus::Nav;
                    self.reset_tab();
                }
                // The mutation's refresh lands under this gen (see mod.rs).
                let gen = self.bump_fetch_gen("watch");
                self.states.insert("watch", LensState::Loading);
                vec![Action::WatchMutate { add, remove, gen }]
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

    /// Handle `:rdap <target>` — routes to the correct RDAP sub-tab based on
    /// whether the target looks like an IP address, an ASN, or a domain name.
    fn rdap_command(&mut self, target: &str) -> Vec<Action> {
        let Some(rdap_idx) = lenses::find_by_cmd_or_key("rdap") else {
            return vec![];
        };
        self.lens = rdap_idx;
        self.sel = 0;
        self.focus = Focus::Nav;

        // IP address?
        if target.parse::<std::net::IpAddr>().is_ok() {
            self.tab = 1;
            return vec![self.fetch_action(FetchReq::RdapIp(target.to_string()))];
        }

        // ASN? Match AS15169, as15169, or bare 15169.
        if let Some(asn) = parse_asn(target) {
            self.tab = 2;
            return vec![self.fetch_action(FetchReq::RdapAsn(asn))];
        }

        // Default: domain lookup on tab 0.
        self.tab = 0;
        vec![self.fetch_action(FetchReq::RdapDomain(target.to_string()))]
    }

    /// Handle `:tld <tld>` — select the requested TLD slot in the switcher and
    /// fetch its info WITHOUT touching the global session domain. If the TLD is
    /// not one of the known slots, show an error toast and change nothing.
    fn tld_command(&mut self, tld: &str) -> Vec<Action> {
        let Some(tld_idx) = lenses::find_by_cmd_or_key("tld") else {
            return vec![];
        };
        if !self.panes.tld.select(tld) {
            self.set_toast("fail", &format!("unknown tld: {tld}"));
            return vec![];
        }
        self.lens = tld_idx;
        self.sel = 0;
        self.focus = Focus::Nav;
        self.reset_tab();
        // `fetch_action` replaces any cached TLD state with Loading.
        vec![self.fetch_action(FetchReq::Tld(self.panes.tld.current()))]
    }

    /// Standard `:theme` error, naming the valid themes (mirrors BadFormat).
    fn bad_theme_toast(&mut self) {
        let msg = format!("themes: {}", Theme::NAMES.join(" · "));
        self.set_toast("fail", &msg);
    }

    /// Fetch the current lens at the existing domain (if any).
    fn fetch_with_current(&mut self) -> Vec<Action> {
        match self.fetch_current() {
            Some(a) => vec![a],
            None => vec![],
        }
    }

    fn reset_tab(&mut self) {
        self.tab = 0;
    }

    fn on_normal_action(&mut self, ka: KeyAction) -> Vec<Action> {
        let n_lenses = lenses::lenses().len();
        match ka {
            KeyAction::Down => {
                if self.focus == Focus::Nav {
                    self.lens = (self.lens + 1) % n_lenses;
                    self.sel = 0;
                    self.reset_tab();
                    return self.fetch_with_current();
                }
                let max = self.row_count().saturating_sub(1);
                self.sel = (self.sel + 1).min(max);
                vec![]
            }
            KeyAction::Up => {
                if self.focus == Focus::Nav {
                    self.lens = (self.lens + n_lenses - 1) % n_lenses;
                    self.sel = 0;
                    self.reset_tab();
                    return self.fetch_with_current();
                }
                self.sel = self.sel.saturating_sub(1);
                vec![]
            }
            KeyAction::Top => {
                if self.focus == Focus::Pane {
                    self.sel = 0;
                } else {
                    self.lens = 0;
                    return self.fetch_with_current();
                }
                vec![]
            }
            KeyAction::Bottom => {
                if self.focus == Focus::Pane {
                    self.sel = self.row_count().saturating_sub(1);
                } else {
                    self.lens = n_lenses - 1;
                    return self.fetch_with_current();
                }
                vec![]
            }
            KeyAction::JumpLens(i) => {
                if i < n_lenses {
                    self.lens = i;
                    self.sel = 0;
                    self.focus = Focus::Nav;
                    self.reset_tab();
                    return self.fetch_with_current();
                }
                vec![]
            }
            KeyAction::ToggleFocus => {
                self.focus = self.focus.toggled();
                vec![]
            }
            KeyAction::NextTab => {
                self.tab = lenses::cycle_tab(self.current_lens(), self.tab, true);
                self.sel = 0;
                self.refetch_for_tab()
            }
            KeyAction::PrevTab => {
                self.tab = lenses::cycle_tab(self.current_lens(), self.tab, false);
                self.sel = 0;
                self.refetch_for_tab()
            }
            KeyAction::EnterPane => {
                // Allow entering interactive lenses even when row_count is 0 (they have
                // in-pane controls that work without pre-loaded rows).
                // "watch": with an empty watchlist there are no rows, yet `a`
                // (add) is the pane's whole point.
                const INTERACTIVE_LENSES: &[&str] = &[
                    "tld", "diff", "compare", "follow", "bulk", "dns", "rdap", "watch",
                ];
                let lens_key = self.current_lens().key;
                if self.row_count() > 0 || INTERACTIVE_LENSES.contains(&lens_key) {
                    self.focus = Focus::Pane;
                }
                vec![]
            }
            KeyAction::Back => {
                self.focus = Focus::Nav;
                vec![]
            }
            KeyAction::ToggleRaw => {
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
                let cur = self.domain.clone().unwrap_or_default();
                self.input_mode = InputMode::Field {
                    target: EditTarget::Target,
                    buf: cur.into(),
                };
                vec![]
            }
            KeyAction::Command => {
                self.input_mode = InputMode::Command(crate::tui::line_editor::LineEditor::new());
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

    /// Build a Copy action from the current lens's loaded output.
    fn copy_action(&mut self) -> Vec<Action> {
        let label = self.current_lens().label;
        // History has no serialized form (the shared payload serializer
        // yields a placeholder string), so copying would put that placeholder
        // on the clipboard and still report success.
        if self.current_lens().key == "history" {
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

    #[test]
    fn new_starts_on_overview_nav_focus() {
        let app = App::new(None);
        assert_eq!(app.lens, 0);
        assert_eq!(app.focus, Focus::Nav);
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
    fn number_jump_to_whois_fetches_whois() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        let actions = key(&mut app, KeyCode::Char('2'));
        assert_eq!(app.lens, 1);
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Fetch {
                req: FetchReq::Whois(_),
                ..
            }
        )));
    }

    #[test]
    fn editing_target_field_enter_fetches() {
        let mut app = App::new(None);
        key(&mut app, KeyCode::Char('/'));
        assert!(matches!(
            app.input_mode,
            InputMode::Field {
                target: EditTarget::Target,
                ..
            }
        ));
        for c in "acme.io".chars() {
            key(&mut app, KeyCode::Char(c));
        }
        let actions = key(&mut app, KeyCode::Enter);
        assert_eq!(app.domain.as_deref(), Some("acme.io"));
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Fetch {
                req: FetchReq::Overview(_),
                ..
            }
        )));
    }

    #[test]
    fn data_message_keyed_by_lens_string_stores_state() {
        let mut app = App::new(None);
        // gen 0 matches the initial fetch_gen (entry absent → 0), so result is stored.
        app.update(Msg::Data {
            lens: "dns".into(),
            gen: 0,
            result: Ok(LensData::Dns(vec![])),
        });
        let dns_idx = lenses::find_by_cmd_or_key("dns").unwrap();
        assert!(matches!(app.state_of(dns_idx), LensState::Loaded(_)));
    }

    #[test]
    fn r_toggles_raw_format() {
        let mut app = App::new(None);
        assert_eq!(app.format, OutputFormat::Human);
        key(&mut app, KeyCode::Char('r'));
        assert_eq!(app.format, OutputFormat::Json);
    }

    #[test]
    fn tick_clears_expired_toast() {
        let mut app = App::new(None);
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
        let mut app = App::new(None);
        let idx = watch_lens_idx();
        app.lens = idx;
        app.focus = Focus::Pane;
        app.sel = 0;
        app.states
            .insert(lenses::lenses()[idx].key, make_watch_state(domain));
        app
    }

    #[test]
    fn watch_d_emits_watch_mutate_remove() {
        let mut app = app_on_watch_with_domain("example.com");
        let actions = key(&mut app, KeyCode::Char('d'));
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
        assert_eq!(app.focus, Focus::Nav);
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
        let mut app = App::new(None);
        let idx = history_lens_idx();
        app.lens = idx;
        app.focus = Focus::Pane;
        app.states
            .insert(lenses::lenses()[idx].key, make_history_state("old.com"));
        let actions = key(&mut app, KeyCode::Char('c'));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::HistoryClear { .. })),
            "expected HistoryClear, got {actions:?}",
        );
    }

    #[test]
    fn history_enter_switches_to_overview() {
        let mut app = App::new(None);
        let idx = history_lens_idx();
        app.lens = idx;
        app.focus = Focus::Pane;
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
        let mut app = App::new(None);
        let dns_idx = lenses::find_by_cmd_or_key("dns").unwrap();
        // Bump gen to 1 by simulating a fetch (domain set → fetch triggered).
        app.domain = Some("example.com".into());
        app.fetch_gen.insert(lenses::lenses()[dns_idx].key, 1);
        // Send a stale result with gen 0.
        app.update(Msg::Data {
            lens: "dns".into(),
            gen: 0,
            result: Ok(LensData::Dns(vec![])),
        });
        // Lens should remain Idle — stale result was dropped.
        assert!(
            matches!(app.state_of(dns_idx), LensState::Idle),
            "stale gen-0 result must be dropped when current gen is 1",
        );
    }

    #[test]
    fn current_gen_data_msg_is_stored() {
        let mut app = App::new(None);
        let dns_idx = lenses::find_by_cmd_or_key("dns").unwrap();
        app.fetch_gen.insert(lenses::lenses()[dns_idx].key, 2);
        app.update(Msg::Data {
            lens: "dns".into(),
            gen: 2,
            result: Ok(LensData::Dns(vec![])),
        });
        assert!(
            matches!(app.state_of(dns_idx), LensState::Loaded(_)),
            "matching gen must be stored",
        );
    }

    #[test]
    fn follow_step_dropped_on_stale_gen() {
        use chrono::Utc;
        let mut app = App::new(None);
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
        let mut app = App::new(None);
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

        let mut app = App::new(None);
        // Establish an in-flight follow run on the first domain.
        let _ = app.set_domain_and_fetch("a.com");
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
        let actions = app.set_domain_and_fetch("b.com");
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
    fn rdap_command_ip_routes_to_tab1() {
        let mut app = App::new(None);
        let actions = app.rdap_command("8.8.8.8");
        assert_eq!(app.tab, 1, ":rdap <ip> must switch to tab 1");
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
    fn rdap_command_asn_routes_to_tab2() {
        let mut app = App::new(None);
        let actions = app.rdap_command("AS15169");
        assert_eq!(app.tab, 2, ":rdap AS<n> must switch to tab 2");
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
    fn rdap_command_domain_routes_to_tab0() {
        let mut app = App::new(None);
        let actions = app.rdap_command("example.com");
        assert_eq!(app.tab, 0, ":rdap <domain> must stay on tab 0");
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
            "takeover",
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
        let actions = key(&mut app, KeyCode::Char('d'));
        let gen = actions.iter().find_map(|a| match a {
            Action::WatchMutate { gen, .. } => Some(*gen),
            _ => None,
        });
        assert_eq!(gen, Some(2), "mutation must carry a freshly-bumped gen");
        // A Data refresh at that gen must be accepted (not dropped as stale).
        app.update(Msg::Data {
            lens: "watch".into(),
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
            .insert("watch", LensState::Loaded(LensData::Watch(report)));
        app.sel = 2; // "c.com", the last row
        app.fetch_gen.insert("watch", 1);
        // The refresh after removing "c.com" returns one row.
        app.update(Msg::Data {
            lens: "watch".into(),
            gen: 1,
            result: Ok(make_watch_state_data("a.com")),
        });
        assert_eq!(app.sel, 0, "selection must move onto the remaining row");
        assert_eq!(app.selected_watch_domain().as_deref(), Some("a.com"));
    }

    #[test]
    fn enter_pane_allowed_for_bulk_lens_empty() {
        let mut app = App::new(None);
        let bulk_idx = lenses::find_by_cmd_or_key("bulk").unwrap();
        app.lens = bulk_idx;
        assert_eq!(app.row_count(), 0, "no rows");
        // Enter maps to KeyAction::EnterPane when focus is Nav.
        key(&mut app, KeyCode::Enter);
        assert_eq!(
            app.focus,
            Focus::Pane,
            "bulk lens should allow EnterPane even with 0 rows",
        );
    }

    #[test]
    fn history_always_refetches_even_when_loaded() {
        let mut app = App::new(None);
        app.domain = Some("example.com".into());
        let hidx = history_lens_idx();
        app.lens = hidx;
        // First entry → a History fetch is issued.
        let a1 = app.fetch_current();
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
        let a2 = app.fetch_current();
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
        let mut app = App::new(None); // no target domain
        app.lens = history_lens_idx();
        let a = app.fetch_current();
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
        let mut app = App::new(None);
        app.input_mode = InputMode::Field {
            target: EditTarget::DiffB,
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
        let mut app = App::new(None);
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
        let mut app = App::new(None);
        let _ = app.set_domain_and_fetch("a.com");
        // Simulate an in-flight DNS fetch for a.com on a non-current lens.
        let dns_idx = lenses::find_by_cmd_or_key("dns").unwrap();
        let dns_key = lenses::lenses()[dns_idx].key;
        app.fetch_gen.insert(dns_key, 1);
        app.states.insert(dns_key, LensState::Loading);
        // Switch domains, then let the old domain's result land late.
        let _ = app.set_domain_and_fetch("b.com");
        app.update(Msg::Data {
            lens: "dns".into(),
            gen: 1,
            result: Ok(LensData::Dns(vec![])),
        });
        assert!(
            !matches!(app.state_of(dns_idx), LensState::Loaded(_)),
            "a late result fetched under the old domain must not be stored as the new domain's data",
        );
    }

    #[test]
    fn history_enter_with_filter_pivots_to_filtered_selection() {
        let mut app = App::new(None);
        let idx = history_lens_idx();
        app.lens = idx;
        app.focus = Focus::Pane;
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

    #[test]
    fn rdap_tab_switch_without_default_req_drops_inflight_result() {
        let mut app = App::new(None);
        app.domain = Some("example.com".into());
        let idx = lenses::find_by_cmd_or_key("rdap").unwrap();
        let rdap_key = lenses::lenses()[idx].key;
        app.lens = idx;
        // Simulate an in-flight domain-tab fetch.
        app.fetch_gen.insert(rdap_key, 1);
        app.states.insert(rdap_key, LensState::Loading);
        // Switch to the IP tab with no resolved IP: there is no default
        // request, so no new fetch is issued...
        app.tab = 1;
        let actions = app.refetch_for_tab();
        assert!(
            actions.is_empty(),
            "IP tab without a resolved IP must not fetch, got {actions:?}",
        );
        // ...and the stale domain-tab result landing late must be dropped, not
        // rendered as the IP tab's data.
        let rdap: seer_core::RdapResponse =
            serde_json::from_str("{}").expect("empty RDAP object deserializes");
        app.update(Msg::Data {
            lens: "rdap".into(),
            gen: 1,
            result: Ok(LensData::Rdap(Box::new(rdap))),
        });
        assert!(
            !matches!(app.state_of(idx), LensState::Loaded(_)),
            "stale domain result must not render as the IP/ASN tab's data",
        );
    }

    // ---- Theme tests ----

    #[test]
    fn theme_command_swaps_live_theme() {
        let mut app = App::new(None);
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
        let mut app = App::new(None);
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
        let mut app = App::new(None);
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
        app.lens = lenses::find_by_cmd_or_key(lens).unwrap();
        app
    }

    #[test]
    fn ctrl_c_on_history_pane_shows_quit_hint_instead_of_clearing() {
        let mut app = app_on_lens(None, "history");
        app.focus = Focus::Pane;
        app.states.insert("history", make_history_state("old.com"));
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

        // Bulk: Ctrl-R must not start a run, Alt-E must not overwrite the CSV.
        let mut app = app_on_lens(None, "bulk");
        app.focus = Focus::Pane;
        app.panes.bulk.domains = "a.com".into();
        let actions = chord(&mut app, KeyCode::Char('r'), KeyModifiers::CONTROL);
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

        // Follow: Ctrl-S must not start a run.
        let mut app = app_on_lens(Some("example.com"), "follow");
        app.focus = Focus::Pane;
        let actions = chord(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
        assert!(
            actions.is_empty() && !app.panes.follow.running,
            "{actions:?}"
        );
    }

    #[test]
    fn shift_and_altgr_keys_keep_working_in_normal_mode() {
        // `G` arrives with SHIFT; it must still jump to the last lens.
        let mut app = App::new(None);
        chord(&mut app, KeyCode::Char('G'), KeyModifiers::SHIFT);
        assert_eq!(app.lens, lenses::lenses().len() - 1);
        // `]` typed with AltGr (CONTROL|ALT on Windows) still switches tabs.
        let mut app = app_on_lens(None, "rdap");
        chord(
            &mut app,
            KeyCode::Char(']'),
            KeyModifiers::CONTROL | KeyModifiers::ALT,
        );
        assert_eq!(app.tab, 1);
    }

    #[test]
    fn dns_revisit_does_not_serve_dnssec_cache_under_records_tab() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        let first = key(&mut app, KeyCode::Char('7')); // DNS · Records
        let gen = first
            .iter()
            .find_map(|a| match a {
                Action::Fetch { gen, .. } => Some(*gen),
                _ => None,
            })
            .expect("records fetch");
        app.update(Msg::Data {
            lens: "dns".into(),
            gen,
            result: Ok(LensData::Dns(vec![])),
        });
        let dnssec = key(&mut app, KeyCode::Char(']')); // DNSSEC tab
        assert!(dnssec.iter().any(|a| matches!(
            a,
            Action::Fetch {
                req: FetchReq::Dnssec(_),
                ..
            }
        )));
        // Pressing 7 again resets to tab 0: the cached DNSSEC state must not
        // be served there (it rendered blank); Records are refetched.
        let again = key(&mut app, KeyCode::Char('7'));
        assert_eq!(app.tab, 0);
        assert!(
            again.iter().any(|a| matches!(
                a,
                Action::Fetch {
                    req: FetchReq::Dns { .. },
                    ..
                }
            )),
            "expected a Records refetch, got {again:?}"
        );
    }

    #[test]
    fn rdap_asn_cache_is_not_served_on_the_domain_tab() {
        let rdap = |app: &mut App, gen| {
            let r: seer_core::RdapResponse = serde_json::from_str("{}").unwrap();
            app.update(Msg::Data {
                lens: "rdap".into(),
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

        // With a session domain: the revisit refetches the domain object.
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        let asn = app.exec_command("rdap AS15169");
        rdap(&mut app, gen_of(&asn).unwrap());
        key(&mut app, KeyCode::Char('j'));
        let back = key(&mut app, KeyCode::Char('k'));
        assert_eq!(app.tab, 0);
        assert!(
            back.iter().any(|a| matches!(
                a,
                Action::Fetch { req: FetchReq::RdapDomain(d), .. } if d == "example.com"
            )),
            "expected RdapDomain refetch, got {back:?}"
        );

        // Without one: nothing to refetch, but the ASN object must not render
        // as the Domain tab's data.
        let mut app = App::new(None);
        let asn = app.exec_command("rdap AS15169");
        rdap(&mut app, gen_of(&asn).unwrap());
        key(&mut app, KeyCode::Char('j'));
        key(&mut app, KeyCode::Char('k'));
        let idx = lenses::find_by_cmd_or_key("rdap").unwrap();
        assert!(
            matches!(app.state_of(idx), LensState::Idle),
            "stale ASN object served under the Domain tab"
        );
    }

    #[test]
    fn follow_interval_field_opens_empty_so_typing_replaces() {
        let mut app = app_on_lens(Some("example.com"), "follow");
        app.focus = Focus::Pane;
        key(&mut app, KeyCode::Char('i'));
        assert!(
            matches!(&app.input_mode, InputMode::Field { target: EditTarget::FollowInterval, buf } if buf.as_str().is_empty()),
            "got {:?}",
            app.input_mode
        );
        key(&mut app, KeyCode::Char('6'));
        key(&mut app, KeyCode::Char('0'));
        key(&mut app, KeyCode::Enter);
        assert_eq!(
            app.panes.follow.interval_secs, 60,
            "was 3060 when prefilled"
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
        let mut app = App::new(None);
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
        app.focus = Focus::Pane;
        let actions = key(&mut app, KeyCode::Enter);
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch { req: FetchReq::Diff { a, b }, .. } if a == "a.com" && b == "b.com"
            )),
            "↵ must re-run a.com ⇄ b.com, got {actions:?}"
        );
        // A new session target resets A to follow it again.
        let _ = app.set_domain_and_fetch("new.com");
        assert!(app.panes.diff.a.is_empty());
    }

    #[test]
    fn compare_command_domain_drives_resolver_cycling() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        let _ = app.exec_command("compare other.com 9.9.9.9 8.8.4.4");
        app.focus = Focus::Pane;
        let actions = key(&mut app, KeyCode::Char('b'));
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch { req: FetchReq::Compare { domain, a, .. }, .. }
                    if domain == "other.com" && a == "9.9.9.9"
            )),
            "`b` must re-run against other.com, got {actions:?}"
        );
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
        let mut app = App::new(None);
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
            "watch",
            LensState::Loaded(LensData::Watch(Box::new(seer_core::WatchReport {
                checked_at: chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap(),
                results: vec![],
                total: 0,
                warnings: 0,
                critical: 0,
            }))),
        );
        key(&mut app, KeyCode::Enter);
        assert_eq!(app.focus, Focus::Pane);
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
        let mut app = App::new(None);
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
        app.states.insert("history", make_history_state("old.com"));
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
        app.states.insert("history", LensState::Loaded(data));
        let _ = app.apply_field(EditTarget::LensFilter, "beta".into());
        // ...yet the visible-row count still reflects the filter.
        assert_eq!(app.row_count(), 1);
    }

    #[test]
    fn paste_appends_into_command_buffer() {
        let mut app = App::new(None);
        app.input_mode = InputMode::Command("look".into());
        app.update(Msg::Input(Event::Paste("up x.com".into())));
        assert!(
            matches!(&app.input_mode, InputMode::Command(buf) if buf.as_str() == "lookup x.com"),
            "paste should append to the command buffer, got {:?}",
            app.input_mode
        );
    }
}
