//! Pure application state for the TUI. No ratatui imports — `render.rs` reads
//! this. `update(Msg) -> Vec<Action>` is the single state transition.

use std::collections::HashMap;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind};
use seer_core::output::OutputFormat;
use seer_core::RecordType;

use crate::tui::action::{
    Action, EditTarget, FetchReq, Focus, InputMode, LensData, LensState, Msg,
};
use crate::tui::command::{self, CmdOutcome};
use crate::tui::event::{self, KeyAction};
use crate::tui::lenses;
use crate::tui::panes::{PaneOutcome, Panes};

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
    states: HashMap<&'static str, LensState>,
    startup: Vec<Action>,
    /// Per-lens generation counter; stale results carry a lower gen and are dropped.
    fetch_gen: HashMap<&'static str, u64>,
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
            states: HashMap::new(),
            startup: Vec::new(),
            fetch_gen: HashMap::new(),
        };
        if let Some(d) = domain {
            if let Some(action) = app.set_domain_and_fetch(&d) {
                app.startup.push(action);
            }
        }
        app
    }

    /// Drain the actions queued at construction (initial lookup).
    pub fn take_startup_actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.startup)
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

    /// Build a `Fetch` action with the current generation for staleness detection.
    fn fetch_action(&mut self, req: FetchReq) -> Action {
        let gen = self.bump_fetch_gen(req.lens_key());
        Action::Fetch { req, gen }
    }

    /// Number of selectable rows in the current lens's loaded data.
    pub fn row_count(&self) -> usize {
        match self.state_of(self.lens) {
            LensState::Loaded(LensData::Dns(r)) => r.len(),
            LensState::Loaded(LensData::Prop(p)) => p.results.len(),
            LensState::Loaded(LensData::Reverse(r)) => r.len(),
            LensState::Loaded(LensData::Watch(w)) => w.results.len(),
            LensState::Loaded(LensData::History(e)) => e.len(),
            LensState::Loaded(LensData::Subdomains(s)) => s.subdomains.len(),
            _ => 0,
        }
    }

    /// Normalize + record the domain and produce a Fetch for the current lens
    /// if it is implemented. Returns None for unimplemented lenses.
    fn set_domain_and_fetch(&mut self, raw: &str) -> Option<Action> {
        let normalized = seer_core::normalize_domain(raw).unwrap_or_else(|_| raw.to_lowercase());
        // A new target invalidates every cached lens.
        if self.domain.as_deref() != Some(normalized.as_str()) {
            self.states.clear();
        }
        self.domain = Some(normalized);
        self.sel = 0;
        self.fetch_current()
    }

    /// Queue a fetch for the current lens at the current domain, marking it
    /// Loading. Returns None if the lens isn't implemented or there's nothing
    /// to fetch. History and Watch do not require a target domain.
    fn fetch_current(&mut self) -> Option<Action> {
        let lens = self.current_lens();
        let (key, implemented) = (lens.key, lens.implemented);
        if !implemented {
            return None;
        }
        // History reflects on-disk state that lookups mutate behind its back;
        // always re-read it rather than serving a cached (possibly empty) view.
        if key == "history" {
            self.states.remove(key);
        }
        // Cached (or in flight) for the current domain → revisiting is instant.
        if matches!(
            self.states.get(key),
            Some(LensState::Loaded(_) | LensState::Loading)
        ) {
            return None;
        }
        // Most lenses need a target; History/Watch are global views.
        let req = match self.domain.clone() {
            Some(domain) => self.default_req(key, &domain)?,
            None => match key {
                "history" => FetchReq::History,
                "watch" => FetchReq::Watch,
                _ => return None,
            },
        };
        self.states.insert(key, LensState::Loading);
        Some(self.fetch_action(req))
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
                1 => FetchReq::RdapIp(self.panes.dns.resolved_ip.clone().unwrap_or(d)),
                _ => return None, // ASN needs explicit :rdap AS…
            },
            "dns" => match self.tab {
                1 => FetchReq::Dnssec(d),
                2 => FetchReq::Compare {
                    domain: d,
                    record_type: RecordType::A,
                    a: self.panes.compare.a.clone(),
                    b: self.panes.compare.b.clone(),
                },
                _ => FetchReq::Dns {
                    domain: d,
                    record_type: RecordType::A,
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
                    }
                }
                vec![]
            }
            Msg::CopyResult { ok, label } => {
                if ok {
                    self.set_toast("ok", &format!("copied {label}"));
                } else {
                    self.set_toast("fail", "copy failed — clipboard unavailable");
                }
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
        let Some(ka) = event::map(key) else {
            return vec![];
        };
        self.on_normal_action(ka)
    }

    fn on_command_key(&mut self, key: KeyEvent, mut buf: String) -> Vec<Action> {
        match key.code {
            KeyCode::Esc => vec![],
            KeyCode::Enter => self.exec_command(&buf),
            KeyCode::Backspace => {
                buf.pop();
                self.input_mode = InputMode::Command(buf);
                vec![]
            }
            KeyCode::Char(c) => {
                buf.push(c);
                self.input_mode = InputMode::Command(buf);
                vec![]
            }
            _ => {
                self.input_mode = InputMode::Command(buf);
                vec![]
            }
        }
    }

    fn on_field_key(&mut self, key: KeyEvent, target: EditTarget, mut buf: String) -> Vec<Action> {
        match key.code {
            KeyCode::Esc => vec![],
            KeyCode::Enter => self.apply_field(target, buf.trim().to_string()),
            KeyCode::Backspace => {
                buf.pop();
                self.input_mode = InputMode::Field { target, buf };
                vec![]
            }
            KeyCode::Char(c) => {
                buf.push(c);
                self.input_mode = InputMode::Field { target, buf };
                vec![]
            }
            _ => {
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
                self.set_domain_and_fetch(&value).into_iter().collect()
            }
            EditTarget::DiffB => {
                self.panes.diff.b = value.to_lowercase();
                match self.domain.clone() {
                    Some(a) if !self.panes.diff.b.is_empty() => {
                        self.states.remove("diff");
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
                vec![Action::WatchMutate {
                    add: Some(value),
                    remove: None,
                }]
            }
            EditTarget::FollowInterval | EditTarget::FollowCount | EditTarget::BulkPath => {
                self.panes.apply_field(target, value, self.domain.clone())
            }
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
                    buf: String::new(),
                };
                Some(vec![])
            }
            KeyCode::Char('d') => {
                let domain = self.selected_watch_domain()?;
                Some(vec![Action::WatchMutate {
                    add: None,
                    remove: Some(domain),
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
            KeyCode::Char('c') => Some(vec![Action::HistoryClear]),
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
    fn selected_history_domain(&self) -> Option<String> {
        if let LensState::Loaded(LensData::History(entries)) = self.state_of(self.lens) {
            entries.get(self.sel).map(|e| e.domain.clone())
        } else {
            None
        }
    }

    fn apply_pane_outcome(&mut self, outcome: PaneOutcome) -> Vec<Action> {
        match outcome {
            PaneOutcome::None => vec![],
            PaneOutcome::Fetch(req) => {
                self.states.remove(req.lens_key());
                vec![self.fetch_action(req)]
            }
            PaneOutcome::Action(a) => vec![a],
            PaneOutcome::EditField(target) => {
                let cur = self.panes.field_value(target);
                self.input_mode = InputMode::Field { target, buf: cur };
                vec![]
            }
        }
    }

    fn fetch_with(&mut self, domain: &str) -> Vec<Action> {
        match self.set_domain_and_fetch(domain) {
            Some(a) => vec![a],
            None => vec![],
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
                self.set_toast("ok", &format!("output → {f}"));
                vec![]
            }
            CmdOutcome::BadFormat => {
                self.set_toast("fail", "formats: human · json · yaml · markdown");
                vec![]
            }
            CmdOutcome::Lens { lens, target } => {
                // Smart :rdap <target>: route to the right RDAP sub-tab based on target type.
                if lens == "rdap" {
                    if let Some(t) = target {
                        return self.rdap_command(&t);
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
                self.panes.diff.b = b.clone();
                self.states.remove("diff");
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
                self.panes.compare.a = a.clone();
                self.panes.compare.b = b.clone();
                self.states.remove("dns");
                let action = self.fetch_action(FetchReq::Compare {
                    domain,
                    record_type: RecordType::A,
                    a,
                    b,
                });
                vec![action]
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
            self.states.remove("rdap");
            return vec![self.fetch_action(FetchReq::RdapIp(target.to_string()))];
        }

        // ASN? Match AS15169, as15169, or bare 15169.
        let asn_digits: String = target
            .trim_start_matches(|c: char| c.is_alphabetic())
            .to_string();
        if !asn_digits.is_empty()
            && asn_digits.chars().all(|c| c.is_ascii_digit())
            && target
                .to_uppercase()
                .starts_with(|c: char| c == 'A' || c.is_ascii_digit())
        {
            if let Ok(asn) = asn_digits.parse::<u32>() {
                self.tab = 2;
                self.states.remove("rdap");
                return vec![self.fetch_action(FetchReq::RdapAsn(asn))];
            }
        }

        // Default: domain lookup on tab 0.
        self.tab = 0;
        self.states.remove("rdap");
        vec![self.fetch_action(FetchReq::RdapDomain(target.to_string()))]
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
                const INTERACTIVE_LENSES: &[&str] =
                    &["tld", "diff", "compare", "follow", "bulk", "dns", "rdap"];
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
                    buf: cur,
                };
                vec![]
            }
            KeyAction::Command => {
                self.input_mode = InputMode::Command(String::new());
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
        match self.state_of(self.lens) {
            LensState::Loaded(data) => {
                let fmt = if self.format == OutputFormat::Human {
                    OutputFormat::Markdown
                } else {
                    self.format
                };
                let text = crate::tui::raw::serialize(data, fmt);
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
        let dns_idx = crate::tui::lenses::find_by_cmd_or_key("dns").unwrap();
        assert!(matches!(app.state_of(dns_idx), LensState::Loaded(_)));
    }

    #[test]
    fn r_toggles_raw_format() {
        let mut app = App::new(None);
        assert_eq!(app.format, seer_core::output::OutputFormat::Human);
        key(&mut app, KeyCode::Char('r'));
        assert_eq!(app.format, seer_core::output::OutputFormat::Json);
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

    fn make_watch_state(domain: &str) -> LensState {
        use chrono::DateTime;
        let checked_at = DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap();
        LensState::Loaded(LensData::Watch(Box::new(seer_core::WatchReport {
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
        })))
    }

    fn make_history_state(domain: &str) -> LensState {
        use chrono::DateTime;
        use seer_core::{HistoryEntry, LookupResult, WhoisResponse};
        let timestamp = DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap();
        let whois = WhoisResponse {
            domain: domain.to_string(),
            registrar: None,
            registrant: None,
            organization: None,
            registrant_email: None,
            registrant_phone: None,
            registrant_address: None,
            registrant_country: None,
            admin_name: None,
            admin_organization: None,
            admin_email: None,
            admin_phone: None,
            tech_name: None,
            tech_organization: None,
            tech_email: None,
            tech_phone: None,
            creation_date: None,
            expiration_date: None,
            updated_date: None,
            nameservers: vec![],
            status: vec![],
            dnssec: None,
            whois_server: String::new(),
            raw_response: String::new(),
        };
        LensState::Loaded(LensData::History(vec![HistoryEntry {
            domain: domain.to_string(),
            timestamp,
            result: LookupResult::Whois {
                data: whois,
                rdap_error: None,
                rdap_fallback: None,
            },
        }]))
    }

    fn watch_lens_idx() -> usize {
        crate::tui::lenses::find_by_cmd_or_key("watch").unwrap()
    }

    fn history_lens_idx() -> usize {
        crate::tui::lenses::find_by_cmd_or_key("history").unwrap()
    }

    fn app_on_watch_with_domain(domain: &str) -> App {
        let mut app = App::new(None);
        let idx = watch_lens_idx();
        app.lens = idx;
        app.focus = Focus::Pane;
        app.sel = 0;
        app.states.insert(
            crate::tui::lenses::lenses()[idx].key,
            make_watch_state(domain),
        );
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
        app.states.insert(
            crate::tui::lenses::lenses()[idx].key,
            make_history_state("old.com"),
        );
        let actions = key(&mut app, KeyCode::Char('c'));
        assert!(
            actions.iter().any(|a| matches!(a, Action::HistoryClear)),
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
        app.states.insert(
            crate::tui::lenses::lenses()[idx].key,
            make_history_state("old.com"),
        );
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
        let dns_idx = crate::tui::lenses::find_by_cmd_or_key("dns").unwrap();
        // Bump gen to 1 by simulating a fetch (domain set → fetch triggered).
        app.domain = Some("example.com".into());
        app.fetch_gen
            .insert(crate::tui::lenses::lenses()[dns_idx].key, 1);
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
        let dns_idx = crate::tui::lenses::find_by_cmd_or_key("dns").unwrap();
        app.fetch_gen
            .insert(crate::tui::lenses::lenses()[dns_idx].key, 2);
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
    fn enter_pane_allowed_for_bulk_lens_empty() {
        let mut app = App::new(None);
        let bulk_idx = crate::tui::lenses::find_by_cmd_or_key("bulk").unwrap();
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
            matches!(a1, Some(Action::Fetch { req: FetchReq::History, .. })),
            "first visit should fetch history, got {a1:?}",
        );
        // Simulate the result arriving.
        app.states.insert(
            crate::tui::lenses::lenses()[hidx].key,
            LensState::Loaded(LensData::History(vec![])),
        );
        // Second entry → cache is dropped, so it fetches again (fresh disk read).
        let a2 = app.fetch_current();
        assert!(
            matches!(a2, Some(Action::Fetch { req: FetchReq::History, .. })),
            "history must always refetch even when already Loaded, got {a2:?}",
        );
    }

    #[test]
    fn history_fetches_without_a_domain() {
        let mut app = App::new(None); // no target domain
        app.lens = history_lens_idx();
        let a = app.fetch_current();
        assert!(
            matches!(a, Some(Action::Fetch { req: FetchReq::History, .. })),
            "history should load with no domain set, got {a:?}",
        );
    }
}
