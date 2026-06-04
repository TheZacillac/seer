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
    /// Loading. Returns None if the lens isn't implemented or no domain set.
    fn fetch_current(&mut self) -> Option<Action> {
        let lens = self.current_lens();
        let (key, implemented) = (lens.key, lens.implemented);
        if !implemented {
            return None;
        }
        // Cached (or already in flight) for the current domain → re-visiting a
        // lens is instant and never re-fetches. Errored lenses are allowed to
        // retry. `states` is cleared whenever the target domain changes (see
        // `set_domain_and_fetch`), so a Loaded entry here is always current.
        if matches!(
            self.states.get(key),
            Some(LensState::Loaded(_) | LensState::Loading)
        ) {
            return None;
        }
        let domain = self.domain.clone()?;
        let req = self.default_req(key, &domain)?;
        self.states.insert(key, LensState::Loading);
        Some(Action::Fetch(req))
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
            Msg::Data { lens, result } => {
                // Resolve the string key back to a &'static str via the registry.
                if let Some(reg) = lenses::lenses().iter().find(|l| l.key == lens) {
                    self.states.insert(
                        reg.key,
                        match result {
                            Ok(data) => LensState::Loaded(data),
                            Err(e) => LensState::Error(e),
                        },
                    );
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
            Msg::FollowStep(it) => {
                self.panes.follow.push(*it);
                vec![]
            }
            Msg::FollowDone => {
                self.panes.follow.running = false;
                vec![]
            }
            Msg::BulkStep(r) => {
                self.panes.bulk.push(*r);
                vec![]
            }
            Msg::BulkDone => {
                self.panes.bulk.running = false;
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
                        vec![Action::Fetch(FetchReq::Diff {
                            a,
                            b: self.panes.diff.b.clone(),
                        })]
                    }
                    _ => vec![],
                }
            }
            EditTarget::FollowInterval
            | EditTarget::FollowCount
            | EditTarget::BulkPath
            | EditTarget::WatchAdd => self.panes.apply_field(target, value, self.domain.clone()),
        }
    }

    fn handle_pane_key(&mut self, key: KeyEvent) -> Option<Vec<Action>> {
        if self.focus != Focus::Pane {
            return None;
        }
        let lens_key = self.current_lens().key;
        let domain = self.domain.clone();
        let outcome = self
            .panes
            .handle_key(lens_key, self.tab, key, domain.as_deref())?;
        Some(self.apply_pane_outcome(outcome))
    }

    fn apply_pane_outcome(&mut self, outcome: PaneOutcome) -> Vec<Action> {
        match outcome {
            PaneOutcome::None => vec![],
            PaneOutcome::Fetch(req) => {
                self.states.remove(req.lens_key());
                vec![Action::Fetch(req)]
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
                vec![Action::Fetch(FetchReq::Diff { a, b })]
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
                vec![Action::Fetch(FetchReq::Compare {
                    domain,
                    record_type: RecordType::A,
                    a,
                    b,
                })]
            }
            CmdOutcome::Unknown(c) => {
                self.set_toast("fail", &format!("unknown command: {c}"));
                vec![]
            }
        }
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
                if self.row_count() > 0 {
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
            [Action::Fetch(FetchReq::Overview(_))]
        ));
    }

    #[test]
    fn number_jump_to_whois_fetches_whois() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        let actions = key(&mut app, KeyCode::Char('2'));
        assert_eq!(app.lens, 1);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Fetch(FetchReq::Whois(_)))));
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
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Fetch(FetchReq::Overview(_)))));
    }

    #[test]
    fn data_message_keyed_by_lens_string_stores_state() {
        let mut app = App::new(None);
        app.update(Msg::Data {
            lens: "dns".into(),
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
}
