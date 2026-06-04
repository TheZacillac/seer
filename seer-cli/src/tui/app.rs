//! Pure application state for the TUI. No ratatui imports — `render.rs` reads
//! this. `update(Msg) -> Vec<Action>` is the single state transition.

use std::collections::HashMap;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind};
use seer_core::output::OutputFormat;

use crate::tui::action::{Action, Focus, InputMode, LensData, LensState, Msg};
use crate::tui::command::{self, CmdOutcome};
use crate::tui::event::{self, KeyAction};
use crate::tui::lenses;

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
            _ => 0,
        }
    }

    /// Normalize + record the domain and produce a Fetch for the current lens
    /// if it is implemented. Returns None for unimplemented lenses.
    fn set_domain_and_fetch(&mut self, raw: &str) -> Option<Action> {
        let normalized = seer_core::normalize_domain(raw).unwrap_or_else(|_| raw.to_lowercase());
        self.domain = Some(normalized.clone());
        self.sel = 0;
        self.fetch_current()
    }

    /// Queue a fetch for the current lens at the current domain, marking it
    /// Loading. Returns None if the lens isn't implemented or no domain set.
    fn fetch_current(&mut self) -> Option<Action> {
        let lens = self.current_lens();
        let (key, implemented) = (lens.key, lens.implemented);
        let domain = self.domain.clone()?;
        if !implemented {
            return None;
        }
        self.states.insert(key, LensState::Loading);
        Some(Action::Fetch {
            lens: self.lens,
            domain,
        })
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
            Msg::Data {
                lens,
                domain,
                result,
            } => {
                // Ignore stale results for a domain we've since changed.
                // When self.domain is None (no domain set yet), accept any data.
                let current = self.domain.as_deref();
                if current.is_none() || current == Some(domain.as_str()) {
                    let key = lenses::lenses()[lens].key;
                    self.states.insert(
                        key,
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
            Msg::Input(Event::Key(key)) if key.kind == KeyEventKind::Press => self.on_key(key),
            Msg::Input(_) => vec![],
        }
    }

    fn on_key(&mut self, key: KeyEvent) -> Vec<Action> {
        // Mode-specific capture takes precedence.
        match std::mem::take(&mut self.input_mode) {
            InputMode::Command(buf) => return self.on_command_key(key, buf),
            InputMode::EditDomain(buf) => return self.on_edit_key(key, buf),
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

    fn on_edit_key(&mut self, key: KeyEvent, mut buf: String) -> Vec<Action> {
        match key.code {
            KeyCode::Esc => vec![],
            KeyCode::Enter => {
                let target = buf.trim().to_lowercase();
                if target.is_empty() {
                    return vec![];
                }
                self.lens = 0;
                self.focus = Focus::Nav;
                self.fetch_with(&target)
            }
            KeyCode::Backspace => {
                buf.pop();
                self.input_mode = InputMode::EditDomain(buf);
                vec![]
            }
            KeyCode::Char(c) => {
                buf.push(c);
                self.input_mode = InputMode::EditDomain(buf);
                vec![]
            }
            _ => {
                self.input_mode = InputMode::EditDomain(buf);
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
                vec![]
            }
            KeyAction::PrevTab => {
                self.tab = lenses::cycle_tab(self.current_lens(), self.tab, false);
                vec![]
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
                self.input_mode = InputMode::EditDomain(cur);
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
    use crate::tui::action::{Focus, InputMode};
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

    fn key(app: &mut App, code: KeyCode) -> Vec<crate::tui::action::Action> {
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
    fn startup_with_domain_emits_fetch() {
        let mut app = App::new(Some("example.com".into()));
        let actions = app.take_startup_actions();
        assert!(matches!(
            actions.as_slice(),
            [crate::tui::action::Action::Fetch { lens: 0, .. }]
        ));
        assert_eq!(app.domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn j_moves_lens_when_nav_focused() {
        let mut app = App::new(None);
        key(&mut app, KeyCode::Char('j'));
        assert_eq!(app.lens, 1);
    }

    #[test]
    fn number_jump_selects_and_fetches_implemented_lens() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        let actions = key(&mut app, KeyCode::Char('2')); // whois
        assert_eq!(app.lens, 1);
        assert!(actions
            .iter()
            .any(|a| matches!(a, crate::tui::action::Action::Fetch { lens: 1, .. })));
    }

    #[test]
    fn toggling_to_command_mode_and_typing() {
        let mut app = App::new(None);
        key(&mut app, KeyCode::Char(':'));
        assert_eq!(app.input_mode, InputMode::Command(String::new()));
        key(&mut app, KeyCode::Char('q'));
        assert_eq!(app.input_mode, InputMode::Command("q".into()));
        let actions = key(&mut app, KeyCode::Enter);
        assert!(actions
            .iter()
            .any(|a| matches!(a, crate::tui::action::Action::Quit)));
        assert!(app.should_quit);
    }

    #[test]
    fn r_toggles_raw_format() {
        let mut app = App::new(None);
        assert_eq!(app.format, seer_core::output::OutputFormat::Human);
        key(&mut app, KeyCode::Char('r'));
        assert_eq!(app.format, seer_core::output::OutputFormat::Json);
        key(&mut app, KeyCode::Char('r'));
        assert_eq!(app.format, seer_core::output::OutputFormat::Human);
    }

    #[test]
    fn data_message_stores_loaded_state() {
        let mut app = App::new(None);
        let records = vec![];
        app.update(Msg::Data {
            lens: 6, // dns
            domain: "example.com".into(),
            result: Ok(LensData::Dns(records)),
        });
        assert!(matches!(app.state_of(6), LensState::Loaded(_)));
    }

    #[test]
    fn editing_domain_enter_emits_fetch_and_sets_domain() {
        let mut app = App::new(None);
        key(&mut app, KeyCode::Char('/'));
        assert!(matches!(app.input_mode, InputMode::EditDomain(_)));
        for c in "acme.io".chars() {
            key(&mut app, KeyCode::Char(c));
        }
        let actions = key(&mut app, KeyCode::Enter);
        assert_eq!(app.domain.as_deref(), Some("acme.io"));
        assert!(actions
            .iter()
            .any(|a| matches!(a, crate::tui::action::Action::Fetch { lens: 0, .. })));
    }

    #[test]
    fn tick_clears_expired_toast() {
        let mut app = App::new(None);
        app.set_toast("ok", "hi");
        assert!(app.toast.is_some());
        for _ in 0..40 {
            app.update(Msg::Tick);
        }
        assert!(app.toast.is_none());
    }
}
