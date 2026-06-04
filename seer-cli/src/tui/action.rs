//! Intent (`Action`) and message (`Msg`) types plus per-lens state.

use crossterm::event::Event;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Focus {
    #[default]
    Nav,
    Pane,
}

impl Focus {
    pub fn toggled(self) -> Self {
        match self {
            Focus::Nav => Focus::Pane,
            Focus::Pane => Focus::Nav,
        }
    }
}

/// What the keyboard is currently bound to.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum InputMode {
    #[default]
    Normal,
    /// `:` command line, holding the in-progress buffer.
    Command(String),
    /// Editing the top-bar target field, holding the in-progress buffer.
    EditDomain(String),
}

/// Side-effecting intents returned by `App::update` for the loop to perform.
#[derive(Debug, Clone)]
pub enum Action {
    Quit,
    Fetch { lens: usize, domain: String },
    Copy { text: String, label: String },
}

/// Live data for a wired lens. Boxed to keep the enum small.
#[derive(Debug, Clone)]
pub enum LensData {
    Overview(Box<seer_core::LookupResult>),
    Whois(Box<seer_core::WhoisResponse>),
    Rdap(Box<seer_core::RdapResponse>),
    Dns(Vec<seer_core::DnsRecord>),
    Ssl(Box<seer_core::SslReport>),
    Status(Box<seer_core::StatusResponse>),
    Prop(Box<seer_core::PropagationResult>),
}

#[derive(Debug, Clone, Default)]
pub enum LensState {
    #[default]
    Idle,
    Loading,
    Loaded(LensData),
    Error(String),
}

/// Messages that drive `App::update`.
#[derive(Debug)]
pub enum Msg {
    Input(Event),
    Tick,
    Data {
        lens: usize,
        domain: String,
        result: Result<LensData, String>,
    },
    CopyResult {
        ok: bool,
        label: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_mode_defaults_to_normal() {
        assert_eq!(InputMode::Normal, InputMode::default());
    }

    #[test]
    fn focus_toggles() {
        assert_eq!(Focus::Nav.toggled(), Focus::Pane);
        assert_eq!(Focus::Pane.toggled(), Focus::Nav);
    }
}
