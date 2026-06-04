//! Interactive lens components: per-lens state + key routing.
pub mod compare;
pub mod dns;
pub mod tld;

pub use compare::CompareState;
pub use dns::DnsState;
pub use tld::TldState;

use crossterm::event::KeyEvent;

use crate::tui::action::{Action, EditTarget, FetchReq};

#[allow(dead_code)] // fleshed out in Phase 4
#[derive(Debug)]
pub enum PaneOutcome {
    None,
    Fetch(FetchReq),
    Action(Action),
    EditField(EditTarget),
}

#[derive(Default)]
pub struct Panes {
    pub tld: TldState,
    pub dns: DnsState,
    pub compare: CompareState,
    pub diff: DiffState,
    pub follow: FollowState,
    pub bulk: BulkState,
}

impl Panes {
    /// Route a key to the right pane component. Returns `Some(outcome)` if the
    /// component consumed the key, `None` otherwise (App handles it normally).
    /// CRITICAL: never swallow `Esc` — components must return `None` for it.
    pub fn handle_key(
        &mut self,
        lens_key: &str,
        tab: usize,
        key: KeyEvent,
        domain: Option<&str>,
    ) -> Option<PaneOutcome> {
        match lens_key {
            "tld" => self.tld.handle_key(key),
            "dns" => match tab {
                0 => self.dns.handle_key(key, domain),
                2 => self.compare.handle_key(key, domain),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn apply_field(
        &mut self,
        _t: EditTarget,
        _v: String,
        _domain: Option<String>,
    ) -> Vec<Action> {
        vec![]
    }

    pub fn field_value(&self, _t: EditTarget) -> String {
        String::new()
    }
}

#[allow(dead_code)] // fleshed out in Phase 2/3
#[derive(Default)]
pub struct DiffState {
    pub b: String,
}

#[allow(dead_code)] // fleshed out in Phase 4
#[derive(Default)]
pub struct FollowState {
    pub running: bool,
    pub log: Vec<seer_core::dns::FollowIteration>,
}
impl FollowState {
    pub fn push(&mut self, it: seer_core::dns::FollowIteration) {
        self.log.insert(0, it);
    }
}

#[allow(dead_code)] // fleshed out in Phase 4
#[derive(Default)]
pub struct BulkState {
    pub running: bool,
    pub rows: Vec<seer_core::bulk::BulkResult>,
}
impl BulkState {
    pub fn push(&mut self, r: seer_core::bulk::BulkResult) {
        self.rows.push(r);
    }
}
