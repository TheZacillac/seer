//! Interactive lens components (stub — completed in Task 8+).
use crossterm::event::KeyEvent;

use crate::tui::action::{Action, EditTarget, FetchReq};

#[allow(dead_code)] // fleshed out in Phase 2/3
#[derive(Default)]
pub struct Panes {
    pub tld: TldState,
    pub dns: DnsState,
    pub compare: CompareState,
    pub diff: DiffState,
    pub follow: FollowState,
    pub bulk: BulkState,
}

#[allow(dead_code)] // fleshed out in Phase 2/3
pub enum PaneOutcome {
    None,
    Fetch(FetchReq),
    Action(Action),
    EditField(EditTarget),
}

impl Panes {
    pub fn handle_key(
        &mut self,
        _lens_key: &str,
        _tab: usize,
        _key: KeyEvent,
        _domain: Option<&str>,
    ) -> Option<PaneOutcome> {
        None
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
pub struct TldState {
    pub idx: usize,
}
impl TldState {
    pub fn current(&self) -> String {
        ".com".to_string()
    }
}

#[allow(dead_code)] // fleshed out in Phase 2/3
#[derive(Default)]
pub struct DnsState {
    pub ns_idx: usize,
    pub resolved_ip: Option<String>,
}
impl DnsState {
    pub fn nameserver(&self) -> Option<String> {
        None
    }
}

#[allow(dead_code)] // fleshed out in Phase 2/3
#[derive(Default)]
pub struct CompareState {
    pub a: String,
    pub b: String,
}

#[allow(dead_code)] // fleshed out in Phase 2/3
#[derive(Default)]
pub struct DiffState {
    pub b: String,
}

#[allow(dead_code)] // fleshed out in Phase 2/3
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

#[allow(dead_code)] // fleshed out in Phase 2/3
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
