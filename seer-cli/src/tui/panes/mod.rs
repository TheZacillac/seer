//! Interactive lens components: per-lens state + key routing.
pub mod bulk;
pub mod compare;
pub mod diff;
pub mod dns;
pub mod follow;
pub mod tld;

pub use bulk::BulkState;
pub use compare::CompareState;
pub use diff::DiffState;
pub use dns::DnsState;
pub use follow::FollowState;
pub use tld::TldState;

use crossterm::event::KeyEvent;

use crate::tui::action::{Action, EditTarget, FetchReq};

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
            "diff" => self.diff.handle_key(key),
            "follow" => self.follow.handle_key(key, domain),
            "bulk" => self.bulk.handle_key(key),
            _ => None,
        }
    }

    pub fn apply_field(
        &mut self,
        t: EditTarget,
        v: String,
        _domain: Option<String>,
    ) -> Vec<Action> {
        match t {
            EditTarget::FollowInterval => {
                if let Ok(val) = v.parse::<u64>() {
                    self.follow.interval_secs = val.max(1);
                }
                vec![]
            }
            EditTarget::FollowCount => {
                if let Ok(val) = v.parse::<usize>() {
                    self.follow.count = val.max(1);
                }
                vec![]
            }
            EditTarget::BulkPath => {
                self.bulk.running = true;
                self.bulk.rows.clear();
                self.bulk.note = None;
                self.bulk.gen += 1;
                // total is unknown for file loads; 0 means the gauge falls back to rows.
                self.bulk.total = 0;
                vec![Action::StartBulkFromFile {
                    op: self.bulk.op().to_string(),
                    path: v,
                    gen: self.bulk.gen,
                }]
            }
            _ => vec![],
        }
    }

    pub fn field_value(&self, t: EditTarget) -> String {
        match t {
            EditTarget::DiffB => self.diff.b.clone(),
            EditTarget::FollowInterval => self.follow.interval_secs.to_string(),
            EditTarget::FollowCount => self.follow.count.to_string(),
            EditTarget::BulkPath => String::new(),
            _ => String::new(),
        }
    }
}
