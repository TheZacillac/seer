//! Interactive lens components: per-lens runtime state + key routing.
//! Settings live in `options`.
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

use crate::tui::action::{Action, EditTarget, FetchReq, LensKey};
use crate::tui::options::Options;

/// Why `↵` did not start a Follow or Bulk run: one is in progress, and
/// restarting would clear its results.
pub(crate) fn already_running() -> PaneOutcome {
    PaneOutcome::Toast {
        tone: "info",
        msg: "already running — x in Details stops it".to_string(),
    }
}

#[derive(Debug)]
pub enum PaneOutcome {
    None,
    Fetch(FetchReq),
    Action(Action),
    EditField(EditTarget),
    /// Show a transient toast (App calls `set_toast`).
    Toast {
        tone: &'static str,
        msg: String,
    },
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
    /// Route a key to the lens's runtime component. `opts` supplies the run
    /// parameters Follow and Bulk start with. `Some(outcome)` if consumed.
    /// CRITICAL: never swallow `Esc` — components must return `None` for it.
    pub fn handle_key(
        &mut self,
        lens_key: LensKey,
        key: KeyEvent,
        domain: Option<&str>,
        opts: &Options,
    ) -> Option<PaneOutcome> {
        match lens_key {
            LensKey::Tld => self.tld.handle_key(key),
            LensKey::Follow => self.follow.handle_key(key, domain, opts.follow_run()),
            LensKey::Bulk => self.bulk.handle_key(key, opts.bulk_run()),
            _ => None,
        }
    }
}
