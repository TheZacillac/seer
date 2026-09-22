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
    /// Show a transient toast (App calls `set_toast`).
    Toast {
        tone: &'static str,
        msg: &'static str,
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
            "diff" => self.diff.handle_key(key, domain),
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
                    // Clamp to the same range core enforces so a valid-looking
                    // over-range value can't fail FollowConfig::new and silently
                    // no-op the run.
                    self.follow.interval_secs = val.clamp(1, seer_core::MAX_FOLLOW_INTERVAL_SECS);
                }
                vec![]
            }
            EditTarget::FollowCount => {
                if let Ok(val) = v.parse::<usize>() {
                    self.follow.count = val.clamp(1, seer_core::MAX_FOLLOW_ITERATIONS);
                }
                vec![]
            }
            EditTarget::BulkPath => self.bulk.start_file_run(v).into_iter().collect(),
            EditTarget::BulkDomains => {
                self.bulk.domains = v;
                vec![]
            }
            _ => vec![],
        }
    }

    /// Initial buffer when a field opens. The numeric Follow fields open EMPTY
    /// (the current value is shown in the prompt label): prefilling "30" with
    /// the caret at the end turned typing "60" into 3060.
    pub fn field_value(&self, t: EditTarget) -> String {
        match t {
            EditTarget::DiffB => self.diff.b.clone(),
            EditTarget::FollowInterval | EditTarget::FollowCount | EditTarget::BulkPath => {
                String::new()
            }
            EditTarget::BulkDomains => self.bulk.domains.clone(),
            EditTarget::TldFilter => self.tld.filter.clone(),
            _ => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Follow interval/count edits must be clamped to the SAME upper bound
    /// `seer_core::FollowConfig::new` enforces. Otherwise an in-range-looking
    /// value (e.g. 3601s / 10001 iterations) passes the field-level check but is
    /// later rejected by core, and the run silently no-ops with no feedback.
    #[test]
    fn follow_interval_is_clamped_to_core_max() {
        let mut panes = Panes::default();
        panes.apply_field(EditTarget::FollowInterval, "3601".to_string(), None);
        assert_eq!(
            panes.follow.interval_secs,
            seer_core::MAX_FOLLOW_INTERVAL_SECS,
            "over-range interval must be clamped to the core maximum"
        );
    }

    #[test]
    fn follow_count_is_clamped_to_core_max() {
        let mut panes = Panes::default();
        panes.apply_field(EditTarget::FollowCount, "10001".to_string(), None);
        assert_eq!(
            panes.follow.count,
            seer_core::MAX_FOLLOW_ITERATIONS,
            "over-range count must be clamped to the core maximum"
        );
    }

    #[test]
    fn follow_fields_open_empty_so_typing_replaces_the_value() {
        let panes = Panes::default();
        assert_eq!(panes.field_value(EditTarget::FollowInterval), "");
        assert_eq!(panes.field_value(EditTarget::FollowCount), "");
        // Submitting the empty buffer leaves the setting unchanged.
        let mut panes = Panes::default();
        panes.apply_field(EditTarget::FollowInterval, String::new(), None);
        assert_eq!(panes.follow.interval_secs, 30);
    }

    #[test]
    fn empty_bulk_path_is_ignored() {
        let mut panes = Panes::default();
        let actions = panes.apply_field(EditTarget::BulkPath, String::new(), None);
        assert!(actions.is_empty(), "no StartBulkFromFile for an empty path");
        assert!(!panes.bulk.running);
        assert_eq!(panes.bulk.gen, 0, "run counter must not advance");
    }

    #[test]
    fn follow_fields_keep_lower_bound_of_one() {
        let mut panes = Panes::default();
        panes.apply_field(EditTarget::FollowInterval, "0".to_string(), None);
        panes.apply_field(EditTarget::FollowCount, "0".to_string(), None);
        assert_eq!(panes.follow.interval_secs, 1);
        assert_eq!(panes.follow.count, 1);
    }
}
