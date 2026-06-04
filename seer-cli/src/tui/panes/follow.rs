//! Follow pane component — live DNS monitor state + key handling.
use crossterm::event::{KeyCode, KeyEvent};

use crate::tui::action::{Action, EditTarget, FollowParams};
use crate::tui::panes::PaneOutcome;

/// Per-run state for the Follow (live DNS monitor) lens.
pub struct FollowState {
    /// Interval between checks in seconds.
    pub interval_secs: u64,
    /// Total number of checks to run.
    pub count: usize,
    /// Whether a follow run is currently in progress.
    pub running: bool,
    /// Log of completed iterations, newest first.
    pub log: Vec<seer_core::dns::FollowIteration>,
}

impl Default for FollowState {
    fn default() -> Self {
        Self {
            interval_secs: 30,
            count: 20,
            running: false,
            log: vec![],
        }
    }
}

impl FollowState {
    /// Prepend a new iteration to the log (newest-first order).
    pub fn push(&mut self, it: seer_core::dns::FollowIteration) {
        self.log.insert(0, it);
    }

    /// Handle a key event for the Follow pane.
    ///
    /// Returns `Some(outcome)` when the key is consumed, `None` to fall through.
    /// Never swallows `Esc`.
    pub fn handle_key(&mut self, key: KeyEvent, domain: Option<&str>) -> Option<PaneOutcome> {
        match key.code {
            // 's' or Enter — start a new follow run
            KeyCode::Char('s') | KeyCode::Enter => {
                let Some(d) = domain else {
                    // No domain set — consume but do nothing
                    return Some(PaneOutcome::None);
                };
                self.log.clear();
                self.running = true;
                Some(PaneOutcome::Action(Action::StartFollow(FollowParams {
                    domain: d.to_string(),
                    iterations: self.count,
                    interval_secs: self.interval_secs,
                })))
            }
            // 'i' — edit interval
            KeyCode::Char('i') => Some(PaneOutcome::EditField(EditTarget::FollowInterval)),
            // 'n' — edit iteration count
            KeyCode::Char('n') => Some(PaneOutcome::EditField(EditTarget::FollowCount)),
            // 'x' — stop showing as running (in-flight task is not cancelled)
            KeyCode::Char('x') => {
                self.running = false;
                Some(PaneOutcome::None)
            }
            // Esc and everything else → fall through
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::action::Action;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn default_has_expected_values() {
        let s = FollowState::default();
        assert_eq!(s.interval_secs, 30);
        assert_eq!(s.count, 20);
        assert!(!s.running);
        assert!(s.log.is_empty());
    }

    #[test]
    fn s_with_domain_sets_running_and_returns_start_follow() {
        let mut s = FollowState::default();
        let outcome = s.handle_key(key(KeyCode::Char('s')), Some("x.com"));
        assert!(s.running);
        assert!(matches!(
            outcome,
            Some(PaneOutcome::Action(Action::StartFollow(ref p)))
            if p.domain == "x.com" && p.iterations == 20 && p.interval_secs == 30
        ));
    }

    #[test]
    fn enter_with_domain_also_starts() {
        let mut s = FollowState::default();
        let outcome = s.handle_key(key(KeyCode::Enter), Some("y.com"));
        assert!(s.running);
        assert!(matches!(
            outcome,
            Some(PaneOutcome::Action(Action::StartFollow(_)))
        ));
    }

    #[test]
    fn s_without_domain_consumes_but_noop() {
        let mut s = FollowState::default();
        let outcome = s.handle_key(key(KeyCode::Char('s')), None);
        assert!(!s.running);
        assert!(matches!(outcome, Some(PaneOutcome::None)));
    }

    #[test]
    fn i_returns_edit_interval() {
        let mut s = FollowState::default();
        let outcome = s.handle_key(key(KeyCode::Char('i')), None);
        assert!(matches!(
            outcome,
            Some(PaneOutcome::EditField(EditTarget::FollowInterval))
        ));
    }

    #[test]
    fn n_returns_edit_count() {
        let mut s = FollowState::default();
        let outcome = s.handle_key(key(KeyCode::Char('n')), None);
        assert!(matches!(
            outcome,
            Some(PaneOutcome::EditField(EditTarget::FollowCount))
        ));
    }

    #[test]
    fn x_stops_running() {
        let mut s = FollowState::default();
        s.running = true;
        let outcome = s.handle_key(key(KeyCode::Char('x')), None);
        assert!(!s.running);
        assert!(matches!(outcome, Some(PaneOutcome::None)));
    }

    #[test]
    fn esc_returns_none() {
        let mut s = FollowState::default();
        let outcome = s.handle_key(key(KeyCode::Esc), None);
        assert!(outcome.is_none(), "Esc must not be swallowed");
    }

    #[test]
    fn push_prepends_newest_first() {
        use chrono::Utc;
        let mut s = FollowState::default();
        let it1 = seer_core::dns::FollowIteration {
            iteration: 1,
            total_iterations: 5,
            timestamp: Utc::now(),
            records: vec![],
            changed: false,
            added: vec![],
            removed: vec![],
            error: None,
        };
        let it2 = seer_core::dns::FollowIteration {
            iteration: 2,
            total_iterations: 5,
            timestamp: Utc::now(),
            records: vec![],
            changed: true,
            added: vec!["1.2.3.4".into()],
            removed: vec![],
            error: None,
        };
        s.push(it1);
        s.push(it2);
        assert_eq!(s.log[0].iteration, 2, "newest (iter 2) should be first");
        assert_eq!(s.log[1].iteration, 1);
    }
}
