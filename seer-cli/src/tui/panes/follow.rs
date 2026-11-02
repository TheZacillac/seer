//! Follow pane component — live DNS monitor state + key handling.
use crossterm::event::{KeyCode, KeyEvent};

use crate::tui::action::{Action, FollowParams};
use crate::tui::panes::PaneOutcome;

/// Per-run state for the Follow (live DNS monitor) lens.
#[derive(Default)]
pub struct FollowState {
    /// Whether a follow run is currently in progress.
    pub running: bool,
    /// Log of completed iterations, newest first.
    pub log: Vec<seer_core::dns::FollowIteration>,
    /// Generation counter — callbacks from superseded runs are dropped.
    pub gen: u64,
    /// `(count, interval_secs)` the current/last run was started with. The
    /// options apply to the NEXT run, so the progress view reads the run's
    /// own parameters instead.
    pub last_run: Option<(usize, u64)>,
}

impl FollowState {
    /// Prepend a new iteration to the log (newest-first order).
    pub fn push(&mut self, it: seer_core::dns::FollowIteration) {
        self.log.insert(0, it);
    }

    /// Invalidate any in-flight run when the followed domain changes. Bumping
    /// `gen` causes late callbacks from the previous domain's run to be
    /// dropped by the generation guard; the log and running flag are cleared.
    /// The options (interval/count) are intentionally preserved.
    pub fn reset_for_new_domain(&mut self) {
        self.gen += 1;
        self.running = false;
        self.log.clear();
        self.last_run = None;
    }

    /// Total checks of the current/last run: the core-reported
    /// `total_iterations` once a check has landed, else the parameters the
    /// run was started with, else `next` (the options' count).
    pub fn run_total(&self, next: usize) -> usize {
        self.log
            .first()
            .map(|it| it.total_iterations)
            .or(self.last_run.map(|(n, _)| n))
            .unwrap_or(next)
    }

    /// Begin a run with the options' `count` and `interval_secs`.
    pub fn start(&mut self, domain: &str, count: usize, interval_secs: u64) -> Action {
        self.log.clear();
        self.running = true;
        self.gen += 1;
        self.last_run = Some((count, interval_secs));
        Action::StartFollow(FollowParams {
            domain: domain.to_string(),
            iterations: count,
            interval_secs,
            gen: self.gen,
        })
    }

    /// `↵` starts a run (with a domain), `x` stops one. Never swallows `Esc`.
    pub fn handle_key(
        &mut self,
        key: KeyEvent,
        domain: Option<&str>,
        run: Option<(usize, u64)>,
    ) -> Option<PaneOutcome> {
        match key.code {
            KeyCode::Enter => match (domain, run) {
                (Some(d), Some((count, secs))) => {
                    Some(PaneOutcome::Action(self.start(d, count, secs)))
                }
                _ => Some(PaneOutcome::None),
            },
            // Also cancels the in-flight background DNS loop.
            KeyCode::Char('x') => {
                self.running = false;
                Some(PaneOutcome::Action(Action::StopFollow))
            }
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
        assert!(!s.running);
        assert!(s.log.is_empty());
        assert_eq!(s.gen, 0);
    }

    #[test]
    fn enter_with_domain_also_starts() {
        let mut s = FollowState::default();
        let outcome = s.handle_key(key(KeyCode::Enter), Some("x.com"), Some((5, 10)));
        assert!(s.running);
        assert!(matches!(
            outcome,
            Some(PaneOutcome::Action(Action::StartFollow(ref p)))
            if p.domain == "x.com" && p.iterations == 5 && p.interval_secs == 10 && p.gen == 1
        ));
        assert_eq!(s.last_run, Some((5, 10)));
    }

    #[test]
    fn enter_without_domain_consumes_but_noop() {
        let mut s = FollowState::default();
        let outcome = s.handle_key(key(KeyCode::Enter), None, Some((5, 10)));
        assert!(!s.running);
        assert!(matches!(outcome, Some(PaneOutcome::None)));
    }

    #[test]
    fn x_stops_running_and_cancels_follow() {
        let mut s = FollowState {
            running: true,
            ..Default::default()
        };
        let outcome = s.handle_key(key(KeyCode::Char('x')), None, None);
        assert!(!s.running);
        // 'x' now also cancels the in-flight background follow loop.
        assert!(matches!(
            outcome,
            Some(PaneOutcome::Action(Action::StopFollow))
        ));
    }

    #[test]
    fn esc_returns_none() {
        let mut s = FollowState::default();
        let outcome = s.handle_key(key(KeyCode::Esc), None, None);
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
