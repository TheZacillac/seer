//! DNS Compare component state and key handling.
use crossterm::event::{KeyCode, KeyEvent};
use seer_core::RecordType;

use crate::tui::action::FetchReq;
use crate::tui::panes::PaneOutcome;

/// Resolver pool for `a`/`b` cycling.
const RESOLVERS: &[&str] = &["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"];

pub struct CompareState {
    /// Nameserver A (index into `RESOLVERS`).
    pub a_idx: usize,
    /// Nameserver B (index into `RESOLVERS`).
    pub b_idx: usize,
    /// String representation kept in sync with `a_idx`.
    pub a: String,
    /// String representation kept in sync with `b_idx`.
    pub b: String,
}

impl Default for CompareState {
    fn default() -> Self {
        Self {
            a_idx: 0,
            b_idx: 1,
            a: RESOLVERS[0].to_string(),
            b: RESOLVERS[1].to_string(),
        }
    }
}

impl CompareState {
    fn build_fetch(&self, domain: &str) -> PaneOutcome {
        PaneOutcome::Fetch(FetchReq::Compare {
            domain: domain.to_string(),
            record_type: RecordType::A,
            a: self.a.clone(),
            b: self.b.clone(),
        })
    }

    /// Handle a key event. Consumes only `a` (cycle resolver A) and `b`
    /// (cycle resolver B). Returns `None` for every other key.
    pub fn handle_key(&mut self, key: KeyEvent, domain: Option<&str>) -> Option<PaneOutcome> {
        let domain = domain?;
        match key.code {
            KeyCode::Char('a') => {
                self.a_idx = (self.a_idx + 1) % RESOLVERS.len();
                self.a = RESOLVERS[self.a_idx].to_string();
                Some(self.build_fetch(domain))
            }
            KeyCode::Char('b') => {
                self.b_idx = (self.b_idx + 1) % RESOLVERS.len();
                self.b = RESOLVERS[self.b_idx].to_string();
                Some(self.build_fetch(domain))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn default_state_has_google_and_cloudflare() {
        let s = CompareState::default();
        assert_eq!(s.a, "8.8.8.8");
        assert_eq!(s.b, "1.1.1.1");
    }

    #[test]
    fn b_cycles_and_returns_fetch_compare() {
        let mut state = CompareState::default();
        let outcome = state.handle_key(press(KeyCode::Char('b')), Some("x.com"));
        // b_idx 1 → 2 → "9.9.9.9"
        assert_eq!(state.b, "9.9.9.9");
        assert!(
            matches!(
                outcome,
                Some(PaneOutcome::Fetch(FetchReq::Compare {
                    ref b, ..
                })) if b == "9.9.9.9"
            ),
            "expected Fetch(Compare{{b:9.9.9.9}}), got {outcome:?}",
        );
    }

    #[test]
    fn a_cycles_and_returns_fetch_compare() {
        let mut state = CompareState::default();
        let outcome = state.handle_key(press(KeyCode::Char('a')), Some("x.com"));
        // a_idx 0 → 1 → "1.1.1.1"
        assert_eq!(state.a, "1.1.1.1");
        assert!(matches!(
            outcome,
            Some(PaneOutcome::Fetch(FetchReq::Compare { .. }))
        ));
    }

    #[test]
    fn without_domain_returns_none() {
        let mut state = CompareState::default();
        assert!(state.handle_key(press(KeyCode::Char('b')), None).is_none());
    }

    #[test]
    fn unowned_keys_return_none() {
        let mut state = CompareState::default();
        assert!(state
            .handle_key(press(KeyCode::Esc), Some("x.com"))
            .is_none());
        assert!(state
            .handle_key(press(KeyCode::Tab), Some("x.com"))
            .is_none());
        assert!(state
            .handle_key(press(KeyCode::Char('j')), Some("x.com"))
            .is_none());
        assert!(state
            .handle_key(press(KeyCode::Char('l')), Some("x.com"))
            .is_none());
    }

    #[test]
    fn resolvers_wrap_around() {
        let mut state = CompareState::default();
        for _ in 0..RESOLVERS.len() {
            state.handle_key(press(KeyCode::Char('a')), Some("x.com"));
        }
        assert_eq!(state.a_idx, 0);
        assert_eq!(state.a, RESOLVERS[0]);
    }
}
