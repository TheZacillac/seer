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
    /// Domain set by `:compare <domain> …`; `None` compares the session
    /// domain. Reset when the session domain changes.
    pub domain: Option<String>,
}

impl Default for CompareState {
    fn default() -> Self {
        Self {
            a_idx: 0,
            b_idx: 1,
            a: RESOLVERS[0].to_string(),
            b: RESOLVERS[1].to_string(),
            domain: None,
        }
    }
}

/// Pool index for a resolver string. A custom resolver (not in the pool) maps
/// to the last slot, so the next `a`/`b` press cycles to the pool's first.
fn pool_idx(server: &str) -> usize {
    RESOLVERS
        .iter()
        .position(|r| *r == server)
        .unwrap_or(RESOLVERS.len() - 1)
}

impl CompareState {
    /// Set both resolvers (e.g. from `:compare`), keeping the cycling indices
    /// in sync with the strings.
    pub fn set_servers(&mut self, a: String, b: String) {
        self.a_idx = pool_idx(&a);
        self.b_idx = pool_idx(&b);
        self.a = a;
        self.b = b;
    }

    /// The domain being compared: the `:compare` override, else `session`.
    pub fn effective_domain(&self, session: Option<&str>) -> Option<String> {
        self.domain.clone().or_else(|| session.map(str::to_string))
    }

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
        let domain = self.effective_domain(domain)?;
        let domain = domain.as_str();
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
    fn command_domain_and_servers_drive_later_cycling() {
        let mut state = CompareState {
            domain: Some("other.com".into()),
            ..Default::default()
        };
        state.set_servers("9.9.9.9".into(), "8.8.4.4".into());
        assert_eq!(state.a_idx, 2, "pool resolver syncs its index");
        let outcome = state.handle_key(press(KeyCode::Char('b')), Some("session.com"));
        // Custom B (not in the pool) cycles to the pool's first entry, and the
        // re-run stays on the :compare domain, not the session domain.
        assert!(
            matches!(
                outcome,
                Some(PaneOutcome::Fetch(FetchReq::Compare { ref domain, ref a, ref b, .. }))
                    if domain == "other.com" && a == "9.9.9.9" && b == RESOLVERS[0]
            ),
            "got {outcome:?}"
        );
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
