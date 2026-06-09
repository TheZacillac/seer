//! TLD switcher component state and key handling.
use crossterm::event::{KeyCode, KeyEvent};

use crate::tui::action::FetchReq;
use crate::tui::panes::PaneOutcome;

pub const TLDS: &[&str] = &[".com", ".net", ".org", ".io", ".dev", ".app", ".co"];

#[derive(Default)]
pub struct TldState {
    pub idx: usize,
}

impl TldState {
    /// Returns the currently selected TLD string.
    pub fn current(&self) -> String {
        TLDS[self.idx].to_string()
    }

    /// Select a TLD by name (tolerant of a leading dot and case). Returns
    /// `true` and updates the index if found in `TLDS`, `false` otherwise.
    pub fn select(&mut self, tld: &str) -> bool {
        let want = tld.trim().trim_start_matches('.').to_lowercase();
        if let Some(i) = TLDS
            .iter()
            .position(|t| t.trim_start_matches('.') == want)
        {
            self.idx = i;
            true
        } else {
            false
        }
    }

    /// Handle a key event. Consumes only `h`/`l` for cycling; returns `None`
    /// for all other keys so App's normal handling (Esc, Tab, etc.) still runs.
    pub fn handle_key(&mut self, key: KeyEvent) -> Option<PaneOutcome> {
        match key.code {
            KeyCode::Char('l') => {
                self.idx = (self.idx + 1) % TLDS.len();
                Some(PaneOutcome::Fetch(FetchReq::Tld(self.current())))
            }
            KeyCode::Char('h') => {
                self.idx = (self.idx + TLDS.len() - 1) % TLDS.len();
                Some(PaneOutcome::Fetch(FetchReq::Tld(self.current())))
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
    fn advance_with_l_returns_fetch_tld() {
        let mut state = TldState::default();
        assert_eq!(state.idx, 0);
        let outcome = state.handle_key(press(KeyCode::Char('l')));
        assert_eq!(state.idx, 1);
        assert!(
            matches!(outcome, Some(PaneOutcome::Fetch(FetchReq::Tld(ref s))) if s == ".net"),
            "expected Fetch(Tld(.net)), got {outcome:?}",
        );
    }

    #[test]
    fn retreat_with_h_returns_fetch_tld() {
        let mut state = TldState { idx: 2 };
        let outcome = state.handle_key(press(KeyCode::Char('h')));
        assert_eq!(state.idx, 1);
        assert!(matches!(
            outcome,
            Some(PaneOutcome::Fetch(FetchReq::Tld(_)))
        ));
    }

    #[test]
    fn idx_wraps_forward() {
        let mut state = TldState {
            idx: TLDS.len() - 1,
        };
        state.handle_key(press(KeyCode::Char('l')));
        assert_eq!(state.idx, 0);
    }

    #[test]
    fn idx_wraps_backward() {
        let mut state = TldState::default();
        state.handle_key(press(KeyCode::Char('h')));
        assert_eq!(state.idx, TLDS.len() - 1);
    }

    #[test]
    fn unowned_keys_return_none() {
        let mut state = TldState::default();
        // Esc must NOT be swallowed
        assert!(state.handle_key(press(KeyCode::Esc)).is_none());
        assert!(state.handle_key(press(KeyCode::Tab)).is_none());
        assert!(state.handle_key(press(KeyCode::Char('j'))).is_none());
        assert!(state.handle_key(press(KeyCode::Char('k'))).is_none());
        assert!(state.handle_key(press(KeyCode::Char('['))).is_none());
        assert!(state.handle_key(press(KeyCode::Char(']'))).is_none());
    }

    #[test]
    fn current_returns_correct_tld() {
        let state = TldState { idx: 3 };
        assert_eq!(state.current(), ".io");
    }
}
