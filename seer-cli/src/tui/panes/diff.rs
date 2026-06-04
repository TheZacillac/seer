//! Diff pane component state and key handling.
use crossterm::event::{KeyCode, KeyEvent};

use crate::tui::action::EditTarget;
use crate::tui::panes::PaneOutcome;

#[derive(Default)]
pub struct DiffState {
    /// The second domain to compare against (domain B).
    pub b: String,
}

impl DiffState {
    /// Handle a key event. Consumes `e`/`i` to enter the DiffB field prompt;
    /// returns `None` for all other keys so App's normal handling still runs.
    /// CRITICAL: never swallows `Esc`.
    pub fn handle_key(&mut self, key: KeyEvent) -> Option<PaneOutcome> {
        match key.code {
            KeyCode::Char('e') | KeyCode::Char('i') => {
                Some(PaneOutcome::EditField(EditTarget::DiffB))
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
    fn e_returns_edit_field_diffb() {
        let mut state = DiffState::default();
        let outcome = state.handle_key(press(KeyCode::Char('e')));
        assert!(
            matches!(outcome, Some(PaneOutcome::EditField(EditTarget::DiffB))),
            "expected EditField(DiffB), got {outcome:?}",
        );
    }

    #[test]
    fn i_returns_edit_field_diffb() {
        let mut state = DiffState::default();
        let outcome = state.handle_key(press(KeyCode::Char('i')));
        assert!(
            matches!(outcome, Some(PaneOutcome::EditField(EditTarget::DiffB))),
            "expected EditField(DiffB), got {outcome:?}",
        );
    }

    #[test]
    fn esc_returns_none() {
        let mut state = DiffState::default();
        assert!(
            state.handle_key(press(KeyCode::Esc)).is_none(),
            "Esc must not be swallowed",
        );
    }

    #[test]
    fn unowned_keys_return_none() {
        let mut state = DiffState::default();
        assert!(state.handle_key(press(KeyCode::Tab)).is_none());
        assert!(state.handle_key(press(KeyCode::Char('j'))).is_none());
        assert!(state.handle_key(press(KeyCode::Char('d'))).is_none());
        assert!(state.handle_key(press(KeyCode::Enter)).is_none());
    }
}
