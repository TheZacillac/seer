//! Diff pane component state and key handling.
use crossterm::event::{KeyCode, KeyEvent};

use crate::tui::action::{EditTarget, FetchReq};
use crate::tui::panes::PaneOutcome;

#[derive(Default)]
pub struct DiffState {
    /// The second domain to compare against (domain B).
    pub b: String,
}

impl DiffState {
    /// Handle a key event. Consumes `e`/`i` to open the DiffB field prompt, and
    /// `Enter` (when B is set and a target exists) to re-run the comparison.
    /// Returns `None` for all other keys so App's normal handling still runs.
    /// CRITICAL: never swallows `Esc`.
    pub fn handle_key(&mut self, key: KeyEvent, domain: Option<&str>) -> Option<PaneOutcome> {
        match key.code {
            KeyCode::Char('e') | KeyCode::Char('i') => {
                Some(PaneOutcome::EditField(EditTarget::DiffB))
            }
            KeyCode::Enter if !self.b.is_empty() => domain.map(|a| {
                PaneOutcome::Fetch(FetchReq::Diff {
                    a: a.to_string(),
                    b: self.b.clone(),
                })
            }),
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
        let outcome = state.handle_key(press(KeyCode::Char('e')), None);
        assert!(
            matches!(outcome, Some(PaneOutcome::EditField(EditTarget::DiffB))),
            "expected EditField(DiffB), got {outcome:?}",
        );
    }

    #[test]
    fn i_returns_edit_field_diffb() {
        let mut state = DiffState::default();
        let outcome = state.handle_key(press(KeyCode::Char('i')), None);
        assert!(
            matches!(outcome, Some(PaneOutcome::EditField(EditTarget::DiffB))),
            "expected EditField(DiffB), got {outcome:?}",
        );
    }

    #[test]
    fn esc_returns_none() {
        let mut state = DiffState::default();
        assert!(
            state.handle_key(press(KeyCode::Esc), None).is_none(),
            "Esc must not be swallowed",
        );
    }

    #[test]
    fn unowned_keys_return_none() {
        let mut state = DiffState::default();
        assert!(state.handle_key(press(KeyCode::Tab), None).is_none());
        assert!(state.handle_key(press(KeyCode::Char('j')), None).is_none());
        assert!(state.handle_key(press(KeyCode::Char('d')), None).is_none());
        // B is empty — Enter must fall through even when a domain is given.
        assert!(state.handle_key(press(KeyCode::Enter), None).is_none());
    }

    #[test]
    fn enter_with_b_set_and_domain_recompares() {
        let mut state = DiffState { b: "b.com".into() };
        let out = state.handle_key(press(KeyCode::Enter), Some("a.com"));
        assert!(
            matches!(out, Some(PaneOutcome::Fetch(FetchReq::Diff { ref a, ref b })) if a == "a.com" && b == "b.com"),
            "Enter with B set + domain should re-run the diff, got {out:?}",
        );
    }

    #[test]
    fn enter_with_empty_b_falls_through() {
        let mut state = DiffState::default();
        assert!(
            state
                .handle_key(press(KeyCode::Enter), Some("a.com"))
                .is_none(),
            "Enter with no B set must fall through (not swallowed)",
        );
    }
}
