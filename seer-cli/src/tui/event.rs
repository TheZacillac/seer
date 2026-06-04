//! Normal-mode key → `KeyAction` mapping. Pure.

use crossterm::event::{KeyCode, KeyEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    Up,
    Down,
    Top,
    Bottom,
    JumpLens(usize),
    ToggleFocus,
    NextTab,
    PrevTab,
    EnterPane,
    Back,
    ToggleRaw,
    Copy,
    EditDomain,
    Command,
    Help,
    QuitHint,
}

pub fn map(key: KeyEvent) -> Option<KeyAction> {
    Some(match key.code {
        KeyCode::Char('j') | KeyCode::Down => KeyAction::Down,
        KeyCode::Char('k') | KeyCode::Up => KeyAction::Up,
        KeyCode::Char('g') => KeyAction::Top,
        KeyCode::Char('G') => KeyAction::Bottom,
        KeyCode::Char(c @ '1'..='9') => KeyAction::JumpLens((c as usize) - ('1' as usize)),
        KeyCode::Tab => KeyAction::ToggleFocus,
        KeyCode::Char(']') => KeyAction::NextTab,
        KeyCode::Char('[') => KeyAction::PrevTab,
        KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right => KeyAction::EnterPane,
        KeyCode::Esc | KeyCode::Char('h') | KeyCode::Left => KeyAction::Back,
        KeyCode::Char('r') => KeyAction::ToggleRaw,
        KeyCode::Char('y') => KeyAction::Copy,
        KeyCode::Char('/') => KeyAction::EditDomain,
        KeyCode::Char(':') => KeyAction::Command,
        KeyCode::Char('?') => KeyAction::Help,
        KeyCode::Char('q') => KeyAction::QuitHint,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn k(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn movement_keys() {
        assert_eq!(map(k(KeyCode::Char('j'))), Some(KeyAction::Down));
        assert_eq!(map(k(KeyCode::Down)), Some(KeyAction::Down));
        assert_eq!(map(k(KeyCode::Char('k'))), Some(KeyAction::Up));
        assert_eq!(map(k(KeyCode::Up)), Some(KeyAction::Up));
    }

    #[test]
    fn number_jump() {
        assert_eq!(map(k(KeyCode::Char('3'))), Some(KeyAction::JumpLens(2)));
        assert_eq!(map(k(KeyCode::Char('1'))), Some(KeyAction::JumpLens(0)));
    }

    #[test]
    fn mode_and_focus_keys() {
        assert_eq!(map(k(KeyCode::Tab)), Some(KeyAction::ToggleFocus));
        assert_eq!(map(k(KeyCode::Char('['))), Some(KeyAction::PrevTab));
        assert_eq!(map(k(KeyCode::Char(']'))), Some(KeyAction::NextTab));
        assert_eq!(map(k(KeyCode::Char('/'))), Some(KeyAction::EditDomain));
        assert_eq!(map(k(KeyCode::Char(':'))), Some(KeyAction::Command));
        assert_eq!(map(k(KeyCode::Char('?'))), Some(KeyAction::Help));
        assert_eq!(map(k(KeyCode::Char('r'))), Some(KeyAction::ToggleRaw));
        assert_eq!(map(k(KeyCode::Char('y'))), Some(KeyAction::Copy));
        assert_eq!(map(k(KeyCode::Enter)), Some(KeyAction::EnterPane));
        assert_eq!(map(k(KeyCode::Esc)), Some(KeyAction::Back));
        assert_eq!(map(k(KeyCode::Char('g'))), Some(KeyAction::Top));
        assert_eq!(map(k(KeyCode::Char('G'))), Some(KeyAction::Bottom));
        assert_eq!(map(k(KeyCode::Char('q'))), Some(KeyAction::QuitHint));
    }

    #[test]
    fn unmapped_key_is_none() {
        assert_eq!(map(k(KeyCode::Char('z'))), None);
    }
}
