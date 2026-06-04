//! DNS nameserver picker component state and key handling.
use crossterm::event::{KeyCode, KeyEvent};
use seer_core::RecordType;

use crate::tui::action::FetchReq;
use crate::tui::panes::PaneOutcome;

/// The three nameserver slots: system (None), Google (8.8.8.8), Cloudflare (1.1.1.1).
const NAMESERVERS: [Option<&str>; 3] = [None, Some("8.8.8.8"), Some("1.1.1.1")];

#[derive(Default)]
pub struct DnsState {
    /// Index into `NAMESERVERS`.
    pub ns_idx: usize,
    /// Cached resolved IP for the current domain (used by RDAP IP tab).
    pub resolved_ip: Option<String>,
}

impl DnsState {
    /// Returns the currently selected nameserver, or `None` for system default.
    pub fn nameserver(&self) -> Option<String> {
        NAMESERVERS[self.ns_idx].map(|s| s.to_string())
    }

    /// Handle a key event. Consumes only `s` to cycle nameservers; returns `None`
    /// for all other keys so App's normal handling still runs.
    pub fn handle_key(&mut self, key: KeyEvent, domain: Option<&str>) -> Option<PaneOutcome> {
        match key.code {
            KeyCode::Char('s') => {
                let domain = domain?;
                self.ns_idx = (self.ns_idx + 1) % NAMESERVERS.len();
                Some(PaneOutcome::Fetch(FetchReq::Dns {
                    domain: domain.to_string(),
                    record_type: RecordType::A,
                    nameserver: self.nameserver(),
                }))
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
    fn nameserver_mapping() {
        let s = DnsState::default();
        assert_eq!(s.nameserver(), None, "idx 0 = system");

        let s1 = DnsState {
            ns_idx: 1,
            resolved_ip: None,
        };
        assert_eq!(s1.nameserver(), Some("8.8.8.8".into()));

        let s2 = DnsState {
            ns_idx: 2,
            resolved_ip: None,
        };
        assert_eq!(s2.nameserver(), Some("1.1.1.1".into()));
    }

    #[test]
    fn s_cycles_nameserver_and_returns_fetch() {
        let mut state = DnsState::default();
        let outcome = state.handle_key(press(KeyCode::Char('s')), Some("x.com"));
        assert_eq!(state.ns_idx, 1);
        assert!(
            matches!(
                outcome,
                Some(PaneOutcome::Fetch(FetchReq::Dns {
                    ref nameserver,
                    ..
                })) if *nameserver == Some("8.8.8.8".to_string())
            ),
            "expected Fetch(Dns{{ nameserver: Some(8.8.8.8) }}), got {outcome:?}",
        );
    }

    #[test]
    fn s_wraps_around() {
        let mut state = DnsState {
            ns_idx: 2,
            resolved_ip: None,
        };
        state.handle_key(press(KeyCode::Char('s')), Some("x.com"));
        assert_eq!(state.ns_idx, 0);
    }

    #[test]
    fn s_without_domain_returns_none() {
        let mut state = DnsState::default();
        assert!(state.handle_key(press(KeyCode::Char('s')), None).is_none());
    }

    #[test]
    fn unowned_keys_return_none() {
        let mut state = DnsState::default();
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
            .handle_key(press(KeyCode::Char('k')), Some("x.com"))
            .is_none());
    }
}
