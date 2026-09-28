//! DNS nameserver picker component state and key handling.
use crossterm::event::{KeyCode, KeyEvent};
use seer_core::RecordType;

use crate::tui::action::FetchReq;
use crate::tui::panes::PaneOutcome;

/// The fixed nameserver slots: system (None — the config file's nameserver,
/// else the default upstream), Google (8.8.8.8), Cloudflare (1.1.1.1).
const NAMESERVERS: [Option<&str>; 3] = [None, Some("8.8.8.8"), Some("1.1.1.1")];

/// The chip label of the system slot.
const SYSTEM_LABEL: &str = "system";

pub struct DnsState {
    /// Index into the slots: `NAMESERVERS`, then `custom_ns` when it is set.
    pub ns_idx: usize,
    /// A nameserver named by `:dig @server …` that is not a fixed slot. It
    /// joins the `s` cycle as a fourth slot until another one replaces it.
    pub custom_ns: Option<String>,
    /// Cached resolved IP for the current domain (used by RDAP IP tab).
    pub resolved_ip: Option<String>,
    /// Record type the Records and Trace tabs query (`:dig <domain> <type>`;
    /// default A).
    pub record_type: RecordType,
}

impl Default for DnsState {
    fn default() -> Self {
        Self {
            ns_idx: 0,
            custom_ns: None,
            resolved_ip: None,
            record_type: RecordType::A,
        }
    }
}

impl DnsState {
    /// Returns the currently selected nameserver, or `None` for system default.
    pub fn nameserver(&self) -> Option<String> {
        match NAMESERVERS.get(self.ns_idx) {
            Some(slot) => slot.map(str::to_string),
            None => self.custom_ns.clone(),
        }
    }

    /// The chip label of every slot, in `s` cycling order.
    pub fn slot_labels(&self) -> Vec<&str> {
        NAMESERVERS
            .iter()
            .map(|slot| slot.unwrap_or(SYSTEM_LABEL))
            .chain(self.custom_ns.as_deref())
            .collect()
    }

    fn slot_count(&self) -> usize {
        NAMESERVERS.len() + usize::from(self.custom_ns.is_some())
    }

    /// Select `server` (a nameserver spec from `:dig @server`): its fixed
    /// slot when it is one, else the custom slot, which it replaces.
    pub fn select_server(&mut self, server: String) {
        match NAMESERVERS
            .iter()
            .position(|slot| *slot == Some(server.as_str()))
        {
            Some(idx) => self.ns_idx = idx,
            None => {
                self.custom_ns = Some(server);
                self.ns_idx = NAMESERVERS.len();
            }
        }
    }

    /// Handle a key event. Consumes only `s` to cycle nameservers; returns `None`
    /// for all other keys so App's normal handling still runs.
    pub fn handle_key(&mut self, key: KeyEvent, domain: Option<&str>) -> Option<PaneOutcome> {
        match key.code {
            KeyCode::Char('s') => {
                let domain = domain?;
                self.ns_idx = (self.ns_idx + 1) % self.slot_count();
                Some(PaneOutcome::Fetch(FetchReq::Dns {
                    domain: domain.to_string(),
                    record_type: self.record_type,
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
            ..Default::default()
        };
        assert_eq!(s1.nameserver(), Some("8.8.8.8".into()));

        let s2 = DnsState {
            ns_idx: 2,
            ..Default::default()
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
            ..Default::default()
        };
        state.handle_key(press(KeyCode::Char('s')), Some("x.com"));
        assert_eq!(state.ns_idx, 0);
    }

    #[test]
    fn s_keeps_the_selected_record_type() {
        let mut state = DnsState {
            record_type: RecordType::MX,
            ..Default::default()
        };
        let outcome = state.handle_key(press(KeyCode::Char('s')), Some("x.com"));
        assert!(matches!(
            outcome,
            Some(PaneOutcome::Fetch(FetchReq::Dns {
                record_type: RecordType::MX,
                ..
            }))
        ));
    }

    #[test]
    fn s_without_domain_returns_none() {
        let mut state = DnsState::default();
        assert!(state.handle_key(press(KeyCode::Char('s')), None).is_none());
    }

    #[test]
    fn a_fixed_server_selects_its_slot() {
        let mut state = DnsState::default();
        state.select_server("1.1.1.1".into());
        assert_eq!(state.ns_idx, 2);
        assert_eq!(state.custom_ns, None, "no extra slot for a fixed one");
        assert_eq!(state.slot_labels(), ["system", "8.8.8.8", "1.1.1.1"]);
    }

    #[test]
    fn a_custom_server_joins_the_cycle_as_a_fourth_slot() {
        let mut state = DnsState::default();
        state.select_server("tls://9.9.9.9".into());
        assert_eq!(state.nameserver().as_deref(), Some("tls://9.9.9.9"));
        assert_eq!(
            state.slot_labels(),
            ["system", "8.8.8.8", "1.1.1.1", "tls://9.9.9.9"]
        );
        // `s` wraps from the custom slot back to system, then reaches it again.
        state.handle_key(press(KeyCode::Char('s')), Some("x.com"));
        assert_eq!(state.nameserver(), None);
        for _ in 0..3 {
            state.handle_key(press(KeyCode::Char('s')), Some("x.com"));
        }
        assert_eq!(state.nameserver().as_deref(), Some("tls://9.9.9.9"));
        // A second custom server replaces the first rather than stacking.
        state.select_server("9.9.9.10".into());
        assert_eq!(state.slot_labels().len(), 4);
        assert_eq!(state.nameserver().as_deref(), Some("9.9.9.10"));
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
