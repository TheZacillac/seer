//! Bulk pane component — multi-domain batch operation state + key handling.
use crossterm::event::{KeyCode, KeyEvent};
use seer_core::bulk::{BulkOperation, BulkResult};

use crate::tui::action::{Action, BulkParams, EditTarget};
use crate::tui::panes::PaneOutcome;

/// Operation presets selectable with `o`.
pub const OPS: &[&str] = &["lookup", "status", "dig", "avail", "info"];

/// State for the Bulk lens — op selection, entered domains, rows, run status.
#[derive(Default)]
pub struct BulkState {
    /// Index into `OPS`.
    pub op_idx: usize,
    /// Raw domains text entered/pasted by the user (space/comma/newline separated).
    pub domains: String,
    /// Accumulated results for the current run.
    pub rows: Vec<BulkResult>,
    /// True while a bulk task is in flight.
    pub running: bool,
    /// Optional status note (e.g. error from file load).
    pub note: Option<String>,
    /// Generation counter — callbacks from superseded runs are dropped.
    pub gen: u64,
    /// Expected row count for the current run (drives the gauge denominator).
    pub total: usize,
}

/// Parse a free-form domains blob (typed or pasted) into a capped list. Same
/// filtering as `parse_domains_from_file` (trim, skip blank/`#`, require a dot)
/// but split on whitespace / comma / newline so single- or multi-line input works.
/// Lines starting with `#` are dropped before token splitting so that a token
/// following the comment marker on the same line is also excluded.
pub fn parse_domains_input(s: &str) -> Vec<String> {
    s.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .flat_map(|line| line.split([',', ' ', '\t']))
        .map(str::trim)
        .filter(|t| !t.is_empty() && !t.starts_with('#') && t.contains('.'))
        .map(str::to_string)
        .take(50)
        .collect()
}

impl BulkState {
    /// Current operation name.
    pub fn op(&self) -> &str {
        OPS[self.op_idx]
    }

    /// Append a result row (called from `App::update` on `Msg::BulkStep`).
    pub fn push(&mut self, r: BulkResult) {
        self.rows.push(r);
    }

    /// Handle a key event for the Bulk pane. `Some(_)` = consumed; never `Esc`.
    pub fn handle_key(&mut self, key: KeyEvent) -> Option<PaneOutcome> {
        match key.code {
            // Cycle operation
            KeyCode::Char('o') => {
                self.op_idx = (self.op_idx + 1) % OPS.len();
                Some(PaneOutcome::None)
            }
            // Edit the domains list
            KeyCode::Char('d') => Some(PaneOutcome::EditField(EditTarget::BulkDomains)),
            // Start a run with the entered domains
            KeyCode::Char('r') | KeyCode::Enter => {
                let domains = parse_domains_input(&self.domains);
                if domains.is_empty() {
                    return Some(PaneOutcome::Toast {
                        tone: "info",
                        msg: "enter domains first (d)",
                    });
                }
                self.rows.clear();
                self.running = true;
                self.note = None;
                self.gen += 1;
                self.total = domains.len();
                Some(PaneOutcome::Action(Action::StartBulk(BulkParams {
                    op: self.op().to_string(),
                    domains,
                    gen: self.gen,
                })))
            }
            // Open file-path field
            KeyCode::Char('f') => Some(PaneOutcome::EditField(EditTarget::BulkPath)),
            // Export results to CSV
            KeyCode::Char('e') => {
                if self.rows.is_empty() {
                    Some(PaneOutcome::None)
                } else {
                    let path = format!("seer-bulk-{}.csv", self.op());
                    let contents = self.to_csv();
                    Some(PaneOutcome::Action(Action::WriteCsv { path, contents }))
                }
            }
            _ => None,
        }
    }

    /// Build a CSV string from the current rows.
    pub fn to_csv(&self) -> String {
        let mut out = String::from("domain,success,error,duration_ms\n");
        for r in &self.rows {
            let domain = op_domain(&r.operation);
            let err = r.error.as_deref().unwrap_or("").replace(',', ";");
            out.push_str(&format!(
                "{},{},{},{}\n",
                domain, r.success, err, r.duration_ms
            ));
        }
        out
    }
}

/// Extract the domain string from a `BulkOperation` (all variants carry one).
pub fn op_domain(op: &BulkOperation) -> &str {
    match op {
        BulkOperation::Whois { domain }
        | BulkOperation::Rdap { domain }
        | BulkOperation::Lookup { domain }
        | BulkOperation::Status { domain }
        | BulkOperation::Avail { domain }
        | BulkOperation::Info { domain }
        | BulkOperation::Ssl { domain }
        | BulkOperation::Dns { domain, .. }
        | BulkOperation::Propagation { domain, .. } => domain.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn make_lookup_result(domain: &str) -> BulkResult {
        BulkResult {
            operation: BulkOperation::Lookup {
                domain: domain.to_string(),
            },
            success: true,
            data: None,
            error: None,
            duration_ms: 5,
        }
    }

    #[test]
    fn default_state_is_zeroed() {
        let s = BulkState::default();
        assert_eq!(s.op_idx, 0);
        assert!(s.domains.is_empty());
        assert!(!s.running);
        assert!(s.rows.is_empty());
        assert!(s.note.is_none());
    }

    #[test]
    fn o_cycles_op() {
        let mut s = BulkState::default();
        assert_eq!(s.op(), "lookup");
        let out = s.handle_key(key(KeyCode::Char('o')));
        assert!(matches!(out, Some(PaneOutcome::None)));
        assert_eq!(s.op(), "status");
        // Cycle through all remaining ops and wrap
        for _ in 0..OPS.len() - 1 {
            s.handle_key(key(KeyCode::Char('o')));
        }
        assert_eq!(s.op(), "lookup");
    }

    #[test]
    fn parse_domains_input_splits_and_filters() {
        let got = parse_domains_input("google.com, github.com\nrust-lang.org  bad\n# comment.skip");
        assert_eq!(got, vec!["google.com", "github.com", "rust-lang.org"]);
        // "bad" has no dot → dropped; "# comment.skip" starts with # → dropped.
    }

    #[test]
    fn parse_domains_input_caps_at_50() {
        let many = (0..80).map(|i| format!("d{i}.com")).collect::<Vec<_>>().join(" ");
        assert_eq!(parse_domains_input(&many).len(), 50);
    }

    #[test]
    fn d_opens_domains_field() {
        let mut s = BulkState::default();
        let out = s.handle_key(key(KeyCode::Char('d')));
        assert!(matches!(
            out,
            Some(PaneOutcome::EditField(EditTarget::BulkDomains))
        ));
    }

    #[test]
    fn r_with_empty_domains_toasts_and_does_not_run() {
        let mut s = BulkState::default();
        let out = s.handle_key(key(KeyCode::Char('r')));
        assert!(!s.running, "empty run must not start");
        assert!(matches!(out, Some(PaneOutcome::Toast { .. })));
    }

    #[test]
    fn r_with_domains_starts_run_with_parsed_list() {
        let mut s = BulkState::default();
        s.domains = "a.com b.com".into();
        let out = s.handle_key(key(KeyCode::Char('r')));
        assert!(s.running);
        assert_eq!(s.gen, 1);
        match out {
            Some(PaneOutcome::Action(Action::StartBulk(p))) => {
                assert_eq!(p.op, "lookup");
                assert_eq!(p.domains, vec!["a.com", "b.com"]);
                assert_eq!(p.gen, 1);
            }
            other => panic!("expected StartBulk, got {other:?}"),
        }
    }

    #[test]
    fn f_returns_edit_field_bulk_path() {
        let mut s = BulkState::default();
        let out = s.handle_key(key(KeyCode::Char('f')));
        assert!(matches!(
            out,
            Some(PaneOutcome::EditField(EditTarget::BulkPath))
        ));
    }

    #[test]
    fn e_with_no_rows_returns_pane_outcome_none() {
        let mut s = BulkState::default();
        let out = s.handle_key(key(KeyCode::Char('e')));
        assert!(matches!(out, Some(PaneOutcome::None)));
    }

    #[test]
    fn e_with_rows_returns_write_csv() {
        let mut s = BulkState::default();
        s.rows.push(make_lookup_result("x.com"));
        let out = s.handle_key(key(KeyCode::Char('e')));
        assert!(matches!(
            out,
            Some(PaneOutcome::Action(Action::WriteCsv { .. }))
        ));
    }

    #[test]
    fn esc_returns_none() {
        let mut s = BulkState::default();
        let out = s.handle_key(key(KeyCode::Esc));
        assert!(out.is_none(), "Esc must not be swallowed");
    }

    #[test]
    fn to_csv_produces_header_and_row() {
        let mut s = BulkState::default();
        s.rows.push(make_lookup_result("x.com"));
        let csv = s.to_csv();
        assert!(csv.starts_with("domain,success,error,duration_ms\n"));
        assert!(csv.contains("x.com,true,,5"));
    }

    #[test]
    fn to_csv_escapes_commas_in_error() {
        let mut s = BulkState::default();
        s.rows.push(BulkResult {
            operation: BulkOperation::Lookup {
                domain: "bad.com".to_string(),
            },
            success: false,
            data: None,
            error: Some("timeout, retry failed".to_string()),
            duration_ms: 10,
        });
        let csv = s.to_csv();
        // Commas inside the error field must be replaced with semicolons
        assert!(csv.contains("timeout; retry failed"));
        assert!(!csv.contains("timeout, retry failed"));
    }

    #[test]
    fn op_domain_works_for_all_variants() {
        use seer_core::RecordType;
        assert_eq!(
            op_domain(&BulkOperation::Whois {
                domain: "a.com".into()
            }),
            "a.com"
        );
        assert_eq!(
            op_domain(&BulkOperation::Dns {
                domain: "b.com".into(),
                record_type: RecordType::A
            }),
            "b.com"
        );
        assert_eq!(
            op_domain(&BulkOperation::Propagation {
                domain: "c.com".into(),
                record_type: RecordType::MX
            }),
            "c.com"
        );
    }
}
