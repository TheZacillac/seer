//! Bulk pane component — multi-domain batch operation state + key handling.
use crossterm::event::{KeyCode, KeyEvent};
use seer_core::bulk::{BulkOperation, BulkResult};

use crate::tui::action::{Action, BulkParams, EditTarget};
use crate::tui::panes::PaneOutcome;

/// Operation presets selectable with `o`.
pub const OPS: &[&str] = &["lookup", "status", "dig", "avail", "info"];

/// Built-in sample domain lists selectable with `t`.
pub const SAMPLES: &[(&str, &[&str])] = &[
    (
        "top-sites",
        &[
            "google.com",
            "github.com",
            "cloudflare.com",
            "wikipedia.org",
        ],
    ),
    ("portfolio", &["example.com", "rust-lang.org", "python.org"]),
    (
        "infrastructure",
        &[
            "1.1.1.1",
            "8.8.8.8",
            "github.com",
            "fastly.com",
            "akamai.com",
        ],
    ),
];

/// State for the Bulk lens — op selection, source selection, rows, run status.
#[derive(Default)]
pub struct BulkState {
    /// Index into `OPS`.
    pub op_idx: usize,
    /// Index into `SAMPLES`.
    pub source_idx: usize,
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

impl BulkState {
    /// Current operation name.
    pub fn op(&self) -> &str {
        OPS[self.op_idx]
    }

    /// Current sample source name.
    pub fn source_name(&self) -> &str {
        SAMPLES[self.source_idx].0
    }

    /// Domain list for the currently selected sample.
    pub fn sample_domains(&self) -> Vec<String> {
        SAMPLES[self.source_idx]
            .1
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// Append a result row (called from `App::update` on `Msg::BulkStep`).
    pub fn push(&mut self, r: BulkResult) {
        self.rows.push(r);
    }

    /// Handle a key event for the Bulk pane.
    ///
    /// Returns `Some(outcome)` when consumed, `None` to fall through.
    /// Never swallows `Esc`.
    pub fn handle_key(&mut self, key: KeyEvent) -> Option<PaneOutcome> {
        match key.code {
            // Cycle operation
            KeyCode::Char('o') => {
                self.op_idx = (self.op_idx + 1) % OPS.len();
                Some(PaneOutcome::None)
            }
            // Cycle sample source
            KeyCode::Char('t') => {
                self.source_idx = (self.source_idx + 1) % SAMPLES.len();
                Some(PaneOutcome::None)
            }
            // Start a run with the selected sample
            KeyCode::Char('r') | KeyCode::Enter => {
                self.rows.clear();
                self.running = true;
                self.note = None;
                self.gen += 1;
                let domains = self.sample_domains();
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
            // Esc and anything else → fall through
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
        assert_eq!(s.source_idx, 0);
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
    fn t_cycles_source() {
        let mut s = BulkState::default();
        assert_eq!(s.source_name(), SAMPLES[0].0);
        s.handle_key(key(KeyCode::Char('t')));
        assert_eq!(s.source_name(), SAMPLES[1].0);
    }

    #[test]
    fn r_sets_running_and_returns_start_bulk() {
        let mut s = BulkState::default();
        let out = s.handle_key(key(KeyCode::Char('r')));
        assert!(s.running);
        assert!(s.rows.is_empty());
        assert_eq!(s.gen, 1, "gen must be bumped to 1 on first start");
        let expected_domains = s.sample_domains();
        // Re-create sample for comparison (s.op() is still "lookup" here)
        assert!(matches!(
            out,
            Some(PaneOutcome::Action(Action::StartBulk(ref p)))
            if p.op == "lookup" && !p.domains.is_empty() && p.gen == 1
        ));
        // Domains should match the first sample
        if let Some(PaneOutcome::Action(Action::StartBulk(p))) = out {
            assert_eq!(p.domains, expected_domains);
        }
    }

    #[test]
    fn enter_also_starts_run() {
        let mut s = BulkState::default();
        let out = s.handle_key(key(KeyCode::Enter));
        assert!(s.running);
        assert!(matches!(
            out,
            Some(PaneOutcome::Action(Action::StartBulk(_)))
        ));
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
