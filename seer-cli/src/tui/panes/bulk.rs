//! Bulk pane component — multi-domain batch operation state + key handling.
use crossterm::event::{KeyCode, KeyEvent};
use seer_core::bulk::{BulkOperation, BulkResult};

use crate::tui::action::{Action, BulkParams, EditTarget};
use crate::tui::panes::PaneOutcome;

/// Operation presets selectable with `o`.
pub const OPS: &[&str] = &[
    "lookup", "status", "dig", "avail", "info", "whois", "rdap", "ssl", "prop",
];

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
    /// Selected result row. `None` follows the tail (newest row, the default
    /// while streaming); `Some(i)` pins a user-chosen row for inspection.
    pub selected: Option<usize>,
    /// Whether the detail panel for the selected row is expanded.
    pub detail: bool,
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

    /// Count of successful / failed rows in the current run.
    pub fn tally(&self) -> (usize, usize) {
        let ok = self.rows.iter().filter(|r| r.success).count();
        (ok, self.rows.len() - ok)
    }

    /// Effective selected row index: the user's pinned selection, or the tail
    /// (newest row) when following the stream. `None` only when there are no
    /// rows yet.
    pub fn effective_selected(&self) -> Option<usize> {
        if self.rows.is_empty() {
            return None;
        }
        Some(
            self.selected
                .unwrap_or(self.rows.len() - 1)
                .min(self.rows.len() - 1),
        )
    }

    /// Reset run-scoped view state shared by `r` and file-load starts.
    fn begin_run(&mut self) {
        self.rows.clear();
        self.running = true;
        self.note = None;
        self.gen += 1;
        self.selected = None;
        self.detail = false;
    }

    /// Move the selection by `delta` rows, pinning it (leaving tail-follow).
    fn move_selection(&mut self, delta: isize) {
        if self.rows.is_empty() {
            return;
        }
        let last = self.rows.len() - 1;
        let cur = self.selected.unwrap_or(last) as isize;
        let next = (cur + delta).clamp(0, last as isize) as usize;
        self.selected = Some(next);
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
            KeyCode::Char('r') => Some(self.start_run()),
            // Move the result selection
            KeyCode::Char('j') | KeyCode::Down => {
                self.move_selection(1);
                Some(PaneOutcome::None)
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.move_selection(-1);
                Some(PaneOutcome::None)
            }
            // Enter / 'v' — toggle the detail panel for the selected row when
            // results exist; otherwise Enter starts a run (empty-state shortcut).
            KeyCode::Enter | KeyCode::Char('v') => {
                if self.rows.is_empty() {
                    if matches!(key.code, KeyCode::Enter) {
                        return Some(self.start_run());
                    }
                    return Some(PaneOutcome::None);
                }
                self.detail = !self.detail;
                Some(PaneOutcome::None)
            }
            // Cancel an in-flight run
            KeyCode::Char('x') => {
                if self.running {
                    self.running = false;
                    Some(PaneOutcome::Action(Action::StopBulk))
                } else {
                    Some(PaneOutcome::None)
                }
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

    /// Validate the entered domains and emit a `StartBulk` action, or a toast
    /// when the list is empty.
    fn start_run(&mut self) -> PaneOutcome {
        let domains = parse_domains_input(&self.domains);
        if domains.is_empty() {
            return PaneOutcome::Toast {
                tone: "info",
                msg: "enter domains first (d)",
            };
        }
        self.begin_run();
        self.total = domains.len();
        PaneOutcome::Action(Action::StartBulk(BulkParams {
            op: self.op().to_string(),
            domains,
            gen: self.gen,
        }))
    }

    /// Build a CSV string from the current rows. Reuses the CLI's
    /// `escape_csv_field` so the export is RFC 4180 quoted and protected
    /// against spreadsheet formula injection.
    pub fn to_csv(&self) -> String {
        use crate::utils::{escape_csv_field, get_domain_from_operation};
        let mut out = String::from("domain,success,error,duration_ms\n");
        for r in &self.rows {
            let domain = escape_csv_field(&get_domain_from_operation(&r.operation));
            let err = escape_csv_field(r.error.as_deref().unwrap_or(""));
            out.push_str(&format!(
                "{},{},{},{}\n",
                domain, r.success, err, r.duration_ms
            ));
        }
        out
    }
}

/// Extract the domain string from a `BulkOperation` (all variants carry one).
/// Used by the lens renderer for per-row display.
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
        let many = (0..80)
            .map(|i| format!("d{i}.com"))
            .collect::<Vec<_>>()
            .join(" ");
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
    fn enter_with_no_rows_starts_run() {
        let mut s = BulkState::default();
        s.domains = "a.com".into();
        let out = s.handle_key(key(KeyCode::Enter));
        assert!(s.running, "Enter in the empty state should start a run");
        assert!(matches!(
            out,
            Some(PaneOutcome::Action(Action::StartBulk(_)))
        ));
    }

    #[test]
    fn enter_with_rows_toggles_detail_not_run() {
        let mut s = BulkState::default();
        s.rows.push(make_lookup_result("x.com"));
        assert!(!s.detail);
        let out = s.handle_key(key(KeyCode::Enter));
        assert!(s.detail, "Enter with rows should open the detail panel");
        assert!(!s.running, "Enter with rows must not start a run");
        assert!(matches!(out, Some(PaneOutcome::None)));
        // Toggling again closes it.
        s.handle_key(key(KeyCode::Enter));
        assert!(!s.detail);
    }

    #[test]
    fn v_toggles_detail() {
        let mut s = BulkState::default();
        s.rows.push(make_lookup_result("x.com"));
        s.handle_key(key(KeyCode::Char('v')));
        assert!(s.detail);
    }

    #[test]
    fn jk_move_selection_and_pin() {
        let mut s = BulkState::default();
        for i in 0..4 {
            s.rows.push(make_lookup_result(&format!("d{i}.com")));
        }
        // No manual selection → effective selection follows the tail.
        assert_eq!(s.selected, None);
        assert_eq!(s.effective_selected(), Some(3));
        // k moves up from the tail and pins.
        s.handle_key(key(KeyCode::Char('k')));
        assert_eq!(s.selected, Some(2));
        // j moves down.
        s.handle_key(key(KeyCode::Char('j')));
        assert_eq!(s.selected, Some(3));
        // j is clamped at the last row.
        s.handle_key(key(KeyCode::Char('j')));
        assert_eq!(s.selected, Some(3));
    }

    #[test]
    fn arrows_also_move_selection() {
        let mut s = BulkState::default();
        s.rows.push(make_lookup_result("a.com"));
        s.rows.push(make_lookup_result("b.com"));
        s.handle_key(key(KeyCode::Up));
        assert_eq!(s.selected, Some(0));
        s.handle_key(key(KeyCode::Down));
        assert_eq!(s.selected, Some(1));
    }

    #[test]
    fn x_stops_running_and_cancels() {
        let mut s = BulkState::default();
        s.running = true;
        let out = s.handle_key(key(KeyCode::Char('x')));
        assert!(!s.running);
        assert!(matches!(out, Some(PaneOutcome::Action(Action::StopBulk))));
    }

    #[test]
    fn x_when_idle_is_noop() {
        let mut s = BulkState::default();
        let out = s.handle_key(key(KeyCode::Char('x')));
        assert!(matches!(out, Some(PaneOutcome::None)));
    }

    #[test]
    fn run_resets_selection_and_detail() {
        let mut s = BulkState::default();
        s.domains = "a.com b.com".into();
        s.rows.push(make_lookup_result("old.com"));
        s.selected = Some(0);
        s.detail = true;
        s.handle_key(key(KeyCode::Char('r')));
        assert_eq!(s.selected, None, "selection resets on a new run");
        assert!(!s.detail, "detail closes on a new run");
        assert!(s.rows.is_empty(), "prior rows cleared on a new run");
    }

    #[test]
    fn tally_counts_ok_and_failed() {
        let mut s = BulkState::default();
        s.rows.push(make_lookup_result("ok1.com"));
        s.rows.push(BulkResult {
            operation: BulkOperation::Lookup {
                domain: "bad.com".into(),
            },
            success: false,
            data: None,
            error: Some("nope".into()),
            duration_ms: 1,
        });
        assert_eq!(s.tally(), (1, 1));
    }

    #[test]
    fn effective_selected_is_none_when_empty() {
        let s = BulkState::default();
        assert_eq!(s.effective_selected(), None);
    }

    #[test]
    fn extended_ops_are_available() {
        for op in ["whois", "rdap", "ssl", "prop"] {
            assert!(OPS.contains(&op), "op preset {op} should be selectable");
        }
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
        // Commas inside the error field must be RFC 4180 quoted (not stripped).
        assert!(
            csv.contains("\"timeout, retry failed\""),
            "error with comma must be quoted, got: {csv}"
        );
    }

    #[test]
    fn to_csv_protects_against_formula_injection() {
        let mut s = BulkState::default();
        s.rows.push(BulkResult {
            operation: BulkOperation::Lookup {
                domain: "=cmd.com".to_string(),
            },
            success: false,
            data: None,
            error: Some("=HYPERLINK(\"evil\")".to_string()),
            duration_ms: 10,
        });
        let csv = s.to_csv();
        // Formula-leading fields are prefixed with a single quote.
        assert!(csv.contains("'=cmd.com"), "domain must be guarded: {csv}");
        assert!(
            csv.contains("\"'=HYPERLINK(\"\"evil\"\")\""),
            "error must be guarded + quoted: {csv}"
        );
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
