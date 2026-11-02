//! Bulk pane component — multi-domain batch operation state + key handling.
use crossterm::event::{KeyCode, KeyEvent};
use seer_core::bulk::BulkResult;

use crate::ops::BULK_OPS;
use crate::tui::action::{Action, BulkParams};
use crate::tui::options::BulkInput;
use crate::tui::panes::{already_running, PaneOutcome};

/// Runtime state for the Bulk lens — rows and run status. What to run
/// (op, domains, file) is in the options (`options::BULK`).
#[derive(Default)]
pub struct BulkState {
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
    /// First line of the detail panel shown (PgUp/PgDn scroll it).
    pub detail_scroll: u16,
    /// Op the current results were produced with (`None` before any run).
    pub run_op: Option<&'static str>,
}

/// Rows a PgUp/PgDn moves the detail panel.
const DETAIL_PAGE: u16 = 5;

/// Parse the domains field (typed or pasted; a single line, so domains are
/// separated by spaces or commas) into the run's list. Each token becomes a
/// line for `ops::parse_bulk_domains`, the one bulk-list parser the CLI's
/// files go through too: dotted names only, `#`-tokens skipped, and more
/// than `MAX_BULK_DOMAINS` an error rather than a silent truncation.
/// `Ok(vec![])` when nothing was entered.
pub fn parse_domains_input(s: &str) -> Result<Vec<String>, String> {
    let lines: Vec<&str> = s
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|t| !t.is_empty())
        .collect();
    if lines.is_empty() {
        return Ok(Vec::new());
    }
    crate::ops::parse_bulk_domains(&lines.join("\n"))
}

impl BulkState {
    /// Op the current results were produced with (the first op before any run).
    pub fn results_op(&self) -> &str {
        self.run_op.unwrap_or(BULK_OPS[0].0)
    }

    /// Start a run of `op` over `input` (the options' Op and Source), or say
    /// what is missing. An empty file path or domain list never clears the
    /// current results, and neither does `↵` during a run.
    pub fn start(&mut self, op: &'static str, input: BulkInput) -> PaneOutcome {
        if self.running {
            return already_running();
        }
        match input {
            BulkInput::File(path) => {
                if path.is_empty() {
                    return PaneOutcome::Toast {
                        tone: "info",
                        msg: "set a file in Options first".to_string(),
                    };
                }
                self.begin_run(op);
                // Unknown until the file is read: the gauge falls back to rows.
                self.total = 0;
                PaneOutcome::Action(Action::StartBulkFromFile {
                    op: op.to_string(),
                    path,
                    gen: self.gen,
                })
            }
            BulkInput::Domains(text) => {
                let domains = match parse_domains_input(&text) {
                    Ok(d) if d.is_empty() => {
                        return PaneOutcome::Toast {
                            tone: "info",
                            msg: "enter domains in Options first".to_string(),
                        }
                    }
                    Ok(d) => d,
                    Err(msg) => return PaneOutcome::Toast { tone: "fail", msg },
                };
                self.begin_run(op);
                self.total = domains.len();
                PaneOutcome::Action(Action::StartBulk(BulkParams {
                    op: op.to_string(),
                    domains,
                    gen: self.gen,
                }))
            }
        }
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

    /// Reset run-scoped view state for a new run of `op`.
    fn begin_run(&mut self, op: &'static str) {
        self.rows.clear();
        self.running = true;
        self.note = None;
        self.gen += 1;
        self.selected = None;
        self.detail = false;
        self.detail_scroll = 0;
        self.run_op = Some(op);
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
        self.detail_scroll = 0;
    }

    /// Handle a key event for the Bulk pane. `Some(_)` = consumed; never `Esc`.
    pub fn handle_key(
        &mut self,
        key: KeyEvent,
        run: Option<(&'static str, BulkInput)>,
    ) -> Option<PaneOutcome> {
        match key.code {
            // Move the result selection
            KeyCode::Char('j') | KeyCode::Down => {
                self.move_selection(1);
                Some(PaneOutcome::None)
            }
            // Scroll the open detail panel.
            KeyCode::PageDown if self.detail => {
                self.detail_scroll = self.detail_scroll.saturating_add(DETAIL_PAGE);
                Some(PaneOutcome::None)
            }
            KeyCode::PageUp if self.detail => {
                self.detail_scroll = self.detail_scroll.saturating_sub(DETAIL_PAGE);
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
                        return Some(match run {
                            Some((op, input)) => self.start(op, input),
                            None => PaneOutcome::None,
                        });
                    }
                    return Some(PaneOutcome::None);
                }
                self.detail = !self.detail;
                self.detail_scroll = 0;
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
            // Export results to CSV
            KeyCode::Char('e') => {
                if self.rows.is_empty() {
                    Some(PaneOutcome::None)
                } else {
                    let op = self.results_op();
                    Some(PaneOutcome::Action(Action::WriteCsv {
                        name: format!("seer-bulk-{op}.csv"),
                        // The CLI's table-driven exporter: the op's own columns.
                        contents: crate::utils::bulk_results_to_csv(&self.rows, op),
                    }))
                }
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use seer_core::bulk::BulkOperation;

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
        assert!(s.run_op.is_none());
        assert!(!s.running);
        assert!(s.rows.is_empty());
        assert!(s.note.is_none());
    }

    #[test]
    fn parse_domains_input_splits_and_filters() {
        let got = parse_domains_input("google.com, github.com rust-lang.org  bad #comment.skip");
        assert_eq!(
            got.unwrap(),
            vec!["google.com", "github.com", "rust-lang.org"]
        );
        // "bad" has no dot → dropped; "#comment.skip" starts with # → dropped.
        assert_eq!(parse_domains_input("  ").unwrap(), Vec::<String>::new());
    }

    /// More than 50 domains used to be cut to 50 without a word; the pane
    /// now shares the CLI's cap, and an over-long list is an error.
    #[test]
    fn parse_domains_input_uses_the_cli_cap_instead_of_truncating() {
        let list = |n: usize| {
            (0..n)
                .map(|i| format!("d{i}.com"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        assert_eq!(parse_domains_input(&list(80)).unwrap().len(), 80);
        let err = parse_domains_input(&list(crate::ops::MAX_BULK_DOMAINS + 1)).unwrap_err();
        assert!(err.contains("maximum"), "got: {err}");

        let mut s = BulkState::default();
        let out = s.start(
            "lookup",
            BulkInput::Domains(list(crate::ops::MAX_BULK_DOMAINS + 1)),
        );
        assert!(!s.running, "an over-long list must not start");
        assert!(matches!(out, PaneOutcome::Toast { tone: "fail", .. }));
    }

    #[test]
    fn start_with_empty_domains_toasts_and_does_not_run() {
        let mut s = BulkState::default();
        let out = s.start("lookup", BulkInput::Domains(String::new()));
        assert!(!s.running, "empty run must not start");
        assert!(matches!(out, PaneOutcome::Toast { .. }));
    }

    #[test]
    fn start_is_refused_while_running() {
        let mut s = BulkState::default();
        s.start("lookup", BulkInput::Domains("a.com".into()));
        let out = s.start("status", BulkInput::Domains("b.com".into()));
        assert!(matches!(out, PaneOutcome::Toast { .. }), "{out:?}");
        assert_eq!((s.gen, s.run_op), (1, Some("lookup")), "the run survives");
    }

    #[test]
    fn start_with_domains_starts_run_with_parsed_list() {
        let mut s = BulkState::default();
        let out = s.start("lookup", BulkInput::Domains("a.com, b.com".into()));
        assert!(s.running);
        assert_eq!(s.gen, 1);
        assert_eq!(s.run_op, Some("lookup"));
        match out {
            PaneOutcome::Action(Action::StartBulk(p)) => {
                assert_eq!(p.op, "lookup");
                assert_eq!(p.domains, vec!["a.com", "b.com"]);
                assert_eq!(p.gen, 1);
            }
            other => panic!("expected StartBulk, got {other:?}"),
        }
    }

    #[test]
    fn start_with_a_file_emits_a_file_run() {
        let mut s = BulkState::default();
        let out = s.start("status", BulkInput::File("list.txt".into()));
        assert!(s.running);
        assert_eq!(s.run_op, Some("status"));
        assert!(matches!(
            out,
            PaneOutcome::Action(Action::StartBulkFromFile { ref path, ref op, gen: 1 })
                if path == "list.txt" && op == "status"
        ));
    }

    #[test]
    fn start_with_an_empty_file_keeps_the_rows() {
        let mut s = BulkState::default();
        s.rows.push(make_lookup_result("kept.com"));
        let out = s.start("lookup", BulkInput::File(String::new()));
        assert!(matches!(out, PaneOutcome::Toast { .. }));
        assert!(!s.running);
        assert_eq!(s.gen, 0);
        assert_eq!(s.rows.len(), 1, "existing results must survive");
    }

    #[test]
    fn e_with_no_rows_returns_pane_outcome_none() {
        let mut s = BulkState::default();
        let out = s.handle_key(key(KeyCode::Char('e')), None);
        assert!(matches!(out, Some(PaneOutcome::None)));
    }

    #[test]
    fn e_with_rows_returns_write_csv() {
        let mut s = BulkState::default();
        s.rows.push(make_lookup_result("x.com"));
        let out = s.handle_key(key(KeyCode::Char('e')), None);
        assert!(matches!(
            out,
            Some(PaneOutcome::Action(Action::WriteCsv { .. }))
        ));
    }

    #[test]
    fn esc_returns_none() {
        let mut s = BulkState::default();
        let out = s.handle_key(key(KeyCode::Esc), None);
        assert!(out.is_none(), "Esc must not be swallowed");
    }

    #[test]
    fn enter_with_no_rows_starts_run() {
        let mut s = BulkState::default();
        let out = s.handle_key(
            key(KeyCode::Enter),
            Some(("lookup", BulkInput::Domains("a.com".into()))),
        );
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
        let out = s.handle_key(key(KeyCode::Enter), None);
        assert!(s.detail, "Enter with rows should open the detail panel");
        assert!(!s.running, "Enter with rows must not start a run");
        assert!(matches!(out, Some(PaneOutcome::None)));
        // Toggling again closes it.
        s.handle_key(key(KeyCode::Enter), None);
        assert!(!s.detail);
    }

    #[test]
    fn v_toggles_detail() {
        let mut s = BulkState::default();
        s.rows.push(make_lookup_result("x.com"));
        s.handle_key(key(KeyCode::Char('v')), None);
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
        s.handle_key(key(KeyCode::Char('k')), None);
        assert_eq!(s.selected, Some(2));
        // j moves down.
        s.handle_key(key(KeyCode::Char('j')), None);
        assert_eq!(s.selected, Some(3));
        // j is clamped at the last row.
        s.handle_key(key(KeyCode::Char('j')), None);
        assert_eq!(s.selected, Some(3));
    }

    #[test]
    fn arrows_also_move_selection() {
        let mut s = BulkState::default();
        s.rows.push(make_lookup_result("a.com"));
        s.rows.push(make_lookup_result("b.com"));
        s.handle_key(key(KeyCode::Up), None);
        assert_eq!(s.selected, Some(0));
        s.handle_key(key(KeyCode::Down), None);
        assert_eq!(s.selected, Some(1));
    }

    #[test]
    fn x_stops_running_and_cancels() {
        let mut s = BulkState {
            running: true,
            ..Default::default()
        };
        let out = s.handle_key(key(KeyCode::Char('x')), None);
        assert!(!s.running);
        assert!(matches!(out, Some(PaneOutcome::Action(Action::StopBulk))));
    }

    #[test]
    fn x_when_idle_is_noop() {
        let mut s = BulkState::default();
        let out = s.handle_key(key(KeyCode::Char('x')), None);
        assert!(matches!(out, Some(PaneOutcome::None)));
    }

    #[test]
    fn run_resets_selection_and_detail() {
        let mut s = BulkState::default();
        s.rows.push(make_lookup_result("old.com"));
        s.selected = Some(0);
        s.detail = true;
        s.start("lookup", BulkInput::Domains("a.com b.com".into()));
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
        for op in [
            "whois",
            "rdap",
            "ssl",
            "prop",
            "posture",
            "confusables",
            "caa",
        ] {
            assert!(
                BULK_OPS.iter().any(|(name, _)| *name == op),
                "op preset {op} should be selectable"
            );
        }
    }

    #[test]
    fn every_op_preset_is_a_valid_bulk_operation() {
        // The pane's presets must all map through the shared ops-module
        // mapping (no preset may silently fall back to `lookup`).
        for (op, _) in BULK_OPS {
            assert!(
                crate::ops::bulk_operation_for(op, "a.com".into(), seer_core::RecordType::A)
                    .is_some(),
                "preset {op} must map to a BulkOperation"
            );
        }
    }

    /// The export is the CLI's table-driven CSV for the run's op, not a
    /// four-column summary.
    #[test]
    fn export_uses_the_cli_csv_for_the_runs_op() {
        let mut s = BulkState::default();
        s.rows.push(make_lookup_result("x.com"));
        s.rows.push(BulkResult {
            operation: BulkOperation::Lookup {
                domain: "=bad.com".to_string(),
            },
            success: false,
            data: None,
            error: Some("timeout, retry failed".to_string()),
            duration_ms: 10,
        });
        let Some(PaneOutcome::Action(Action::WriteCsv { contents, .. })) =
            s.handle_key(key(KeyCode::Char('e')), None)
        else {
            panic!("expected WriteCsv");
        };
        assert_eq!(
            contents,
            crate::utils::bulk_results_to_csv(&s.rows, "lookup")
        );
        let header = contents.lines().next().unwrap();
        assert!(header.starts_with("domain,success,"), "{header}");
        assert!(header.ends_with(",error"), "{header}");
        assert_ne!(header, "domain,success,error,duration_ms");
    }

    #[test]
    fn page_keys_scroll_the_open_detail_and_reset_on_move() {
        let mut s = BulkState::default();
        s.rows.push(make_lookup_result("a.com"));
        s.rows.push(make_lookup_result("b.com"));
        // Closed detail: PgDn is not the pane's.
        assert!(s.handle_key(key(KeyCode::PageDown), None).is_none());
        s.handle_key(key(KeyCode::Char('v')), None);
        s.handle_key(key(KeyCode::PageDown), None);
        s.handle_key(key(KeyCode::PageDown), None);
        assert_eq!(s.detail_scroll, 2 * DETAIL_PAGE);
        s.handle_key(key(KeyCode::PageUp), None);
        assert_eq!(s.detail_scroll, DETAIL_PAGE);
        s.handle_key(key(KeyCode::Char('k')), None);
        assert_eq!(s.detail_scroll, 0, "another row starts at its top");
    }
}
