//! Shared command pipeline for the CLI subcommands and the interactive REPL.
//!
//! Both surfaces run the same fetch-then-format pipelines; before this module
//! existed, `main.rs` and `repl/mod.rs` were two hand-maintained copies of the
//! bulk-operation mapping, domain-list validation, output-path derivation,
//! progress wiring, and drift/history-snapshot logic. Keeping those pieces
//! here means a new bulk operation or a semantics fix lands in one place and
//! every surface (CLI, REPL, and the TUI's op mapping) picks it up.

use seer_core::bulk::BulkOperation;
use seer_core::RecordType;

/// Maximum number of domains accepted for a single CLI/REPL bulk run.
pub const MAX_BULK_DOMAINS: usize = 1000;

/// Canonical bulk operation names, as shown in help text and offered by the
/// REPL tab-completer. `dig`/`dns` and `prop`/`propagation` are accepted as
/// aliases by [`bulk_operation_for`].
pub const BULK_OPS: &[&str] = &[
    "lookup",
    "whois",
    "rdap",
    "dig",
    "prop",
    "status",
    "avail",
    "info",
    "ssl",
    "posture",
    "confusables",
    "caa",
];

/// Human-readable list of valid bulk operations for error messages and help.
pub const BULK_OPS_SUMMARY: &str =
    "lookup, whois, rdap, dig/dns, prop, status, avail, info, ssl, posture, confusables, caa";

/// Help text for the `bulk` subcommand's OPERATION argument (clap `help =`).
pub const BULK_OP_HELP: &str = "Operation type: lookup, whois, rdap, dig/dns, prop, status, avail, info, ssl, posture, confusables, caa";

/// Maps an operation name (including the `dns`/`propagation` aliases) and a
/// target domain to a [`BulkOperation`]. Returns `None` for unknown names.
///
/// `record_type` only applies to the `dig`/`prop` families; other operations
/// ignore it.
pub fn bulk_operation_for(
    op: &str,
    domain: String,
    record_type: RecordType,
) -> Option<BulkOperation> {
    Some(match op {
        "lookup" => BulkOperation::Lookup { domain },
        "whois" => BulkOperation::Whois { domain },
        "rdap" => BulkOperation::Rdap { domain },
        "dig" | "dns" => BulkOperation::Dns {
            domain,
            record_type,
        },
        "propagation" | "prop" => BulkOperation::Propagation {
            domain,
            record_type,
        },
        "status" => BulkOperation::Status { domain },
        "avail" => BulkOperation::Avail { domain },
        "info" => BulkOperation::Info { domain },
        "ssl" => BulkOperation::Ssl { domain },
        "posture" => BulkOperation::Posture { domain },
        "confusables" => BulkOperation::Confusables { domain },
        "caa" => BulkOperation::Caa { domain },
        _ => return None,
    })
}

/// Builds the full operation list for a bulk run, or an error message naming
/// the valid operations when `op` is unknown.
pub fn build_bulk_operations(
    op: &str,
    domains: &[String],
    record_type: RecordType,
) -> Result<Vec<BulkOperation>, String> {
    // Validate the op name once up front (with a throwaway domain) so an
    // unknown op errors even before any domains are inspected.
    if bulk_operation_for(op, String::new(), record_type).is_none() {
        return Err(format!(
            "Unknown operation: {}. Use: {}",
            op, BULK_OPS_SUMMARY
        ));
    }
    Ok(domains
        .iter()
        .filter_map(|d| bulk_operation_for(op, d.clone(), record_type))
        .collect())
}

/// Parses a bulk input blob into a validated domain list: non-empty and at
/// most [`MAX_BULK_DOMAINS`] entries.
pub fn parse_bulk_domains(content: &str) -> Result<Vec<String>, String> {
    let domains = seer_core::bulk::parse_domains_from_file(content);
    if domains.is_empty() {
        return Err(
            "No valid domains found in file. Expected format: one domain per line, \
             # for comments, or CSV (first column)"
                .to_string(),
        );
    }
    if domains.len() > MAX_BULK_DOMAINS {
        return Err(format!(
            "Bulk file contains {} domains, maximum is {}",
            domains.len(),
            MAX_BULK_DOMAINS
        ));
    }
    Ok(domains)
}

/// Default bulk output CSV path: a sibling `<stem>_results.csv` of the input
/// file (`domains.txt` → `domains_results.csv`).
pub fn default_bulk_output_path(input_file: &str) -> String {
    let input_path = std::path::Path::new(input_file);
    let stem = input_path.file_stem().unwrap_or_default().to_string_lossy();
    let parent = input_path.parent().unwrap_or(std::path::Path::new("."));
    parent
        .join(format!("{}_results.csv", stem))
        .to_string_lossy()
        .to_string()
}

/// Progress callback that drives an indicatif bar: advances the position and
/// shows the most recently completed domain as the bar message.
pub fn bar_progress_callback(bar: &indicatif::ProgressBar) -> seer_core::bulk::ProgressCallback {
    let bar = bar.clone();
    Box::new(move |completed: usize, _total: usize, domain: &str| {
        bar.set_position(completed as u64);
        bar.set_message(domain.to_string());
    })
}

/// Records a lookup result to `~/.seer/history.toml` off the async executor
/// (the file I/O is blocking). Errors are deliberately swallowed — history is
/// best-effort and must never fail the lookup that produced it.
pub async fn record_lookup_history(domain: &str, result: seer_core::LookupResult) {
    let domain = domain.to_string();
    tokio::task::spawn_blocking(move || {
        let mut history = seer_core::LookupHistory::load();
        history.record(&domain, result);
        let _ = history.save();
    })
    .await
    .ok();
}

/// Outcome of a [`drift_check`]: the computed report plus whether a previous
/// snapshot existed to compare against (drives the "no baseline" note).
pub struct DriftOutcome {
    /// Changed fields between the previous snapshot and the fresh lookup
    /// (empty when there was no previous snapshot).
    pub report: seer_core::DriftReport,
    /// True when a stored history snapshot existed before this check.
    pub had_previous: bool,
}

/// Runs a fresh lookup for `domain` and compares it against the most recent
/// stored history snapshot, optionally recording the fresh result as the new
/// baseline afterwards. This is the single source of the drift semantics
/// shared by the CLI `drift` subcommand and the REPL `drift` command.
pub async fn drift_check(
    lookup: &seer_core::SmartLookup,
    domain: &str,
    record: bool,
) -> seer_core::Result<DriftOutcome> {
    let result = lookup.lookup(domain).await?;

    // Compare the fresh lookup against the most recent stored snapshot
    // before (optionally) recording the new one. History I/O is blocking.
    let domain_key = domain.to_string();
    let previous = tokio::task::spawn_blocking(move || {
        seer_core::LookupHistory::load()
            .get(&domain_key)
            .last()
            .map(|e| e.result.clone())
    })
    .await
    .ok()
    .flatten();

    let report = match &previous {
        Some(prev) => seer_core::DriftReport::from_lookups(domain, prev, &result),
        None => seer_core::DriftReport {
            domain: domain.to_string(),
            changes: Vec::new(),
        },
    };

    if record {
        record_lookup_history(domain, result).await;
    }

    Ok(DriftOutcome {
        report,
        had_previous: previous.is_some(),
    })
}

/// The advisory note shown when a drift check finds no previous snapshot.
pub fn no_baseline_note(domain: &str, record: bool) -> String {
    format!(
        "no previous snapshot for {} — {}",
        domain,
        if record {
            "recorded a baseline"
        } else {
            "run with --record to establish a baseline"
        }
    )
}

/// Outcome of a [`subdomain_baseline_check`]: the fresh enumeration plus its
/// diff against the stored baseline (`report.baseline_missing` drives the
/// "no baseline" note the way [`DriftOutcome::had_previous`] does for drift).
pub struct SubdomainBaselineOutcome {
    /// The fresh CT-log enumeration.
    pub result: seer_core::SubdomainResult,
    /// Diff of the fresh enumeration against the stored baseline.
    pub report: seer_core::SubdomainBaselineDiff,
}

/// Enumerates subdomains for `domain` and diffs the result against the stored
/// baseline (`~/.seer/subdomain_baselines.json`), optionally recording the
/// fresh set as the new baseline afterwards. Single source of the
/// `subdomains --diff/--record` semantics shared by the CLI subcommand and
/// the REPL command, mirroring [`drift_check`].
///
/// Unlike lookup history (best-effort), a failed baseline save propagates:
/// recording is the whole point of `--record`, so silently losing it would
/// make every later diff lie.
pub async fn subdomain_baseline_check(
    domain: &str,
    record: bool,
) -> seer_core::Result<SubdomainBaselineOutcome> {
    let enumerator = seer_core::SubdomainEnumerator::new();
    // `enumerate` normalizes the domain; use `result.domain` as the key so
    // the baseline store and the note agree on the canonical name.
    let result = enumerator.enumerate(domain).await?;

    // Baseline file I/O is blocking — keep it off the async executor.
    let domain_key = result.domain.clone();
    let names = result.subdomains.clone();
    let source = result.source.clone();
    let report = tokio::task::spawn_blocking(move || -> seer_core::Result<_> {
        let mut baselines = seer_core::SubdomainBaselines::load();
        let report = baselines.diff(&domain_key, &names);
        if record {
            baselines.record(&domain_key, &names, &source);
            baselines.save()?;
        }
        Ok(report)
    })
    .await
    .map_err(|e| seer_core::SeerError::ConfigError(format!("baseline task failed: {e}")))??;

    Ok(SubdomainBaselineOutcome { result, report })
}

/// The advisory note shown when a subdomain diff finds no stored baseline.
pub fn no_subdomain_baseline_note(domain: &str, record: bool) -> String {
    format!(
        "no subdomain baseline for {} — {}",
        domain,
        if record {
            "recorded one from this run"
        } else {
            "run with --record to establish a baseline"
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_canonical_op_maps_to_an_operation() {
        for op in BULK_OPS {
            assert!(
                bulk_operation_for(op, "example.com".to_string(), RecordType::A).is_some(),
                "canonical op {op} must be accepted"
            );
        }
    }

    #[test]
    fn aliases_map_like_their_canonical_names() {
        let dig = bulk_operation_for("dig", "a.com".into(), RecordType::MX);
        let dns = bulk_operation_for("dns", "a.com".into(), RecordType::MX);
        assert!(matches!(dig, Some(BulkOperation::Dns { .. })));
        assert!(matches!(dns, Some(BulkOperation::Dns { .. })));
        let prop = bulk_operation_for("prop", "a.com".into(), RecordType::A);
        let propagation = bulk_operation_for("propagation", "a.com".into(), RecordType::A);
        assert!(matches!(prop, Some(BulkOperation::Propagation { .. })));
        assert!(matches!(
            propagation,
            Some(BulkOperation::Propagation { .. })
        ));
    }

    #[test]
    fn new_ops_map_to_their_variants() {
        assert!(matches!(
            bulk_operation_for("posture", "a.com".into(), RecordType::A),
            Some(BulkOperation::Posture { .. })
        ));
        assert!(matches!(
            bulk_operation_for("confusables", "a.com".into(), RecordType::A),
            Some(BulkOperation::Confusables { .. })
        ));
        assert!(matches!(
            bulk_operation_for("caa", "a.com".into(), RecordType::A),
            Some(BulkOperation::Caa { .. })
        ));
    }

    #[test]
    fn unknown_op_is_rejected_with_op_list() {
        assert!(bulk_operation_for("bogus", "a.com".into(), RecordType::A).is_none());
        let err = build_bulk_operations("bogus", &["a.com".to_string()], RecordType::A)
            .expect_err("unknown op must error");
        assert!(err.contains("Unknown operation: bogus"), "got: {err}");
        // The error must name the full valid set, including the new ops.
        for op in ["posture", "confusables", "caa", "ssl"] {
            assert!(err.contains(op), "error should list {op}: {err}");
        }
    }

    #[test]
    fn build_bulk_operations_builds_one_per_domain() {
        let domains = vec!["a.com".to_string(), "b.com".to_string()];
        let ops = build_bulk_operations("caa", &domains, RecordType::A).expect("valid op");
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].domain(), "a.com");
        assert_eq!(ops[1].domain(), "b.com");
    }

    #[test]
    fn parse_bulk_domains_rejects_empty_input() {
        let err = parse_bulk_domains("# only a comment\n").expect_err("empty must error");
        assert!(err.contains("No valid domains"), "got: {err}");
    }

    #[test]
    fn parse_bulk_domains_rejects_oversized_lists() {
        let content: String = (0..=MAX_BULK_DOMAINS)
            .map(|i| format!("d{i}.com\n"))
            .collect();
        let err = parse_bulk_domains(&content).expect_err("oversized must error");
        assert!(err.contains("maximum is"), "got: {err}");
    }

    #[test]
    fn parse_bulk_domains_accepts_valid_lists() {
        let domains = parse_bulk_domains("a.com\n# skip\nb.com\n").expect("valid list");
        assert_eq!(domains, vec!["a.com", "b.com"]);
    }

    #[test]
    fn default_bulk_output_path_derives_sibling_csv() {
        assert_eq!(
            default_bulk_output_path("domains.txt"),
            "domains_results.csv"
        );
        // Build the expected sibling path through the same Path API so the
        // separator matches the host OS (Windows joins with `\`, not `/`).
        let nested = std::path::Path::new("lists").join("domains.csv");
        let expected = std::path::Path::new("lists")
            .join("domains_results.csv")
            .to_string_lossy()
            .to_string();
        assert_eq!(
            default_bulk_output_path(&nested.to_string_lossy()),
            expected
        );
    }

    #[test]
    fn no_baseline_note_reflects_record_flag() {
        assert!(no_baseline_note("a.com", true).contains("recorded a baseline"));
        assert!(no_baseline_note("a.com", false).contains("--record"));
    }

    #[test]
    fn no_subdomain_baseline_note_reflects_record_flag() {
        assert!(no_subdomain_baseline_note("a.com", true).contains("recorded one"));
        assert!(no_subdomain_baseline_note("a.com", false).contains("--record"));
    }
}
