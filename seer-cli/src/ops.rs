//! Shared command pipeline for the CLI subcommands and the interactive REPL.
//!
//! Both surfaces run the same fetch-then-format pipelines; before this module
//! existed, `main.rs` and `repl/mod.rs` were two hand-maintained copies of the
//! bulk-operation mapping, domain-list validation, output-path derivation,
//! progress wiring, and drift/history-snapshot logic. Keeping those pieces
//! here means a new bulk operation or a semantics fix lands in one place and
//! every surface (CLI, REPL, and the TUI's op mapping) picks it up.

use std::sync::LazyLock;

use seer_core::bulk::{BulkOperation, BulkResult};
use seer_core::colors::CatppuccinExt;
use seer_core::RecordType;

/// Maximum number of domains accepted for a single CLI/REPL bulk run.
pub const MAX_BULK_DOMAINS: usize = 1000;

/// Bulk operations with one-line descriptions, in the TUI's `o` cycling
/// order: the single list behind help text, error messages, the REPL
/// completer, and the TUI presets. [`bulk_operation_for`] also accepts the
/// `dns`/`propagation` aliases.
pub const BULK_OPS: &[(&str, &str)] = &[
    ("lookup", "Smart lookup (RDAP first, WHOIS fallback)"),
    ("status", "Check HTTP, SSL, and domain expiration"),
    ("dig", "Query DNS records (alias: dns)"),
    ("avail", "Check domain registration availability"),
    ("info", "Comprehensive domain info (RDAP + WHOIS merged)"),
    ("whois", "Query WHOIS information"),
    ("rdap", "Query RDAP registry data"),
    ("ssl", "Inspect SSL certificate chain (deep)"),
    ("prop", "Check DNS propagation (alias: propagation)"),
    ("posture", "SPF, DMARC, MTA-STS, BIMI, DANE posture"),
    ("confusables", "Look-alike scan (costly per domain)"),
    ("caa", "Look up CAA (cert authority) policy"),
];

/// Comma-separated bulk operation names, for error messages and help.
pub static BULK_OPS_SUMMARY: LazyLock<String> = LazyLock::new(|| {
    let names: Vec<&str> = BULK_OPS.iter().map(|(name, _)| *name).collect();
    names.join(", ")
});

/// The accepted bulk input formats, shared by `seer bulk --help` and the
/// REPL's `bulk -h`.
pub const BULK_INPUT_FORMATS: &str = "  Plain text (one domain per line, # for comments):
    # My domains to check
    example.com
    google.com
    github.com

  CSV (uses first column, skips header if present):
    domain,owner,notes
    example.com,Alice,Main site
    google.com,Bob,Search
    github.com,Carol,Code hosting
";

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
            op, *BULK_OPS_SUMMARY
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

/// Progress bar for a bulk run, registered with the tracing writer so log
/// lines print above it instead of tearing it. Pair with [`finish_bulk_bar`].
pub fn bulk_bar(total: usize) -> indicatif::ProgressBar {
    let bar = indicatif::ProgressBar::new(total as u64);
    bar.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("{bar:40.cyan/blue} {pos}/{len} ({percent}%) eta {eta} {msg}")
            .expect("valid progress bar template")
            .progress_chars("=>-"),
    );
    crate::display::set_bulk_progress_bar(bar.clone());
    bar
}

/// Unregisters and clears a [`bulk_bar`].
pub fn finish_bulk_bar(bar: &indicatif::ProgressBar) {
    crate::display::clear_bulk_progress_bar();
    bar.finish_and_clear();
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

/// The "Processing N domains with OP operation..." line printed before a run.
pub fn bulk_banner(domain_count: usize, op: &str) -> String {
    format!(
        "Processing {} domains with {} operation...",
        domain_count.to_string().ctp_green(),
        op.ctp_yellow()
    )
}

/// Writes a run's CSV atomically, so a crash or full disk mid-write cannot
/// leave a truncated file that downstream pipelines treat as authoritative.
pub fn write_bulk_csv(results: &[BulkResult], op: &str, path: &str) -> Result<(), String> {
    let csv = crate::utils::bulk_results_to_csv(results, op);
    crate::utils::atomic_write(path, &csv)
        .map_err(|e| format!("Failed to write output file {}: {}", path, e))
}

/// The "  N successful, M failed" line after a run.
pub fn bulk_summary(results: &[BulkResult]) -> String {
    let ok = results.iter().filter(|r| r.success).count();
    let failed = results.len() - ok;
    let failed = if failed > 0 {
        failed.to_string().ctp_red()
    } else {
        failed.to_string().ctp_green()
    };
    format!(
        "  {} successful, {} failed",
        ok.to_string().ctp_green(),
        failed
    )
}

/// Runs a live `follow` for the CLI and the REPL: raw mode so Esc / Ctrl-C
/// cancel (restored on drop, even if a panic unwinds — issue #60), and each
/// iteration streamed to stdout as it lands. The key listener is stopped
/// before returning so it cannot swallow keystrokes meant for whatever reads
/// the terminal next. `handle_sigint` also cancels on SIGINT, the only
/// interrupt path when there is no terminal for the key listener.
pub async fn run_live_follow(
    follower: &seer_core::DnsFollower,
    domain: &str,
    record_type: RecordType,
    nameserver: Option<&str>,
    config: seer_core::FollowConfig,
    format: seer_core::output::OutputFormat,
    handle_sigint: bool,
) -> seer_core::Result<seer_core::FollowResult> {
    use std::io::Write;

    // `cancel_tx` must stay alive until the follow returns: once every sender
    // is dropped, the follow's interruptible sleep wakes immediately.
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    if handle_sigint {
        let cancel_tx = cancel_tx.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            let _ = cancel_tx.send(true);
        });
    }

    let raw_guard = crate::utils::RawModeGuard::new();
    let key_listener =
        crate::utils::FollowKeyListener::spawn(cancel_tx.clone(), raw_guard.is_enabled());

    // In raw mode `\n` alone doesn't return to column 0, so use `\r\n`.
    let callback: seer_core::dns::FollowProgressCallback = std::sync::Arc::new(move |iteration| {
        let formatter = seer_core::output::get_formatter(format);
        let output = formatter
            .format_follow_iteration(iteration)
            .replace('\n', "\r\n");
        let mut stdout = std::io::stdout().lock();
        let _ = stdout.write_all(output.as_bytes());
        let _ = stdout.write_all(b"\r\n");
        let _ = stdout.flush();
    });

    let result = follower
        .follow(
            domain,
            record_type,
            nameserver,
            config,
            Some(callback),
            Some(cancel_rx),
        )
        .await;

    // Stop the listener, then restore cooked mode, before the caller prints.
    if let Some(listener) = key_listener {
        listener.stop().await;
    }
    drop(raw_guard);
    result
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

/// Runs blocking `~/.seer` state-file I/O off the async executor, folding a
/// failed task into the same `Failed to <what>: …` error as the I/O itself.
async fn state_io<T, F>(what: &str, io: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> seer_core::Result<T> + Send + 'static,
{
    match tokio::task::spawn_blocking(io).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(format!("Failed to {}: {}", what, e)),
        Err(e) => Err(format!("Failed to {}: {}", what, e)),
    }
}

pub async fn load_watchlist() -> Result<seer_core::Watchlist, String> {
    state_io("load watchlist", || Ok(seer_core::Watchlist::load())).await
}

/// Runs `watch add|remove|list` and returns the confirmation to print.
/// `cmd` is how the user invokes watch on this surface (`seer watch` in the
/// CLI, `watch` in the REPL), for the usage error and the empty-list hint.
pub async fn watch_edit(action: &str, domain: Option<&str>, cmd: &str) -> Result<String, String> {
    let adding = match action {
        "list" => return Ok(watchlist_listing(&load_watchlist().await?, cmd)),
        "add" => true,
        "remove" => false,
        other => {
            return Err(format!(
                "Unknown watch action: {}. Use: add, remove, list",
                other
            ))
        }
    };
    let domain = domain.ok_or_else(|| format!("Usage: {} {} <domain>", cmd, action))?;

    let mut watchlist = load_watchlist().await?;
    let changed = if adding {
        watchlist
            .add(domain)
            .map_err(|e| format!("Invalid domain: {}", e))?
    } else {
        watchlist.remove(domain)
    };
    if changed {
        state_io("save watchlist", move || watchlist.save()).await?;
    }
    Ok(match (adding, changed) {
        (true, true) => format!("Added {} to watchlist", domain.ctp_green()),
        (true, false) => format!("{} is already in the watchlist", domain),
        (false, true) => format!("Removed {} from watchlist", domain.ctp_green()),
        (false, false) => format!("{} was not in the watchlist", domain),
    })
}

/// The `watch list` text, or the empty-watchlist hint (see [`watch_edit`]
/// for `cmd`).
pub fn watchlist_listing(watchlist: &seer_core::Watchlist, cmd: &str) -> String {
    if watchlist.domains.is_empty() {
        return format!(
            "Watchlist is empty. Use '{} add <domain>' to add domains.",
            cmd
        );
    }
    let mut out = format!("Watchlist ({} domains):", watchlist.domains.len());
    for domain in &watchlist.domains {
        out.push_str(&format!("\n  - {}", domain));
    }
    out
}

pub async fn load_history() -> Result<seer_core::LookupHistory, String> {
    state_io("load history", || Ok(seer_core::LookupHistory::load())).await
}

/// Empties `~/.seer/history.toml`.
pub async fn clear_history() -> Result<(), String> {
    state_io("clear history", || {
        let mut history = seer_core::LookupHistory::load();
        history.clear();
        history.save()
    })
    .await
}

/// The `history` listing: one domain's lookups, or a per-domain summary.
/// `lookup_cmd` (`seer lookup` / `lookup`) names the command in the
/// empty-history hint.
pub fn history_listing(
    history: &seer_core::LookupHistory,
    domain: Option<&str>,
    lookup_cmd: &str,
) -> String {
    let Some(domain) = domain else {
        let total: usize = history.entries.values().map(Vec::len).sum();
        if total == 0 {
            return format!(
                "No lookup history. Run '{} <domain>' to build history.",
                lookup_cmd
            );
        }
        let mut out = format!(
            "Lookup history ({} entries across {} domains):",
            total,
            history.entries.len()
        );
        for (domain, entries) in &history.entries {
            out.push_str(&format!("\n  {} ({} entries)", domain, entries.len()));
        }
        return out;
    };

    let entries = history.get(domain);
    if entries.is_empty() {
        return format!("No history for {}", domain);
    }
    let mut out = format!(
        "History for {} ({} entries):",
        domain.ctp_green(),
        entries.len()
    );
    for entry in entries {
        out.push_str(&format!(
            "\n  [{}] via {} - registrar: {}",
            entry.timestamp.format("%Y-%m-%d %H:%M"),
            lookup_source(&entry.result).unwrap_or("availability"),
            entry.result.registrar().unwrap_or_else(|| "—".to_string())
        ));
    }
    out
}

/// Which protocol answered a lookup, or `None` for an availability verdict
/// (neither registry had the domain). Callers pick their own fallback text.
pub fn lookup_source(result: &seer_core::LookupResult) -> Option<&'static str> {
    match result {
        seer_core::LookupResult::Rdap { .. } => Some("RDAP"),
        seer_core::LookupResult::Whois { .. } => Some("WHOIS"),
        seer_core::LookupResult::Available { .. } => None,
    }
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
    // The baseline is the most recent snapshot that carries registration
    // data, so one throttled run recorded with --record does not become the
    // point every later run is compared against.
    let previous = tokio::task::spawn_blocking(move || {
        let history = seer_core::LookupHistory::load();
        seer_core::drift::baseline_snapshot(history.get(&domain_key).iter().map(|e| &e.result))
            .cloned()
    })
    .await
    .ok()
    .flatten();

    let report = match &previous {
        Some(prev) => seer_core::DriftReport::from_lookups(domain, prev, &result),
        None => seer_core::DriftReport::empty(domain),
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
        for (op, _) in BULK_OPS {
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

    #[tokio::test]
    async fn watch_edit_rejects_bad_actions_and_missing_domains_before_io() {
        let err = watch_edit("bogus", Some("a.com"), "watch")
            .await
            .unwrap_err();
        assert!(err.starts_with("Unknown watch action: bogus"), "got: {err}");
        let err = watch_edit("add", None, "seer watch").await.unwrap_err();
        assert_eq!(err, "Usage: seer watch add <domain>");
        let err = watch_edit("remove", None, "watch").await.unwrap_err();
        assert_eq!(err, "Usage: watch remove <domain>");
    }

    #[test]
    fn watchlist_listing_names_the_surface_command_when_empty() {
        let mut watchlist = seer_core::Watchlist::default();
        assert_eq!(
            watchlist_listing(&watchlist, "seer watch"),
            "Watchlist is empty. Use 'seer watch add <domain>' to add domains."
        );
        watchlist.domains = vec!["a.com".into(), "b.com".into()];
        assert_eq!(
            watchlist_listing(&watchlist, "watch"),
            "Watchlist (2 domains):\n  - a.com\n  - b.com"
        );
    }

    #[test]
    fn history_listing_covers_empty_summary_and_per_domain_views() {
        let mut history = seer_core::LookupHistory::default();
        assert_eq!(
            history_listing(&history, None, "lookup"),
            "No lookup history. Run 'lookup <domain>' to build history."
        );
        assert_eq!(
            history_listing(&history, Some("a.com"), "lookup"),
            "No history for a.com"
        );

        let available = seer_core::LookupResult::Available {
            data: Box::new(seer_core::AvailabilityResult {
                domain: "a.com".into(),
                available: true,
                confidence: "high".into(),
                method: "rdap".into(),
                details: None,
            }),
            rdap_error: "404".into(),
            whois_error: "no match".into(),
            whois_data: None,
        };
        history.record("a.com", available);
        assert_eq!(
            history_listing(&history, None, "seer lookup"),
            "Lookup history (1 entries across 1 domains):\n  a.com (1 entries)"
        );
        let listing = history_listing(&history, Some("a.com"), "lookup");
        assert!(listing.contains("(1 entries):"), "got: {listing}");
        assert!(
            listing.ends_with("via availability - registrar: —"),
            "got: {listing}"
        );
    }

    #[test]
    fn no_subdomain_baseline_note_reflects_record_flag() {
        assert!(no_subdomain_baseline_note("a.com", true).contains("recorded one"));
        assert!(no_subdomain_baseline_note("a.com", false).contains("--record"));
    }
}
