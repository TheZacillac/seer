//! Shared command pieces for the CLI subcommands, the interactive REPL and
//! the TUI: the bulk-operation catalog and mapping, domain-list validation,
//! the live `follow` runner, `~/.seer` state I/O, and the drift and
//! subdomain-baseline checks. Before this module existed, `main.rs` and
//! `repl/mod.rs` were two hand-maintained copies of this logic; keeping it
//! here means a new bulk operation or a semantics fix lands in one place and
//! every surface picks it up. The `bulk` command's run itself is
//! [`crate::bulk`]; the watch/history/config commands are [`crate::manage`].

use std::sync::LazyLock;

use seer_core::bulk::BulkOperation;
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
            "No valid domains found. Expected format: one domain per line, \
             # for comments, or CSV (first column)"
                .to_string(),
        );
    }
    if domains.len() > MAX_BULK_DOMAINS {
        return Err(format!(
            "Bulk input contains {} domains, maximum is {}",
            domains.len(),
            MAX_BULK_DOMAINS
        ));
    }
    Ok(domains)
}

/// Runs a live `follow` for the CLI and the REPL: raw mode so Esc / Ctrl-C
/// cancel, and each iteration streamed to stdout as it lands. Raw mode is
/// left by [`RawModeGuard`](crate::utils::RawModeGuard) on return or unwind,
/// and by `main`'s panic hook when `panic = "abort"` skips Drop (issue #60).
/// The key listener is stopped before returning so it cannot swallow
/// keystrokes meant for whatever reads the terminal next. SIGINT cancels
/// too: it is the interrupt path when stdin is not a terminal (raw mode and
/// the key listener are then off), and raw mode never raises it otherwise.
pub async fn run_live_follow(
    follower: &seer_core::DnsFollower,
    domain: &str,
    record_type: RecordType,
    nameserver: Option<&str>,
    config: seer_core::FollowConfig,
    format: seer_core::output::OutputFormat,
) -> seer_core::Result<seer_core::FollowResult> {
    use std::io::Write;

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let sigint = {
        let cancel_tx = cancel_tx.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            let _ = cancel_tx.send(true);
        })
    };

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
    // The SIGINT task goes too, so it cannot outlive this follow.
    sigint.abort();
    if let Some(listener) = key_listener {
        listener.stop().await;
    }
    drop(raw_guard);
    result
}

/// Whether `follow`'s prose (the "Following …" banner and the interrupted
/// note) belongs on stderr: yes for every non-human format, so stdout carries
/// only the formatted iterations and summary and stays machine-parseable.
pub fn follow_notes_to_stderr(format: seer_core::output::OutputFormat) -> bool {
    format != seer_core::output::OutputFormat::Human
}

/// The `follow` command for the CLI and the REPL: the banner, the live
/// follow ([`run_live_follow`]) and its summary. The nameserver falls back to
/// the config file's, like `dig`.
pub async fn follow_command(
    follower: &seer_core::DnsFollower,
    args: crate::dns_args::FollowArgs,
    config: &seer_core::SeerConfig,
    format: seer_core::output::OutputFormat,
) -> Result<(), String> {
    use std::io::Write;

    let follow_config = seer_core::FollowConfig::new(args.iterations, args.interval_minutes)
        .map_err(|e| e.to_string())?
        .with_changes_only(args.changes_only);
    let nameserver = args.nameserver.as_deref().or(config.nameserver.as_deref());

    // The banner is prose, so under a machine format it goes to stderr and
    // stdout stays a parseable stream (`seer --format json follow … | jq`).
    // `\r\n` matches the raw-mode iteration lines that follow.
    let notes_to_stderr = follow_notes_to_stderr(format);
    let banner = format!(
        "Following {} {} records ({} iterations, {} interval)\r\nPress {} or {} to stop early\r\n\r\n",
        args.domain.ctp_green(),
        args.record_type.to_string().ctp_yellow(),
        args.iterations.to_string().ctp_yellow(),
        crate::utils::format_interval(args.interval_minutes),
        "Esc".ctp_yellow(),
        "Ctrl+C".ctp_yellow()
    );
    if notes_to_stderr {
        eprint!("{}", banner);
        let _ = std::io::stderr().flush();
    } else {
        print!("{}", banner);
        let _ = std::io::stdout().flush();
    }

    let result = run_live_follow(
        follower,
        &args.domain,
        args.record_type,
        nameserver,
        follow_config,
        format,
    )
    .await
    .map_err(|e| e.to_string())?;

    if result.interrupted {
        let note = "Follow interrupted by user".ctp_yellow();
        if notes_to_stderr {
            eprintln!("{}", note);
        } else {
            println!("\n{}", note);
        }
    }
    println!(
        "\n{}",
        seer_core::output::get_formatter(format).format_follow(&result)
    );
    Ok(())
}

/// Serializes this process's load→modify→save cycles on the `~/.seer`
/// stores (history, watchlist): two overlapping cycles each save their own
/// snapshot, so the later save silently undoes the earlier one's change.
/// The TUI records history, clears it and edits the watchlist concurrently.
/// Move the guard into the blocking closure, so a cancelled caller cannot
/// release it while the orphaned write still runs.
pub static STORE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Records a lookup result to the `~/.seer` history off the async executor
/// (the file I/O is blocking). The caller decides what a failure means: a
/// plain lookup's history is best-effort and only warns, while `drift
/// --record` fails — recording is the whole point there.
pub async fn record_lookup_history(
    domain: &str,
    result: seer_core::LookupResult,
) -> seer_core::Result<()> {
    let domain = domain.to_string();
    let store = STORE_LOCK.lock().await;
    tokio::task::spawn_blocking(move || {
        let _store = store;
        // An unreadable history is left alone rather than saved over.
        let mut history = seer_core::LookupHistory::load()?;
        history.record(&domain, result);
        history.save()
    })
    .await
    .map_err(|e| seer_core::SeerError::ConfigError(format!("history task failed: {e}")))?
}

/// Runs blocking `~/.seer` state-file I/O off the async executor, folding a
/// failed task into the same `Failed to <what>: …` error as the I/O itself.
pub(crate) async fn state_io<T, F>(what: &str, io: F) -> Result<T, String>
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
    state_io("load watchlist", seer_core::Watchlist::load).await
}

pub async fn load_history() -> Result<seer_core::LookupHistory, String> {
    state_io("load history", seer_core::LookupHistory::load).await
}

/// Empties the `~/.seer` lookup history.
pub async fn clear_history() -> Result<(), String> {
    let store = STORE_LOCK.lock().await;
    state_io("clear history", move || {
        let _store = store;
        let mut history = seer_core::LookupHistory::load()?;
        history.clear();
        history.save()
    })
    .await
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
    // An unreadable history is an error, not "no baseline".
    let previous = tokio::task::spawn_blocking(move || -> seer_core::Result<_> {
        let history = seer_core::LookupHistory::load()?;
        Ok(
            seer_core::drift::baseline_snapshot(history.get(&domain_key).iter().map(|e| &e.result))
                .cloned(),
        )
    })
    .await
    .map_err(|e| seer_core::SeerError::ConfigError(format!("history task failed: {e}")))??;

    finish_drift(
        domain,
        previous,
        result,
        record,
        |domain, result| async move { record_lookup_history(&domain, result).await },
    )
    .await
}

/// The rest of [`drift_check`] once the fresh lookup and the stored baseline
/// are in hand: the report, then — with `record` — the save through `save`.
/// A failed save fails the check (it used to be swallowed while the note
/// still said "recorded a baseline", so every later run compared against a
/// stale snapshot). `save` is a seam so tests need not touch `~/.seer`.
async fn finish_drift<F, Fut>(
    domain: &str,
    previous: Option<seer_core::LookupResult>,
    result: seer_core::LookupResult,
    record: bool,
    save: F,
) -> seer_core::Result<DriftOutcome>
where
    F: FnOnce(String, seer_core::LookupResult) -> Fut,
    Fut: std::future::Future<Output = seer_core::Result<()>>,
{
    let report = match &previous {
        Some(prev) => seer_core::DriftReport::from_lookups(domain, prev, &result),
        None => seer_core::DriftReport::empty(domain),
    };
    if record {
        save(domain.to_string(), result).await?;
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
    config: &seer_core::SeerConfig,
) -> seer_core::Result<SubdomainBaselineOutcome> {
    let enumerator = seer_core::SubdomainEnumerator::from_config(config);
    // `enumerate` normalizes the domain; use `result.domain` as the key so
    // the baseline store and the note agree on the canonical name.
    let result = enumerator.enumerate(domain).await?;

    // Baseline file I/O is blocking — keep it off the async executor.
    let (result, report) = tokio::task::spawn_blocking(move || -> seer_core::Result<_> {
        let mut baselines = seer_core::SubdomainBaselines::load()?;
        let report = baselines.diff(&result.domain, &result.subdomains);
        if record {
            baselines.record(&result);
            baselines.save()?;
        }
        Ok((result, report))
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

    fn available(domain: &str) -> seer_core::LookupResult {
        seer_core::LookupResult::Available {
            data: Box::new(seer_core::AvailabilityResult {
                domain: domain.into(),
                available: true,
                confidence: "high".into(),
                method: "rdap".into(),
                details: None,
            }),
            rdap_error: "404".into(),
            whois_error: "no match".into(),
            whois_data: None,
        }
    }

    /// `drift --record` swallowed a failed history save and still reported
    /// "recorded a baseline"; the error must now fail the check.
    #[tokio::test]
    async fn drift_record_propagates_a_failed_save() {
        let failing = |_: String, _: seer_core::LookupResult| async {
            Err(seer_core::SeerError::ConfigError("disk full".into()))
        };
        let err = finish_drift("a.com", None, available("a.com"), true, failing)
            .await
            .err()
            .expect("a failed save fails the check");
        assert!(err.to_string().contains("disk full"), "{err}");

        // Without --record nothing is saved, so nothing can fail.
        let outcome = finish_drift("a.com", None, available("a.com"), false, failing)
            .await
            .expect("no save attempted");
        assert!(!outcome.had_previous);

        let saved = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = saved.clone();
        let recording = move |domain: String, _: seer_core::LookupResult| async move {
            assert_eq!(domain, "a.com");
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        };
        finish_drift("a.com", None, available("a.com"), true, recording)
            .await
            .expect("saved");
        assert!(saved.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn no_baseline_note_reflects_record_flag() {
        assert!(no_baseline_note("a.com", true).contains("recorded a baseline"));
        assert!(no_baseline_note("a.com", false).contains("--record"));
    }

    /// `seer --format json follow … | jq` broke on the prose banner and the
    /// "interrupted" note written to stdout.
    #[test]
    fn follow_prose_leaves_stdout_for_machine_formats() {
        use seer_core::output::OutputFormat;
        assert!(!follow_notes_to_stderr(OutputFormat::Human));
        for format in [
            OutputFormat::Json,
            OutputFormat::Yaml,
            OutputFormat::Markdown,
        ] {
            assert!(follow_notes_to_stderr(format), "{format:?}");
        }
    }

    #[test]
    fn no_subdomain_baseline_note_reflects_record_flag() {
        assert!(no_subdomain_baseline_note("a.com", true).contains("recorded one"));
        assert!(no_subdomain_baseline_note("a.com", false).contains("--record"));
    }
}
