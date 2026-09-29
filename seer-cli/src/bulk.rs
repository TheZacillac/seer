//! The `bulk` command, run the same way by `seer bulk` and the REPL `bulk`:
//! read and validate the domain list, run it concurrently with a progress
//! bar (and per-item lines as results arrive), then stream JSON/YAML to
//! stdout and/or write the CSV, and summarize. Prose (the banner, progress,
//! the CSV path under a structured format) goes to stderr, so a structured
//! stdout stays one parseable document.

use seer_core::bulk::BulkResult;
use seer_core::colors::CatppuccinExt;
use seer_core::output::OutputFormat;
use seer_core::RecordType;

/// Progress display for a bulk run (`--progress`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "lowercase")]
pub enum ProgressMode {
    /// Progress bar only (default in a TTY)
    Bar,
    /// Progress bar plus a line per completed item, as it completes
    Verbose,
    /// Progress bar plus a line per failure, as it happens; successes silent
    Failures,
    /// No bar, no per-item output (default when piped or when --format json)
    None,
}

/// Resolves the effective progress mode given the user's flag, whether stderr
/// is a TTY, and the output format.
///
/// Rules:
/// - An explicit `--progress <mode>` always wins.
/// - Otherwise `--format json` implies `None` (JSON output must be clean).
/// - Otherwise on a non-TTY stderr, default to `None`.
/// - Otherwise default to `Bar`.
pub fn resolve_progress_mode(
    flag: Option<ProgressMode>,
    stderr_is_tty: bool,
    format: OutputFormat,
) -> ProgressMode {
    if let Some(mode) = flag {
        return mode;
    }
    if format == OutputFormat::Json || !stderr_is_tty {
        return ProgressMode::None;
    }
    ProgressMode::Bar
}

/// One bulk run's arguments, as either surface parsed them.
pub struct BulkRequest {
    /// Operation name as typed (validated by `ops::build_bulk_operations`).
    pub operation: String,
    /// Input file path as typed, or `-` for stdin.
    pub input: String,
    /// Record type for the dig/prop operations.
    pub record_type: RecordType,
    /// Output CSV path from `-o/--output`, as typed.
    pub output: Option<String>,
    pub progress: Option<ProgressMode>,
}

/// How a finished run went.
pub struct BulkTally {
    pub succeeded: usize,
    pub total: usize,
}

impl BulkTally {
    /// Zero successes over a non-empty batch fails the run (see
    /// [`crate::utils::bulk_exit_code`]); partial failures do not.
    pub fn exit_code(&self) -> i32 {
        crate::utils::bulk_exit_code(self.succeeded, self.total)
    }
}

/// Runs a bulk request (see the module docs). Input and usage errors are
/// `Err` before any network I/O; per-domain failures are rows in the result,
/// and listed after the summary unless `--progress` already printed them.
pub async fn run_bulk(
    request: BulkRequest,
    format: OutputFormat,
    config: &seer_core::SeerConfig,
) -> Result<BulkTally, String> {
    let stderr_is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let mode = resolve_progress_mode(request.progress, stderr_is_tty, format);

    // `-` reads a newline/CSV-delimited domain list from stdin so bulk
    // composes with shell pipelines (`grep … | seer bulk status -`); a
    // derived CSV path then uses a synthetic "bulk" stem. `~` is expanded
    // once here so the read and the derived output path agree.
    let from_stdin = request.input == "-";
    let input = if from_stdin {
        "bulk".to_string()
    } else {
        crate::utils::expand_tilde(&request.input)
    };
    // `read_bulk_input` rejects FIFOs, sockets, devices, directories, and
    // oversized files via a pre-read metadata check, so a `mkfifo`'d path
    // can't hang the process; stdin gets the same cap via a bounded read.
    let content = if from_stdin {
        crate::utils::read_bulk_stdin(std::io::stdin().lock())
    } else {
        crate::utils::read_bulk_input(&input)
    }?;
    let domains = crate::ops::parse_bulk_domains(&content)?;
    // Validated before any progress UI exists, so an unknown op can't leave
    // a bar registered.
    let operations =
        crate::ops::build_bulk_operations(&request.operation, &domains, request.record_type)?;

    // A structured format streams the results to stdout — pipeline-friendly
    // and free of the spreadsheet escaping CSV needs; `-o` still writes the
    // CSV too. Everything else about the run is then prose for stderr.
    let structured = matches!(format, OutputFormat::Json | OutputFormat::Yaml);
    let csv_path = bulk_csv_path(request.output.as_deref(), structured, &input);
    let report = |line: &str| {
        if structured {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    };

    eprintln!("{}", bulk_banner(domains.len(), &request.operation));
    let executor = seer_core::BulkExecutor::from_config(config);
    let results = match (mode != ProgressMode::None).then(|| BulkBar::new(operations.len())) {
        Some(bar) => {
            let on_result = bar.on_result(mode);
            let results = executor.execute_streaming(operations, on_result).await;
            drop(bar);
            results
        }
        None => executor.execute(operations, None).await,
    };

    if let Some(rendered) = crate::payload::structured(&results, format) {
        println!("{rendered}");
    }
    if let Some(csv_path) = &csv_path {
        write_bulk_csv(&results, &request.operation, csv_path)?;
        report(&format!("Results written to: {}", csv_path.ctp_green()));
    }
    report(&bulk_summary(&results));
    // Failures already streamed by `--progress verbose|failures` aren't
    // repeated; otherwise they would be visible only inside the CSV/JSON.
    let failures: Vec<&BulkResult> = results.iter().filter(|r| !r.success).collect();
    if !failures.is_empty() && !matches!(mode, ProgressMode::Verbose | ProgressMode::Failures) {
        report(&format!("{}", "Failures:".ctp_red()));
        for result in failures {
            report(&format!(
                "  {} - {}",
                result.operation.domain(),
                result.error.as_deref().unwrap_or("unknown error")
            ));
        }
    }

    Ok(BulkTally {
        succeeded: results.iter().filter(|r| r.success).count(),
        total: results.len(),
    })
}

/// Where a bulk run writes its CSV, or `None` when no CSV is written.
///
/// An explicit `-o/--output` always yields a CSV — including under a
/// structured `--format json|yaml` (flag or config file), which previously
/// ignored `-o` and silently wrote nothing. Without `-o`, structured formats
/// stream to stdout only, and human/markdown default to `<input>_results.csv`.
pub fn bulk_csv_path(
    explicit: Option<&str>,
    structured_output: bool,
    input: &str,
) -> Option<String> {
    match explicit {
        Some(path) => Some(crate::utils::expand_tilde(path)),
        None if structured_output => None,
        None => Some(default_bulk_output_path(input)),
    }
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

/// A bulk run's progress bar, registered with the tracing writer so log lines
/// print above it instead of tearing it. Dropping it unregisters and clears
/// it — also when the run is cancelled (the REPL's Ctrl-C drops the run), so
/// no stale bar stays registered.
struct BulkBar(indicatif::ProgressBar);

impl BulkBar {
    fn new(total: usize) -> Self {
        let bar = indicatif::ProgressBar::new(total as u64);
        bar.set_style(
            indicatif::ProgressStyle::default_bar()
                .template("{bar:40.cyan/blue} {pos}/{len} ({percent}%) eta {eta} {msg}")
                .expect("valid progress bar template")
                .progress_chars("=>-"),
        );
        crate::display::set_bulk_progress_bar(bar.clone());
        Self(bar)
    }

    /// The per-result callback: advances the bar, shows the latest domain,
    /// and prints `mode`'s line for the result as it arrives (through the
    /// bar, so it doesn't tear; `bar_println` falls back to plain stderr when
    /// indicatif hid the bar on a non-TTY stderr).
    fn on_result(&self, mode: ProgressMode) -> seer_core::bulk::ResultCallback {
        let bar = self.0.clone();
        Box::new(move |result: &BulkResult| {
            bar.inc(1);
            bar.set_message(result.operation.domain().to_string());
            if let Some(line) = item_line(mode, result) {
                let _ = crate::display::bar_println(&bar, &line);
            }
        })
    }
}

impl Drop for BulkBar {
    fn drop(&mut self) {
        crate::display::clear_bulk_progress_bar();
        self.0.finish_and_clear();
    }
}

/// The line `mode` prints for one finished result, if any.
fn item_line(mode: ProgressMode, result: &BulkResult) -> Option<String> {
    let domain = result.operation.domain();
    match (mode, result.success) {
        (ProgressMode::Verbose, true) => Some(format!(
            "{} {} ({}ms)",
            "\u{2713}".ctp_green(),
            domain,
            result.duration_ms
        )),
        (ProgressMode::Verbose | ProgressMode::Failures, false) => {
            let err = result.error.as_deref().unwrap_or("unknown error");
            Some(format!("{} {} ({})", "\u{2717}".ctp_red(), domain, err))
        }
        _ => None,
    }
}

/// The "Processing N domains with OP operation..." line printed before a run.
fn bulk_banner(domain_count: usize, op: &str) -> String {
    format!(
        "Processing {} domains with {} operation...",
        domain_count.to_string().ctp_green(),
        op.ctp_yellow()
    )
}

/// Writes a run's CSV atomically, so a crash or full disk mid-write cannot
/// leave a truncated file that downstream pipelines treat as authoritative.
fn write_bulk_csv(results: &[BulkResult], op: &str, path: &str) -> Result<(), String> {
    let csv = crate::utils::bulk_results_to_csv(results, op);
    crate::utils::atomic_write(path, &csv)
        .map_err(|e| format!("Failed to write output file {}: {}", path, e))
}

/// The "  N successful, M failed" line after a run.
fn bulk_summary(results: &[BulkResult]) -> String {
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

/// `seer bulk --help` epilogue: the input formats (shared with the REPL's
/// `bulk -h`), usage examples, and sample output per operation, whose header
/// lines come from the CSV writer itself.
pub fn long_help() -> String {
    let mut help = format!(
        "\nInput File Formats:\n{}\n{}",
        crate::ops::BULK_INPUT_FORMATS,
        BULK_EXAMPLES
    );
    for (op, rows) in SAMPLE_OUTPUT {
        help.push_str(&format!(
            "\nExample Output ({op} operation):\n  {}\n",
            crate::utils::bulk_csv_header(op)
        ));
        for row in *rows {
            help.push_str(&format!("  {row}\n"));
        }
    }
    help
}

const BULK_EXAMPLES: &str = "Example Usage:
  seer bulk status domains.txt              # Output: domains_results.csv
  seer bulk lookup domains.csv              # Output: domains_results.csv
  seer bulk dig domains.txt MX              # Output: domains_results.csv
  seer bulk ssl domains.txt -o out.csv      # Output: out.csv
  grep -v staging domains.txt | seer bulk avail -
  seer --format json bulk caa domains.txt   # JSON array on stdout, no CSV
";

/// Sample CSV rows per operation for [`long_help`], each row matching the
/// operation's header (pinned by a test). `info` is too wide for a row.
const SAMPLE_OUTPUT: &[(&str, &[&str])] = &[
    (
        "status",
        &["example.com,true,200,OK,Example Domain,DigiCert Inc,2027-01-15,108,2027-08-13,318,\
           RESERVED-Internet Assigned Numbers Authority,true,93.184.215.14,\
           2606:2800:21f:cb07:6820:80da:af6b:8b2c,,a.iana-servers.net;b.iana-servers.net,1245,"],
    ),
    (
        "lookup",
        &[
            "example.com,true,RESERVED-Internet Assigned Numbers Authority,1995-08-14,2027-08-13,\
             2026-08-14,523,,",
            "google.com,true,MarkMonitor Inc.,1997-09-15,2028-09-14,2019-09-09,412,,",
        ],
    ),
    (
        "dig",
        &[
            "example.com,true,A,93.184.215.14,45,",
            "google.com,true,MX,10 smtp.google.com.,38,",
        ],
    ),
    (
        "avail",
        &[
            "nonexistent-seer-123.com,true,true,high,rdap,No RDAP object; domain unregistered,1523,",
            "google.com,true,false,high,rdap,Domain is registered (status: client delete prohibited),412,",
        ],
    ),
    ("info", &[]),
    (
        "ssl",
        &["example.com,true,CN=*.example.com,\"C=US, O=DigiCert Inc, CN=DigiCert Global G3 TLS ECC \
           SHA384 2020 CA1\",2026-01-15,2027-01-15,108,ecdsa-with-SHA384,EC,256,2,2,\
           *.example.com;example.com,TLSv1.3,true,612,"],
    ),
    (
        "posture",
        &["example.com,true,strict,-,strict,reject,absent,absent,absent,,842,"],
    ),
    (
        "confusables",
        &["example.com,true,214,180,2,examp1e.com(homoglyph);exampel.com(transposition),9214,"],
    ),
    (
        "caa",
        &["example.com,true,true,example.com,letsencrypt.org;digicert.com,,\
           mailto:security@example.com,,133,"],
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use seer_core::bulk::BulkOperation;

    #[test]
    fn explicit_mode_is_honored_whatever_the_terminal_or_format() {
        for (flag, tty, format) in [
            (ProgressMode::Verbose, true, OutputFormat::Human),
            (ProgressMode::None, true, OutputFormat::Human),
            (ProgressMode::Bar, false, OutputFormat::Human),
            (ProgressMode::Bar, true, OutputFormat::Json),
        ] {
            assert_eq!(resolve_progress_mode(Some(flag), tty, format), flag);
        }
    }

    #[test]
    fn default_is_a_bar_only_on_a_tty_without_json() {
        assert_eq!(
            resolve_progress_mode(None, true, OutputFormat::Human),
            ProgressMode::Bar
        );
        assert_eq!(
            resolve_progress_mode(None, false, OutputFormat::Human),
            ProgressMode::None
        );
        assert_eq!(
            resolve_progress_mode(None, true, OutputFormat::Json),
            ProgressMode::None
        );
    }

    fn result(domain: &str, error: Option<&str>) -> BulkResult {
        BulkResult {
            operation: BulkOperation::Avail {
                domain: domain.into(),
            },
            success: error.is_none(),
            data: None,
            error: error.map(Into::into),
            duration_ms: 12,
        }
    }

    /// `--progress verbose|failures` printed its per-item lines only after
    /// the whole batch; they now come from the per-result callback. Each
    /// mode's line for a result:
    #[test]
    fn per_item_lines_follow_the_mode() {
        let ok = result("ok.example", None);
        let bad = result("bad.example", Some("timed out"));
        let verbose_ok = item_line(ProgressMode::Verbose, &ok).expect("a line");
        assert!(verbose_ok.contains("ok.example (12ms)"), "{verbose_ok}");
        for mode in [ProgressMode::Verbose, ProgressMode::Failures] {
            let line = item_line(mode, &bad).expect("a line");
            assert!(line.contains("bad.example (timed out)"), "{line}");
        }
        assert_eq!(item_line(ProgressMode::Failures, &ok), None);
        assert_eq!(item_line(ProgressMode::Bar, &bad), None);
    }

    /// The callback the executor streams results into advances the bar as
    /// each result lands, not after the batch.
    #[test]
    fn the_result_callback_advances_the_bar_per_result() {
        let bar = BulkBar(indicatif::ProgressBar::hidden());
        bar.0.set_length(2);
        let on_result = bar.on_result(ProgressMode::Bar);
        on_result(&result("a.example", None));
        assert_eq!(bar.0.position(), 1);
        assert_eq!(bar.0.message(), "a.example");
        on_result(&result("b.example", Some("boom")));
        assert_eq!(bar.0.position(), 2);
    }

    /// `-o` under a structured format (flag or config-file default) was
    /// computed but ignored: no CSV, exit 0.
    #[test]
    fn explicit_output_writes_csv_even_for_structured_formats() {
        for structured in [true, false] {
            assert_eq!(
                bulk_csv_path(Some("out.csv"), structured, "domains.txt").as_deref(),
                Some("out.csv")
            );
        }
    }

    #[test]
    fn default_csv_only_for_human_style_formats() {
        assert_eq!(bulk_csv_path(None, true, "domains.txt"), None);
        assert_eq!(
            bulk_csv_path(None, false, "domains.txt").as_deref(),
            Some("domains_results.csv")
        );
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

    /// Splits one CSV line into fields, honoring double quotes.
    fn csv_fields(line: &str) -> usize {
        let (mut fields, mut quoted) = (1, false);
        for c in line.chars() {
            match c {
                '"' => quoted = !quoted,
                ',' if !quoted => fields += 1,
                _ => {}
            }
        }
        fields
    }

    /// The help's header lines used to be hand-copied (info's abbreviated
    /// with `...`) from the CSV writer; they are now generated from it, and
    /// every sample row must still fit its header.
    #[test]
    fn sample_rows_match_the_generated_headers() {
        for (op, rows) in SAMPLE_OUTPUT {
            assert!(
                crate::ops::bulk_operation_for(op, String::new(), RecordType::A).is_some(),
                "{op} is not a bulk operation"
            );
            let header = crate::utils::bulk_csv_header(op);
            for row in *rows {
                assert_eq!(csv_fields(row), csv_fields(&header), "{op}: {row}");
            }
        }
        let help = long_help();
        assert!(help.contains(&crate::utils::bulk_csv_header("info")));
    }
}
