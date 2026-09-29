mod bulk;
mod clipboard;
mod dig_args;
mod display;
mod dns_args;
mod manage;
mod ops;
mod payload;
mod query;
mod repl;
mod tui;
mod utils;

use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use payload::Payload;
use query::Query;
use seer_core::colors::CatppuccinExt;
use seer_core::output::OutputFormat;
use utils::machine_error;

/// Severity threshold for `seer watch`'s non-zero exit (`--fail-on`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "lowercase")]
enum FailOn {
    /// Exit 1 when any issue is reported (warnings or critical)
    Warning,
    /// Exit 1 only when critical issues are reported
    Critical,
}

/// `seer dig`'s usage lines: the dig-style form, shared with the REPL, and
/// the `-x` reverse form.
fn dig_usage() -> String {
    format!(
        "seer dig [OPTIONS] {}\n       seer dig [OPTIONS] -x <IP>",
        dig_args::USAGE
    )
}

/// `seer dig --help` epilogue: [`DIG_EXAMPLES`], then the record types.
fn dig_long_help() -> String {
    format!("{}\nRecord types: {}\n", DIG_EXAMPLES, *VALID_RECORD_TYPES)
}

const DIG_EXAMPLES: &str = r#"Examples:
  seer dig example.com                    # A records (the default type)
  seer dig example.com A AAAA MX          # several types, queried concurrently
  seer dig @1.1.1.1 example.com MX        # ask one nameserver (also -s 1.1.1.1)
  seer dig example.com HTTPS +short       # values only, one per line
  seer dig -x 8.8.8.8                     # reverse lookup (PTR)
  seer dig www.example.com +trace         # walk down from the root servers
  seer dig _sip._tcp.example.com SRV      # SRV names take _service._proto.name
  seer dig example.com '*'                # ANY: the common types, fanned out
  seer --format json dig example.com      # the result object (an array for several types)
  seer --fields status,answers.name dig example.com
"#;

/// `seer compare`'s usage line, from the grammar the REPL shares.
fn compare_usage() -> String {
    format!("seer compare {}", dns_args::COMPARE_USAGE)
}

/// `seer follow`'s usage line, from the grammar the REPL shares.
fn follow_usage() -> String {
    format!("seer follow [OPTIONS] {}", dns_args::FOLLOW_USAGE)
}

/// `--format`'s parser: core's names and aliases, so a typo (`jsno`) is a
/// usage error instead of silently printing human output.
fn parse_output_format(value: &str) -> Result<OutputFormat, String> {
    value.parse()
}

#[derive(Parser)]
#[command(name = "seer")]
#[command(about = "Domain name helper - WHOIS, RDAP, DIG, and propagation checking")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Output format: human, json, yaml, or markdown (also text, yml, md).
    /// Defaults to the config file's `output_format`, or "human"
    #[arg(short, long, value_parser = parse_output_format)]
    format: Option<OutputFormat>,

    /// Quiet mode - suppress headers and formatting, output the result as
    /// compact JSON (or just the --fields)
    #[arg(short, long)]
    quiet: bool,

    /// Comma-separated list of fields to print, one value per line (implies
    /// --quiet). Dotted paths reach nested values (certificate.issuer),
    /// numeric segments index arrays (answers.0.name), and a name applied to
    /// a list extracts it from every element (e.g. `--fields
    /// status,answers.name dig example.com`). On a list result (`dig` with
    /// several types) the fields print element by element, unless a path
    /// starts with an index (1.status)
    #[arg(long, value_delimiter = ',')]
    fields: Option<Vec<String>>,
}

#[derive(Subcommand)]
enum Commands {
    /// Smart lookup (tries RDAP first, falls back to WHOIS)
    Lookup {
        /// Domain name to look up
        domain: String,
    },
    /// Comprehensive domain info (merges RDAP + WHOIS into flat fields)
    Info {
        /// Domain name to look up
        domain: String,
    },
    /// Look up WHOIS information for a domain
    Whois {
        /// Domain name to look up
        domain: String,
    },
    /// Look up RDAP information for a domain, IP, or ASN
    Rdap {
        /// Domain, IP address, or ASN (e.g., AS15169)
        query: String,
    },
    /// Query DNS records (like dig)
    ///
    /// Takes dig-style arguments in any order: the name, one or more record
    /// types, `@server`, and `+short` / `+trace`. Reports the response
    /// status (NOERROR, NXDOMAIN, SERVFAIL, …) and header flags, the CNAME
    /// chain with every record under its real owner name, and whether a
    /// wildcard answers for the name's siblings. NXDOMAIN (the name does not
    /// exist) is told apart from NODATA (it exists, but has no records of
    /// the type).
    ///
    /// Not check-style: like dig, it exits 0 whenever a server answered —
    /// NXDOMAIN, NODATA and SERVFAIL are results — and 1 on invalid input,
    /// a refused `@server`, a timeout or other transport failure, when any
    /// of several types failed (the others are still printed), or when a
    /// `+short` trace stopped early (its error goes to stderr).
    #[command(override_usage = dig_usage(), after_long_help = dig_long_help())]
    Dig {
        /// The name to query, record types, `@server`, `+short` and
        /// `+trace`, in any order (e.g. `@1.1.1.1 example.com A AAAA
        /// +short`). A token without a dot that names a type is a type (`*`
        /// is ANY); the default is A. To query a name that spells a type
        /// (the `mx` zone), write it with its trailing dot (`mx.`)
        #[arg(value_name = "ARGS")]
        args: Vec<String>,
        /// Nameserver to query (same as `@server`): `IP/host[:port]` (UDP),
        /// `tls://host[:port]` (DoT), or `https://host[/path]` (DoH) — e.g.
        /// `8.8.8.8`, `tls://1.1.1.1`, `https://cloudflare-dns.com/dns-query`
        #[arg(short, long)]
        server: Option<String>,
        /// Print only the record values, one per line (same as `+short`).
        /// A plain-text mode: it ignores --format and cannot be combined
        /// with -q/--fields
        #[arg(long)]
        short: bool,
        /// Walk the delegation from the root servers down to the
        /// authoritative server, one hop per zone (same as `+trace`). Takes
        /// one record type and no nameserver
        #[arg(long)]
        trace: bool,
        /// Reverse lookup: the PTR record of this IP address (like dig -x)
        #[arg(short = 'x', long, value_name = "IP")]
        reverse: Option<String>,
    },
    /// Check DNS propagation across global servers
    Prop {
        /// Domain name to check
        domain: String,
        /// Record type to check
        #[arg(default_value = "A")]
        record_type: String,
    },
    /// Execute bulk operations from a file, output results to CSV.
    /// CSV output includes anti-formula protection for spreadsheets; use `--format json`
    /// for programmatic consumption without spreadsheet escaping.
    #[command(after_long_help = bulk::long_help())]
    Bulk {
        #[arg(
            value_name = "OPERATION",
            help = format!("Operation type: {}", *ops::BULK_OPS_SUMMARY)
        )]
        operation: String,

        /// Input file path (text or CSV format), or `-` to read the domain
        /// list from stdin (e.g. `grep … | seer bulk status -`)
        #[arg(value_name = "FILE")]
        file: String,

        /// Record type for dig/prop operations
        #[arg(value_name = "TYPE", default_value = "A")]
        record_type: String,

        /// Output CSV file path (defaults to <input>_results.csv)
        #[arg(short, long, value_name = "OUTPUT")]
        output: Option<String>,

        /// Progress display mode for bulk runs
        #[arg(long, value_enum)]
        progress: Option<bulk::ProgressMode>,
    },
    /// Check domain status (HTTP, SSL cert, registration expiration)
    Status {
        /// Domain name to check
        domain: String,
    },
    /// Monitor DNS records over time
    ///
    /// Arguments come in any order, read by their shape: the domain, up to
    /// two numbers — the number of checks (default 10), then the minutes
    /// between them (default 1; decimals allowed, e.g. 0.5 for 30 seconds; a
    /// decimal is always the interval) — a record type (default A), and
    /// `@server`.
    #[command(override_usage = follow_usage())]
    Follow {
        /// The domain, [iterations] [interval_minutes], [type] and
        /// [@server], in any order (e.g. `example.com 20 0.5 MX @1.1.1.1`)
        #[arg(value_name = "ARGS")]
        args: Vec<String>,
        /// Nameserver to query (same as `@server`): `IP/host[:port]` (UDP),
        /// `tls://host[:port]` (DoT), or `https://host[/path]` (DoH) — e.g.
        /// `8.8.8.8`, `tls://1.1.1.1`, `https://cloudflare-dns.com/dns-query`
        #[arg(short, long)]
        server: Option<String>,
        /// Only show output when records change
        #[arg(long)]
        changes_only: bool,
    },
    /// Reverse DNS lookup for an IP address
    Reverse {
        /// IP address to look up (IPv4 or IPv6)
        ip: String,
    },
    /// Check if a domain is available for registration
    Avail {
        /// Domain name to check
        domain: String,
    },
    /// Check DNSSEC configuration for a domain
    Dnssec {
        /// Domain name to check
        domain: String,
    },
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Show or initialize configuration
    Config {
        /// Initialize default config file at ~/.seer/config.toml
        #[arg(long)]
        init: bool,
    },
    /// Generate a random API key for seer-api / MCP Streamable HTTP
    ///
    /// Plain mode prints just the token, so you can capture it:
    ///   KEY=$(seer generate-key)
    /// `--export` prints a shell line ready for `eval`:
    ///   eval "$(seer generate-key --export)"
    GenerateKey {
        /// Print as `export SEER_API_KEY=...` for shell `eval`
        #[arg(long)]
        export: bool,
        /// Number of random bytes, 1-4096 (default: 32 = 256 bits of entropy)
        #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u16).range(1..=4096))]
        bytes: u16,
    },
    /// Inspect SSL certificate chain for a domain
    Ssl {
        /// Domain name to check
        domain: String,
    },
    /// Look up TLD information (WHOIS server, RDAP endpoint, registry)
    Tld {
        /// TLD to look up (e.g., .com, com, .uk)
        tld: String,
    },
    /// Compare DNS records from two nameservers
    ///
    /// Arguments come in any order: the domain (the first bare word), two
    /// nameservers — `@server`, or bare after the domain — and a record type
    /// (default A). Nameservers are `IP/host[:port]` (UDP), `tls://host`
    /// (DoT) or `https://host/path` (DoH). Check-style: exits 1 when the two
    /// servers disagree.
    #[command(override_usage = compare_usage())]
    Compare {
        /// The domain, two nameservers and [type], in any order (e.g.
        /// `example.com 8.8.8.8 1.1.1.1 MX` or `example.com MX @8.8.8.8
        /// @tls://1.1.1.1`)
        #[arg(value_name = "ARGS")]
        args: Vec<String>,
    },
    /// Enumerate subdomains via Certificate Transparency logs
    ///
    /// With --diff, compares the fresh enumeration against the stored
    /// baseline and exits 1 when NEW names appeared (removals are reported
    /// but non-fatal — CT logs are append-mostly, so a vanished name usually
    /// means source flakiness). A first run with no baseline exits 0.
    Subdomains {
        /// Domain to enumerate subdomains for
        domain: String,
        /// Resolve each discovered name and classify live/dead + dangling-CNAME
        /// takeover risk
        #[arg(long)]
        resolve: bool,
        /// Diff the fresh enumeration against the stored baseline (exits 1
        /// when new names appeared)
        #[arg(long, conflicts_with = "resolve")]
        diff: bool,
        /// Record the fresh enumeration as the new baseline after reporting
        /// (usable alone or with --diff)
        #[arg(long, conflicts_with = "resolve")]
        record: bool,
    },
    /// Compare two domains side-by-side (registration, DNS, SSL)
    Diff {
        /// First domain
        domain_a: String,
        /// Second domain
        domain_b: String,
    },
    /// Monitor domain watchlist for expiration and health issues
    ///
    /// The check-all form (`seer watch` with no action) exits 1 when the
    /// report contains issues at or above the `--fail-on` threshold
    /// (default: critical), and 0 otherwise — so it can gate cron jobs and
    /// CI checks like `drift` does. `add`/`remove`/`list` exit 0 on success.
    Watch {
        /// Subcommand: add, remove, list (or omit to check all)
        action: Option<String>,
        /// Domains for add/remove (one or more)
        #[arg(value_name = "DOMAIN")]
        domains: Vec<String>,
        /// Severity threshold for a non-zero exit when checking all domains
        #[arg(long, value_enum, default_value_t = FailOn::Critical)]
        fail_on: FailOn,
        /// POST the check-all report as JSON to this webhook URL (overrides
        /// the config file's `watch.webhook_url`). Delivery is best-effort:
        /// a failed POST prints a stderr warning but never changes the
        /// check's exit code.
        #[arg(long, value_name = "URL")]
        webhook: Option<String>,
    },
    /// Show lookup history for a domain
    History {
        /// Domain to show history for (omit to show all)
        domain: Option<String>,
        /// Clear all history
        #[arg(long, conflicts_with = "domain")]
        clear: bool,
    },
    /// Detect drift versus the previous stored lookup for a domain
    ///
    /// Compares a fresh lookup against the most recent history snapshot and
    /// reports changed fields (nameservers, registrar, expiry, DNSSEC,
    /// registrant). Exits non-zero when material drift is found.
    Drift {
        /// Domain to check for drift
        domain: String,
        /// Record the fresh lookup to history after comparing (establishes or
        /// updates the baseline); a failed save fails the command
        #[arg(long)]
        record: bool,
    },
    /// Look up the CAA (Certification Authority Authorization) policy
    Caa {
        /// Domain to look up
        domain: String,
    },
    /// Inspect email/DNS security posture (SPF, DMARC, MTA-STS, BIMI, DANE)
    Posture {
        /// Domain to inspect
        domain: String,
    },
    /// Audit HTTP security headers, cookie flags, and version disclosure
    ///
    /// Issues one non-intrusive GET and grades the response: security headers
    /// (HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy,
    /// Permissions-Policy, COOP/COEP/CORP), Set-Cookie flags, and
    /// version-disclosing banners, as a 0-100 score and a letter grade.
    Headers {
        /// Domain to audit
        domain: String,
    },
    /// Scan subdomains for takeover exposure, confirmed over HTTP
    ///
    /// Enumerates subdomains via Certificate Transparency logs, then checks
    /// each one whose CNAME points at a takeover-prone provider. A host that
    /// serves the provider's unclaimed-resource page is reported VULNERABLE
    /// with the matched fingerprint as evidence; a dangling CNAME that does
    /// not resolve is reported as potential (nothing answered to confirm it).
    /// Check-style command: exits 1 when any host is vulnerable or potential.
    Takeover {
        /// Domain to scan (e.g. example.com)
        domain: String,
        /// Scan these hosts instead of enumerating via CT logs (repeatable)
        #[arg(long = "host", value_name = "HOST")]
        hosts: Vec<String>,
    },
    /// Find registered typosquat / look-alike domains for a domain
    Confusables {
        /// Domain to generate and score look-alikes for
        domain: String,
    },
    /// Diagnose the seer environment (config, DNS, WHOIS, RDAP reachability)
    ///
    /// Runs four checks — config file parse, DNS resolution, WHOIS port-43
    /// reachability, and RDAP bootstrap HTTPS — and reports PASS/WARN/FAIL
    /// per check. Exits 1 only when a check FAILs; WARN (degraded but
    /// usable, e.g. a malformed config running on defaults) still exits 0.
    Doctor,
    /// Check NS delegation health (parent delegation vs zone NS, lame servers)
    ///
    /// Compares the parent zone's delegation NS set against the zone's own
    /// authoritative NS RRset and probes each delegated server for lameness.
    /// Check-style command: exits 1 when the sets are out of sync or any
    /// delegated server answers lamely, 0 when the delegation is healthy.
    Delegation {
        /// Domain to check (e.g. example.com)
        domain: String,
    },
    /// Generate man pages for seer and all subcommands into a directory
    #[command(hide = true)]
    Mangen {
        /// Output directory (created if missing)
        dir: std::path::PathBuf,
    },
    /// Launch the full-screen interactive TUI
    Tui {
        /// Optional domain to look up on launch
        domain: Option<String>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    // First, so no panic leaves crossterm's raw mode on, even under the dist
    // profile's panic = "abort", which skips RawModeGuard's Drop.
    utils::install_raw_mode_panic_hook();

    // Initialize tracing with progress-aware writer.
    // Routes log output through the progress bar when one is active,
    // preventing logs from interfering with progress bar display.
    // Respects ARCANUM_LOG_LEVEL, ARCANUM_LOG_FORMAT, ARCANUM_LOG_FILE env vars.
    // Every path below returns to here — none calls `process::exit` — so this
    // guard drops and flushes buffered log lines before the process ends.
    let _log_guard = seer_core::logging::init_logging_with_writer(
        "seer",
        "error",
        display::ProgressWriterFactory::new(),
    );

    let cli = Cli::parse();

    // Load the user config once: it provides the default output format plus the
    // per-protocol timeouts, nameserver, and bulk settings threaded into the
    // command handlers below.
    let config = seer_core::SeerConfig::load();

    let (format, result) = match cli.command {
        Some(command) => {
            let format = cli
                .format
                .unwrap_or_else(|| config_output_format(&config.output_format));
            let output = Output::new(format, cli.quiet, cli.fields);
            (format, execute_command(command, &output, &config).await)
        }
        None => {
            // Start the interactive REPL. An explicit `--format` becomes its
            // initial output format (as if `set output <fmt>` was typed);
            // without one the REPL keeps the config file's default.
            let format = cli.format.unwrap_or_default();
            let result = async {
                let mut repl = repl::Repl::new()?;
                if let Some(format) = cli.format {
                    repl.set_output_format(format);
                }
                repl.run().await
            }
            .await
            .map(|()| 0)
            .map_err(Failure::from);
            (format, result)
        }
    };
    match result {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(failure) => {
            print_error(format, &failure.0);
            ExitCode::FAILURE
        }
    }
}

/// A failed command: `main` prints it in `--format`'s error form and exits
/// 1. Anything displayable converts, so `?` works on every error type here.
#[derive(Debug)]
struct Failure(String);

impl<E: std::fmt::Display> From<E> for Failure {
    fn from(e: E) -> Self {
        Self(e.to_string())
    }
}

/// The config file's `output_format`, or the default when it is empty. A
/// value that names no format warns on stderr and falls back rather than
/// failing: unlike `--format` it isn't typed per invocation, so a typo there
/// must not break every command — but it must not pass silently either.
pub(crate) fn config_output_format(configured: &str) -> OutputFormat {
    parse_config_format(configured).unwrap_or_else(|warning| {
        eprintln!("{} {}", "Warning:".ctp_yellow(), warning);
        OutputFormat::default()
    })
}

/// [`config_output_format`] without the side effect: the format, or the
/// warning to print.
fn parse_config_format(configured: &str) -> Result<OutputFormat, String> {
    if configured.trim().is_empty() {
        return Ok(OutputFormat::default());
    }
    configured
        .parse()
        .map_err(|e| format!("config file output_format: {e} (using human)"))
}

/// How one-shot mode prints a result: the global `--format`, `-q` and
/// `--fields` (which implies `-q`).
struct Output {
    format: OutputFormat,
    quiet: bool,
    fields: Option<Vec<String>>,
}

impl Output {
    fn new(format: OutputFormat, quiet: bool, fields: Option<Vec<String>>) -> Self {
        Self {
            format,
            // `--fields` selects from the quiet JSON; alone it used to be
            // silently ignored.
            quiet: quiet || fields.is_some(),
            fields,
        }
    }

    /// Prints a single-shot result.
    fn show_payload(&self, payload: &Payload) {
        if self.quiet {
            handle_quiet_output(payload, &self.fields);
        } else {
            println!("{}", payload::serialize(payload, self.format));
        }
    }

    /// Prints a local-state command's result (watch, history, config).
    fn show_listing(&self, listing: &manage::Listing) {
        if self.quiet {
            handle_quiet_output(&listing.data, &self.fields);
        } else {
            println!("{}", listing.render(self.format));
        }
    }
}

/// Resolves a dotted field path (`certificate.issuer`) against `value`,
/// collecting every match into `out`. A numeric segment indexes an array
/// (`records.0.name`); any other segment applied to an array fans out over
/// its elements, so `--fields name` on a record list yields one value per
/// record. A path that does not resolve contributes a single `Null`.
fn resolve_field_path<'a>(
    value: &'a serde_json::Value,
    parts: &[&str],
    out: &mut Vec<&'a serde_json::Value>,
) {
    use serde_json::Value;
    let Some((part, rest)) = parts.split_first() else {
        out.push(value);
        return;
    };
    match value {
        Value::Object(map) => match map.get(*part) {
            Some(next) => resolve_field_path(next, rest, out),
            None => out.push(&Value::Null),
        },
        Value::Array(items) => match part.parse::<usize>() {
            Ok(index) => match items.get(index) {
                Some(next) => resolve_field_path(next, rest, out),
                None => out.push(&Value::Null),
            },
            Err(_) => {
                for item in items {
                    resolve_field_path(item, parts, out);
                }
            }
        },
        _ => out.push(&Value::Null),
    }
}

/// Renders the requested fields of a JSON value as output lines, one per
/// resolved value (see [`resolve_field_path`] for the path syntax). Strings
/// print bare, a missing field prints an empty line, anything else as JSON.
///
/// On a list root (a multi-type `dig`), the fields are extracted element by
/// element, so each element's values stay together — unless a path starts
/// with an index (`1.status`), which picks elements itself.
fn extract_field_lines(value: &serde_json::Value, fields: &[String]) -> Vec<String> {
    if let serde_json::Value::Array(items) = value {
        let indexes_the_list = fields.iter().any(|field| {
            field
                .split('.')
                .next()
                .is_some_and(|first| first.parse::<usize>().is_ok())
        });
        if !indexes_the_list {
            return items
                .iter()
                .flat_map(|item| extract_field_lines(item, fields))
                .collect();
        }
    }
    let mut lines = Vec::new();
    for field in fields {
        let parts: Vec<&str> = field.split('.').collect();
        let mut matches = Vec::new();
        resolve_field_path(value, &parts, &mut matches);
        lines.extend(matches.into_iter().map(|v| match v {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Null => String::new(),
            other => other.to_string(),
        }));
    }
    lines
}

/// Quiet (`-q`) output: the requested `--fields` one per line, or the whole
/// result as compact JSON.
fn handle_quiet_output<T: serde::Serialize>(value: &T, fields: &Option<Vec<String>>) {
    if let Some(ref fields) = fields {
        let json_value = serde_json::to_value(value).unwrap_or_default();
        for line in extract_field_lines(&json_value, fields) {
            println!("{}", line);
        }
    } else {
        let json = serde_json::to_string(value).unwrap_or_default();
        println!("{}", json);
    }
}

/// Prints a format-appropriate error to stderr, so scripted consumers of
/// `--format json|yaml` get structured output instead of ANSI-colored prose
/// when a command fails.
fn print_error(format: OutputFormat, msg: &str) {
    match machine_error(format, msg) {
        Some(structured) => eprintln!("{}", structured),
        None => eprintln!("{} {}", "Error:".ctp_red(), msg),
    }
}

/// Every name `RecordType::from_str` accepts, for error messages —
/// `SeerError::InvalidRecordType` names only the offending input.
///
/// Rendered from `RecordType::ALL_NAMES` rather than re-typed, so it cannot
/// advertise a type core rejects (or omit one it accepts). `LazyLock` because
/// joining needs an allocation a `const` can't do; only the error path and
/// the drift test read it.
pub(crate) static VALID_RECORD_TYPES: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| seer_core::RecordType::ALL_NAMES.join(", "));

/// Parses a DNS record type, extending the core error with the list of valid
/// types. A typo must surface as a visible error, never silently fall back to
/// A records. Shared with the REPL, which maps the error to `CommandResult`.
pub(crate) fn try_parse_record_type(s: &str) -> Result<seer_core::RecordType, String> {
    s.parse::<seer_core::RecordType>()
        .map_err(|e| format!("{} (valid types: {})", e, *VALID_RECORD_TYPES))
}

/// Runs a subcommand and returns its exit code. Single-shot queries share
/// [`query::run`] with the REPL and render through the one path at the end;
/// the other subcommands (bulk, follow, watchlist/history management, local
/// utilities) run their own bodies. Failures return as [`Failure`] — nothing
/// here exits the process — and every argument error is caught before any
/// network I/O.
async fn execute_command(
    command: Commands,
    output: &Output,
    config: &seer_core::SeerConfig,
) -> Result<i32, Failure> {
    let format = output.format;
    let query = match command {
        Commands::Lookup { domain } => Query::Lookup(domain),
        Commands::Info { domain } => Query::Info(domain),
        Commands::Whois { domain } => Query::Whois(domain),
        Commands::Rdap { query } => Query::Rdap(query),
        Commands::Dig {
            args,
            server,
            short,
            trace,
            reverse,
        } => {
            let flags = dig_args::DigFlags {
                server,
                short,
                trace,
                reverse,
            };
            dig_query(&args, flags, output.quiet, output.fields.is_some())?
        }
        Commands::Prop {
            domain,
            record_type,
        } => Query::Prop {
            domain,
            record_type: try_parse_record_type(&record_type)?,
        },
        Commands::Status { domain } => Query::Status(domain),
        Commands::Reverse { ip } => Query::Reverse(ip),
        Commands::Avail { domain } => Query::Avail(domain),
        Commands::Dnssec { domain } => Query::Dnssec(domain),
        Commands::Ssl { domain } => Query::Ssl(domain),
        Commands::Tld { tld } => Query::Tld(tld),
        Commands::Compare { args } => dns_args::parse_compare(&args)?.into_query(),
        Commands::Subdomains {
            domain,
            resolve,
            diff,
            record,
        } => Query::Subdomains {
            domain,
            resolve,
            diff,
            record,
        },
        Commands::Diff { domain_a, domain_b } => Query::Diff(domain_a, domain_b),
        Commands::Drift { domain, record } => Query::Drift { domain, record },
        Commands::Caa { domain } => Query::Caa(domain),
        Commands::Posture { domain } => Query::Posture(domain),
        Commands::Headers { domain } => Query::Headers(domain),
        Commands::Takeover { domain, hosts } => Query::Takeover { domain, hosts },
        Commands::Confusables { domain } => Query::Confusables(domain),
        Commands::Doctor => Query::Doctor,
        Commands::Delegation { domain } => Query::Delegation(domain),
        Commands::Bulk {
            operation,
            file,
            record_type,
            output: csv,
            progress,
        } => {
            let request = bulk::BulkRequest {
                operation,
                input: file,
                record_type: try_parse_record_type(&record_type)?,
                output: csv,
                progress,
            };
            // A run with zero successes is a total failure (network down,
            // every domain malformed) — scripted callers gate on $?.
            return Ok(bulk::run_bulk(request, format, config).await?.exit_code());
        }
        Commands::Follow {
            args,
            server,
            changes_only,
        } => {
            let flags = dns_args::FollowFlags {
                server,
                changes_only,
            };
            let args = dns_args::parse_follow(&args, flags)?;
            // Honor the config file's DNS timeout like `dig` does.
            let follower = seer_core::DnsFollower::from_config(config);
            ops::follow_command(&follower, args, config, format).await?;
            return Ok(0);
        }
        Commands::Watch {
            action,
            domains,
            fail_on,
            webhook,
        } => return watch_command(action, &domains, fail_on, webhook, output, config).await,
        Commands::History { domain, clear } => {
            output.show_listing(&manage::history(domain.as_deref(), clear, "seer lookup").await?);
            return Ok(0);
        }
        Commands::Config { init } => {
            let listing = if init {
                manage::config_init()?
            } else {
                manage::config_show(config)
            };
            output.show_listing(&listing);
            return Ok(0);
        }
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            generate(shell, &mut cmd, "seer", &mut std::io::stdout());
            return Ok(0);
        }
        Commands::GenerateKey { export, bytes } => {
            use base64::Engine;

            // clap bounds `--bytes` to 1..=4096 (a usage error, exit 2).
            let mut buf = vec![0u8; usize::from(bytes)];
            // Fill with OS entropy directly via getrandom — the CSPRNG source
            // that rand's OsRng merely wraps. It's the right primitive for key
            // material and immune to rand's RNG-trait churn across versions.
            getrandom::fill(&mut buf).map_err(|e| format!("OS RNG unavailable: {e}"))?;
            let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&buf);
            if export {
                println!("export SEER_API_KEY={}", token);
            } else {
                println!("{}", token);
            }
            return Ok(0);
        }
        Commands::Mangen { dir } => {
            std::fs::create_dir_all(&dir)?;
            // Renders seer.1 plus one page per (non-hidden) subcommand,
            // recursively — `mangen` itself is hidden and skipped.
            clap_mangen::generate_to(Cli::command(), &dir)?;
            println!(
                "Man pages written to: {}",
                dir.display().to_string().ctp_green()
            );
            return Ok(0);
        }
        Commands::Tui { domain } => {
            tui::run(domain).await?;
            return Ok(0);
        }
    };

    let spin = cli_spinner(&query);
    let clients = query::Clients::from_config(config);
    let outcome = query::run(query, &clients, config, spin).await?;
    outcome.present(format, |payload| output.show_payload(payload));
    Ok(outcome_exit_code(&outcome))
}

/// `seer watch`: `add`/`remove`/`list` edit or show the watchlist; with no
/// action, every watched domain is checked, the report is (optionally)
/// POSTed to the webhook, and the exit code follows `--fail-on`.
async fn watch_command(
    action: Option<String>,
    domains: &[String],
    fail_on: FailOn,
    webhook: Option<String>,
    output: &Output,
    config: &seer_core::SeerConfig,
) -> Result<i32, Failure> {
    if let Some(action) = action {
        output.show_listing(&manage::watch_edit(&action, domains, "seer watch").await?);
        return Ok(0);
    }
    let report = match manage::watch_check(config, "seer watch").await? {
        manage::WatchCheck::Empty(listing) => {
            output.show_listing(&listing);
            return Ok(0);
        }
        manage::WatchCheck::Report(report) => report,
    };
    output.show_payload(&Payload::Watch(report.clone()));
    // Best-effort webhook delivery of the report: the --webhook flag
    // overrides the config file's watch.webhook_url. A failed POST warns on
    // stderr but never alters the check's exit code below.
    if let Some(url) = webhook.as_deref().or(config.watch.webhook_url.as_deref()) {
        let client = seer_core::webhook::WebhookClient::from_config(config);
        if let Err(e) = client.post_json(url, &report).await {
            eprintln!("{} webhook delivery failed: {}", "Warning:".ctp_yellow(), e);
        }
    }
    // Exit 1 when issues at or above the --fail-on threshold exist (mirrors
    // drift/avail/dnssec). `warnings` counts every result with issues, so it
    // already subsumes the critical ones; the `||` keeps the check robust if
    // that tally ever changes.
    let failed = match fail_on {
        FailOn::Critical => report.critical > 0,
        FailOn::Warning => report.warnings > 0 || report.critical > 0,
    };
    Ok(i32::from(failed))
}

/// Whether one-shot mode shows a progress spinner for `query`. The REPL spins
/// for every networked query; one-shot mode only ever has for these slower,
/// multi-stage ones, and keeps stderr quiet for the rest.
fn cli_spinner(query: &Query) -> bool {
    matches!(
        query,
        Query::Lookup(_)
            | Query::Info(_)
            | Query::Subdomains { .. }
            | Query::Drift { .. }
            | Query::Headers(_)
            | Query::Takeover { .. }
            | Query::Confusables(_)
            | Query::Diff(..)
            | Query::Doctor
            | Query::Delegation(_)
            | Query::Trace { .. }
    )
}

/// `seer dig`'s query: its dig-style arguments merged with the flags clap
/// parsed (see [`dig_args`]), and `--short` checked against `-q`/`--fields`.
fn dig_query(
    args: &[String],
    flags: dig_args::DigFlags,
    quiet: bool,
    fields: bool,
) -> Result<Query, String> {
    let dig = dig_args::parse(args, flags)?;
    check_short_output(dig.short, quiet, fields)?;
    Ok(dig.into_query())
}

/// `--short` is a plain-text output mode of its own (bare values, whatever
/// `--format` says), while `-q`/`--fields` select from the JSON result — so
/// asking for both is a usage error rather than one silently winning.
fn check_short_output(short: bool, quiet: bool, fields: bool) -> Result<(), String> {
    if short && (quiet || fields) {
        return Err(
            "+short/--short prints bare values, so it cannot be combined with -q/--fields \
             (which select from the JSON result)"
                .to_string(),
        );
    }
    Ok(())
}

/// The process exit code for a finished query: 1 when part of it failed
/// (a type of a multi-type `dig`, or the walk of a `+short` trace),
/// otherwise [`exit_code`] of its result.
fn outcome_exit_code(outcome: &query::Outcome) -> i32 {
    if outcome.failed() {
        1
    } else {
        exit_code(&outcome.payload)
    }
}

/// Process exit code for a query's result: check-style commands exit 1 when
/// the check fails, everything else 0. This is a scripting contract (cron
/// jobs and CI gate on `$?`), so every rule is pinned by a test.
fn exit_code(payload: &Payload) -> i32 {
    let failed = match payload {
        // Unhealthy: no 2xx answer, an invalid or <30-day certificate, or a
        // registration expiring within 30 days.
        Payload::Status(s) => {
            s.http_status.is_none_or(|code| !(200..300).contains(&code))
                || s.certificate
                    .as_ref()
                    .is_some_and(|c| !c.is_valid || c.days_until_expiry < 30)
                || s.domain_expiration
                    .as_ref()
                    .is_some_and(|d| d.days_until_expiry < 30)
        }
        Payload::Avail(a) => !a.available,
        // Core's vocabulary is signed | unsigned | partial | misconfigured —
        // it never says "secure", so only "signed" passes.
        Payload::Dnssec(r) => r.status != "signed",
        Payload::Compare(c) => !c.matches,
        Payload::Drift(d) => d.has_drift(),
        // Any confirmed or potential takeover is actionable.
        Payload::Takeover(t) => t.has_findings(),
        // Only ADDED names are material; removals and a first run pass.
        Payload::SubdomainBaselineDiff(d) => d.has_new_names(),
        // Only FAIL is fatal; WARN (degraded but usable) exits 0.
        Payload::Doctor(r) => r.overall == seer_core::doctor::CheckStatus::Fail,
        // Lame servers already veto in_sync; the explicit check keeps the
        // contract if that coupling ever changes.
        Payload::Delegation(d) => !d.in_sync || !d.lame.is_empty(),
        // Not check-style, like dig: an answered query is a result whatever
        // its status (NXDOMAIN, SERVFAIL), and a trace reports where it
        // stopped. Failed queries are errors, which exit 1 on their own.
        Payload::Dig(_) | Payload::DigMany(_) | Payload::Trace(_) => false,
        _ => false,
    };
    i32::from(failed)
}

/// Renders a doctor report in the requested output format. Shared with the
/// REPL `doctor` command so both surfaces present diagnostics identically.
/// Human output mirrors the summary style of sibling commands (Catppuccin
/// status colors); markdown is a simple inline table since no
/// `OutputFormatter` method exists for doctor reports.
pub(crate) fn render_doctor_report(
    report: &seer_core::doctor::DoctorReport,
    format: OutputFormat,
) -> String {
    use colored::Colorize as _;
    use seer_core::doctor::CheckStatus;

    match format {
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
        OutputFormat::Yaml => seer_core::output::YamlFormatter::new().to_yaml_value(report),
        OutputFormat::Markdown => {
            let mut out = String::from(
                "# Doctor Report\n\n| Check | Status | Latency | Detail |\n|---|---|---|---|\n",
            );
            for check in &report.checks {
                let latency = check
                    .latency_ms
                    .map(|ms| format!("{}ms", ms))
                    .unwrap_or_else(|| "—".to_string());
                // Escape pipes so a probe error message can't break the table.
                let detail = check.detail.replace('|', "\\|");
                out.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    check.name, check.status, latency, detail
                ));
            }
            out.push_str(&format!("\n**Overall:** {}\n", report.overall));
            out
        }
        OutputFormat::Human => {
            let status_str = |s: CheckStatus| match s {
                CheckStatus::Pass => "PASS".ctp_green().bold().to_string(),
                CheckStatus::Warn => "WARN".ctp_yellow().bold().to_string(),
                CheckStatus::Fail => "FAIL".ctp_red().bold().to_string(),
            };
            let mut out = format!("{}\n\n", "Doctor Report".sky().bold());
            for check in &report.checks {
                let latency = check
                    .latency_ms
                    .map(|ms| format!(" ({}ms)", ms))
                    .unwrap_or_default();
                out.push_str(&format!(
                    "  {} {:<16} {}{}\n",
                    status_str(check.status),
                    check.name,
                    check.detail,
                    latency
                ));
            }
            out.push_str(&format!("\nOverall: {}", status_str(report.overall)));
            out
        }
    }
}

#[cfg(test)]
mod compare_follow_cli_tests {
    //! `seer compare` / `seer follow` argv through clap into the grammars
    //! the REPL shares (tested in full in `dns_args`).
    use super::{dns_args, Cli, Commands, Query};
    use clap::Parser;
    use seer_core::RecordType;

    fn compare(argv: &[&str]) -> Result<Query, String> {
        let cli = Cli::try_parse_from(["seer", "compare"].iter().chain(argv).copied())
            .map_err(|e| e.to_string())?;
        let Some(Commands::Compare { args }) = cli.command else {
            panic!("expected Compare command");
        };
        dns_args::parse_compare(&args).map(dns_args::CompareArgs::into_query)
    }

    /// The documented positional form keeps working, and the REPL's `@`
    /// form now works on the command line too.
    #[test]
    fn compare_accepts_the_positional_and_at_forms() {
        for (argv, want) in [
            (&["example.com", "8.8.8.8", "1.1.1.1"][..], RecordType::A),
            (&["example.com", "8.8.8.8", "1.1.1.1", "MX"], RecordType::MX),
            (
                &["example.com", "MX", "@8.8.8.8", "@1.1.1.1"],
                RecordType::MX,
            ),
        ] {
            let Ok(Query::Compare {
                domain,
                record_type,
                server_a,
                server_b,
            }) = compare(argv)
            else {
                panic!("{argv:?} should parse");
            };
            assert_eq!(domain, "example.com");
            assert_eq!(record_type, want, "{argv:?}");
            assert_eq!(
                (server_a.as_str(), server_b.as_str()),
                ("8.8.8.8", "1.1.1.1")
            );
        }
        let err = compare(&["example.com", "8.8.8.8"])
            .err()
            .expect("one server");
        assert!(err.contains("two nameservers"), "{err}");
    }

    #[test]
    fn follow_merges_clap_flags_into_the_grammar() {
        let cli = Cli::try_parse_from([
            "seer",
            "follow",
            "example.com",
            "5",
            "0.5",
            "MX",
            "-s",
            "1.1.1.1",
            "--changes-only",
        ])
        .expect("follow parses");
        let Some(Commands::Follow {
            args,
            server,
            changes_only,
        }) = cli.command
        else {
            panic!("expected Follow command");
        };
        let got = dns_args::parse_follow(
            &args,
            dns_args::FollowFlags {
                server,
                changes_only,
            },
        )
        .expect("valid");
        assert_eq!(got.domain, "example.com");
        assert_eq!((got.iterations, got.interval_minutes), (5, 0.5));
        assert_eq!(got.record_type, RecordType::MX);
        assert_eq!(got.nameserver.as_deref(), Some("1.1.1.1"));
        assert!(got.changes_only);
    }
}

#[cfg(test)]
mod dig_cli_tests {
    //! `seer dig` argv → [`Query`]: clap's flags merged with the dig-style
    //! tokens by the parser the REPL shares (tested in full in `dig_args`).
    use super::{dig_query, Cli, Commands, Query};
    use clap::Parser;
    use seer_core::RecordType;

    /// Parses `seer <argv…>` down to the dig query, as `execute_command`
    /// does, with the global `-q`/`--fields`.
    fn query(argv: &[&str]) -> Result<Query, String> {
        let cli = Cli::try_parse_from(std::iter::once("seer").chain(argv.iter().copied()))
            .map_err(|e| e.to_string())?;
        let Some(Commands::Dig {
            args,
            server,
            short,
            trace,
            reverse,
        }) = cli.command
        else {
            panic!("expected Dig command");
        };
        let flags = super::dig_args::DigFlags {
            server,
            short,
            trace,
            reverse,
        };
        dig_query(&args, flags, cli.quiet, cli.fields.is_some())
    }

    #[test]
    fn positional_tokens_and_flags_interleave() {
        for argv in [
            &["dig", "@1.1.1.1", "example.com", "A", "MX", "+short"][..],
            &["dig", "example.com", "--short", "A", "-s", "1.1.1.1", "MX"],
            &[
                "dig",
                "-s",
                "@1.1.1.1",
                "A",
                "example.com",
                "MX",
                "A",
                "--short",
            ],
        ] {
            let Ok(Query::Dig {
                name,
                types,
                server,
                short,
            }) = query(argv)
            else {
                panic!("{argv:?} should be a dig query");
            };
            assert_eq!(name, "example.com", "{argv:?}");
            assert_eq!(types, vec![RecordType::A, RecordType::MX], "{argv:?}");
            assert_eq!(server.as_deref(), Some("1.1.1.1"), "{argv:?}");
            assert!(short, "{argv:?}");
        }
    }

    #[test]
    fn defaults_reverse_and_trace() {
        assert!(matches!(
            query(&["dig", "example.com"]),
            Ok(Query::Dig { ref name, ref types, server: None, short: false })
                if name == "example.com" && types == &[RecordType::A]
        ));
        assert!(matches!(
            query(&["dig", "-x", "2001:db8::1"]),
            Ok(Query::Dig { ref name, ref types, .. })
                if name == "2001:db8::1" && types == &[RecordType::PTR]
        ));
        assert!(matches!(
            query(&["dig", "--reverse", "192.0.2.1", "+short"]),
            Ok(Query::Dig { short: true, .. })
        ));
        for argv in [
            &["dig", "--trace", "www.example.com", "AAAA"][..],
            &["dig", "www.example.com", "AAAA", "+trace"],
        ] {
            assert!(
                matches!(
                    query(argv),
                    Ok(Query::Trace { ref name, record_type: RecordType::AAAA, short: false })
                        if name == "www.example.com"
                ),
                "{argv:?}"
            );
        }
        assert!(matches!(
            query(&["dig", "example.com", "--trace", "--short"]),
            Ok(Query::Trace {
                record_type: RecordType::A,
                short: true,
                ..
            })
        ));
    }

    #[test]
    fn flag_conflicts_are_usage_errors() {
        for (argv, problem) in [
            (&["dig"][..], "no name to query"),
            (
                &["dig", "--trace", "-s", "8.8.8.8", "example.com"],
                "root servers",
            ),
            (
                &["dig", "--trace", "example.com", "A", "MX"],
                "one record type",
            ),
            (
                &["dig", "-s", "8.8.8.8", "@1.1.1.1", "example.com"],
                "one nameserver",
            ),
            (&["dig", "-x", "8.8.8.8", "example.com"], "one name"),
            (&["dig", "-x", "not-an-ip"], "-x needs an IP address"),
            (&["dig", "example.com", "+tcp"], "unknown dig option '+tcp'"),
        ] {
            let err = query(argv).err().expect("must be rejected");
            assert!(err.contains(problem), "{argv:?}: {err}");
        }
    }

    /// `--short` prints bare values whatever `--format` says, but `-q` and
    /// `--fields` select from the JSON result: asking for both is an error.
    #[test]
    fn short_conflicts_with_quiet_and_fields_but_not_format() {
        for argv in [
            &["-q", "dig", "example.com", "+short"][..],
            &["--fields", "status", "dig", "example.com", "--short"],
            &["-q", "--fields", "status", "dig", "example.com", "+short"],
        ] {
            let err = query(argv).err().expect("must be rejected");
            assert!(err.contains("-q/--fields"), "{argv:?}: {err}");
        }
        assert!(query(&["--format", "json", "dig", "example.com", "+short"]).is_ok());
        assert!(query(&["-q", "--fields", "status", "dig", "example.com"]).is_ok());
    }
}

#[cfg(test)]
mod feature_suite_cli_tests {
    use super::{Cli, Commands};
    use clap::Parser;

    #[test]
    fn doctor_parses_with_no_args() {
        let cli = Cli::try_parse_from(["seer", "doctor"]).expect("doctor should parse");
        assert!(matches!(cli.command, Some(Commands::Doctor)));
    }

    #[test]
    fn delegation_requires_a_domain() {
        assert!(Cli::try_parse_from(["seer", "delegation"]).is_err());
        let cli = Cli::try_parse_from(["seer", "delegation", "example.com"])
            .expect("delegation should parse");
        let Some(Commands::Delegation { domain }) = cli.command else {
            panic!("expected Delegation command");
        };
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn headers_requires_a_domain() {
        assert!(Cli::try_parse_from(["seer", "headers"]).is_err());
        let cli =
            Cli::try_parse_from(["seer", "headers", "example.com"]).expect("headers should parse");
        let Some(Commands::Headers { domain }) = cli.command else {
            panic!("expected Headers command");
        };
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn takeover_requires_a_domain_and_defaults_to_ct_enumeration() {
        assert!(Cli::try_parse_from(["seer", "takeover"]).is_err());
        let cli = Cli::try_parse_from(["seer", "takeover", "example.com"])
            .expect("takeover should parse");
        let Some(Commands::Takeover { domain, hosts }) = cli.command else {
            panic!("expected Takeover command");
        };
        assert_eq!(domain, "example.com");
        // No --host means enumerate via CT logs.
        assert!(hosts.is_empty());
    }

    #[test]
    fn takeover_host_flag_is_repeatable() {
        let cli = Cli::try_parse_from([
            "seer",
            "takeover",
            "example.com",
            "--host",
            "a.example.com",
            "--host",
            "b.example.com",
        ])
        .expect("takeover --host should parse");
        let Some(Commands::Takeover { hosts, .. }) = cli.command else {
            panic!("expected Takeover command");
        };
        assert_eq!(hosts, vec!["a.example.com", "b.example.com"]);
    }

    #[test]
    fn watch_webhook_flag_parses_and_defaults_to_none() {
        let cli = Cli::try_parse_from([
            "seer",
            "watch",
            "--webhook",
            "https://hooks.example.com/seer",
        ])
        .expect("watch --webhook should parse");
        let Some(Commands::Watch { webhook, .. }) = cli.command else {
            panic!("expected Watch command");
        };
        assert_eq!(webhook.as_deref(), Some("https://hooks.example.com/seer"));

        let cli = Cli::try_parse_from(["seer", "watch"]).expect("bare watch should parse");
        let Some(Commands::Watch { webhook, .. }) = cli.command else {
            panic!("expected Watch command");
        };
        assert_eq!(webhook, None);
    }

    #[test]
    fn mangen_parses_and_is_hidden_from_help() {
        let cli = Cli::try_parse_from(["seer", "mangen", "/tmp/man"]).expect("mangen parses");
        let Some(Commands::Mangen { dir }) = cli.command else {
            panic!("expected Mangen command");
        };
        assert_eq!(dir, std::path::PathBuf::from("/tmp/man"));

        // Hidden: the subcommand must not appear in --help output.
        use clap::CommandFactory;
        let mut help = Vec::new();
        Cli::command()
            .write_long_help(&mut help)
            .expect("help renders");
        let help = String::from_utf8(help).expect("utf8 help");
        assert!(
            !help.contains("mangen"),
            "mangen should be hidden from help"
        );
    }

    /// Smoke test: mangen generates seer.1 plus per-subcommand pages into a
    /// fresh directory (hermetic — pure file I/O, no network).
    #[test]
    fn mangen_generates_root_and_subcommand_pages() {
        use clap::CommandFactory;
        let dir = std::env::temp_dir().join(format!(
            "seer-mangen-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("create tempdir");

        clap_mangen::generate_to(Cli::command(), &dir).expect("man generation succeeds");

        assert!(dir.join("seer.1").is_file(), "root page seer.1 missing");
        assert!(
            dir.join("seer-lookup.1").is_file(),
            "subcommand page seer-lookup.1 missing"
        );
        assert!(
            dir.join("seer-doctor.1").is_file(),
            "subcommand page seer-doctor.1 missing"
        );
        // Hidden subcommands get no page.
        assert!(
            !dir.join("seer-mangen.1").exists(),
            "hidden mangen must not get a man page"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup tempdir");
    }
}

#[cfg(test)]
mod doctor_render_tests {
    use super::render_doctor_report;
    use seer_core::doctor::{CheckStatus, DoctorCheck, DoctorReport};
    use seer_core::output::OutputFormat;

    fn sample_report() -> DoctorReport {
        DoctorReport::from_checks(vec![
            DoctorCheck {
                name: "config".into(),
                status: CheckStatus::Pass,
                detail: "using built-in defaults".into(),
                latency_ms: None,
            },
            DoctorCheck {
                name: "dns".into(),
                status: CheckStatus::Fail,
                detail: "query timed out | resolver unreachable".into(),
                latency_ms: Some(5000),
            },
        ])
    }

    #[test]
    fn human_output_lists_checks_and_overall() {
        let out = render_doctor_report(&sample_report(), OutputFormat::Human);
        assert!(out.contains("config"));
        assert!(out.contains("PASS"));
        assert!(out.contains("FAIL"));
        assert!(out.contains("5000ms"));
        assert!(out.contains("Overall:"));
    }

    #[test]
    fn json_output_round_trips_through_serde() {
        let out = render_doctor_report(&sample_report(), OutputFormat::Json);
        let parsed: DoctorReport = serde_json::from_str(&out).expect("valid JSON report");
        assert_eq!(parsed.overall, CheckStatus::Fail);
        assert_eq!(parsed.checks.len(), 2);
    }

    #[test]
    fn markdown_output_is_a_table_with_escaped_pipes() {
        let out = render_doctor_report(&sample_report(), OutputFormat::Markdown);
        assert!(out.starts_with("# Doctor Report"));
        assert!(out.contains("| config | PASS |"));
        // The pipe inside the detail must be escaped so the table stays valid.
        assert!(out.contains("timed out \\| resolver"));
        assert!(out.contains("**Overall:** FAIL"));
    }

    #[test]
    fn yaml_output_is_non_empty() {
        let out = render_doctor_report(&sample_report(), OutputFormat::Yaml);
        assert!(out.contains("overall"));
    }
}

#[cfg(test)]
mod record_type_parse_tests {
    use super::try_parse_record_type;

    #[test]
    fn parses_valid_types_case_insensitively() {
        assert_eq!(
            try_parse_record_type("mx").unwrap(),
            seer_core::RecordType::MX
        );
        assert_eq!(
            try_parse_record_type("AAAA").unwrap(),
            seer_core::RecordType::AAAA
        );
    }

    /// A typo'd type previously fell back to A silently (bulk dig/prop
    /// returned A answers for a user who asked for MX). The error must name
    /// the bad input and list the valid types, since the core error doesn't.
    #[test]
    fn invalid_type_error_names_input_and_lists_valid_types() {
        let err = try_parse_record_type("MXX").unwrap_err();
        assert!(err.contains("MXX"), "error should name the input: {err}");
        assert!(
            err.contains("AAAA") && err.contains("SSHFP"),
            "error should list valid types: {err}"
        );
    }

    /// Guards `VALID_RECORD_TYPES` against drifting from
    /// `RecordType::from_str` — a renamed or removed core type would
    /// otherwise leave the error message advertising a name that no
    /// longer parses.
    #[test]
    fn valid_types_list_stays_parseable() {
        for name in super::VALID_RECORD_TYPES.split(", ") {
            assert!(
                try_parse_record_type(name).is_ok(),
                "VALID_RECORD_TYPES lists {name}, which no longer parses"
            );
        }
    }
}

#[cfg(test)]
mod exit_code_tests {
    //! The check-style exit contract, one rule per payload. Every check
    //! pairs a passing and a failing result so a flipped condition fails.
    use super::{exit_code, Payload};
    use chrono::TimeZone;

    fn dnssec(status: &str) -> Payload {
        Payload::Dnssec(Box::new(seer_core::DnssecReport {
            domain: "example.com".into(),
            enabled: status != "unsigned",
            has_ds_records: false,
            has_dnskey_records: false,
            ds_records: vec![],
            dnskey_records: vec![],
            issues: vec![],
            status: status.into(),
            chain_valid: status == "signed",
            authentication_tier: seer_core::dns::AuthenticationTier::DigestOnly,
        }))
    }

    /// Core never reports "secure" — the CLI once compared against it, so a
    /// correctly signed zone always exited 1.
    #[test]
    fn only_a_signed_zone_passes_dnssec() {
        assert_eq!(exit_code(&dnssec("signed")), 0);
        for status in ["unsigned", "partial", "misconfigured", "secure"] {
            assert_eq!(exit_code(&dnssec(status)), 1, "{status} must fail");
        }
    }

    fn status(http: Option<u16>, cert_days: Option<i64>, expiry_days: Option<i64>) -> Payload {
        let at = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut s = seer_core::StatusResponse::new("example.com".into());
        s.http_status = http;
        s.certificate = cert_days.map(|days| seer_core::CertificateInfo {
            issuer: "CA".into(),
            subject: "example.com".into(),
            valid_from: at,
            valid_until: at,
            days_until_expiry: days,
            is_valid: days > 0,
            hostname_verified: true,
        });
        s.domain_expiration = expiry_days.map(|days| seer_core::DomainExpiration {
            expiration_date: at,
            days_until_expiry: days,
            registrar: None,
        });
        Payload::Status(Box::new(s))
    }

    #[test]
    fn status_fails_on_non_2xx_or_expiry_within_30_days() {
        assert_eq!(exit_code(&status(Some(200), Some(90), Some(365))), 0);
        assert_eq!(exit_code(&status(Some(204), None, None)), 0);
        assert_eq!(exit_code(&status(None, Some(90), Some(365))), 1);
        assert_eq!(exit_code(&status(Some(503), Some(90), Some(365))), 1);
        assert_eq!(exit_code(&status(Some(200), Some(29), Some(365))), 1);
        assert_eq!(exit_code(&status(Some(200), Some(-1), Some(365))), 1);
        assert_eq!(exit_code(&status(Some(200), Some(90), Some(29))), 1);
    }

    #[test]
    fn avail_compare_drift_and_takeover_fail_on_their_finding() {
        let avail = |available| {
            Payload::Avail(Box::new(seer_core::AvailabilityResult {
                domain: "example.com".into(),
                available,
                confidence: "high".into(),
                method: "rdap".into(),
                details: None,
            }))
        };
        assert_eq!(exit_code(&avail(true)), 0);
        assert_eq!(exit_code(&avail(false)), 1);

        let compare = |matches| {
            let side = |ns: &str| seer_core::dns::ServerResult {
                nameserver: ns.into(),
                status: Some(seer_core::DnsStatus::NoError),
                cname_chain: vec![],
                records: vec![],
                error: None,
            };
            Payload::Compare(Box::new(seer_core::DnsComparison {
                domain: "example.com".into(),
                record_type: seer_core::RecordType::A,
                server_a: side("8.8.8.8"),
                server_b: side("1.1.1.1"),
                matches,
                only_in_a: vec![],
                only_in_b: vec![],
                common: vec![],
            }))
        };
        assert_eq!(exit_code(&compare(true)), 0);
        assert_eq!(exit_code(&compare(false)), 1);

        let mut drift = seer_core::DriftReport::empty("example.com");
        assert_eq!(exit_code(&Payload::Drift(Box::new(drift.clone()))), 0);
        drift.changes.push(seer_core::FieldChange {
            field: "registrar".into(),
            old: Some("A".into()),
            new: Some("B".into()),
        });
        assert_eq!(exit_code(&Payload::Drift(Box::new(drift))), 1);

        let takeover = |vulnerable, potential| {
            Payload::Takeover(Box::new(seer_core::TakeoverReport {
                domain: "example.com".into(),
                hosts_checked: 3,
                hosts_skipped: 0,
                vulnerable,
                potential,
                inconclusive: 0,
                findings: vec![],
                notes: vec![],
            }))
        };
        assert_eq!(exit_code(&takeover(0, 0)), 0);
        assert_eq!(exit_code(&takeover(1, 0)), 1);
        assert_eq!(exit_code(&takeover(0, 1)), 1);
    }

    #[test]
    fn subdomain_diff_fails_only_on_added_names() {
        let diff = |added: &[&str], removed: &[&str], baseline_missing| {
            Payload::SubdomainBaselineDiff(Box::new(seer_core::SubdomainBaselineDiff {
                domain: "example.com".into(),
                baseline_recorded_at: None,
                added: added.iter().map(|s| s.to_string()).collect(),
                removed: removed.iter().map(|s| s.to_string()).collect(),
                unchanged_count: 1,
                baseline_missing,
                baseline_truncated: false,
            }))
        };
        assert_eq!(exit_code(&diff(&[], &[], true)), 0, "first run");
        assert_eq!(exit_code(&diff(&[], &["old.example.com"], false)), 0);
        assert_eq!(exit_code(&diff(&["new.example.com"], &[], false)), 1);
    }

    #[test]
    fn doctor_fails_only_on_fail_and_delegation_on_drift_or_lameness() {
        use seer_core::doctor::{CheckStatus, DoctorCheck, DoctorReport};
        let doctor = |status| {
            Payload::Doctor(Box::new(DoctorReport::from_checks(vec![DoctorCheck {
                name: "dns".into(),
                status,
                detail: String::new(),
                latency_ms: None,
            }])))
        };
        assert_eq!(exit_code(&doctor(CheckStatus::Pass)), 0);
        assert_eq!(exit_code(&doctor(CheckStatus::Warn)), 0);
        assert_eq!(exit_code(&doctor(CheckStatus::Fail)), 1);

        let delegation = |in_sync, lame: Vec<seer_core::dns::LameNs>| {
            Payload::Delegation(Box::new(seer_core::dns::DelegationReport {
                domain: "example.com".into(),
                parent_zone: "com".into(),
                parent_server_queried: vec![],
                delegated_ns: vec![],
                zone_ns: vec![],
                in_sync,
                missing_from_zone: vec![],
                missing_from_parent: vec![],
                lame,
                warnings: vec![],
            }))
        };
        let lame = || {
            vec![seer_core::dns::LameNs {
                host: "ns1.example.com".into(),
                reason: "REFUSED".into(),
            }]
        };
        assert_eq!(exit_code(&delegation(true, vec![])), 0);
        assert_eq!(exit_code(&delegation(false, vec![])), 1);
        assert_eq!(exit_code(&delegation(true, lame())), 1);
    }

    #[test]
    fn informational_results_exit_zero() {
        assert_eq!(exit_code(&Payload::Reverse(vec![])), 0);
    }

    /// Like dig, an answered query exits 0 whatever its status: NXDOMAIN,
    /// NODATA and SERVFAIL are results. So does a trace that stopped early.
    #[test]
    fn dig_and_trace_are_not_check_style() {
        use crate::payload::fixtures;
        use seer_core::{DnsStatus, RecordType};
        for status in [
            DnsStatus::NoError,
            DnsStatus::NxDomain,
            DnsStatus::ServFail,
            DnsStatus::Refused,
        ] {
            let result = fixtures::dig_status(RecordType::A, status);
            assert_eq!(exit_code(&Payload::Dig(Box::new(result.clone()))), 0);
            assert_eq!(exit_code(&Payload::DigMany(vec![result])), 0);
        }
        let stopped = fixtures::trace(vec![], Some("every server of seer.test. failed"));
        assert_eq!(exit_code(&Payload::Trace(Box::new(stopped))), 0);
        let answered = fixtures::trace(vec![fixtures::a("www.seer.test", "192.0.2.7")], None);
        assert_eq!(exit_code(&Payload::Trace(Box::new(answered))), 0);
    }

    /// `+short` leaves a stopped trace's error out of its (empty) values,
    /// so it goes to stderr and the command exits 1 — else a script could
    /// not tell a failed walk from a name with no records.
    #[test]
    fn a_stopped_trace_exits_one_only_when_short() {
        use crate::payload::fixtures;
        use crate::query::trace_outcome;
        let stopped = || fixtures::trace(vec![], Some("every server of seer.test. failed"));
        assert_eq!(super::outcome_exit_code(&trace_outcome(stopped(), true)), 1);
        assert_eq!(
            super::outcome_exit_code(&trace_outcome(stopped(), false)),
            0
        );
        let answered = fixtures::trace(vec![fixtures::a("www.seer.test", "192.0.2.7")], None);
        assert_eq!(super::outcome_exit_code(&trace_outcome(answered, true)), 0);
    }

    /// A multi-type dig with a failed type still prints the rest, but the
    /// command failed: exit 1. A clean run keeps the payload's code.
    #[test]
    fn a_partly_failed_dig_exits_one() {
        use crate::payload::fixtures;
        use seer_core::{DnsStatus, RecordType, SeerError};
        let outcome = crate::query::dig_outcome(vec![
            (
                RecordType::A,
                Ok(fixtures::dig_status(RecordType::A, DnsStatus::NxDomain)),
            ),
            (
                RecordType::MX,
                Err(SeerError::DnsError("MX lookup failed: timed out".into())),
            ),
        ])
        .expect("one type answered");
        assert_eq!(super::outcome_exit_code(&outcome), 1);

        let outcome = crate::query::dig_outcome(vec![(
            RecordType::A,
            Ok(fixtures::dig_status(RecordType::A, DnsStatus::ServFail)),
        )])
        .expect("answered");
        assert_eq!(super::outcome_exit_code(&outcome), 0);
    }
}
#[cfg(test)]
mod quiet_fields_tests {
    use super::extract_field_lines;
    use serde_json::json;

    fn fields(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    /// `-q --fields name reverse …` (then also `dig`) printed blank lines
    /// because the record-list root (an array) resolved every path to Null.
    #[test]
    fn field_path_applies_to_each_array_element() {
        let records = json!([
            {"name": "example.com", "ttl": 300},
            {"name": "www.example.com", "ttl": 60}
        ]);
        assert_eq!(
            extract_field_lines(&records, &fields(&["name"])),
            vec!["example.com", "www.example.com"]
        );
    }

    #[test]
    fn numeric_segments_index_arrays() {
        let value = json!({"records": [{"data": {"address": "1.2.3.4"}}, {"data": {"address": "5.6.7.8"}}]});
        assert_eq!(
            extract_field_lines(&value, &fields(&["records.1.data.address"])),
            vec!["5.6.7.8"]
        );
        assert_eq!(
            extract_field_lines(&json!(["a", "b"]), &fields(&["0"])),
            vec!["a"]
        );
        // Out-of-range index behaves like a missing field: one empty line.
        assert_eq!(
            extract_field_lines(&json!(["a"]), &fields(&["5"])),
            vec![""]
        );
    }

    /// `seer dig` is one result object: its fields and a fan-out over the
    /// answers (the CNAME chain first, every record under its owner name).
    #[test]
    fn dig_fields_select_from_the_result_object() {
        use crate::payload::{fixtures, Payload};
        let result = fixtures::dig(
            seer_core::RecordType::A,
            vec![
                fixtures::cname("www.seer.test", "edge.cdn.test."),
                fixtures::a("edge.cdn.test", "192.0.2.7"),
            ],
        );
        let value = serde_json::to_value(Payload::Dig(Box::new(result))).unwrap();
        assert_eq!(
            extract_field_lines(
                &value,
                &fields(&["status", "flags", "answers.name", "wildcard"])
            ),
            vec![
                "NOERROR",
                r#"["qr","rd","ra"]"#,
                "www.seer.test",
                "edge.cdn.test",
                ""
            ]
        );
        assert_eq!(
            extract_field_lines(&value, &fields(&["answers.1.data.value.address"])),
            vec!["192.0.2.7"]
        );
    }

    /// Several dig types are an array of results: each result's fields
    /// print together, in the order the types were asked for, so a script
    /// can read them as rows. A leading index still picks one result.
    #[test]
    fn list_roots_extract_fields_element_by_element() {
        use crate::payload::{fixtures, Payload};
        use seer_core::{DnsStatus, RecordType};
        let many = Payload::DigMany(vec![
            fixtures::dig(
                RecordType::A,
                vec![fixtures::a("www.seer.test", "192.0.2.7")],
            ),
            fixtures::dig_status(RecordType::AAAA, DnsStatus::NoError),
            fixtures::dig(
                RecordType::MX,
                vec![fixtures::mx("www.seer.test", "mail.seer.test.")],
            ),
        ]);
        let value = serde_json::to_value(many).unwrap();
        assert_eq!(
            extract_field_lines(&value, &fields(&["record_type", "status"])),
            vec!["A", "NOERROR", "AAAA", "NOERROR", "MX", "NOERROR"]
        );
        assert_eq!(
            extract_field_lines(&value, &fields(&["2.record_type", "0.status"])),
            vec!["MX", "NOERROR"]
        );
        // A single field reads the same either way.
        assert_eq!(
            extract_field_lines(&value, &fields(&["record_type"])),
            vec!["A", "AAAA", "MX"]
        );
    }

    #[test]
    fn object_paths_and_missing_fields_are_unchanged() {
        let value = json!({"certificate": {"issuer": "Test CA", "days": 30}});
        assert_eq!(
            extract_field_lines(
                &value,
                &fields(&["certificate.issuer", "certificate.days", "nope"])
            ),
            vec!["Test CA", "30", ""]
        );
    }
}

#[cfg(test)]
mod global_option_tests {
    use super::{parse_config_format, Cli, Commands, Output};
    use clap::Parser;
    use seer_core::output::OutputFormat;

    /// `--format jsno` silently printed human output; it is now a usage
    /// error naming the valid formats. Aliases still parse.
    #[test]
    fn a_mistyped_format_flag_is_a_usage_error() {
        let err = Cli::try_parse_from(["seer", "--format", "jsno", "lookup", "example.com"])
            .err()
            .expect("must be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
        assert!(
            err.to_string().contains("human, json, yaml, markdown"),
            "{err}"
        );
        for (flag, want) in [
            ("json", OutputFormat::Json),
            ("YML", OutputFormat::Yaml),
            ("md", OutputFormat::Markdown),
            ("text", OutputFormat::Human),
        ] {
            let cli = Cli::try_parse_from(["seer", "-f", flag, "doctor"]).expect("valid");
            assert_eq!(cli.format, Some(want), "{flag}");
        }
    }

    /// The config file is not retyped per invocation, so a bad value falls
    /// back to human — with a warning, where it used to pass silently.
    #[test]
    fn the_config_format_falls_back_with_a_warning() {
        assert_eq!(parse_config_format("yaml"), Ok(OutputFormat::Yaml));
        assert_eq!(parse_config_format(""), Ok(OutputFormat::Human));
        let warning = parse_config_format("jsno").expect_err("warns");
        assert!(
            warning.contains("jsno") && warning.contains("using human"),
            "{warning}"
        );
    }

    /// `--fields` without `-q` used to be silently ignored.
    #[test]
    fn fields_imply_quiet() {
        let fields = Some(vec!["status".to_string()]);
        assert!(Output::new(OutputFormat::Human, false, fields).quiet);
        assert!(Output::new(OutputFormat::Human, true, None).quiet);
        assert!(!Output::new(OutputFormat::Human, false, None).quiet);
    }

    #[test]
    fn generate_key_bytes_are_bounded_by_clap() {
        for bytes in ["0", "4097"] {
            let err = Cli::try_parse_from(["seer", "generate-key", "--bytes", bytes])
                .err()
                .expect("out of range");
            assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
        }
        let cli = Cli::try_parse_from(["seer", "generate-key", "--bytes", "4096"]).expect("max");
        assert!(matches!(
            cli.command,
            Some(Commands::GenerateKey { bytes: 4096, .. })
        ));
    }

    /// `history example.com --clear` cleared all history, ignoring the
    /// domain.
    #[test]
    fn history_clear_conflicts_with_a_domain() {
        assert!(Cli::try_parse_from(["seer", "history", "example.com", "--clear"]).is_err());
        assert!(Cli::try_parse_from(["seer", "history", "--clear"]).is_ok());
    }

    /// `watch add` takes several domains.
    #[test]
    fn watch_add_takes_several_domains() {
        let cli = Cli::try_parse_from(["seer", "watch", "add", "a.com", "b.com"]).expect("valid");
        let Some(Commands::Watch {
            action, domains, ..
        }) = cli.command
        else {
            panic!("expected Watch command");
        };
        assert_eq!(action.as_deref(), Some("add"));
        assert_eq!(domains, vec!["a.com", "b.com"]);
    }

    /// Command errors come back to `main` as a `Failure` instead of calling
    /// `process::exit`, which skipped the log guard's flush. These fail
    /// before any I/O.
    #[tokio::test]
    async fn command_errors_return_instead_of_exiting() {
        let config = seer_core::SeerConfig::default();
        let output = Output::new(OutputFormat::Json, false, None);
        for argv in [
            &["seer", "compare", "example.com"][..],
            &["seer", "prop", "example.com", "MXX"],
            &["seer", "dig", "mx", "NS"],
            &["seer", "follow", "example.com", "1", "2", "3"],
        ] {
            let cli = Cli::try_parse_from(argv).expect("clap accepts it");
            let command = cli.command.expect("a command");
            let failure = super::execute_command(command, &output, &config)
                .await
                .expect_err("usage error");
            assert!(!failure.0.is_empty(), "{argv:?}");
        }
    }
}
