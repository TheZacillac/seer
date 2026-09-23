mod clipboard;
mod display;
mod ops;
mod payload;
mod query;
mod repl;
mod tui;
mod utils;

use std::io::Write;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use payload::Payload;
use query::Query;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "lowercase")]
enum ProgressMode {
    /// Progress bar only (default in a TTY)
    Bar,
    /// Progress bar plus per-item completion lines
    Verbose,
    /// Progress bar plus per-failure lines; successes silent
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
fn resolve_progress_mode(
    flag: Option<ProgressMode>,
    stderr_is_tty: bool,
    format: seer_core::output::OutputFormat,
) -> ProgressMode {
    if let Some(mode) = flag {
        return mode;
    }
    if format == seer_core::output::OutputFormat::Json {
        return ProgressMode::None;
    }
    if !stderr_is_tty {
        return ProgressMode::None;
    }
    ProgressMode::Bar
}
use seer_core::colors::CatppuccinExt;

/// Severity threshold for `seer watch`'s non-zero exit (`--fail-on`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "lowercase")]
enum FailOn {
    /// Exit 1 when any issue is reported (warnings or critical)
    Warning,
    /// Exit 1 only when critical issues are reported
    Critical,
}

/// `seer bulk --help` epilogue: the input formats (shared with the REPL's
/// `bulk -h`), then [`BULK_EXAMPLES`].
fn bulk_long_help() -> String {
    format!(
        "\nInput File Formats:\n{}\n{}",
        ops::BULK_INPUT_FORMATS,
        BULK_EXAMPLES
    )
}

const BULK_EXAMPLES: &str = r#"Example Usage:
  seer bulk status domains.txt              # Output: domains_results.csv
  seer bulk lookup domains.csv              # Output: domains_results.csv
  seer bulk dig domains.txt MX              # Output: domains_results.csv
  seer bulk avail domains.txt               # Output: domains_results.csv
  seer bulk info domains.txt                # Output: domains_results.csv
  seer bulk ssl domains.txt                 # Output: domains_results.csv
  seer bulk posture domains.txt             # Output: domains_results.csv
  seer bulk confusables domains.txt         # Output: domains_results.csv
  seer bulk caa domains.txt                 # Output: domains_results.csv
  seer bulk status domains.txt -o out.csv   # Output: out.csv

Example Output (status operation):
  domain,success,http_status,http_status_text,title,ssl_issuer,ssl_valid_until,ssl_days_remaining,domain_expires,domain_days_remaining,registrar,dns_resolves,dns_a_records,dns_aaaa_records,dns_cname,dns_nameservers,duration_ms,error
  example.com,true,200,OK,Example Domain,DigiCert Inc,2025-03-01,89,2025-08-13,204,RESERVED-Internet Assigned Numbers Authority,true,93.184.216.34,2606:2800:220:1:248:1893:25c8:1946,,a.iana-servers.net;b.iana-servers.net,1245,
  google.com,true,200,OK,Google,Google Trust Services,2025-02-15,75,2028-09-14,1332,MarkMonitor Inc.,true,142.250.185.46,2607:f8b0:4004:800::200e,,ns1.google.com;ns2.google.com,892,

Example Output (lookup/whois/rdap operation):
  domain,success,registrar,created,expires,updated,duration_ms,availability_verdict,error
  example.com,true,RESERVED-Internet Assigned Numbers Authority,1995-08-14,2025-08-13,2024-08-14,523,,
  google.com,true,MarkMonitor Inc.,1997-09-15,2028-09-14,2019-09-09,412,,

Example Output (dig operation):
  domain,success,record_type,records,duration_ms,error
  example.com,true,A,93.184.216.34,45,
  google.com,true,MX,10 smtp.google.com; 20 smtp2.google.com,38,

Example Output (avail operation):
  domain,success,available,confidence,method,details,duration_ms,error
  nonexistent123.com,true,true,high,whois,WHOIS indicates domain is not registered,1523,
  google.com,true,false,high,rdap,Domain is registered (status: client delete prohibited),412,

Example Output (info operation):
  domain,success,source,registrar,registrant,organization,created,expires,updated,nameservers,status,dnssec,...,whois_server,rdap_url,availability_verdict,duration_ms,error
  example.com,true,Both,RESERVED-Internet Assigned Numbers Authority,,Internet Assigned Numbers Authority,1995-08-14,2025-08-13,2024-08-14,a.iana-servers.net;b.iana-servers.net,client delete prohibited,signed,...,whois.iana.org,https://rdap.iana.org/domain/example.com,,1523,

Example Output (ssl operation):
  domain,success,subject,issuer,valid_from,valid_until,days_remaining,signature_algorithm,key_type,key_bits,chain_length,san_count,sans,protocol_version,is_valid,duration_ms,error
  example.com,true,CN=*.example.com,"C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1",2024-01-30,2025-03-01,89,sha256WithRSAEncryption,RSA,2048,3,2,*.example.com;example.com,TLSv1.3,true,612,

Example Output (posture operation):
  domain,success,spf_verdict,spf_all_qualifier,dmarc_verdict,dmarc_policy,mta_sts_verdict,bimi_verdict,dane_verdict,notes,duration_ms,error
  example.com,true,strict,-,strict,reject,present,absent,absent,,842,

Example Output (confusables operation):
  domain,success,candidates_generated,candidates_checked,registered_count,registered,duration_ms,error
  example.com,true,214,180,2,examp1e.com(homoglyph);exampel.com(transposition),9214,

Example Output (caa operation):
  domain,success,has_policy,effective_domain,issue,issuewild,iodef,wildcard_note,duration_ms,error
  example.com,true,true,example.com,letsencrypt.org;digicert.com,,mailto:security@example.com,,133,
"#;

#[derive(Parser)]
#[command(name = "seer")]
#[command(about = "Domain name helper - WHOIS, RDAP, DIG, and propagation checking")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Output format (human, json, yaml, or markdown).
    /// Defaults to the config file's `output_format`, or "human".
    #[arg(short, long)]
    format: Option<String>,

    /// Quiet mode - suppress headers and formatting, output raw values only
    #[arg(short, long)]
    quiet: bool,

    /// Comma-separated list of fields to extract (use with --quiet). Dotted
    /// paths reach nested values (certificate.issuer), numeric segments index
    /// arrays (0.name), and a name applied to a list extracts it from every
    /// element (e.g. `-q --fields name dig example.com`)
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
    Dig {
        /// Domain name to query
        domain: String,
        /// Record type (A, AAAA, MX, TXT, NS, SOA, etc.)
        #[arg(default_value = "A")]
        record_type: String,
        /// Nameserver to query: IP/host[:port] (UDP), tls://host[:port] (DoT),
        /// or https://host[/path] (DoH) — e.g. 8.8.8.8, tls://1.1.1.1,
        /// https://cloudflare-dns.com/dns-query
        #[arg(short, long)]
        server: Option<String>,
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
    #[command(after_long_help = bulk_long_help())]
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
        progress: Option<ProgressMode>,
    },
    /// Check domain status (HTTP, SSL cert, registration expiration)
    Status {
        /// Domain name to check
        domain: String,
    },
    /// Monitor DNS records over time
    Follow {
        /// Domain name to monitor
        domain: String,
        /// Number of checks to perform
        #[arg(default_value = "10")]
        iterations: usize,
        /// Minutes between checks (can be decimal, e.g., 0.5 for 30 seconds)
        #[arg(default_value = "1")]
        interval_minutes: f64,
        /// Record type (A, AAAA, MX, NS, TXT, etc.)
        #[arg(default_value = "A")]
        record_type: String,
        /// Nameserver to query: IP/host[:port] (UDP), tls://host[:port] (DoT),
        /// or https://host[/path] (DoH) — e.g. 8.8.8.8, tls://1.1.1.1,
        /// https://cloudflare-dns.com/dns-query
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
        /// Number of random bytes (default: 32 = 256 bits of entropy)
        #[arg(long, default_value_t = 32)]
        bytes: usize,
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
    Compare {
        /// Domain name to query
        domain: String,
        /// First nameserver (e.g., 8.8.8.8 or tls://1.1.1.1)
        server_a: String,
        /// Second nameserver (e.g., 1.1.1.1 or https://dns.google/dns-query)
        server_b: String,
        /// Record type (A, AAAA, MX, etc.)
        // Trails the required nameservers: clap forbids a defaulted positional
        // from preceding a required one (it panics on a debug_assert otherwise).
        #[arg(default_value = "A")]
        record_type: String,
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
        /// Domain for add/remove actions
        domain: Option<String>,
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
        #[arg(long)]
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
        /// updates the baseline)
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
async fn main() -> anyhow::Result<()> {
    // Initialize tracing with progress-aware writer.
    // Routes log output through the progress bar when one is active,
    // preventing logs from interfering with progress bar display.
    // Respects ARCANUM_LOG_LEVEL, ARCANUM_LOG_FORMAT, ARCANUM_LOG_FILE env vars.
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
    let output_format = resolve_output_format(cli.format.as_deref(), &config.output_format);

    match cli.command {
        Some(cmd) => execute_command(cmd, output_format, cli.quiet, cli.fields, &config).await,
        None => {
            // Start interactive REPL. An explicit `--format` becomes its
            // initial output format (as if `set output <fmt>` was typed);
            // without one the REPL keeps the config file's default.
            let mut repl = repl::Repl::new()?;
            if cli.format.is_some() {
                repl.set_output_format(output_format);
            }
            repl.run().await
        }
    }
}

/// Resolves the effective output format. An explicit `--format` flag always
/// wins; otherwise the config file's `output_format` applies; otherwise the
/// `Default`. An unparseable value falls back to the `Default` (matching the
/// prior lenient behavior).
fn resolve_output_format(
    cli_format: Option<&str>,
    config_format: &str,
) -> seer_core::output::OutputFormat {
    match cli_format {
        Some(f) => f.parse().unwrap_or_default(),
        None => config_format.parse().unwrap_or_default(),
    }
}

/// Where `seer bulk` writes its CSV, or `None` when no CSV is written.
///
/// An explicit `-o/--output` always yields a CSV — including under a
/// structured `--format json|yaml` (flag or config file), which previously
/// ignored `-o` and silently wrote nothing. Without `-o`, structured formats
/// stream to stdout only, and human/markdown default to `<input>_results.csv`.
fn bulk_csv_path(explicit: Option<&str>, structured_output: bool, input: &str) -> Option<String> {
    match explicit {
        Some(path) => Some(utils::expand_tilde(path)),
        None if structured_output => None,
        None => Some(ops::default_bulk_output_path(input)),
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
fn extract_field_lines(value: &serde_json::Value, fields: &[String]) -> Vec<String> {
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

/// Extract specific fields from a JSON value and print them.
/// Supports nested field access via dot notation (e.g., "certificate.issuer"),
/// numeric array indices, and fan-out over arrays.
fn extract_fields(value: &serde_json::Value, fields: &[String]) {
    for line in extract_field_lines(value, fields) {
        println!("{}", line);
    }
}

/// Quiet (`-q`) output: the requested `--fields` one per line, or the whole
/// result as compact JSON.
fn handle_quiet_output<T: serde::Serialize>(value: &T, fields: &Option<Vec<String>>) {
    if let Some(ref fields) = fields {
        let json_value = serde_json::to_value(value).unwrap_or_default();
        extract_fields(&json_value, fields);
    } else {
        let json = serde_json::to_string(value).unwrap_or_default();
        println!("{}", json);
    }
}

use utils::machine_error;

/// Prints a format-appropriate error to stderr and exits non-zero. Honors the
/// global `--format` flag so scripted consumers get structured output instead
/// of ANSI-colored prose when a command fails.
fn emit_error<E: std::fmt::Display>(output_format: seer_core::output::OutputFormat, e: &E) -> ! {
    let msg = e.to_string();
    match machine_error(output_format, &msg) {
        Some(structured) => eprintln!("{}", structured),
        None => eprintln!("{} {}", "Error:".ctp_red(), msg),
    }
    std::process::exit(1);
}

/// Whether `follow`'s prose (the "Following …" banner and the interrupted
/// note) belongs on stderr: yes for every non-human format, so stdout carries
/// only the formatted iterations and summary and stays machine-parseable.
fn follow_notes_to_stderr(output_format: seer_core::output::OutputFormat) -> bool {
    output_format != seer_core::output::OutputFormat::Human
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

/// Parses a DNS record type, routing a bad value through [`emit_error`] so the
/// `--format json|yaml` error contract still holds. Using `?` here instead would
/// bubble a raw `anyhow` error past the formatter and print ANSI prose even when
/// the caller asked for structured output.
fn parse_record_type(
    record_type: &str,
    output_format: seer_core::output::OutputFormat,
) -> seer_core::RecordType {
    match try_parse_record_type(record_type) {
        Ok(rt) => rt,
        Err(e) => emit_error(output_format, &e),
    }
}

/// Runs a subcommand. Single-shot queries share [`query::run`] with the REPL
/// and render through the one path at the end; the other subcommands (bulk,
/// follow, watchlist/history management, local utilities) run inline.
async fn execute_command(
    command: Commands,
    output_format: seer_core::output::OutputFormat,
    quiet: bool,
    fields: Option<Vec<String>>,
    config: &seer_core::SeerConfig,
) -> anyhow::Result<()> {
    let formatter = seer_core::output::get_formatter(output_format);
    // Record types are validated before any network I/O, through
    // `emit_error` so a typo honors `--format json|yaml` too.
    let parse_type = |name: &str| parse_record_type(name, output_format);
    let query = match command {
        Commands::Lookup { domain } => Query::Lookup(domain),
        Commands::Info { domain } => Query::Info(domain),
        Commands::Whois { domain } => Query::Whois(domain),
        Commands::Rdap { query } => Query::Rdap(query),
        Commands::Dig {
            domain,
            record_type: rt,
            server,
        } => Query::Dig {
            domain,
            record_type: parse_type(&rt),
            server: server.map(|s| s.trim_start_matches('@').to_string()),
        },
        Commands::Prop {
            domain,
            record_type: rt,
        } => Query::Prop {
            domain,
            record_type: parse_type(&rt),
        },
        Commands::Status { domain } => Query::Status(domain),
        Commands::Reverse { ip } => Query::Reverse(ip),
        Commands::Avail { domain } => Query::Avail(domain),
        Commands::Dnssec { domain } => Query::Dnssec(domain),
        Commands::Ssl { domain } => Query::Ssl(domain),
        Commands::Tld { tld } => Query::Tld(tld),
        Commands::Compare {
            domain,
            server_a,
            server_b,
            record_type: rt,
        } => Query::Compare {
            domain,
            record_type: parse_type(&rt),
            server_a: server_a.trim_start_matches('@').to_string(),
            server_b: server_b.trim_start_matches('@').to_string(),
        },
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
            output,
            progress,
        } => {
            let stderr_is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
            let progress_mode = resolve_progress_mode(progress, stderr_is_tty, output_format);

            // `-` reads a newline/CSV-delimited domain list from stdin so bulk
            // composes with shell pipelines (`grep … | seer bulk status -`).
            let from_stdin = file == "-";
            // Expand `~` / `~/...` once at the boundary so both the bulk-input
            // read and the auto-derived output path see a home-resolved path.
            // For stdin, use a synthetic "bulk" stem for any derived CSV path.
            let file = if from_stdin {
                "bulk".to_string()
            } else {
                utils::expand_tilde(&file)
            };

            // `read_bulk_input` rejects FIFOs, sockets, devices, directories,
            // and oversized files via a pre-read metadata check, so malicious
            // `mkfifo`'d paths can't hang the process. stdin gets the same
            // size cap via a bounded read. Errors go through `emit_error` so
            // `--format json|yaml` stays machine-readable on this path too.
            let content = if from_stdin {
                utils::read_bulk_stdin(std::io::stdin().lock())
            } else {
                utils::read_bulk_input(&file)
            }
            .unwrap_or_else(|e| emit_error(output_format, &e));

            // When a structured global format is requested, bulk streams results
            // to stdout — pipeline-friendly and free of the spreadsheet-safety
            // escaping CSV requires. An explicit `-o` still writes the CSV too.
            let structured_output = matches!(
                output_format,
                seer_core::output::OutputFormat::Json | seer_core::output::OutputFormat::Yaml
            );

            let domains =
                ops::parse_bulk_domains(&content).unwrap_or_else(|e| emit_error(output_format, &e));

            // Determine the CSV path (tilde-expanded when supplied), or None
            // when a structured stream to stdout replaces the default CSV.
            let csv_path = bulk_csv_path(output.as_deref(), structured_output, &file);

            let rt = parse_record_type(&record_type, output_format);
            let executor = seer_core::BulkExecutor::from_config(config);

            let operations = ops::build_bulk_operations(&operation, &domains, rt)
                .unwrap_or_else(|e| emit_error(output_format, &e));

            // Status goes to stderr so it never pollutes a structured stdout stream.
            eprintln!("{}", ops::bulk_banner(domains.len(), &operation));

            let bar =
                (progress_mode != ProgressMode::None).then(|| ops::bulk_bar(operations.len()));
            let callback = bar.as_ref().map(ops::bar_progress_callback);
            let results = executor.execute(operations, callback).await;

            // Emit per-item lines according to mode, then clear the bar.
            // `bar_println` falls back to plain stderr when indicatif hid the
            // bar (non-TTY stderr), where `println` would silently drop them.
            if let Some(bar) = &bar {
                for r in &results {
                    let domain = r.operation.domain();
                    let line = match (progress_mode, r.success) {
                        (ProgressMode::Verbose, true) => Some(format!(
                            "{} {} ({}ms)",
                            "\u{2713}".ctp_green(),
                            domain,
                            r.duration_ms
                        )),
                        (ProgressMode::Verbose, false) | (ProgressMode::Failures, false) => {
                            let err = r.error.as_deref().unwrap_or("unknown error");
                            Some(format!("{} {} ({})", "\u{2717}".ctp_red(), domain, err))
                        }
                        _ => None,
                    };
                    if let Some(line) = line {
                        let _ = display::bar_println(bar, &line);
                    }
                }
                ops::finish_bulk_bar(bar);
            }

            if structured_output {
                // Serialize the full result set to stdout (JSON array / YAML).
                let rendered = match output_format {
                    seer_core::output::OutputFormat::Yaml => {
                        seer_core::output::YamlFormatter::new().to_yaml_value(&results)
                    }
                    _ => serde_json::to_string_pretty(&results)
                        .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
                };
                println!("{}", rendered);
            }

            if let Some(csv_path) = &csv_path {
                if let Err(e) = ops::write_bulk_csv(&results, &operation, csv_path) {
                    emit_error(output_format, &e);
                }
                let written = format!("Results written to: {}", csv_path.ctp_green());
                // Keep stdout a clean JSON/YAML document in structured mode.
                if structured_output {
                    eprintln!("{}", written);
                } else {
                    println!("{}", written);
                }
            }

            let summary = ops::bulk_summary(&results);
            if structured_output {
                eprintln!("{}", summary);
            } else {
                println!("{}", summary);
            }

            // A run with zero successes is a total failure (network down,
            // every domain malformed) — scripted callers gate on $?.
            let success_count = results.iter().filter(|r| r.success).count();
            let code = utils::bulk_exit_code(success_count, results.len());
            if code != 0 {
                std::process::exit(code);
            }
            return Ok(());
        }
        Commands::Follow {
            domain,
            iterations,
            interval_minutes,
            record_type,
            server,
            changes_only,
        } => {
            let rt = parse_record_type(&record_type, output_format);
            let ns = server
                .as_ref()
                .map(|s| s.trim_start_matches('@'))
                .or(config.nameserver.as_deref());

            let follow_config = match seer_core::FollowConfig::new(iterations, interval_minutes) {
                Ok(cfg) => cfg.with_changes_only(changes_only),
                Err(e) => {
                    emit_error(output_format, &e);
                }
            };

            // Honor the config file's DNS timeout like `dig` does.
            let follower = seer_core::DnsFollower::from_config(config);

            // The banner is prose, so under a machine format it goes to stderr
            // and stdout stays a parseable stream (`seer --format json follow
            // … | jq`). `\r\n` matches the raw-mode iteration lines that follow.
            let notes_to_stderr = follow_notes_to_stderr(output_format);
            let banner = format!(
                "Following {} {} records ({} iterations, {} interval)\r\nPress {} or {} to stop early\r\n\r\n",
                domain.ctp_green(),
                record_type.ctp_yellow(),
                iterations.to_string().ctp_yellow(),
                utils::format_interval(interval_minutes),
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

            let result = ops::run_live_follow(
                &follower,
                &domain,
                rt,
                ns,
                follow_config,
                output_format,
                true,
            )
            .await;

            match result {
                Ok(result) => {
                    if result.interrupted {
                        let note = "Follow interrupted by user".ctp_yellow();
                        if notes_to_stderr {
                            eprintln!("{}", note);
                        } else {
                            println!("\n{}", note);
                        }
                    }
                    println!("\n{}", formatter.format_follow(&result));
                }
                Err(e) => {
                    emit_error(output_format, &e);
                }
            }
            return Ok(());
        }
        Commands::Watch {
            action,
            domain,
            fail_on,
            webhook,
        } => {
            // add/remove/list share their pipeline with the REPL; failures go
            // through `emit_error` so `--format json|yaml` stays structured.
            if let Some(action) = action.as_deref() {
                match ops::watch_edit(action, domain.as_deref(), "seer watch").await {
                    Ok(message) => println!("{}", message),
                    Err(e) => emit_error(output_format, &e),
                }
                return Ok(());
            }
            let watchlist = ops::load_watchlist()
                .await
                .unwrap_or_else(|e| emit_error(output_format, &e));
            if watchlist.domains.is_empty() {
                println!("{}", ops::watchlist_listing(&watchlist, "seer watch"));
                return Ok(());
            }
            let spinner =
                display::Spinner::new(&format!("Checking {} domains", watchlist.domains.len()));
            let report = seer_core::check_watchlist_with_config(&watchlist.domains, config).await;
            spinner.finish();
            if quiet {
                handle_quiet_output(&report, &fields);
            } else {
                println!("{}", formatter.format_watch(&report));
            }
            // Best-effort webhook delivery of the report: the --webhook flag
            // overrides the config file's watch.webhook_url. A failed POST
            // warns on stderr but never alters the check's exit code below.
            let webhook_url = webhook.as_deref().or(config.watch.webhook_url.as_deref());
            if let Some(url) = webhook_url {
                let client = seer_core::webhook::WebhookClient::from_config(config);
                if let Err(e) = client.post_json(url, &report).await {
                    eprintln!("{} webhook delivery failed: {}", "Warning:".ctp_yellow(), e);
                }
            }
            // Exit 1 when issues at or above the --fail-on threshold exist
            // (mirrors drift/avail/dnssec). `warnings` counts every result
            // with issues, so it already subsumes the critical ones; the `||`
            // keeps the check robust if that tally ever changes.
            let should_fail = match fail_on {
                FailOn::Critical => report.critical > 0,
                FailOn::Warning => report.warnings > 0 || report.critical > 0,
            };
            if should_fail {
                std::process::exit(1);
            }
            return Ok(());
        }
        Commands::History { domain, clear } => {
            if clear {
                if let Err(e) = ops::clear_history().await {
                    emit_error(output_format, &e);
                }
                println!("Lookup history cleared");
            } else {
                let history = ops::load_history()
                    .await
                    .unwrap_or_else(|e| emit_error(output_format, &e));
                println!(
                    "{}",
                    ops::history_listing(&history, domain.as_deref(), "seer lookup")
                );
            }
            return Ok(());
        }
        Commands::Config { init } => {
            if init {
                let config_path = seer_core::SeerConfig::config_path();
                // Every failure goes through `emit_error` (non-zero exit) so
                // `--format json|yaml` gets a structured error here as well.
                match config_path {
                    Some(path) => {
                        if let Some(parent) = path.parent() {
                            if let Err(e) = std::fs::create_dir_all(parent) {
                                emit_error(
                                    output_format,
                                    &format!("Could not create {}: {}", parent.display(), e),
                                );
                            }
                        }
                        if path.exists() {
                            emit_error(
                                output_format,
                                &format!("Config file already exists at: {}", path.display()),
                            );
                        }
                        let content = seer_core::SeerConfig::default_toml();
                        if let Err(e) = std::fs::write(&path, content) {
                            emit_error(
                                output_format,
                                &format!("Could not write {}: {}", path.display(), e),
                            );
                        }
                        println!(
                            "Created config file at: {}",
                            path.display().to_string().ctp_green()
                        );
                    }
                    None => emit_error(output_format, &"Could not determine home directory"),
                }
            } else {
                let config = seer_core::SeerConfig::load();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&config).unwrap_or_default()
                );
            }
            return Ok(());
        }
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            generate(shell, &mut cmd, "seer", &mut std::io::stdout());
            return Ok(());
        }
        Commands::GenerateKey { export, bytes } => {
            use base64::Engine;

            if bytes == 0 || bytes > 4096 {
                eprintln!("{} --bytes must be between 1 and 4096", "Error:".ctp_red());
                std::process::exit(2);
            }
            let mut buf = vec![0u8; bytes];
            // Fill with OS entropy directly via getrandom — the CSPRNG source
            // that rand's OsRng merely wraps. It's the right primitive for key
            // material and immune to rand's RNG-trait churn across versions.
            if let Err(e) = getrandom::fill(&mut buf) {
                eprintln!("{} OS RNG unavailable: {}", "Error:".ctp_red(), e);
                std::process::exit(1);
            }
            let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&buf);
            if export {
                println!("export SEER_API_KEY={}", token);
            } else {
                println!("{}", token);
            }
            return Ok(());
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
            return Ok(());
        }
        Commands::Tui { domain } => {
            tui::run(domain).await?;
            return Ok(());
        }
    };

    let spin = cli_spinner(&query);
    let clients = query::Clients::from_config(config);
    match query::run(query, &clients, config, spin).await {
        Ok(outcome) => {
            outcome.present(|payload| {
                if quiet {
                    handle_quiet_output(payload, &fields);
                } else {
                    println!("{}", payload::serialize(payload, output_format));
                }
            });
            let code = exit_code(&outcome.payload);
            if code != 0 {
                std::process::exit(code);
            }
        }
        Err(e) => emit_error(output_format, &e),
    }
    Ok(())
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
    )
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
    format: seer_core::output::OutputFormat,
) -> String {
    use colored::Colorize as _;
    use seer_core::doctor::CheckStatus;
    use seer_core::output::OutputFormat;

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
mod compare_cli_tests {
    use super::{Cli, Commands};
    use clap::Parser;

    /// `compare` must parse cleanly. The required `server_a`/`server_b`
    /// positionals previously sat AFTER the defaulted `record_type`, which trips
    /// clap's debug_assert (a required positional cannot follow an optional one)
    /// and panics on parse in debug builds. record_type must default to "A".
    #[test]
    fn compare_parses_with_default_record_type() {
        let cli = Cli::try_parse_from(["seer", "compare", "example.com", "8.8.8.8", "1.1.1.1"])
            .expect("compare should parse");
        let Some(Commands::Compare {
            domain,
            server_a,
            server_b,
            record_type,
        }) = cli.command
        else {
            panic!("expected Compare command");
        };
        assert_eq!(domain, "example.com");
        assert_eq!(server_a, "8.8.8.8");
        assert_eq!(server_b, "1.1.1.1");
        assert_eq!(record_type, "A");
    }

    #[test]
    fn compare_parses_with_explicit_record_type() {
        let cli =
            Cli::try_parse_from(["seer", "compare", "example.com", "8.8.8.8", "1.1.1.1", "MX"])
                .expect("compare with explicit type should parse");
        let Some(Commands::Compare { record_type, .. }) = cli.command else {
            panic!("expected Compare command");
        };
        assert_eq!(record_type, "MX");
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
            rrsig_records: vec![],
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
        assert_eq!(exit_code(&Payload::Dns(vec![])), 0);
        assert_eq!(exit_code(&Payload::Reverse(vec![])), 0);
    }
}
#[cfg(test)]
mod bulk_output_tests {
    use super::bulk_csv_path;

    /// `-o` under a structured format (flag or config-file default) was
    /// computed but ignored: no CSV, exit 0.
    #[test]
    fn explicit_output_writes_csv_even_for_structured_formats() {
        assert_eq!(
            bulk_csv_path(Some("out.csv"), true, "domains.txt").as_deref(),
            Some("out.csv")
        );
        assert_eq!(
            bulk_csv_path(Some("out.csv"), false, "domains.txt").as_deref(),
            Some("out.csv")
        );
    }

    #[test]
    fn default_csv_only_for_human_style_formats() {
        assert_eq!(bulk_csv_path(None, true, "domains.txt"), None);
        assert_eq!(
            bulk_csv_path(None, false, "domains.txt").as_deref(),
            Some("domains_results.csv")
        );
    }
}

#[cfg(test)]
mod quiet_fields_tests {
    use super::extract_field_lines;
    use serde_json::json;

    fn fields(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    /// `-q --fields name dig example.com` printed blank lines because the
    /// record-list root (an array) resolved every path to Null.
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
mod follow_output_tests {
    use super::follow_notes_to_stderr;
    use seer_core::output::OutputFormat;

    /// `seer --format json follow … | jq` broke on the prose banner and the
    /// "interrupted" note written to stdout.
    #[test]
    fn prose_notes_leave_stdout_for_machine_formats() {
        assert!(!follow_notes_to_stderr(OutputFormat::Human));
        for format in [
            OutputFormat::Json,
            OutputFormat::Yaml,
            OutputFormat::Markdown,
        ] {
            assert!(follow_notes_to_stderr(format), "{format:?}");
        }
    }
}

#[cfg(test)]
mod progress_mode_tests {
    use super::{resolve_progress_mode, ProgressMode};
    use seer_core::output::OutputFormat;

    #[test]
    fn explicit_mode_is_honored_on_tty() {
        assert_eq!(
            resolve_progress_mode(Some(ProgressMode::Verbose), true, OutputFormat::Human),
            ProgressMode::Verbose
        );
        assert_eq!(
            resolve_progress_mode(Some(ProgressMode::None), true, OutputFormat::Human),
            ProgressMode::None
        );
    }

    #[test]
    fn explicit_mode_is_honored_on_non_tty() {
        assert_eq!(
            resolve_progress_mode(Some(ProgressMode::Bar), false, OutputFormat::Human),
            ProgressMode::Bar
        );
    }

    #[test]
    fn explicit_mode_overrides_json_format() {
        assert_eq!(
            resolve_progress_mode(Some(ProgressMode::Bar), true, OutputFormat::Json),
            ProgressMode::Bar
        );
    }

    #[test]
    fn default_is_bar_on_tty_with_human_format() {
        assert_eq!(
            resolve_progress_mode(None, true, OutputFormat::Human),
            ProgressMode::Bar
        );
    }

    #[test]
    fn default_is_none_on_non_tty() {
        assert_eq!(
            resolve_progress_mode(None, false, OutputFormat::Human),
            ProgressMode::None
        );
    }

    #[test]
    fn default_is_none_with_json_format() {
        assert_eq!(
            resolve_progress_mode(None, true, OutputFormat::Json),
            ProgressMode::None
        );
    }

    #[test]
    fn explicit_format_flag_overrides_config_default() {
        // An explicit `--format human` must win even when the config default
        // is non-human — the previous code re-read config in that case and
        // silently ignored the flag.
        assert_eq!(
            super::resolve_output_format(Some("human"), "json"),
            OutputFormat::Human
        );
        assert_eq!(
            super::resolve_output_format(Some("json"), "human"),
            OutputFormat::Json
        );
    }

    #[test]
    fn format_falls_back_to_config_when_flag_absent() {
        assert_eq!(
            super::resolve_output_format(None, "yaml"),
            OutputFormat::Yaml
        );
        assert_eq!(
            super::resolve_output_format(None, "json"),
            OutputFormat::Json
        );
    }

    #[test]
    fn format_defaults_when_unset_or_invalid() {
        assert_eq!(
            super::resolve_output_format(None, ""),
            OutputFormat::default()
        );
        assert_eq!(
            super::resolve_output_format(Some("bogus"), "json"),
            OutputFormat::default()
        );
    }
}
