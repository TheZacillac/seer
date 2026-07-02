mod display;
mod ops;
mod repl;
mod tui;
mod utils;

use std::io::Write;
use std::sync::Arc;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use indicatif::{ProgressBar, ProgressStyle};

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
    format: &str,
) -> ProgressMode {
    if let Some(mode) = flag {
        return mode;
    }
    if format.eq_ignore_ascii_case("json") {
        return ProgressMode::None;
    }
    if !stderr_is_tty {
        return ProgressMode::None;
    }
    ProgressMode::Bar
}
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
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

const BULK_EXAMPLES: &str = r#"
Input File Formats:
  Plain text (one domain per line, # for comments):
    # My domains to check
    example.com
    google.com
    github.com

  CSV (uses first column, skips header if present):
    domain,owner,notes
    example.com,Alice,Main site
    google.com,Bob,Search
    github.com,Carol,Code hosting

Example Usage:
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
  example.com,true,CN=*.example.com,"C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1",2024-01-30,2025-03-01,89,sha256WithRSAEncryption,RSA,2048,3,2,*.example.com;example.com,TLS 1.3,true,612,

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

    /// Comma-separated list of fields to extract (use with --quiet)
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
        /// Nameserver to query (e.g., @8.8.8.8)
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
    #[command(after_long_help = BULK_EXAMPLES)]
    Bulk {
        #[arg(value_name = "OPERATION", help = ops::BULK_OP_HELP)]
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
        /// Nameserver to query (e.g., @8.8.8.8)
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
        /// First nameserver (e.g., 8.8.8.8)
        server_a: String,
        /// Second nameserver (e.g., 1.1.1.1)
        server_b: String,
        /// Record type (A, AAAA, MX, etc.)
        // Trails the required nameservers: clap forbids a defaulted positional
        // from preceding a required one (it panics on a debug_assert otherwise).
        #[arg(default_value = "A")]
        record_type: String,
    },
    /// Enumerate subdomains via Certificate Transparency logs
    Subdomains {
        /// Domain to enumerate subdomains for
        domain: String,
        /// Resolve each discovered name and classify live/dead + dangling-CNAME
        /// takeover risk
        #[arg(long)]
        resolve: bool,
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
    /// Find registered typosquat / look-alike domains for a domain
    Confusables {
        /// Domain to generate and score look-alikes for
        domain: String,
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
            // Start interactive REPL
            let mut repl = repl::Repl::new()?;
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

/// Extract specific fields from a JSON value and print them.
/// Supports nested field access via dot notation (e.g., "certificate.issuer").
fn extract_fields(value: &serde_json::Value, fields: &[String]) {
    for field in fields {
        let parts: Vec<&str> = field.split('.').collect();
        let mut current = value;
        for part in &parts {
            current = match current {
                serde_json::Value::Object(map) => {
                    map.get(*part).unwrap_or(&serde_json::Value::Null)
                }
                _ => &serde_json::Value::Null,
            };
        }
        match current {
            serde_json::Value::String(s) => println!("{}", s),
            serde_json::Value::Null => println!(),
            other => println!("{}", other),
        }
    }
}

/// Handle quiet output for a serializable result.
/// If `fields` is Some, extracts and prints the requested fields and returns true.
/// If `fields` is None, prints compact JSON and returns true.
fn handle_quiet_output<T: serde::Serialize>(value: &T, fields: &Option<Vec<String>>) -> bool {
    if let Some(ref fields) = fields {
        let json_value = serde_json::to_value(value).unwrap_or_default();
        extract_fields(&json_value, fields);
        true
    } else {
        let json = serde_json::to_string(value).unwrap_or_default();
        println!("{}", json);
        true
    }
}

/// Renders a machine-readable CLI error payload for non-human formats so that
/// `--format json|yaml` stays parseable on the error path. Returns `None` for
/// Human (rendered with color by [`emit_error`]). JSON is a subset of YAML, so
/// the same `{"error": ...}` document is valid for both.
fn machine_error(output_format: seer_core::output::OutputFormat, msg: &str) -> Option<String> {
    use seer_core::output::OutputFormat;
    match output_format {
        OutputFormat::Human => None,
        OutputFormat::Json | OutputFormat::Yaml => {
            Some(serde_json::json!({ "error": msg }).to_string())
        }
        OutputFormat::Markdown => Some(format!("**Error:** {}", msg)),
    }
}

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

/// Parses a DNS record type, routing a bad value through [`emit_error`] so the
/// `--format json|yaml` error contract still holds. Using `?` here instead would
/// bubble a raw `anyhow` error past the formatter and print ANSI prose even when
/// the caller asked for structured output.
fn parse_record_type(
    record_type: &str,
    output_format: seer_core::output::OutputFormat,
) -> seer_core::RecordType {
    match record_type.parse::<seer_core::RecordType>() {
        Ok(rt) => rt,
        Err(e) => emit_error(output_format, &e),
    }
}

async fn execute_command(
    command: Commands,
    output_format: seer_core::output::OutputFormat,
    quiet: bool,
    fields: Option<Vec<String>>,
    config: &seer_core::SeerConfig,
) -> anyhow::Result<()> {
    let formatter = seer_core::output::get_formatter(output_format);

    match command {
        Commands::Lookup { domain } => {
            let spinner = Arc::new(display::Spinner::new(&format!(
                "Smart lookup for {} (trying RDAP first)",
                domain
            )));

            // Create progress callback that updates the spinner
            let spinner_clone = spinner.clone();
            let progress: seer_core::LookupProgressCallback = Arc::new(move |message| {
                spinner_clone.set_message(message);
            });

            let lookup = seer_core::SmartLookup::from_config(config);
            match lookup.lookup_with_progress(&domain, Some(progress)).await {
                Ok(result) => {
                    spinner.finish();
                    // Record to history (file I/O off the async executor)
                    ops::record_lookup_history(&domain, result.clone()).await;

                    if quiet {
                        handle_quiet_output(&result, &fields);
                    } else {
                        println!("{}", formatter.format_lookup(&result));
                    }
                }
                Err(e) => {
                    spinner.finish();
                    emit_error(output_format, &e);
                }
            }
        }
        Commands::Info { domain } => {
            let spinner = Arc::new(display::Spinner::new(&format!(
                "Getting comprehensive info for {}",
                domain
            )));

            let lookup = seer_core::SmartLookup::from_config(config);
            match lookup.lookup(&domain).await {
                Ok(result) => {
                    spinner.finish();
                    let info = seer_core::DomainInfo::from_lookup_result(&result);
                    if quiet {
                        handle_quiet_output(&info, &fields);
                    } else {
                        println!("{}", formatter.format_domain_info(&info));
                    }
                }
                Err(e) => {
                    spinner.finish();
                    emit_error(output_format, &e);
                }
            }
        }
        Commands::Whois { domain } => {
            let client = seer_core::WhoisClient::from_config(config);
            match client.lookup(&domain).await {
                Ok(response) => {
                    if quiet {
                        handle_quiet_output(&response, &fields);
                    } else {
                        println!("{}", formatter.format_whois(&response));
                    }
                }
                Err(e) => {
                    emit_error(output_format, &e);
                }
            }
        }
        Commands::Rdap { query } => {
            let client = seer_core::RdapClient::from_config(config);
            // Use seer_core::rdap::auto_lookup so the `AS<digits>` route only
            // fires when the remainder is all digits AND the query contains no
            // `.` — otherwise `as1234.io` / `asset.io` would misroute to ASN
            // and surface a "parse" error instead of a domain lookup.
            let result = seer_core::rdap::auto_lookup(&client, &query).await;

            match result {
                Ok(response) => {
                    if quiet {
                        handle_quiet_output(&response, &fields);
                    } else {
                        println!("{}", formatter.format_rdap(&response));
                    }
                }
                Err(e) => {
                    emit_error(output_format, &e);
                }
            }
        }
        Commands::Dig {
            domain,
            record_type,
            server,
        } => {
            let resolver = seer_core::DnsResolver::from_config(config);
            let rt = parse_record_type(&record_type, output_format);
            let ns = server
                .as_ref()
                .map(|s| s.trim_start_matches('@'))
                .or(config.nameserver.as_deref());

            match resolver.resolve(&domain, rt, ns).await {
                Ok(records) => {
                    if quiet {
                        handle_quiet_output(&records, &fields);
                    } else {
                        println!("{}", formatter.format_dns(&records));
                    }
                }
                Err(e) => {
                    emit_error(output_format, &e);
                }
            }
        }
        Commands::Prop {
            domain,
            record_type,
        } => {
            let checker = seer_core::dns::PropagationChecker::new();
            let rt = parse_record_type(&record_type, output_format);

            match checker.check(&domain, rt).await {
                Ok(result) => {
                    if quiet {
                        handle_quiet_output(&result, &fields);
                    } else {
                        println!("{}", formatter.format_propagation(&result));
                    }
                }
                Err(e) => {
                    emit_error(output_format, &e);
                }
            }
        }
        Commands::Bulk {
            operation,
            file,
            record_type,
            output,
            progress,
        } => {
            let stderr_is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
            let format_str = match output_format {
                seer_core::output::OutputFormat::Json => "json",
                seer_core::output::OutputFormat::Human => "human",
                seer_core::output::OutputFormat::Yaml => "yaml",
                seer_core::output::OutputFormat::Markdown => "markdown",
            };
            let progress_mode = resolve_progress_mode(progress, stderr_is_tty, format_str);

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
            // `mkfifo`'d paths can't hang the process.
            let content = if from_stdin {
                use std::io::Read;
                let mut buf = String::new();
                std::io::stdin()
                    .read_to_string(&mut buf)
                    .map_err(|e| anyhow::anyhow!("reading domains from stdin: {e}"))?;
                buf
            } else {
                utils::read_bulk_input(&file).map_err(|e| anyhow::anyhow!(e))?
            };

            // When a structured global format is requested, bulk streams results
            // to stdout instead of writing a CSV — pipeline-friendly and free of
            // the spreadsheet-safety escaping CSV requires.
            let structured_output = matches!(
                output_format,
                seer_core::output::OutputFormat::Json | seer_core::output::OutputFormat::Yaml
            );

            let domains = match ops::parse_bulk_domains(&content) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("{} {}", "Error:".ctp_red(), e);
                    std::process::exit(1);
                }
            };

            // Determine output path (also tilde-expanded when supplied)
            let output_path = output
                .map(|s| utils::expand_tilde(&s))
                .unwrap_or_else(|| ops::default_bulk_output_path(&file));

            let rt: seer_core::RecordType = record_type.parse().unwrap_or(seer_core::RecordType::A);
            let executor = seer_core::BulkExecutor::from_config(config);

            let operations = match ops::build_bulk_operations(&operation, &domains, rt) {
                Ok(operations) => operations,
                Err(e) => {
                    eprintln!("{} {}", "Error:".ctp_red(), e);
                    std::process::exit(1);
                }
            };

            // Status goes to stderr so it never pollutes a structured stdout stream.
            eprintln!(
                "Processing {} domains with {} operation...",
                domains.len().to_string().ctp_green(),
                operation.ctp_yellow()
            );

            let total = operations.len();

            // Construct the progress bar (when applicable) and activate it for
            // tracing integration so log lines route through pb.println().
            let pb: Option<Arc<ProgressBar>> = match progress_mode {
                ProgressMode::None => None,
                ProgressMode::Bar | ProgressMode::Verbose | ProgressMode::Failures => {
                    let bar = ProgressBar::new(total as u64);
                    bar.set_style(
                        ProgressStyle::default_bar()
                            .template("{bar:40.cyan/blue} {pos}/{len} ({percent}%) eta {eta} {msg}")
                            .expect("valid progress bar template")
                            .progress_chars("=>-"),
                    );
                    display::set_bulk_progress_bar(bar.clone());
                    Some(Arc::new(bar))
                }
            };

            let callback: Option<seer_core::bulk::ProgressCallback> = pb
                .as_ref()
                .map(|bar| ops::bar_progress_callback(bar.as_ref()));

            let results = executor.execute(operations, callback).await;

            // Emit per-item lines according to mode, then clear the bar.
            if let Some(bar) = pb.as_ref() {
                for r in &results {
                    let domain = r.operation.domain();
                    match (progress_mode, r.success) {
                        (ProgressMode::Verbose, true) => {
                            bar.println(format!(
                                "{} {} ({}ms)",
                                "\u{2713}".ctp_green(),
                                domain,
                                r.duration_ms
                            ));
                        }
                        (ProgressMode::Verbose, false) | (ProgressMode::Failures, false) => {
                            let err = r.error.as_deref().unwrap_or("unknown error");
                            bar.println(format!("{} {} ({})", "\u{2717}".ctp_red(), domain, err));
                        }
                        _ => {}
                    }
                }
                bar.finish_and_clear();
                display::clear_bulk_progress_bar();
            }

            let success_count = results.iter().filter(|r| r.success).count();
            let fail_count = results.len() - success_count;

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
                eprintln!(
                    "  {} successful, {} failed",
                    success_count.to_string().ctp_green(),
                    fail_count
                );
            } else {
                // Convert results to CSV. Write atomically so a crash mid-write
                // cannot leave a truncated CSV that downstream pipelines treat
                // as authoritative.
                let csv_content = utils::bulk_results_to_csv(&results, &operation);
                utils::atomic_write(&output_path, &csv_content)?;

                println!("Results written to: {}", output_path.ctp_green());
                println!(
                    "  {} successful, {} failed",
                    success_count.to_string().ctp_green(),
                    if fail_count > 0 {
                        fail_count.to_string().ctp_red()
                    } else {
                        fail_count.to_string().ctp_green()
                    }
                );
            }
        }
        Commands::Status { domain } => {
            let client = seer_core::StatusClient::from_config(config);
            match client.check(&domain).await {
                Ok(response) => {
                    if quiet {
                        handle_quiet_output(&response, &fields);
                    } else {
                        println!("{}", formatter.format_status(&response));
                    }
                    // Exit with 1 if any health issues detected
                    let has_issues = response
                        .http_status
                        .is_none_or(|s| !(200..300).contains(&s))
                        || response
                            .certificate
                            .as_ref()
                            .is_some_and(|c| !c.is_valid || c.days_until_expiry < 30)
                        || response
                            .domain_expiration
                            .as_ref()
                            .is_some_and(|d| d.days_until_expiry < 30);
                    if has_issues {
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    emit_error(output_format, &e);
                }
            }
        }
        Commands::Reverse { ip } => {
            let resolver = seer_core::DnsResolver::from_config(config);
            match resolver
                .resolve(&ip, seer_core::RecordType::PTR, None)
                .await
            {
                Ok(records) => {
                    if quiet {
                        handle_quiet_output(&records, &fields);
                    } else {
                        println!("{}", formatter.format_dns(&records));
                    }
                }
                Err(e) => {
                    emit_error(output_format, &e);
                }
            }
        }
        Commands::Avail { domain } => {
            let checker = seer_core::AvailabilityChecker::from_config(config);
            match checker.check(&domain).await {
                Ok(result) => {
                    if quiet {
                        handle_quiet_output(&result, &fields);
                    } else {
                        println!("{}", formatter.format_availability(&result));
                    }
                    if !result.available {
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    emit_error(output_format, &e);
                }
            }
        }
        Commands::Dnssec { domain } => {
            let checker = seer_core::DnssecChecker::new();
            match checker.check(&domain).await {
                Ok(report) => {
                    if quiet {
                        handle_quiet_output(&report, &fields);
                    } else {
                        println!("{}", formatter.format_dnssec(&report));
                    }
                    if report.status != "secure" {
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    emit_error(output_format, &e);
                }
            }
        }
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            generate(shell, &mut cmd, "seer", &mut std::io::stdout());
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
        }
        Commands::Config { init } => {
            if init {
                let config_path = seer_core::SeerConfig::config_path();
                match config_path {
                    Some(path) => {
                        if let Some(parent) = path.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        if path.exists() {
                            eprintln!("Config file already exists at: {}", path.display());
                            std::process::exit(1);
                        }
                        let content = seer_core::SeerConfig::default_toml();
                        std::fs::write(&path, content)?;
                        println!(
                            "Created config file at: {}",
                            path.display().to_string().ctp_green()
                        );
                    }
                    None => {
                        eprintln!("{} Could not determine home directory", "Error:".ctp_red());
                        std::process::exit(1);
                    }
                }
            } else {
                let config = seer_core::SeerConfig::load();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&config).unwrap_or_default()
                );
            }
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

            let config = match seer_core::FollowConfig::new(iterations, interval_minutes) {
                Ok(cfg) => cfg.with_changes_only(changes_only),
                Err(e) => {
                    emit_error(output_format, &e);
                }
            };

            let follower = seer_core::DnsFollower::new();

            // Set up cancellation channel
            let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

            // Set up Ctrl+C handler
            let cancel_tx_ctrlc = cancel_tx.clone();
            tokio::spawn(async move {
                tokio::signal::ctrl_c().await.ok();
                let _ = cancel_tx_ctrlc.send(true);
            });

            // Enable raw mode for Escape key detection
            // RAII guard: restores cooked mode on scope exit, including if a
            // panic unwinds through the follow loop (issue #60).
            let raw_guard = utils::RawModeGuard::new();

            // Spawn a task to listen for Escape key
            let cancel_tx_esc = cancel_tx.clone();
            let key_listener = tokio::spawn(async move {
                loop {
                    if event::poll(std::time::Duration::from_millis(100)).unwrap_or(false) {
                        if let Ok(Event::Key(KeyEvent {
                            code, modifiers, ..
                        })) = event::read()
                        {
                            match code {
                                KeyCode::Esc => {
                                    let _ = cancel_tx_esc.send(true);
                                    break;
                                }
                                KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                                    let _ = cancel_tx_esc.send(true);
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                    if cancel_tx_esc.is_closed() {
                        break;
                    }
                }
            });

            // Create progress callback for real-time output
            // Note: raw mode is enabled for key detection, so we need \r\n for proper line breaks
            let follow_format = output_format;
            let callback: seer_core::dns::FollowProgressCallback = Arc::new(move |iteration| {
                let formatter = seer_core::output::get_formatter(follow_format);
                let output = formatter.format_follow_iteration(iteration);
                // In raw mode, \n alone doesn't return to column 0, so use \r\n
                let output = output.replace('\n', "\r\n");
                let mut stdout = std::io::stdout().lock();
                let _ = stdout.write_all(output.as_bytes());
                let _ = stdout.write_all(b"\r\n");
                let _ = stdout.flush();
            });

            // In raw mode, use \r\n for proper line breaks
            print!(
                "Following {} {} records ({} iterations, {} interval)\r\n",
                domain.ctp_green(),
                record_type.ctp_yellow(),
                iterations.to_string().ctp_yellow(),
                utils::format_interval(interval_minutes)
            );
            print!(
                "Press {} or {} to stop early\r\n\r\n",
                "Esc".ctp_yellow(),
                "Ctrl+C".ctp_yellow()
            );
            let _ = std::io::stdout().flush();

            let result = follower
                .follow(&domain, rt, ns, config, Some(callback), Some(cancel_rx))
                .await;

            // Clean up: stop the key listener and restore cooked mode before
            // printing results. The guard's Drop also restores on a panic above.
            key_listener.abort();
            drop(raw_guard);

            match result {
                Ok(result) => {
                    if result.interrupted {
                        println!("\n{}", "Follow interrupted by user".ctp_yellow());
                    }
                    println!("\n{}", formatter.format_follow(&result));
                }
                Err(e) => {
                    emit_error(output_format, &e);
                }
            }
        }
        Commands::Ssl { domain } => {
            let checker = seer_core::SslChecker::from_config(config);
            match checker.check(&domain).await {
                Ok(report) => {
                    if quiet && handle_quiet_output(&report, &fields) {
                    } else {
                        println!("{}", formatter.format_ssl(&report));
                    }
                }
                Err(e) => {
                    emit_error(output_format, &e);
                }
            }
        }
        Commands::Tld { tld } => {
            let info = seer_core::lookup_tld(&tld).await;
            if quiet && handle_quiet_output(&info, &fields) {
            } else {
                println!("{}", formatter.format_tld(&info));
            }
        }
        Commands::Compare {
            domain,
            record_type,
            server_a,
            server_b,
        } => {
            let comparator = seer_core::dns::DnsComparator::new();
            let rt = parse_record_type(&record_type, output_format);
            let ns_a = server_a.trim_start_matches('@');
            let ns_b = server_b.trim_start_matches('@');
            match comparator.compare(&domain, rt, ns_a, ns_b).await {
                Ok(comparison) => {
                    if quiet && handle_quiet_output(&comparison, &fields) {
                    } else {
                        println!("{}", formatter.format_dns_comparison(&comparison));
                    }
                    if !comparison.matches {
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    emit_error(output_format, &e);
                }
            }
        }
        Commands::Subdomains { domain, resolve } => {
            let spinner = Arc::new(display::Spinner::new(&format!(
                "Enumerating subdomains for {}",
                domain
            )));
            let enumerator = seer_core::SubdomainEnumerator::new();
            match enumerator.enumerate(&domain).await {
                Ok(result) => {
                    if resolve {
                        spinner.set_message("Resolving and classifying discovered names");
                        let resolver = seer_core::DnsResolver::from_config(config);
                        let classification = seer_core::classify_subdomains(
                            &resolver,
                            &result.domain,
                            result.subdomains.clone(),
                            config.bulk.concurrency,
                        )
                        .await;
                        spinner.finish();
                        if quiet && handle_quiet_output(&classification, &fields) {
                        } else {
                            println!(
                                "{}",
                                formatter.format_subdomain_classification(&classification)
                            );
                        }
                    } else {
                        spinner.finish();
                        if quiet && handle_quiet_output(&result, &fields) {
                        } else {
                            println!("{}", formatter.format_subdomains(&result));
                        }
                    }
                }
                Err(e) => {
                    spinner.finish();
                    emit_error(output_format, &e);
                }
            }
        }
        Commands::Drift { domain, record } => {
            let spinner = Arc::new(display::Spinner::new(&format!("Looking up {}", domain)));
            let lookup = seer_core::SmartLookup::from_config(config);
            match ops::drift_check(&lookup, &domain, record).await {
                Ok(outcome) => {
                    spinner.finish();
                    if !outcome.had_previous {
                        eprintln!(
                            "{} {}",
                            "note:".ctp_yellow(),
                            ops::no_baseline_note(&domain, record)
                        );
                    }

                    if quiet && handle_quiet_output(&outcome.report, &fields) {
                    } else {
                        println!("{}", formatter.format_drift(&outcome.report));
                    }
                    if outcome.report.has_drift() {
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    spinner.finish();
                    emit_error(output_format, &e);
                }
            }
        }
        Commands::Caa { domain } => {
            let resolver = seer_core::DnsResolver::from_config(config);
            match seer_core::normalize_domain(&domain) {
                Ok(normalized) => {
                    let policy = seer_core::caa::lookup_caa(&resolver, &normalized).await;
                    if quiet && handle_quiet_output(&policy, &fields) {
                    } else {
                        println!("{}", formatter.format_caa(&policy));
                    }
                }
                Err(e) => emit_error(output_format, &e),
            }
        }
        Commands::Posture { domain } => {
            let resolver = seer_core::DnsResolver::from_config(config);
            match seer_core::lookup_email_posture(&resolver, &domain).await {
                Ok(posture) => {
                    if quiet && handle_quiet_output(&posture, &fields) {
                    } else {
                        println!("{}", formatter.format_posture(&posture));
                    }
                }
                Err(e) => emit_error(output_format, &e),
            }
        }
        Commands::Confusables { domain } => {
            let spinner = Arc::new(display::Spinner::new(&format!(
                "Scanning look-alikes for {}",
                domain
            )));
            let lookup = seer_core::SmartLookup::from_config(config);
            match seer_core::find_confusables(&lookup, &domain, config.bulk.concurrency).await {
                Ok(report) => {
                    spinner.finish();
                    if quiet && handle_quiet_output(&report, &fields) {
                    } else {
                        println!("{}", formatter.format_confusables(&report));
                    }
                }
                Err(e) => {
                    spinner.finish();
                    emit_error(output_format, &e);
                }
            }
        }
        Commands::Diff { domain_a, domain_b } => {
            let spinner = Arc::new(display::Spinner::new(&format!(
                "Comparing {} vs {}",
                domain_a, domain_b
            )));
            let differ = seer_core::DomainDiffer::new();
            match differ.diff(&domain_a, &domain_b).await {
                Ok(diff) => {
                    spinner.finish();
                    if quiet && handle_quiet_output(&diff, &fields) {
                    } else {
                        println!("{}", formatter.format_diff(&diff));
                    }
                }
                Err(e) => {
                    spinner.finish();
                    emit_error(output_format, &e);
                }
            }
        }
        Commands::Watch {
            action,
            domain,
            fail_on,
        } => {
            // Watchlist file I/O is blocking — run it on a blocking thread so it
            // doesn't stall the async runtime (mirrors the History handler).
            let mut watchlist = tokio::task::spawn_blocking(seer_core::Watchlist::load)
                .await
                .unwrap_or_default();
            match action.as_deref() {
                Some("add") => {
                    let domain = domain
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("Usage: seer watch add <domain>"))?;
                    match watchlist.add(domain) {
                        Ok(true) => {
                            let save_result =
                                tokio::task::spawn_blocking(move || watchlist.save()).await;
                            match save_result {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => return Err(e.into()),
                                Err(e) => return Err(e.into()),
                            }
                            println!("Added {} to watchlist", domain.ctp_green());
                        }
                        Ok(false) => {
                            println!("{} is already in the watchlist", domain);
                        }
                        Err(e) => {
                            eprintln!("{} Invalid domain: {}", "Error:".ctp_red(), e);
                            std::process::exit(1);
                        }
                    }
                }
                Some("remove") => {
                    let domain = domain
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("Usage: seer watch remove <domain>"))?;
                    if watchlist.remove(domain) {
                        let save_result =
                            tokio::task::spawn_blocking(move || watchlist.save()).await;
                        match save_result {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => return Err(e.into()),
                            Err(e) => return Err(e.into()),
                        }
                        println!("Removed {} from watchlist", domain.ctp_green());
                    } else {
                        println!("{} was not in the watchlist", domain);
                    }
                }
                Some("list") => {
                    if watchlist.domains.is_empty() {
                        println!(
                            "Watchlist is empty. Use 'seer watch add <domain>' to add domains."
                        );
                    } else {
                        println!("Watchlist ({} domains):", watchlist.domains.len());
                        for d in &watchlist.domains {
                            println!("  - {}", d);
                        }
                    }
                }
                None => {
                    if watchlist.domains.is_empty() {
                        println!(
                            "Watchlist is empty. Use 'seer watch add <domain>' to add domains."
                        );
                    } else {
                        let spinner = Arc::new(display::Spinner::new(&format!(
                            "Checking {} domains",
                            watchlist.domains.len()
                        )));
                        let report = seer_core::check_watchlist(&watchlist.domains).await;
                        spinner.finish();
                        if quiet && handle_quiet_output(&report, &fields) {
                        } else {
                            println!("{}", formatter.format_watch(&report));
                        }
                        // Exit 1 when issues at or above the --fail-on
                        // threshold exist (mirrors drift/avail/dnssec).
                        // `warnings` counts every result with issues, so it
                        // already subsumes the critical ones; the `||` keeps
                        // the check robust if that tally ever changes.
                        let should_fail = match fail_on {
                            FailOn::Critical => report.critical > 0,
                            FailOn::Warning => report.warnings > 0 || report.critical > 0,
                        };
                        if should_fail {
                            std::process::exit(1);
                        }
                    }
                }
                Some(other) => {
                    eprintln!(
                        "{} Unknown watch action: {}. Use: add, remove, list",
                        "Error:".ctp_red(),
                        other
                    );
                    std::process::exit(1);
                }
            }
        }
        Commands::History { domain, clear } => {
            let mut history = tokio::task::spawn_blocking(seer_core::LookupHistory::load)
                .await
                .unwrap_or_default();
            if clear {
                history.clear();
                let save_result = tokio::task::spawn_blocking(move || history.save()).await;
                match save_result {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return Err(e.into()),
                    Err(e) => return Err(e.into()),
                }
                println!("Lookup history cleared");
            } else if let Some(domain) = domain {
                let entries = history.get(&domain);
                if entries.is_empty() {
                    println!("No history for {}", domain);
                } else {
                    println!(
                        "History for {} ({} entries):",
                        domain.ctp_green(),
                        entries.len()
                    );
                    for entry in entries {
                        let source = if entry.result.is_rdap() {
                            "RDAP"
                        } else if entry.result.is_whois() {
                            "WHOIS"
                        } else {
                            "availability"
                        };
                        println!(
                            "  [{}] via {} - registrar: {}",
                            entry.timestamp.format("%Y-%m-%d %H:%M"),
                            source,
                            entry.result.registrar().unwrap_or_else(|| "—".to_string())
                        );
                    }
                }
            } else {
                let total: usize = history.entries.values().map(Vec::len).sum();
                if total == 0 {
                    println!("No lookup history. Run 'seer lookup <domain>' to build history.");
                } else {
                    println!(
                        "Lookup history ({} entries across {} domains):",
                        total,
                        history.entries.len()
                    );
                    for (domain, entries) in &history.entries {
                        println!("  {} ({} entries)", domain, entries.len());
                    }
                }
            }
        }
        Commands::Tui { domain } => {
            tui::run(domain).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod cli_error_tests {
    use super::machine_error;
    use seer_core::output::OutputFormat;

    #[test]
    fn json_error_is_parseable_and_carries_message() {
        let s = machine_error(OutputFormat::Json, "lookup failed: boom").unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).expect("valid JSON on error path");
        assert_eq!(v["error"], "lookup failed: boom");
    }

    #[test]
    fn yaml_error_is_structured_json_subset() {
        // JSON is a valid YAML document; assert it parses and carries the message.
        let s = machine_error(OutputFormat::Yaml, "boom").unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["error"], "boom");
    }

    #[test]
    fn human_error_has_no_machine_payload() {
        assert!(machine_error(OutputFormat::Human, "boom").is_none());
    }

    #[test]
    fn markdown_error_is_rendered() {
        assert_eq!(
            machine_error(OutputFormat::Markdown, "boom").unwrap(),
            "**Error:** boom"
        );
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
mod progress_mode_tests {
    use super::{resolve_progress_mode, ProgressMode};

    #[test]
    fn explicit_mode_is_honored_on_tty() {
        assert_eq!(
            resolve_progress_mode(Some(ProgressMode::Verbose), true, "human"),
            ProgressMode::Verbose
        );
        assert_eq!(
            resolve_progress_mode(Some(ProgressMode::None), true, "human"),
            ProgressMode::None
        );
    }

    #[test]
    fn explicit_mode_is_honored_on_non_tty() {
        assert_eq!(
            resolve_progress_mode(Some(ProgressMode::Bar), false, "human"),
            ProgressMode::Bar
        );
    }

    #[test]
    fn explicit_mode_overrides_json_format() {
        assert_eq!(
            resolve_progress_mode(Some(ProgressMode::Bar), true, "json"),
            ProgressMode::Bar
        );
    }

    #[test]
    fn default_is_bar_on_tty_with_human_format() {
        assert_eq!(
            resolve_progress_mode(None, true, "human"),
            ProgressMode::Bar
        );
    }

    #[test]
    fn default_is_none_on_non_tty() {
        assert_eq!(
            resolve_progress_mode(None, false, "human"),
            ProgressMode::None
        );
    }

    #[test]
    fn default_is_none_with_json_format() {
        assert_eq!(
            resolve_progress_mode(None, true, "json"),
            ProgressMode::None
        );
    }

    #[test]
    fn explicit_format_flag_overrides_config_default() {
        use seer_core::output::OutputFormat;
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
        use seer_core::output::OutputFormat;
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
        use seer_core::output::OutputFormat;
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
