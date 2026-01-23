mod display;
mod repl;

use clap::{Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal;
use seer_core::colors::CatppuccinExt;
use seer_core::output::OutputFormatter;
use tracing_subscriber::EnvFilter;

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
  seer bulk status domains.txt -o out.csv   # Output: out.csv

Example Output (status operation):
  domain,success,http_status,http_status_text,title,ssl_issuer,ssl_valid_until,ssl_days_remaining,domain_expires,domain_days_remaining,registrar,duration_ms,error
  example.com,true,200,OK,Example Domain,DigiCert Inc,2025-03-01,89,2025-08-13,204,RESERVED-Internet Assigned Numbers Authority,1245,
  google.com,true,200,OK,Google,Google Trust Services,2025-02-15,75,2028-09-14,1332,MarkMonitor Inc.,892,

Example Output (lookup/whois/rdap operation):
  domain,success,registrar,created,expires,updated,duration_ms,error
  example.com,true,RESERVED-Internet Assigned Numbers Authority,1995-08-14,2025-08-13,2024-08-14,523,
  google.com,true,MarkMonitor Inc.,1997-09-15,2028-09-14,2019-09-09,412,

Example Output (dig operation):
  domain,success,record_type,records,duration_ms,error
  example.com,true,A,93.184.216.34,45,
  google.com,true,MX,10 smtp.google.com; 20 smtp2.google.com,38,
"#;

#[derive(Parser)]
#[command(name = "seer")]
#[command(about = "Domain name helper - WHOIS, RDAP, DIG, and propagation checking")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Output format (human or json)
    #[arg(short, long, default_value = "human")]
    format: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Smart lookup (tries RDAP first, falls back to WHOIS)
    Lookup {
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
    Propagation {
        /// Domain name to check
        domain: String,
        /// Record type to check
        #[arg(default_value = "A")]
        record_type: String,
    },
    /// Execute bulk operations from a file, output results to CSV
    #[command(after_long_help = BULK_EXAMPLES)]
    Bulk {
        /// Operation type: lookup, whois, rdap, dig, propagation, status
        #[arg(value_name = "OPERATION")]
        operation: String,

        /// Input file path (text or CSV format)
        #[arg(value_name = "FILE")]
        file: String,

        /// Record type for dig/propagation operations
        #[arg(value_name = "TYPE", default_value = "A")]
        record_type: String,

        /// Output CSV file path (defaults to <input>_results.csv)
        #[arg(short, long, value_name = "OUTPUT")]
        output: Option<String>,
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    let output_format: seer_core::output::OutputFormat = cli.format.parse().unwrap_or_default();

    match cli.command {
        Some(cmd) => execute_command(cmd, output_format).await,
        None => {
            // Start interactive REPL
            let mut repl = repl::Repl::new()?;
            repl.run().await
        }
    }
}

async fn execute_command(
    command: Commands,
    output_format: seer_core::output::OutputFormat,
) -> anyhow::Result<()> {
    let formatter = seer_core::output::get_formatter(output_format);

    match command {
        Commands::Lookup { domain } => {
            let lookup = seer_core::SmartLookup::new();
            match lookup.lookup(&domain).await {
                Ok(result) => {
                    println!("{}", formatter.format_lookup(&result));
                }
                Err(e) => {
                    eprintln!("{} {}", "Error:".ctp_red(), e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Whois { domain } => {
            let client = seer_core::WhoisClient::new();
            match client.lookup(&domain).await {
                Ok(response) => {
                    println!("{}", formatter.format_whois(&response));
                }
                Err(e) => {
                    eprintln!("{} {}", "Error:".ctp_red(), e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Rdap { query } => {
            let client = seer_core::RdapClient::new();
            let result = if query.starts_with("AS") || query.starts_with("as") {
                let asn: u32 = query[2..].parse()?;
                client.lookup_asn(asn).await
            } else if query.parse::<std::net::IpAddr>().is_ok() {
                client.lookup_ip(&query).await
            } else {
                client.lookup_domain(&query).await
            };

            match result {
                Ok(response) => {
                    println!("{}", formatter.format_rdap(&response));
                }
                Err(e) => {
                    eprintln!("{} {}", "Error:".ctp_red(), e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Dig {
            domain,
            record_type,
            server,
        } => {
            let resolver = seer_core::DnsResolver::new();
            let rt: seer_core::RecordType = record_type.parse()?;
            let ns = server.as_ref().map(|s| s.trim_start_matches('@'));

            match resolver.resolve(&domain, rt, ns).await {
                Ok(records) => {
                    println!("{}", formatter.format_dns(&records));
                }
                Err(e) => {
                    eprintln!("{} {}", "Error:".ctp_red(), e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Propagation {
            domain,
            record_type,
        } => {
            let checker = seer_core::dns::PropagationChecker::new();
            let rt: seer_core::RecordType = record_type.parse()?;

            match checker.check(&domain, rt).await {
                Ok(result) => {
                    println!("{}", formatter.format_propagation(&result));
                }
                Err(e) => {
                    eprintln!("{} {}", "Error:".ctp_red(), e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Bulk {
            operation,
            file,
            record_type,
            output,
        } => {
            let content = std::fs::read_to_string(&file)?;
            let domains = seer_core::bulk::parse_domains_from_file(&content);

            if domains.is_empty() {
                eprintln!(
                    "{} No valid domains found in file. Expected format: one domain per line, # for comments, or CSV (first column)",
                    "Error:".ctp_red()
                );
                std::process::exit(1);
            }

            // Determine output path
            let output_path = output.unwrap_or_else(|| {
                let input_path = std::path::Path::new(&file);
                let stem = input_path.file_stem().unwrap_or_default().to_string_lossy();
                let parent = input_path.parent().unwrap_or(std::path::Path::new("."));
                parent
                    .join(format!("{}_results.csv", stem))
                    .to_string_lossy()
                    .to_string()
            });

            let rt: seer_core::RecordType = record_type.parse().unwrap_or(seer_core::RecordType::A);
            let executor = seer_core::BulkExecutor::new();

            println!(
                "Processing {} domains with {} operation...",
                domains.len().to_string().ctp_green(),
                operation.ctp_yellow()
            );

            let operations: Vec<seer_core::bulk::BulkOperation> = match operation.as_str() {
                "lookup" => domains
                    .iter()
                    .map(|d: &String| seer_core::bulk::BulkOperation::Lookup { domain: d.clone() })
                    .collect(),
                "whois" => domains
                    .iter()
                    .map(|d: &String| seer_core::bulk::BulkOperation::Whois { domain: d.clone() })
                    .collect(),
                "rdap" => domains
                    .iter()
                    .map(|d: &String| seer_core::bulk::BulkOperation::Rdap { domain: d.clone() })
                    .collect(),
                "dig" | "dns" => domains
                    .iter()
                    .map(|d: &String| seer_core::bulk::BulkOperation::Dns {
                        domain: d.clone(),
                        record_type: rt,
                    })
                    .collect(),
                "propagation" | "prop" => domains
                    .iter()
                    .map(|d: &String| seer_core::bulk::BulkOperation::Propagation {
                        domain: d.clone(),
                        record_type: rt,
                    })
                    .collect(),
                "status" => domains
                    .iter()
                    .map(|d: &String| seer_core::bulk::BulkOperation::Status { domain: d.clone() })
                    .collect(),
                _ => {
                    eprintln!(
                        "{} Unknown operation: {}. Use: lookup, whois, rdap, dig, propagation, status",
                        "Error:".ctp_red(),
                        operation
                    );
                    std::process::exit(1);
                }
            };

            let results = executor.execute(operations, None).await;

            // Convert results to CSV
            let csv_content = bulk_results_to_csv(&results, &operation);
            std::fs::write(&output_path, csv_content)?;

            let success_count = results.iter().filter(|r| r.success).count();
            let fail_count = results.len() - success_count;

            println!(
                "Results written to: {}",
                output_path.ctp_green()
            );
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
        Commands::Status { domain } => {
            let client = seer_core::StatusClient::new();
            match client.check(&domain).await {
                Ok(response) => {
                    println!("{}", formatter.format_status(&response));
                }
                Err(e) => {
                    eprintln!("{} {}", "Error:".ctp_red(), e);
                    std::process::exit(1);
                }
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
            let rt: seer_core::RecordType = record_type.parse()?;
            let ns = server.as_ref().map(|s| s.trim_start_matches('@'));

            let config = seer_core::FollowConfig::new(iterations, interval_minutes)
                .with_changes_only(changes_only);

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
            let raw_mode_enabled = terminal::enable_raw_mode().is_ok();

            // Spawn a task to listen for Escape key
            let cancel_tx_esc = cancel_tx.clone();
            let key_listener = tokio::spawn(async move {
                loop {
                    if event::poll(std::time::Duration::from_millis(100)).unwrap_or(false) {
                        if let Ok(Event::Key(KeyEvent { code, modifiers, .. })) = event::read() {
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
            let use_json = matches!(output_format, seer_core::output::OutputFormat::Json);
            let callback: seer_core::dns::FollowProgressCallback =
                std::sync::Arc::new(move |iteration| {
                    if use_json {
                        let json_formatter = seer_core::output::JsonFormatter::new();
                        println!("{}", json_formatter.format_follow_iteration(iteration));
                    } else {
                        let human_formatter = seer_core::output::HumanFormatter::new();
                        println!("{}", human_formatter.format_follow_iteration(iteration));
                    }
                });

            println!(
                "Following {} {} records ({} iterations, {} interval)",
                domain.ctp_green(),
                record_type.ctp_yellow(),
                iterations.to_string().ctp_yellow(),
                format_interval(interval_minutes)
            );
            println!("Press {} or {} to stop early\n", "Esc".ctp_yellow(), "Ctrl+C".ctp_yellow());

            let result = follower
                .follow(&domain, rt, ns, config, Some(callback), Some(cancel_rx))
                .await;

            // Clean up
            key_listener.abort();
            if raw_mode_enabled {
                let _ = terminal::disable_raw_mode();
            }

            match result {
                Ok(result) => {
                    if result.interrupted {
                        println!("\n{}", "Follow interrupted by user".ctp_yellow());
                    }
                    println!("\n{}", formatter.format_follow(&result));
                }
                Err(e) => {
                    eprintln!("{} {}", "Error:".ctp_red(), e);
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}

fn format_interval(minutes: f64) -> String {
    if minutes < 1.0 {
        format!("{}s", (minutes * 60.0) as u64)
    } else if minutes == 1.0 {
        "1m".to_string()
    } else {
        format!("{}m", minutes)
    }
}

fn bulk_results_to_csv(results: &[seer_core::bulk::BulkResult], operation: &str) -> String {
    use seer_core::bulk::BulkResultData;

    let mut csv = String::new();

    // Write header based on operation type
    match operation {
        "status" => {
            csv.push_str("domain,success,http_status,http_status_text,title,ssl_issuer,ssl_valid_until,ssl_days_remaining,domain_expires,domain_days_remaining,registrar,duration_ms,error\n");
        }
        "lookup" | "whois" | "rdap" => {
            csv.push_str("domain,success,registrar,created,expires,updated,duration_ms,error\n");
        }
        "dig" | "dns" => {
            csv.push_str("domain,success,record_type,records,duration_ms,error\n");
        }
        "propagation" | "prop" => {
            csv.push_str("domain,success,propagation_pct,servers_total,servers_responded,duration_ms,error\n");
        }
        _ => {
            csv.push_str("domain,success,duration_ms,error\n");
        }
    }

    // Write data rows
    for result in results {
        let domain = get_domain_from_operation(&result.operation);
        let success = result.success;
        let duration_ms = result.duration_ms;
        let error = escape_csv_field(result.error.as_deref().unwrap_or(""));

        match operation {
            "status" => {
                let (http_status, http_text, title, ssl_issuer, ssl_valid_until, ssl_days, domain_expires, domain_days, registrar) =
                    if let Some(BulkResultData::Status(ref s)) = result.data {
                        (
                            s.http_status.map(|v: u16| v.to_string()).unwrap_or_default(),
                            s.http_status_text.clone().unwrap_or_default(),
                            s.title.clone().unwrap_or_default(),
                            s.certificate.as_ref().map(|c| c.issuer.clone()).unwrap_or_default(),
                            s.certificate.as_ref().map(|c| c.valid_until.format("%Y-%m-%d").to_string()).unwrap_or_default(),
                            s.certificate.as_ref().map(|c| c.days_until_expiry.to_string()).unwrap_or_default(),
                            s.domain_expiration.as_ref().map(|d| d.expiration_date.format("%Y-%m-%d").to_string()).unwrap_or_default(),
                            s.domain_expiration.as_ref().map(|d| d.days_until_expiry.to_string()).unwrap_or_default(),
                            s.domain_expiration.as_ref().and_then(|d| d.registrar.clone()).unwrap_or_default(),
                        )
                    } else {
                        Default::default()
                    };
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                    domain, success, http_status,
                    escape_csv_field(&http_text),
                    escape_csv_field(&title),
                    escape_csv_field(&ssl_issuer),
                    ssl_valid_until, ssl_days, domain_expires, domain_days,
                    escape_csv_field(&registrar),
                    duration_ms, error
                ));
            }
            "lookup" => {
                let (registrar, created, expires, updated) = if let Some(ref data) = result.data {
                    match data {
                        BulkResultData::Lookup(seer_core::lookup::LookupResult::Rdap { data: r, .. }) => {
                            extract_rdap_dates(r)
                        }
                        BulkResultData::Lookup(seer_core::lookup::LookupResult::Whois { data: w, .. }) => {
                            (
                                w.registrar.clone().unwrap_or_default(),
                                w.creation_date.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default(),
                                w.expiration_date.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default(),
                                w.updated_date.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default(),
                            )
                        }
                        _ => Default::default(),
                    }
                } else {
                    Default::default()
                };
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{}\n",
                    domain, success, escape_csv_field(&registrar), created, expires, updated, duration_ms, error
                ));
            }
            "whois" => {
                let (registrar, created, expires, updated) = if let Some(BulkResultData::Whois(ref w)) = result.data {
                    (
                        w.registrar.clone().unwrap_or_default(),
                        w.creation_date.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default(),
                        w.expiration_date.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default(),
                        w.updated_date.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default(),
                    )
                } else {
                    Default::default()
                };
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{}\n",
                    domain, success, escape_csv_field(&registrar), created, expires, updated, duration_ms, error
                ));
            }
            "rdap" => {
                let (registrar, created, expires, updated) = if let Some(BulkResultData::Rdap(ref r)) = result.data {
                    extract_rdap_dates(r)
                } else {
                    Default::default()
                };
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{}\n",
                    domain, success, escape_csv_field(&registrar), created, expires, updated, duration_ms, error
                ));
            }
            "dig" | "dns" => {
                let (record_type, records) = if let Some(BulkResultData::Dns(ref recs)) = result.data {
                    let rt = recs.first().map(|r| r.record_type.to_string()).unwrap_or_default();
                    let vals: Vec<String> = recs.iter().map(|r| r.format_short()).collect();
                    (rt, vals.join("; "))
                } else {
                    Default::default()
                };
                csv.push_str(&format!(
                    "{},{},{},{},{},{}\n",
                    domain, success, record_type, escape_csv_field(&records), duration_ms, error
                ));
            }
            "propagation" | "prop" => {
                let (pct, total, responded) = if let Some(BulkResultData::Propagation(ref p)) = result.data {
                    let total = p.results.len();
                    let responded = p.results.iter().filter(|r| r.success).count();
                    let pct = if total > 0 { (responded as f64 / total as f64) * 100.0 } else { 0.0 };
                    (format!("{:.1}", pct), total.to_string(), responded.to_string())
                } else {
                    Default::default()
                };
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{}\n",
                    domain, success, pct, total, responded, duration_ms, error
                ));
            }
            _ => {
                csv.push_str(&format!(
                    "{},{},{},{}\n",
                    domain, success, duration_ms, error
                ));
            }
        }
    }

    csv
}

fn escape_csv_field(s: &str) -> String {
    // Protect against CSV injection by prefixing formula-starting characters with a single quote
    // This prevents Excel/Sheets from interpreting the content as a formula
    let s = if s.starts_with('=')
        || s.starts_with('+')
        || s.starts_with('-')
        || s.starts_with('@')
        || s.starts_with('\t')
        || s.starts_with('\r')
    {
        format!("'{}", s)
    } else {
        s.to_string()
    };

    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

fn get_domain_from_operation(op: &seer_core::bulk::BulkOperation) -> String {
    use seer_core::bulk::BulkOperation;
    match op {
        BulkOperation::Whois { domain } => domain.clone(),
        BulkOperation::Rdap { domain } => domain.clone(),
        BulkOperation::Dns { domain, .. } => domain.clone(),
        BulkOperation::Propagation { domain, .. } => domain.clone(),
        BulkOperation::Lookup { domain } => domain.clone(),
        BulkOperation::Status { domain } => domain.clone(),
    }
}

fn extract_rdap_dates(r: &seer_core::rdap::RdapResponse) -> (String, String, String, String) {
    let registrar = r.get_registrar().unwrap_or_default();

    let created = r.creation_date()
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default();

    let expires = r.expiration_date()
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default();

    let updated = r.last_updated()
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default();

    (registrar, created, expires, updated)
}
