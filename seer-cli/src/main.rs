mod display;
mod repl;
mod utils;

use std::io::Write;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal;
use seer_core::colors::CatppuccinExt;
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
  domain,success,http_status,http_status_text,title,ssl_issuer,ssl_valid_until,ssl_days_remaining,domain_expires,domain_days_remaining,registrar,dns_resolves,dns_a_records,dns_aaaa_records,dns_cname,dns_nameservers,duration_ms,error
  example.com,true,200,OK,Example Domain,DigiCert Inc,2025-03-01,89,2025-08-13,204,RESERVED-Internet Assigned Numbers Authority,true,93.184.216.34,2606:2800:220:1:248:1893:25c8:1946,,a.iana-servers.net;b.iana-servers.net,1245,
  google.com,true,200,OK,Google,Google Trust Services,2025-02-15,75,2028-09-14,1332,MarkMonitor Inc.,true,142.250.185.46,2607:f8b0:4004:800::200e,,ns1.google.com;ns2.google.com,892,

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

    /// Output format (human, json, or yaml)
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
    Prop {
        /// Domain name to check
        domain: String,
        /// Record type to check
        #[arg(default_value = "A")]
        record_type: String,
    },
    /// Execute bulk operations from a file, output results to CSV
    #[command(after_long_help = BULK_EXAMPLES)]
    Bulk {
        /// Operation type: lookup, whois, rdap, dig, prop, status
        #[arg(value_name = "OPERATION")]
        operation: String,

        /// Input file path (text or CSV format)
        #[arg(value_name = "FILE")]
        file: String,

        /// Record type for dig/prop operations
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing with progress-aware writer
    // This routes log output through the progress bar when one is active,
    // preventing logs from interfering with progress bar display
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(display::ProgressWriterFactory::new())
        .init();

    let cli = Cli::parse();

    // Use config file default when --format is not explicitly provided
    let output_format: seer_core::output::OutputFormat = if cli.format == "human" {
        // Could be explicit or default; check config for a different preference
        let config = seer_core::SeerConfig::load();
        config.output_format.parse().unwrap_or_default()
    } else {
        cli.format.parse().unwrap_or_default()
    };

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
            let spinner = std::sync::Arc::new(display::Spinner::new(&format!(
                "Smart lookup for {} (trying RDAP first)",
                domain
            )));

            // Create progress callback that updates the spinner
            let spinner_clone = spinner.clone();
            let progress: seer_core::LookupProgressCallback = std::sync::Arc::new(move |message| {
                spinner_clone.set_message(message);
            });

            let lookup = seer_core::SmartLookup::new();
            match lookup.lookup_with_progress(&domain, Some(progress)).await {
                Ok(result) => {
                    spinner.finish();
                    println!("{}", formatter.format_lookup(&result));
                }
                Err(e) => {
                    spinner.finish();
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
        Commands::Prop {
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
                        "{} Unknown operation: {}. Use: lookup, whois, rdap, dig/dns, prop, status",
                        "Error:".ctp_red(),
                        operation
                    );
                    std::process::exit(1);
                }
            };

            let results = executor.execute(operations, None).await;

            // Convert results to CSV
            let csv_content = utils::bulk_results_to_csv(&results, &operation);
            std::fs::write(&output_path, csv_content)?;

            let success_count = results.iter().filter(|r| r.success).count();
            let fail_count = results.len() - success_count;

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
        Commands::Reverse { ip } => {
            let resolver = seer_core::DnsResolver::new();
            match resolver
                .resolve(&ip, seer_core::RecordType::PTR, None)
                .await
            {
                Ok(records) => {
                    println!("{}", formatter.format_dns(&records));
                }
                Err(e) => {
                    eprintln!("{} {}", "Error:".ctp_red(), e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Avail { domain } => {
            let checker = seer_core::AvailabilityChecker::new();
            match checker.check(&domain).await {
                Ok(result) => {
                    println!("{}", formatter.format_availability(&result));
                }
                Err(e) => {
                    eprintln!("{} {}", "Error:".ctp_red(), e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Dnssec { domain } => {
            let checker = seer_core::DnssecChecker::new();
            match checker.check(&domain).await {
                Ok(report) => {
                    println!("{}", formatter.format_dnssec(&report));
                }
                Err(e) => {
                    eprintln!("{} {}", "Error:".ctp_red(), e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            generate(shell, &mut cmd, "seer", &mut std::io::stdout());
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
            let callback: seer_core::dns::FollowProgressCallback =
                std::sync::Arc::new(move |iteration| {
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
