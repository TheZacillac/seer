mod display;
mod repl;

use clap::{Parser, Subcommand};
use seer_core::colors::CatppuccinExt;
use tracing_subscriber::EnvFilter;

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
    /// Execute bulk operations from a file
    Bulk {
        /// Operation type (lookup, whois, rdap, dig, propagation, status)
        operation: String,
        /// File containing domains: one per line, # for comments, or CSV (uses first column)
        file: String,
        /// Record type for dig/propagation operations
        #[arg(default_value = "A")]
        record_type: String,
    },
    /// Check domain status (HTTP, SSL cert, registration expiration)
    Status {
        /// Domain name to check
        domain: String,
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

            let rt: seer_core::RecordType = record_type.parse().unwrap_or(seer_core::RecordType::A);
            let executor = seer_core::BulkExecutor::new();

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

            // Output results as JSON array for bulk operations
            println!("{}", serde_json::to_string_pretty(&results)?);
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
    }

    Ok(())
}
