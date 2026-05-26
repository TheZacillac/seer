mod commands;
mod completer;

pub use commands::{CommandContext, CommandResult};
pub use completer::SeerCompleter;

use std::io::Write;
use std::sync::Arc;

use colored::Colorize;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal;
use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;
use rustyline::{CompletionType, Editor};
use seer_core::colors::CatppuccinExt;
use tokio::sync::watch;

use crate::display::{clear_bulk_progress_bar, set_bulk_progress_bar, Spinner};

const HISTORY_FILE: &str = ".seer_history";

pub struct Repl {
    editor: Editor<SeerCompleter, DefaultHistory>,
    context: CommandContext,
    whois_client: seer_core::WhoisClient,
    rdap_client: seer_core::RdapClient,
    dns_resolver: seer_core::DnsResolver,
    propagation_checker: seer_core::dns::PropagationChecker,
    status_client: seer_core::StatusClient,
    dnssec_checker: seer_core::DnssecChecker,
    availability_checker: seer_core::AvailabilityChecker,
    dns_follower: seer_core::DnsFollower,
}

impl Repl {
    pub fn new() -> anyhow::Result<Self> {
        let config = rustyline::Config::builder()
            .history_ignore_space(true)
            .completion_type(CompletionType::List)
            .edit_mode(rustyline::EditMode::Emacs)
            .build();

        let completer = SeerCompleter::new();
        let mut editor = Editor::with_config(config)?;
        editor.set_helper(Some(completer));

        // Load history
        let history_path = dirs::home_dir()
            .map(|p| p.join(HISTORY_FILE))
            .unwrap_or_else(|| HISTORY_FILE.into());

        let _ = editor.load_history(&history_path);

        Ok(Self {
            editor,
            context: CommandContext::new(),
            whois_client: seer_core::WhoisClient::new(),
            rdap_client: seer_core::RdapClient::new(),
            dns_resolver: seer_core::DnsResolver::new(),
            propagation_checker: seer_core::dns::PropagationChecker::new(),
            status_client: seer_core::StatusClient::new(),
            dnssec_checker: seer_core::DnssecChecker::new(),
            availability_checker: seer_core::AvailabilityChecker::new(),
            dns_follower: seer_core::DnsFollower::new(),
        })
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        self.print_banner();

        let mut last_ctrl_c: Option<std::time::Instant> = None;

        loop {
            let prompt = self.get_prompt();

            match self.editor.readline(&prompt) {
                Ok(line) => {
                    last_ctrl_c = None;
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }

                    self.editor.add_history_entry(line)?;

                    match self.execute_line(line).await {
                        CommandResult::Continue => {}
                        CommandResult::Exit => break,
                        CommandResult::Error(e) => {
                            eprintln!("{} {}", "Error:".ctp_red().bold(), e);
                        }
                    }

                    // Add blank line before next prompt for readability
                    println!();
                }
                Err(ReadlineError::Interrupted) => {
                    if last_ctrl_c.is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(2))
                    {
                        println!("exit");
                        break;
                    }
                    last_ctrl_c = Some(std::time::Instant::now());
                    println!("{}", "Press Ctrl+C again to exit (or type 'exit')".dimmed());
                    continue;
                }
                Err(ReadlineError::Eof) => {
                    println!("exit");
                    break;
                }
                Err(err) => {
                    eprintln!("{} {:?}", "Error:".ctp_red().bold(), err);
                    break;
                }
            }
        }

        // Save history
        let history_path = dirs::home_dir()
            .map(|p| p.join(HISTORY_FILE))
            .unwrap_or_else(|| HISTORY_FILE.into());

        let _ = self.editor.save_history(&history_path);

        Ok(())
    }

    fn print_banner(&self) {
        println!();
        println!("{}", "  ✦ ·:*¨¨¨¨¨¨¨¨¨¨¨¨¨¨¨¨*:· ✦".bright_cyan());
        println!("{}", "   ╔═╗    ╔═╗    ╔═╗    ╦═╗".bright_purple());
        println!("{}", "   ╚═╗    ╠═     ╠═     ╠╦╝".bright_purple());
        println!("{}", "   ╚═╝    ╚═╝    ╚═╝    ╩╚═".bright_purple());
        println!("{}", "  ✦ '·:*¨¨¨¨¨¨¨¨¨¨¨¨¨¨*:·' ✦".bright_cyan());
        println!();
        println!(
            "  {} - Domain Name Helper",
            format!("Seer v{}", env!("CARGO_PKG_VERSION"))
                .bright_purple()
                .bold()
        );
        println!("  Type {} for available commands\n", "help".bright_green());
    }

    fn get_prompt(&self) -> String {
        let format_indicator = match self.context.output_format {
            seer_core::output::OutputFormat::Human => "",
            seer_core::output::OutputFormat::Json => " [json]",
            seer_core::output::OutputFormat::Yaml => " [yaml]",
            seer_core::output::OutputFormat::Markdown => " [md]",
        };
        format!(
            "{}{} ",
            "seer".bright_cyan().bold(),
            format!("{}›", format_indicator).white()
        )
    }

    async fn execute_line(&mut self, line: &str) -> CommandResult {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return CommandResult::Continue;
        }

        let command = parts[0].to_lowercase();
        let args = &parts[1..];

        match command.as_str() {
            "help" | "?" => {
                self.print_help();
                CommandResult::Continue
            }
            "exit" | "quit" | "q" => CommandResult::Exit,
            "lookup" => self.execute_lookup(args).await,
            "info" => self.execute_info(args).await,
            "whois" => self.execute_whois(args).await,
            "rdap" => self.execute_rdap(args).await,
            "dig" | "dns" => self.execute_dig(args).await,
            "propagation" | "prop" => self.execute_propagation(args).await,
            "reverse" => self.execute_reverse(args).await,
            "avail" => self.execute_avail(args).await,
            "dnssec" => self.execute_dnssec(args).await,
            "bulk" => self.execute_bulk(args).await,
            "status" => self.execute_status(args).await,
            "follow" => self.execute_follow(args).await,
            "ssl" => self.execute_ssl(args).await,
            "tld" => self.execute_tld(args).await,
            "compare" => self.execute_compare(args).await,
            "subdomains" | "subs" => self.execute_subdomains(args).await,
            "diff" => self.execute_diff(args).await,
            "watch" => self.execute_watch(args).await,
            "history" => self.execute_history(args).await,
            "set" => self.execute_set(args),
            "clear" => {
                print!("\x1B[2J\x1B[1;1H");
                let _ = std::io::stdout().flush();
                CommandResult::Continue
            }
            // Default: treat as domain lookup if it looks like a domain
            _ => {
                // If the input contains a dot, assume it's a domain and run lookup
                if command.contains('.') {
                    self.execute_lookup(&parts).await
                } else {
                    CommandResult::Error(format!(
                        "Unknown command: {}. Type 'help' for available commands.",
                        command
                    ))
                }
            }
        }
    }

    fn print_help(&self) {
        println!();
        println!("{}", "LOOKUP COMMANDS".bright_purple().bold());
        println!(
            "  {:<34} Smart lookup (just type a domain directly)",
            "<domain>".bright_cyan()
        );
        println!(
            "  {:<34} Comprehensive domain info (RDAP + WHOIS merged)",
            "info <domain>".bright_cyan()
        );
        println!(
            "  {:<34} Query WHOIS information",
            "whois <domain>".bright_cyan()
        );
        println!(
            "  {:<34} Query RDAP registry data",
            "rdap <domain|ip|asn>".bright_cyan()
        );
        println!();
        println!("{}", "DNS COMMANDS".bright_purple().bold());
        println!(
            "  {:<34} Query DNS records",
            "dig <domain> [type] [@server]".bright_cyan()
        );
        println!(
            "  {:<34} Check DNS propagation globally",
            "prop <domain> [type]".bright_cyan()
        );
        println!(
            "  {:<34} Monitor DNS records over time",
            "follow <domain> [n] [mins] [type] [@server] [--changes-only]".bright_cyan()
        );
        println!(
            "  {}",
            "Record types: A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV, CAA".dimmed()
        );
        println!(
            "  {:<34} Compare DNS records across nameservers",
            "compare <domain> [type] @ns1 @ns2".bright_cyan()
        );
        println!();
        println!("{}", "UTILITY COMMANDS".bright_purple().bold());
        println!(
            "  {:<34} Reverse DNS lookup for an IP",
            "reverse <ip>".bright_cyan()
        );
        println!(
            "  {:<34} Check domain registration availability",
            "avail <domain>".bright_cyan()
        );
        println!(
            "  {:<34} Check DNSSEC configuration",
            "dnssec <domain>".bright_cyan()
        );
        println!(
            "  {:<34} Look up TLD info (WHOIS server, RDAP, registry)",
            "tld <tld>".bright_cyan()
        );
        println!(
            "  {:<34} Enumerate subdomains via CT logs",
            "subdomains <domain>".bright_cyan()
        );
        println!();
        println!("{}", "STATUS & SSL".bright_purple().bold());
        println!(
            "  {:<34} Check HTTP, SSL, and domain expiration",
            "status <domain>".bright_cyan()
        );
        println!(
            "  {:<34} Inspect SSL certificate chain and SANs",
            "ssl <domain>".bright_cyan()
        );
        println!();
        println!("{}", "COMPARISON".bright_purple().bold());
        println!(
            "  {:<34} Compare two domains side-by-side",
            "diff <domain1> <domain2>".bright_cyan()
        );
        println!();
        println!("{}", "MONITORING".bright_purple().bold());
        println!(
            "  {:<34} Check watchlist / add / remove / list",
            "watch [add|remove|list] [domain]".bright_cyan()
        );
        println!(
            "  {:<34} View lookup history",
            "history [domain] [--clear]".bright_cyan()
        );
        println!();
        println!("{}", "BULK OPERATIONS".bright_purple().bold());
        println!(
            "  {:<34} Run bulk operations from file",
            "bulk <op> <file>".bright_cyan()
        );
        println!(
            "  {}",
            "Operations: lookup, whois, rdap, dig, prop, status, avail, info, ssl".dimmed()
        );
        println!();
        println!("{}", "SETTINGS".bright_purple().bold());
        println!(
            "  {:<34} Change output format",
            "set output <human|json|yaml|markdown>".bright_cyan()
        );
        println!("  {:<34} Clear screen", "clear".bright_cyan());
        println!("  {:<34} Exit the program", "exit".bright_cyan());
        println!();
    }

    fn print_bulk_help(&self) {
        println!();
        println!("{}", "BULK OPERATIONS".bright_purple().bold());
        println!();
        println!("{}", "Usage:".bright_cyan());
        println!("  bulk <operation> <file> [type] [-o output.csv]");
        println!();
        println!("{}", "Operations:".bright_cyan());
        println!(
            "  {}      Smart lookup (RDAP first, WHOIS fallback)",
            "lookup".bright_green()
        );
        println!("  {}       Query WHOIS information", "whois".bright_green());
        println!(
            "  {}        Query RDAP registry data",
            "rdap".bright_green()
        );
        println!("  {}         Query DNS records", "dig".bright_green());
        println!(
            "  {}        Check DNS propagation globally",
            "prop".bright_green()
        );
        println!(
            "  {}      Check HTTP, SSL, and domain expiration",
            "status".bright_green()
        );
        println!(
            "  {}       Check domain registration availability",
            "avail".bright_green()
        );
        println!(
            "  {}        Comprehensive domain info (RDAP + WHOIS merged)",
            "info".bright_green()
        );
        println!(
            "  {}         Inspect SSL certificate chain (deep)",
            "ssl".bright_green()
        );
        println!();
        println!("{}", "Input File Formats:".bright_cyan());
        println!("  Plain text (one domain per line, # for comments):");
        println!("    {}  # My domains", "#".dimmed());
        println!("    example.com");
        println!("    google.com");
        println!();
        println!("  CSV (uses first column, skips header if present):");
        println!("    domain,owner,notes");
        println!("    example.com,Alice,Main site");
        println!();
        println!("{}", "Output:".bright_cyan());
        println!("  Results are written to CSV file (default: <input>_results.csv)");
        println!("  Use -o to specify custom output path");
        println!();
        println!("{}", "Examples:".bright_cyan());
        println!("  bulk status domains.txt");
        println!("  bulk lookup domains.csv -o results.csv");
        println!("  bulk dig domains.txt MX");
        println!();
        println!("{}", "CSV Output Columns by Operation:".bright_cyan());
        println!(
            "  {}: domain, http_status, ssl_days_remaining, domain_expires, ...",
            "status".bright_green()
        );
        println!(
            "  {}: domain, registrar, created, expires, updated, ...",
            "lookup".bright_green()
        );
        println!(
            "  {}: domain, record_type, records, ...",
            "dig".bright_green()
        );
        println!();
    }

    async fn execute_lookup(&self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: lookup <domain>".to_string());
        }

        let domain = args[0];
        let spinner = Arc::new(Spinner::new(&format!(
            "Smart lookup for {} (trying RDAP first)",
            domain
        )));

        // Create progress callback that updates the spinner
        let spinner_clone = spinner.clone();
        let progress: seer_core::LookupProgressCallback = Arc::new(move |message| {
            spinner_clone.set_message(message);
        });

        let lookup = seer_core::SmartLookup::new();
        match lookup.lookup_with_progress(domain, Some(progress)).await {
            Ok(result) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_lookup(&result));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_info(&self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: info <domain>".to_string());
        }

        let domain = args[0];
        let spinner = Arc::new(Spinner::new(&format!(
            "Getting comprehensive info for {}",
            domain
        )));

        let lookup = seer_core::SmartLookup::new();
        match lookup.lookup(domain).await {
            Ok(result) => {
                spinner.finish();
                let info = seer_core::DomainInfo::from_lookup_result(&result);
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_domain_info(&info));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(format!("Info failed: {}", e))
            }
        }
    }

    async fn execute_whois(&self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: whois <domain>".to_string());
        }

        let domain = args[0];
        let spinner = Spinner::new(&format!("Looking up WHOIS for {}", domain));

        match self.whois_client.lookup(domain).await {
            Ok(response) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_whois(&response));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_rdap(&self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: rdap <domain|ip|asn>".to_string());
        }

        let query = args[0];
        let spinner = Spinner::new(&format!("Looking up RDAP for {}", query));

        // Determine query type
        let result = if query.starts_with("AS") || query.starts_with("as") {
            match query[2..].parse::<u32>() {
                Ok(asn) => self.rdap_client.lookup_asn(asn).await,
                Err(_) => {
                    spinner.finish();
                    return CommandResult::Error("Invalid ASN format".to_string());
                }
            }
        } else if query.parse::<std::net::IpAddr>().is_ok() {
            self.rdap_client.lookup_ip(query).await
        } else {
            self.rdap_client.lookup_domain(query).await
        };

        match result {
            Ok(response) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_rdap(&response));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_dig(&self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: dig <domain> [type] [@server]".to_string());
        }

        let domain = args[0];
        let mut record_type = seer_core::RecordType::A;
        let mut nameserver: Option<&str> = None;

        for arg in &args[1..] {
            if let Some(ns) = arg.strip_prefix('@') {
                nameserver = Some(ns);
            } else if let Ok(rt) = arg.parse() {
                record_type = rt;
            }
        }

        let spinner = Spinner::new(&format!("Querying {} {} records", domain, record_type));

        match self
            .dns_resolver
            .resolve(domain, record_type, nameserver)
            .await
        {
            Ok(records) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_dns(&records));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_propagation(&self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: prop <domain> [type]".to_string());
        }

        let domain = args[0];
        let record_type: seer_core::RecordType = args
            .get(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(seer_core::RecordType::A);

        let spinner = Spinner::new(&format!(
            "Checking {} {} propagation across DNS servers",
            domain, record_type
        ));

        match self.propagation_checker.check(domain, record_type).await {
            Ok(result) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_propagation(&result));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_reverse(&self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: reverse <ip>".to_string());
        }

        let ip = args[0];
        let spinner = Spinner::new(&format!("Looking up PTR for {}", ip));

        match self
            .dns_resolver
            .resolve(ip, seer_core::RecordType::PTR, None)
            .await
        {
            Ok(records) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_dns(&records));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_avail(&self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: avail <domain>".to_string());
        }

        let domain = args[0];
        let spinner = Spinner::new(&format!("Checking availability of {}", domain));

        match self.availability_checker.check(domain).await {
            Ok(result) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_availability(&result));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_dnssec(&self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: dnssec <domain>".to_string());
        }

        let domain = args[0];
        let spinner = Spinner::new(&format!("Checking DNSSEC for {}", domain));

        match self.dnssec_checker.check(domain).await {
            Ok(report) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_dnssec(&report));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_bulk(&mut self, args: &[&str]) -> CommandResult {
        // Handle help flags
        if args.is_empty()
            || args
                .iter()
                .any(|a| *a == "-h" || *a == "--help" || *a == "help")
        {
            self.print_bulk_help();
            return CommandResult::Continue;
        }

        if args.len() < 2 {
            return CommandResult::Error(
                "Usage: bulk <operation> <file> [type] [-o output.csv]\nType 'bulk -h' for detailed help."
                    .to_string(),
            );
        }

        let operation = args[0];
        // Expand `~` / `~/...` once at the boundary so both the bulk-input
        // read and the auto-derived output path see a home-resolved path.
        let file_path = crate::utils::expand_tilde(args[1]);

        // Parse remaining args for record type and output path
        let mut record_type = seer_core::RecordType::A;
        let mut output_path: Option<String> = None;

        let mut i = 2;
        while i < args.len() {
            if args[i] == "-o" || args[i] == "--output" {
                if i + 1 < args.len() {
                    output_path = Some(crate::utils::expand_tilde(args[i + 1]));
                    i += 2;
                    continue;
                }
            } else if let Ok(rt) = args[i].parse() {
                record_type = rt;
            }
            i += 1;
        }

        // Determine output path
        let output_path = output_path.unwrap_or_else(|| {
            let input_path = std::path::Path::new(&file_path);
            let stem = input_path.file_stem().unwrap_or_default().to_string_lossy();
            let parent = input_path.parent().unwrap_or(std::path::Path::new("."));
            parent
                .join(format!("{}_results.csv", stem))
                .to_string_lossy()
                .to_string()
        });

        // Read domains from file.
        // `read_bulk_input` rejects FIFOs, sockets, devices, directories, and
        // oversized files via a pre-read metadata check, preventing hangs on
        // `mkfifo`'d paths.
        const MAX_BULK_DOMAINS_CLI: usize = 1000;

        let content = match crate::utils::read_bulk_input(&file_path) {
            Ok(c) => c,
            Err(e) => return CommandResult::Error(e),
        };

        let domains = seer_core::bulk::parse_domains_from_file(&content);
        if domains.is_empty() {
            return CommandResult::Error(
                "No valid domains found in file. Expected format: one domain per line, # for comments, or CSV (first column)".to_string()
            );
        }

        if domains.len() > MAX_BULK_DOMAINS_CLI {
            return CommandResult::Error(format!(
                "Bulk file contains {} domains, maximum is {}",
                domains.len(),
                MAX_BULK_DOMAINS_CLI
            ));
        }

        println!(
            "Processing {} domains with {} operation...",
            domains.len().to_string().bright_green(),
            operation.bright_yellow()
        );

        let progress = indicatif::ProgressBar::new(domains.len() as u64);
        progress.set_style(
            indicatif::ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                .expect("Progress bar template is hardcoded and should be valid")
                .progress_chars("█▓░"),
        );

        // Register progress bar for tracing integration
        set_bulk_progress_bar(progress.clone());

        let executor = seer_core::BulkExecutor::new().with_concurrency(5);

        let progress_callback = progress.clone();
        let callback: seer_core::bulk::ProgressCallback =
            Box::new(move |current, _total, domain| {
                progress_callback.set_position(current as u64);
                progress_callback.set_message(domain.to_string());
            });

        let operations: Vec<seer_core::bulk::BulkOperation> = match operation {
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
                    record_type,
                })
                .collect(),
            "propagation" | "prop" => domains
                .iter()
                .map(|d: &String| seer_core::bulk::BulkOperation::Propagation {
                    domain: d.clone(),
                    record_type,
                })
                .collect(),
            "lookup" => domains
                .iter()
                .map(|d: &String| seer_core::bulk::BulkOperation::Lookup { domain: d.clone() })
                .collect(),
            "status" => domains
                .iter()
                .map(|d: &String| seer_core::bulk::BulkOperation::Status { domain: d.clone() })
                .collect(),
            "avail" => domains
                .iter()
                .map(|d: &String| seer_core::bulk::BulkOperation::Avail { domain: d.clone() })
                .collect(),
            "info" => domains
                .iter()
                .map(|d: &String| seer_core::bulk::BulkOperation::Info { domain: d.clone() })
                .collect(),
            "ssl" => domains
                .iter()
                .map(|d: &String| seer_core::bulk::BulkOperation::Ssl { domain: d.clone() })
                .collect(),
            _ => {
                return CommandResult::Error(format!(
                    "Unknown bulk operation: {}. Use: lookup, whois, rdap, dig/dns, prop, status, avail, info, ssl",
                    operation
                ))
            }
        };

        let results = executor.execute(operations, Some(callback)).await;

        // Clear progress bar registration before printing results
        clear_bulk_progress_bar();
        progress.finish_and_clear();

        // Write results to CSV
        let csv_content = crate::utils::bulk_results_to_csv(&results, operation);
        if let Err(e) = std::fs::write(&output_path, csv_content) {
            return CommandResult::Error(format!("Failed to write output file: {}", e));
        }

        // Print results summary
        let successful = results.iter().filter(|r| r.success).count();
        let failed = results.len() - successful;

        println!("\n");
        println!("Results written to: {}", output_path.bright_green());
        println!(
            "  {} successful, {} failed",
            successful.to_string().bright_green(),
            if failed > 0 {
                failed.to_string().bright_red()
            } else {
                failed.to_string().bright_green()
            }
        );

        // Print failures
        if failed > 0 {
            println!("\n{}", "Failures:".bright_red().bold());
            for result in results.iter().filter(|r| !r.success) {
                let domain = match &result.operation {
                    seer_core::bulk::BulkOperation::Whois { domain }
                    | seer_core::bulk::BulkOperation::Rdap { domain }
                    | seer_core::bulk::BulkOperation::Dns { domain, .. }
                    | seer_core::bulk::BulkOperation::Propagation { domain, .. }
                    | seer_core::bulk::BulkOperation::Lookup { domain }
                    | seer_core::bulk::BulkOperation::Status { domain }
                    | seer_core::bulk::BulkOperation::Avail { domain }
                    | seer_core::bulk::BulkOperation::Info { domain }
                    | seer_core::bulk::BulkOperation::Ssl { domain } => domain,
                };
                println!(
                    "  {} - {}",
                    domain,
                    result.error.as_deref().unwrap_or("Unknown error")
                );
            }
        }

        CommandResult::Continue
    }

    async fn execute_status(&self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: status <domain>".to_string());
        }

        let domain = args[0];
        let spinner = Spinner::new(&format!("Checking status for {}", domain));

        match self.status_client.check(domain).await {
            Ok(response) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_status(&response));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_follow(&self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error(
                "Usage: follow <domain> [iterations] [interval_minutes] [type] [@server] [--changes-only]"
                    .to_string(),
            );
        }

        let domain = args[0];
        let mut iterations: usize = 10;
        let mut interval_minutes: f64 = 1.0;
        let mut record_type = seer_core::RecordType::A;
        let mut nameserver: Option<&str> = None;
        let mut changes_only = false;

        // Parse remaining args
        for arg in &args[1..] {
            if let Some(ns) = arg.strip_prefix('@') {
                nameserver = Some(ns);
            } else if *arg == "--changes-only" {
                changes_only = true;
            } else if let Ok(n) = arg.parse::<usize>() {
                // First number is iterations, second is interval
                if iterations == 10 {
                    iterations = n;
                } else {
                    interval_minutes = n as f64;
                }
            } else if let Ok(mins) = arg.parse::<f64>() {
                interval_minutes = mins;
            } else if let Ok(rt) = arg.parse() {
                record_type = rt;
            }
        }

        let config = match seer_core::FollowConfig::new(iterations, interval_minutes) {
            Ok(cfg) => cfg.with_changes_only(changes_only),
            Err(e) => return CommandResult::Error(e.to_string()),
        };

        println!(
            "Following {} {} records ({} iterations, {} interval)",
            domain.ctp_green(),
            record_type.to_string().ctp_yellow(),
            iterations.to_string().ctp_yellow(),
            crate::utils::format_interval(interval_minutes)
        );
        println!(
            "Press {} or {} to stop early\n",
            "Esc".ctp_yellow(),
            "Ctrl+C".ctp_yellow()
        );

        // Set up cancellation channel
        let (cancel_tx, cancel_rx) = watch::channel(false);

        // Create progress callback for real-time output
        // Note: raw mode is enabled for key detection, so we need \r\n for proper line breaks
        let follow_format = self.context.output_format;
        let callback: seer_core::dns::FollowProgressCallback = Arc::new(move |iteration| {
            let formatter = seer_core::output::get_formatter(follow_format);
            let output = formatter.format_follow_iteration(iteration);
            let output = output.replace('\n', "\r\n");
            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(output.as_bytes());
            let _ = stdout.write_all(b"\r\n");
            let _ = stdout.flush();
        });

        // Enable raw mode to capture key presses
        let raw_mode_enabled = terminal::enable_raw_mode().is_ok();

        // Spawn a task to listen for Escape key or Ctrl+C
        let cancel_tx_clone = cancel_tx.clone();
        let key_listener = tokio::spawn(async move {
            loop {
                // Poll for events with a short timeout
                if event::poll(std::time::Duration::from_millis(100)).unwrap_or(false) {
                    if let Ok(Event::Key(KeyEvent {
                        code, modifiers, ..
                    })) = event::read()
                    {
                        match code {
                            KeyCode::Esc => {
                                let _ = cancel_tx_clone.send(true);
                                break;
                            }
                            KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                                let _ = cancel_tx_clone.send(true);
                                break;
                            }
                            _ => {}
                        }
                    }
                }

                // Check if we should stop listening (main task completed)
                if cancel_tx_clone.is_closed() {
                    break;
                }
            }
        });

        let result = self
            .dns_follower
            .follow(
                domain,
                record_type,
                nameserver,
                config,
                Some(callback),
                Some(cancel_rx),
            )
            .await;

        // Clean up: abort the key listener and disable raw mode
        key_listener.abort();
        if raw_mode_enabled {
            let _ = terminal::disable_raw_mode();
        }

        match result {
            Ok(result) => {
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                if result.interrupted {
                    println!("\n{}", "Follow interrupted by user".ctp_yellow());
                }
                println!("\n{}", formatter.format_follow(&result));
                CommandResult::Continue
            }
            Err(e) => CommandResult::Error(e.to_string()),
        }
    }

    async fn execute_ssl(&self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: ssl <domain>".to_string());
        }
        let domain = args[0];
        let spinner = Spinner::new(&format!("Checking SSL for {}", domain));
        let checker = seer_core::SslChecker::new();
        match checker.check(domain).await {
            Ok(report) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_ssl(&report));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_tld(&self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: tld <tld>".to_string());
        }
        let info = seer_core::lookup_tld(args[0]).await;
        let formatter = seer_core::output::get_formatter(self.context.output_format);
        println!("{}", formatter.format_tld(&info));
        CommandResult::Continue
    }

    async fn execute_compare(&self, args: &[&str]) -> CommandResult {
        if args.len() < 3 {
            return CommandResult::Error(
                "Usage: compare <domain> [type] <@server1> <@server2>".to_string(),
            );
        }
        let domain = args[0];
        let mut record_type = seer_core::RecordType::A;
        let mut servers: Vec<&str> = Vec::new();

        for arg in &args[1..] {
            if let Some(ns) = arg.strip_prefix('@') {
                servers.push(ns);
            } else if let Ok(rt) = arg.parse() {
                record_type = rt;
            }
        }

        if servers.len() < 2 {
            return CommandResult::Error(
                "Need two nameservers (e.g., @8.8.8.8 @1.1.1.1)".to_string(),
            );
        }

        let spinner = Spinner::new(&format!(
            "Comparing {} records from {} servers",
            domain,
            servers.len()
        ));
        let comparator = seer_core::dns::DnsComparator::new();
        match comparator
            .compare(domain, record_type, servers[0], servers[1])
            .await
        {
            Ok(comparison) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_dns_comparison(&comparison));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_subdomains(&self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: subdomains <domain>".to_string());
        }
        let domain = args[0];
        let spinner = Spinner::new(&format!("Enumerating subdomains for {}", domain));
        let enumerator = seer_core::SubdomainEnumerator::new();
        match enumerator.enumerate(domain).await {
            Ok(result) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_subdomains(&result));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_diff(&self, args: &[&str]) -> CommandResult {
        if args.len() < 2 {
            return CommandResult::Error("Usage: diff <domain1> <domain2>".to_string());
        }
        let spinner = Spinner::new(&format!("Comparing {} vs {}", args[0], args[1]));
        let differ = seer_core::DomainDiffer::new();
        match differ.diff(args[0], args[1]).await {
            Ok(diff) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_diff(&diff));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_watch(&mut self, args: &[&str]) -> CommandResult {
        match args.first().copied() {
            Some("add") => {
                let Some(domain) = args.get(1) else {
                    return CommandResult::Error("Usage: watch add <domain>".to_string());
                };
                let mut watchlist = seer_core::Watchlist::load();
                match watchlist.add(domain) {
                    Ok(true) => {
                        if let Err(e) = watchlist.save() {
                            return CommandResult::Error(format!("Failed to save: {}", e));
                        }
                        println!("Added {} to watchlist", domain);
                    }
                    Ok(false) => {
                        println!("{} is already in the watchlist", domain);
                    }
                    Err(e) => {
                        return CommandResult::Error(format!("Invalid domain: {}", e));
                    }
                }
                CommandResult::Continue
            }
            Some("remove") => {
                let Some(domain) = args.get(1) else {
                    return CommandResult::Error("Usage: watch remove <domain>".to_string());
                };
                let mut watchlist = seer_core::Watchlist::load();
                if watchlist.remove(domain) {
                    if let Err(e) = watchlist.save() {
                        return CommandResult::Error(format!("Failed to save: {}", e));
                    }
                    println!("Removed {} from watchlist", domain);
                } else {
                    println!("{} was not in the watchlist", domain);
                }
                CommandResult::Continue
            }
            Some("list") => {
                let watchlist = seer_core::Watchlist::load();
                if watchlist.domains.is_empty() {
                    println!("Watchlist is empty. Use 'watch add <domain>' to add domains.");
                } else {
                    println!("Watchlist ({} domains):", watchlist.domains.len());
                    for d in &watchlist.domains {
                        println!("  - {}", d);
                    }
                }
                CommandResult::Continue
            }
            None => {
                let watchlist = seer_core::Watchlist::load();
                if watchlist.domains.is_empty() {
                    println!("Watchlist is empty. Use 'watch add <domain>' to add domains.");
                    return CommandResult::Continue;
                }
                let spinner =
                    Spinner::new(&format!("Checking {} domains", watchlist.domains.len()));
                let report = seer_core::check_watchlist(&watchlist.domains).await;
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_watch(&report));
                CommandResult::Continue
            }
            Some(other) => CommandResult::Error(format!(
                "Unknown watch action: {}. Use: add, remove, list",
                other
            )),
        }
    }

    async fn execute_history(&self, args: &[&str]) -> CommandResult {
        // History I/O is blocking file work; offload off the Tokio worker so
        // the REPL stays responsive to other in-flight tasks.
        let mut history = match tokio::task::spawn_blocking(seer_core::LookupHistory::load).await {
            Ok(h) => h,
            Err(e) => return CommandResult::Error(format!("Failed to load history: {}", e)),
        };
        if args.contains(&"--clear") {
            history.clear();
            let save_result = tokio::task::spawn_blocking(move || history.save()).await;
            match save_result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return CommandResult::Error(format!("Failed to clear: {}", e)),
                Err(e) => return CommandResult::Error(format!("Failed to clear: {}", e)),
            }
            println!("Lookup history cleared");
            return CommandResult::Continue;
        }
        if let Some(domain) = args.first() {
            let entries = history.get(domain);
            if entries.is_empty() {
                println!("No history for {}", domain);
            } else {
                println!("History for {} ({} entries):", domain, entries.len());
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
                println!("No lookup history.");
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
        CommandResult::Continue
    }

    fn execute_set(&mut self, args: &[&str]) -> CommandResult {
        if args.len() < 2 {
            return CommandResult::Error("Usage: set <setting> <value>".to_string());
        }

        match args[0] {
            "output" => match args[1].parse() {
                Ok(format) => {
                    self.context.output_format = format;
                    println!("Output format set to: {}", args[1]);
                    CommandResult::Continue
                }
                Err(_) => CommandResult::Error(
                    "Invalid format. Use: human, json, yaml, markdown".to_string(),
                ),
            },
            _ => CommandResult::Error(format!("Unknown setting: {}", args[0])),
        }
    }
}
