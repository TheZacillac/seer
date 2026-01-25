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
use seer_core::output::OutputFormatter;
use tokio::sync::watch;

use crate::display::Spinner;

const HISTORY_FILE: &str = ".seer_history";

fn format_interval(minutes: f64) -> String {
    if minutes < 1.0 {
        format!("{}s", (minutes * 60.0) as u64)
    } else if minutes == 1.0 {
        "1m".to_string()
    } else {
        format!("{}m", minutes)
    }
}

pub struct Repl {
    editor: Editor<SeerCompleter, DefaultHistory>,
    context: CommandContext,
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
        })
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        self.print_banner();

        loop {
            let prompt = self.get_prompt();

            match self.editor.readline(&prompt) {
                Ok(line) => {
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
                }
                Err(ReadlineError::Interrupted) => {
                    println!("^C");
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
            format!("Seer v{}", env!("CARGO_PKG_VERSION")).bright_purple().bold()
        );
        println!("  Type {} for available commands\n", "help".bright_green());
    }

    fn get_prompt(&self) -> String {
        let format_indicator = match self.context.output_format {
            seer_core::output::OutputFormat::Human => "",
            seer_core::output::OutputFormat::Json => " [json]",
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
            "whois" => self.execute_whois(args).await,
            "rdap" => self.execute_rdap(args).await,
            "dig" | "dns" => self.execute_dig(args).await,
            "propagation" | "prop" => self.execute_propagation(args).await,
            "bulk" => self.execute_bulk(args).await,
            "status" => self.execute_status(args).await,
            "follow" => self.execute_follow(args).await,
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
                    CommandResult::Error(format!("Unknown command: {}. Type 'help' for available commands.", command))
                }
            }
        }
    }

    fn print_help(&self) {
        println!();
        println!("{}", "LOOKUP COMMANDS".bright_purple().bold());
        println!("  {:<34} Smart lookup (just type a domain directly)", "<domain>".bright_cyan());
        println!("  {:<34} Query WHOIS information", "whois <domain>".bright_cyan());
        println!("  {:<34} Query RDAP registry data", "rdap <domain|ip|asn>".bright_cyan());
        println!();
        println!("{}", "DNS COMMANDS".bright_purple().bold());
        println!("  {:<34} Query DNS records", "dig <domain> [type] [@server]".bright_cyan());
        println!("  {:<34} Check DNS propagation globally", "propagation <domain> [type]".bright_cyan());
        println!("  {:<34} Monitor DNS records over time", "follow <domain> [n] [mins] [type] [@server]".bright_cyan());
        println!("  {}", "Record types: A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV, CAA".dimmed());
        println!();
        println!("{}", "STATUS COMMANDS".bright_purple().bold());
        println!("  {:<34} Check HTTP, SSL, and domain expiration", "status <domain>".bright_cyan());
        println!();
        println!("{}", "BULK OPERATIONS".bright_purple().bold());
        println!("  {:<34} Run bulk operations from file", "bulk <op> <file>".bright_cyan());
        println!("  {}", "Operations: lookup, whois, rdap, dig, propagation, status".dimmed());
        println!();
        println!("{}", "SETTINGS".bright_purple().bold());
        println!("  {:<34} Change output format", "set output <human|json>".bright_cyan());
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
        println!("  {}      Smart lookup (RDAP first, WHOIS fallback)", "lookup".bright_green());
        println!("  {}       Query WHOIS information", "whois".bright_green());
        println!("  {}        Query RDAP registry data", "rdap".bright_green());
        println!("  {}         Query DNS records", "dig".bright_green());
        println!("  {}  Check DNS propagation globally", "propagation".bright_green());
        println!("  {}      Check HTTP, SSL, and domain expiration", "status".bright_green());
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
        println!("  {}: domain, http_status, ssl_days_remaining, domain_expires, ...", "status".bright_green());
        println!("  {}: domain, registrar, created, expires, updated, ...", "lookup".bright_green());
        println!("  {}: domain, record_type, records, ...", "dig".bright_green());
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

    async fn execute_whois(&self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: whois <domain>".to_string());
        }

        let domain = args[0];
        let spinner = Spinner::new(&format!("Looking up WHOIS for {}", domain));

        let client = seer_core::WhoisClient::new();
        match client.lookup(domain).await {
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

        let client = seer_core::RdapClient::new();

        // Determine query type
        let result = if query.starts_with("AS") || query.starts_with("as") {
            match query[2..].parse::<u32>() {
                Ok(asn) => client.lookup_asn(asn).await,
                Err(_) => {
                    spinner.finish();
                    return CommandResult::Error("Invalid ASN format".to_string());
                }
            }
        } else if query.parse::<std::net::IpAddr>().is_ok() {
            client.lookup_ip(query).await
        } else {
            client.lookup_domain(query).await
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

        let resolver = seer_core::DnsResolver::new();
        match resolver.resolve(domain, record_type, nameserver).await {
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
            return CommandResult::Error("Usage: propagation <domain> [type]".to_string());
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

        let checker = seer_core::dns::PropagationChecker::new();
        match checker.check(domain, record_type).await {
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

    async fn execute_bulk(&mut self, args: &[&str]) -> CommandResult {
        // Handle help flags
        if args.is_empty() || args.iter().any(|a| *a == "-h" || *a == "--help" || *a == "help") {
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
        let file_path = args[1];

        // Parse remaining args for record type and output path
        let mut record_type = seer_core::RecordType::A;
        let mut output_path: Option<String> = None;

        let mut i = 2;
        while i < args.len() {
            if args[i] == "-o" || args[i] == "--output" {
                if i + 1 < args.len() {
                    output_path = Some(args[i + 1].to_string());
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
            let input_path = std::path::Path::new(file_path);
            let stem = input_path.file_stem().unwrap_or_default().to_string_lossy();
            let parent = input_path.parent().unwrap_or(std::path::Path::new("."));
            parent
                .join(format!("{}_results.csv", stem))
                .to_string_lossy()
                .to_string()
        });

        // Read domains from file
        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(e) => return CommandResult::Error(format!("Failed to read file: {}", e)),
        };

        let domains = seer_core::bulk::parse_domains_from_file(&content);
        if domains.is_empty() {
            return CommandResult::Error(
                "No valid domains found in file. Expected format: one domain per line, # for comments, or CSV (first column)".to_string()
            );
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

        let executor = seer_core::BulkExecutor::new().with_concurrency(5);

        let callback: seer_core::bulk::ProgressCallback =
            Box::new(move |current, _total, domain| {
                progress.set_position(current as u64);
                progress.set_message(domain.to_string());
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
            _ => {
                return CommandResult::Error(format!(
                    "Unknown bulk operation: {}. Use: lookup, whois, rdap, dig, propagation, status",
                    operation
                ))
            }
        };

        let results = executor.execute(operations, Some(callback)).await;

        // Write results to CSV
        let csv_content = bulk_results_to_csv(&results, operation);
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
                    seer_core::bulk::BulkOperation::Whois { domain } => domain,
                    seer_core::bulk::BulkOperation::Rdap { domain } => domain,
                    seer_core::bulk::BulkOperation::Dns { domain, .. } => domain,
                    seer_core::bulk::BulkOperation::Propagation { domain, .. } => domain,
                    seer_core::bulk::BulkOperation::Lookup { domain } => domain,
                    seer_core::bulk::BulkOperation::Status { domain } => domain,
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

        let client = seer_core::StatusClient::new();
        match client.check(domain).await {
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
                "Usage: follow <domain> [iterations] [interval_minutes] [type] [@server]".to_string(),
            );
        }

        let domain = args[0];
        let mut iterations: usize = 10;
        let mut interval_minutes: f64 = 1.0;
        let mut record_type = seer_core::RecordType::A;
        let mut nameserver: Option<&str> = None;

        // Parse remaining args
        for arg in &args[1..] {
            if let Some(ns) = arg.strip_prefix('@') {
                nameserver = Some(ns);
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

        let config = seer_core::FollowConfig::new(iterations, interval_minutes);

        println!(
            "Following {} {} records ({} iterations, {} interval)",
            domain.ctp_green(),
            record_type.to_string().ctp_yellow(),
            iterations.to_string().ctp_yellow(),
            format_interval(interval_minutes)
        );
        println!("Press {} or {} to stop early\n", "Esc".ctp_yellow(), "Ctrl+C".ctp_yellow());

        let follower = seer_core::DnsFollower::new();

        // Set up cancellation channel
        let (cancel_tx, cancel_rx) = watch::channel(false);

        // Create progress callback for real-time output
        let use_json = matches!(self.context.output_format, seer_core::output::OutputFormat::Json);
        let callback: seer_core::dns::FollowProgressCallback =
            Arc::new(move |iteration| {
                if use_json {
                    let json_formatter = seer_core::output::JsonFormatter::new();
                    println!("{}", json_formatter.format_follow_iteration(iteration));
                } else {
                    let human_formatter = seer_core::output::HumanFormatter::new();
                    println!("{}", human_formatter.format_follow_iteration(iteration));
                }
            });

        // Enable raw mode to capture key presses
        let raw_mode_enabled = terminal::enable_raw_mode().is_ok();

        // Spawn a task to listen for Escape key or Ctrl+C
        let cancel_tx_clone = cancel_tx.clone();
        let key_listener = tokio::spawn(async move {
            loop {
                // Poll for events with a short timeout
                if event::poll(std::time::Duration::from_millis(100)).unwrap_or(false) {
                    if let Ok(Event::Key(KeyEvent { code, modifiers, .. })) = event::read() {
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

        let result = follower
            .follow(domain, record_type, nameserver, config, Some(callback), Some(cancel_rx))
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
                Err(_) => CommandResult::Error("Invalid format. Use: human, json".to_string()),
            },
            _ => CommandResult::Error(format!("Unknown setting: {}", args[0])),
        }
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
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
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
