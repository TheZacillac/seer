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
            _ => CommandResult::Error(format!("Unknown command: {}. Type 'help' for available commands.", command)),
        }
    }

    fn print_help(&self) {
        println!();
        println!("{}", "LOOKUP COMMANDS".bright_purple().bold());
        println!("  {:<34} {}", "lookup <domain>".bright_cyan(), "Smart lookup (RDAP first, WHOIS fallback)");
        println!("  {:<34} {}", "whois <domain>".bright_cyan(), "Query WHOIS information");
        println!("  {:<34} {}", "rdap <domain|ip|asn>".bright_cyan(), "Query RDAP registry data");
        println!();
        println!("{}", "DNS COMMANDS".bright_purple().bold());
        println!("  {:<34} {}", "dig <domain> [type] [@server]".bright_cyan(), "Query DNS records");
        println!("  {:<34} {}", "propagation <domain> [type]".bright_cyan(), "Check DNS propagation globally");
        println!("  {:<34} {}", "follow <domain> [n] [mins] [type] [@server]".bright_cyan(), "Monitor DNS records over time");
        println!("  {}", "Record types: A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV, CAA".dimmed());
        println!();
        println!("{}", "STATUS COMMANDS".bright_purple().bold());
        println!("  {:<34} {}", "status <domain>".bright_cyan(), "Check HTTP, SSL, and domain expiration");
        println!();
        println!("{}", "BULK OPERATIONS".bright_purple().bold());
        println!("  {:<34} {}", "bulk <op> <file>".bright_cyan(), "Run bulk operations from file");
        println!("  {}", "Operations: lookup, whois, rdap, dig, propagation, status".dimmed());
        println!();
        println!("{}", "SETTINGS".bright_purple().bold());
        println!("  {:<34} {}", "set output <human|json>".bright_cyan(), "Change output format");
        println!("  {:<34} {}", "clear".bright_cyan(), "Clear screen");
        println!("  {:<34} {}", "exit".bright_cyan(), "Exit the program");
        println!();
    }

    async fn execute_lookup(&self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: lookup <domain>".to_string());
        }

        let domain = args[0];
        let spinner = Spinner::new(&format!("Smart lookup for {} (trying RDAP first)", domain));

        let lookup = seer_core::SmartLookup::new();
        match lookup.lookup(domain).await {
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
        if args.len() < 2 {
            return CommandResult::Error(
                "Usage: bulk <operation> <file> [type]\nOperations: whois, rdap, dig, propagation"
                    .to_string(),
            );
        }

        let operation = args[0];
        let file_path = args[1];
        let record_type: seer_core::RecordType = args
            .get(2)
            .and_then(|s| s.parse().ok())
            .unwrap_or(seer_core::RecordType::A);

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

        println!("Found {} domains in {}", domains.len(), file_path);

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

        // Print results summary
        let successful = results.iter().filter(|r| r.success).count();
        let failed = results.len() - successful;

        println!("\n\n{}", "Bulk Operation Complete".bright_purple().bold());
        println!("  Successful: {}", successful.to_string().bright_green());
        println!("  Failed: {}", failed.to_string().bright_red());

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
