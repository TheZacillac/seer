mod commands;
mod completer;

pub use commands::{CommandContext, CommandResult};
pub use completer::SeerCompleter;

use std::io::Write;
use std::sync::Arc;

use colored::Colorize;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
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
    ssl_checker: seer_core::SslChecker,
    dns_follower: seer_core::DnsFollower,
    /// Last single-result command output, for the `copy` command.
    last_result: Option<crate::payload::Payload>,
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

        // Build clients from the user config so the REPL honors per-protocol
        // timeouts / nameserver / bulk concurrency (propagation + DNSSEC keep
        // their own tuned timeouts by design — see the config wiring note).
        let context = CommandContext::new();
        let cfg = &context.config;

        Ok(Self {
            editor,
            whois_client: seer_core::WhoisClient::from_config(cfg),
            rdap_client: seer_core::RdapClient::from_config(cfg),
            dns_resolver: seer_core::DnsResolver::from_config(cfg),
            propagation_checker: seer_core::dns::PropagationChecker::new(),
            status_client: seer_core::StatusClient::from_config(cfg),
            dnssec_checker: seer_core::DnssecChecker::new(),
            availability_checker: seer_core::AvailabilityChecker::from_config(cfg),
            ssl_checker: seer_core::SslChecker::from_config(cfg),
            dns_follower: seer_core::DnsFollower::new(),
            last_result: None,
            context,
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
                            // Honor `set output json|yaml|markdown` on the
                            // error path too, so a wrapper consuming REPL
                            // output gets the same structured `{"error": ...}`
                            // shape the CLI emits.
                            match crate::utils::machine_error(self.context.output_format, &e) {
                                Some(structured) => eprintln!("{}", structured),
                                None => eprintln!("{} {}", "Error:".ctp_red().bold(), e),
                            }
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

        // The history file records every queried domain/IP/ASN. Restrict it to
        // the owner (0600), mirroring the posture of the ~/.seer/* state files
        // (history.rs / watchlist.rs); it lives at ~/.seer_history, outside the
        // 0700 ~/.seer dir, so the directory mode does not protect it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&history_path, std::fs::Permissions::from_mode(0o600));
        }

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
        // Shell-style tokenization so quoted arguments (e.g. a bulk file path
        // containing spaces) survive — plain whitespace splitting mangled them.
        let tokens = match commands::tokenize_line(line) {
            Ok(t) => t,
            Err(e) => return CommandResult::Error(e),
        };
        let parts: Vec<&str> = tokens.iter().map(|s| s.as_str()).collect();
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
            "delegation" => self.execute_delegation(args).await,
            "doctor" => self.execute_doctor().await,
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
            "drift" => self.execute_drift(args).await,
            "caa" => self.execute_caa(args).await,
            "posture" => self.execute_posture(args).await,
            "confusables" => self.execute_confusables(args).await,
            "watch" => self.execute_watch(args).await,
            "history" => self.execute_history(args).await,
            "set" => self.execute_set(args),
            "copy" => self.execute_copy(args),
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
        println!(
            "  {:<34} Check NS delegation health (parent vs zone, lameness)",
            "delegation <domain>".bright_cyan()
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
        println!(
            "  {:<34} Diff subdomains vs the stored baseline",
            "subdomains <domain> --diff [--record]".bright_cyan()
        );
        println!(
            "  {:<34} Diagnose seer environment (config, DNS, WHOIS, RDAP)",
            "doctor".bright_cyan()
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
        println!("{}", "SECURITY".bright_purple().bold());
        println!(
            "  {:<34} Look up CAA (cert authority) policy",
            "caa <domain>".bright_cyan()
        );
        println!(
            "  {:<34} Email/DNS posture (SPF, DMARC, MTA-STS, BIMI, DANE)",
            "posture <domain>".bright_cyan()
        );
        println!(
            "  {:<34} Find registered look-alike domains",
            "confusables <domain>".bright_cyan()
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
        println!(
            "  {:<34} Detect drift vs the last stored lookup",
            "drift <domain> [--record]".bright_cyan()
        );
        println!();
        println!("{}", "BULK OPERATIONS".bright_purple().bold());
        println!(
            "  {:<34} Run bulk operations from file",
            "bulk <op> <file>".bright_cyan()
        );
        println!(
            "  {}",
            format!("Operations: {}", crate::ops::BULK_OPS_SUMMARY).dimmed()
        );
        println!();
        println!("{}", "SETTINGS".bright_purple().bold());
        println!(
            "  {:<34} Change output format",
            "set output <human|json|yaml|markdown>".bright_cyan()
        );
        println!(
            "  {:<34} Copy last result to clipboard (default: markdown)",
            "copy [markdown|json|yaml]".bright_cyan()
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
        println!(
            "  {}     Email/DNS posture (SPF, DMARC, MTA-STS, BIMI, DANE)",
            "posture".bright_green()
        );
        println!(
            "  {} Registered look-alike scan (expensive per domain)",
            "confusables".bright_green()
        );
        println!(
            "  {}         Look up CAA (cert authority) policy",
            "caa".bright_green()
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

    async fn execute_lookup(&mut self, args: &[&str]) -> CommandResult {
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

        let lookup = seer_core::SmartLookup::from_config(&self.context.config);
        match lookup.lookup_with_progress(domain, Some(progress)).await {
            Ok(result) => {
                spinner.finish();
                // Record to history (file I/O off the async executor),
                // matching the non-REPL `Commands::Lookup` path. Without this
                // the `history` REPL command always reports an empty file.
                crate::ops::record_lookup_history(domain, result.clone()).await;

                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_lookup(&result));
                self.last_result =
                    Some(crate::payload::Payload::Overview(Box::new(result.clone())));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_info(&mut self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: info <domain>".to_string());
        }

        let domain = args[0];
        let spinner = Arc::new(Spinner::new(&format!(
            "Getting comprehensive info for {}",
            domain
        )));

        let lookup = seer_core::SmartLookup::from_config(&self.context.config);
        match lookup.lookup(domain).await {
            Ok(result) => {
                spinner.finish();
                let info = seer_core::DomainInfo::from_lookup_result(&result);
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_domain_info(&info));
                self.last_result = Some(crate::payload::Payload::Info(Box::new(info.clone())));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(format!("Info failed: {}", e))
            }
        }
    }

    async fn execute_whois(&mut self, args: &[&str]) -> CommandResult {
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
                self.last_result = Some(crate::payload::Payload::Whois(Box::new(response.clone())));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_rdap(&mut self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: rdap <domain|ip|asn>".to_string());
        }

        let query = args[0];
        let spinner = Spinner::new(&format!("Looking up RDAP for {}", query));

        // Mirror the non-REPL CLI path: seer_core::rdap::auto_lookup classifies
        // the query so the `AS<digits>` route only fires when the remainder is
        // all digits AND there's no `.` — otherwise `asana.com` / `as1234.io`
        // would misroute to ASN and surface a parse error.
        let result = seer_core::rdap::auto_lookup(&self.rdap_client, query).await;

        match result {
            Ok(response) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_rdap(&response));
                self.last_result = Some(crate::payload::Payload::Rdap(Box::new(response.clone())));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_dig(&mut self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: dig <domain> [type] [@server]".to_string());
        }

        let domain = args[0];
        let mut record_type = seer_core::RecordType::A;
        let mut nameserver: Option<&str> = None;

        for arg in &args[1..] {
            if let Some(ns) = arg.strip_prefix('@') {
                nameserver = Some(ns);
            } else {
                // A typo'd type must error, not silently query A records.
                match crate::try_parse_record_type(arg) {
                    Ok(rt) => record_type = rt,
                    Err(e) => return CommandResult::Error(e),
                }
            }
        }

        // Fall back to the configured nameserver when none is given inline.
        let nameserver = nameserver.or(self.context.config.nameserver.as_deref());

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
                self.last_result = Some(crate::payload::Payload::Dns(records.clone()));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_propagation(&mut self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: prop <domain> [type]".to_string());
        }

        let domain = args[0];
        // A typo'd type must error, not silently check A-record propagation.
        let record_type = match args.get(1) {
            Some(arg) => match crate::try_parse_record_type(arg) {
                Ok(rt) => rt,
                Err(e) => return CommandResult::Error(e),
            },
            None => seer_core::RecordType::A,
        };

        let spinner = Spinner::new(&format!(
            "Checking {} {} propagation across DNS servers",
            domain, record_type
        ));

        match self.propagation_checker.check(domain, record_type).await {
            Ok(result) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_propagation(&result));
                self.last_result = Some(crate::payload::Payload::Prop(Box::new(result.clone())));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_delegation(&mut self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: delegation <domain>".to_string());
        }

        let domain = args[0];
        let spinner = Spinner::new(&format!("Checking NS delegation for {}", domain));

        // check() normalizes/validates the domain before any network I/O, so
        // an invalid input errors immediately (keeps the tests hermetic).
        let checker = seer_core::dns::DelegationChecker::from_config(&self.context.config);
        match checker.check(domain).await {
            Ok(report) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_delegation(&report));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_doctor(&mut self) -> CommandResult {
        let spinner = Spinner::new("Running environment diagnostics");

        // Infallible by design: probe failures become Fail checks in the
        // report rather than an Err, so there is no error branch here.
        let doctor = seer_core::doctor::Doctor::from_config(&self.context.config);
        let report = doctor.run().await;
        spinner.finish();
        println!(
            "{}",
            crate::render_doctor_report(&report, self.context.output_format)
        );
        CommandResult::Continue
    }

    async fn execute_reverse(&mut self, args: &[&str]) -> CommandResult {
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
                self.last_result = Some(crate::payload::Payload::Reverse(records.clone()));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_avail(&mut self, args: &[&str]) -> CommandResult {
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
                self.last_result = Some(crate::payload::Payload::Avail(Box::new(result.clone())));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_dnssec(&mut self, args: &[&str]) -> CommandResult {
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
                self.last_result = Some(crate::payload::Payload::Dnssec(Box::new(report.clone())));
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

        let parsed = match commands::parse_bulk_args(args) {
            Ok(p) => p,
            Err(e) => return CommandResult::Error(e),
        };

        // Expand `~` / `~/...` once at the boundary so both the bulk-input
        // read and the auto-derived output path see a home-resolved path.
        let file_path = crate::utils::expand_tilde(&parsed.file);
        let output_path = parsed
            .output
            .as_deref()
            .map(crate::utils::expand_tilde)
            .unwrap_or_else(|| crate::ops::default_bulk_output_path(&file_path));

        // Read domains from file.
        // `read_bulk_input` rejects FIFOs, sockets, devices, directories, and
        // oversized files via a pre-read metadata check, preventing hangs on
        // `mkfifo`'d paths.
        let content = match crate::utils::read_bulk_input(&file_path) {
            Ok(c) => c,
            Err(e) => return CommandResult::Error(e),
        };

        let domains = match crate::ops::parse_bulk_domains(&content) {
            Ok(d) => d,
            Err(e) => return CommandResult::Error(e),
        };

        // Validate the operation before any progress UI is set up so an
        // unknown op can't leave a stale progress bar registered.
        let operations = match crate::ops::build_bulk_operations(
            &parsed.operation,
            &domains,
            parsed.record_type,
        ) {
            Ok(operations) => operations,
            Err(e) => return CommandResult::Error(e),
        };

        println!(
            "Processing {} domains with {} operation...",
            domains.len().to_string().bright_green(),
            parsed.operation.bright_yellow()
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

        let executor = seer_core::BulkExecutor::from_config(&self.context.config);
        let callback = crate::ops::bar_progress_callback(&progress);

        let results = executor.execute(operations, Some(callback)).await;

        // Clear progress bar registration before printing results
        clear_bulk_progress_bar();
        progress.finish_and_clear();

        // Write results to CSV atomically — a crash or disk-full mid-write
        // must not leave a truncated CSV that downstream pipelines treat as
        // authoritative.
        let csv_content = crate::utils::bulk_results_to_csv(&results, &parsed.operation);
        if let Err(e) = crate::utils::atomic_write(&output_path, &csv_content) {
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
                let domain = result.operation.domain();
                println!(
                    "  {} - {}",
                    domain,
                    result.error.as_deref().unwrap_or("Unknown error")
                );
            }
        }

        CommandResult::Continue
    }

    async fn execute_status(&mut self, args: &[&str]) -> CommandResult {
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
                self.last_result =
                    Some(crate::payload::Payload::Status(Box::new(response.clone())));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_follow(&self, args: &[&str]) -> CommandResult {
        let commands::FollowArgs {
            domain,
            iterations,
            interval_minutes,
            record_type,
            nameserver,
            changes_only,
        } = match commands::parse_follow_args(args) {
            Ok(p) => p,
            Err(e) => return CommandResult::Error(e),
        };

        // Fall back to the configured nameserver when none is given inline,
        // matching `execute_dig` and the CLI's `seer follow`.
        let nameserver = nameserver.or_else(|| self.context.config.nameserver.clone());

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

        // Enable raw mode to capture key presses. The RAII guard restores
        // cooked mode on scope exit, including if a panic unwinds through the
        // follow loop (issue #60).
        let raw_guard = crate::utils::RawModeGuard::new();

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
                &domain,
                record_type,
                nameserver.as_deref(),
                config,
                Some(callback),
                Some(cancel_rx),
            )
            .await;

        // Clean up: stop the key listener and restore cooked mode before
        // printing results. The guard's Drop also restores on a panic above.
        key_listener.abort();
        drop(raw_guard);

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

    async fn execute_ssl(&mut self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: ssl <domain>".to_string());
        }
        let domain = args[0];
        let spinner = Spinner::new(&format!("Checking SSL for {}", domain));
        match self.ssl_checker.check(domain).await {
            Ok(report) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_ssl(&report));
                self.last_result = Some(crate::payload::Payload::Ssl(Box::new(report.clone())));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_tld(&mut self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: tld <tld>".to_string());
        }
        let info = seer_core::lookup_tld(args[0]).await;
        let formatter = seer_core::output::get_formatter(self.context.output_format);
        println!("{}", formatter.format_tld(&info));
        self.last_result = Some(crate::payload::Payload::Tld(Box::new(info.clone())));
        CommandResult::Continue
    }

    async fn execute_compare(&mut self, args: &[&str]) -> CommandResult {
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
            } else {
                // A typo'd type must error, not silently compare A records.
                match crate::try_parse_record_type(arg) {
                    Ok(rt) => record_type = rt,
                    Err(e) => return CommandResult::Error(e),
                }
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
                self.last_result = Some(crate::payload::Payload::Compare(Box::new(
                    comparison.clone(),
                )));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_subdomains(&mut self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error(
                "Usage: subdomains <domain> [--diff] [--record]".to_string(),
            );
        }
        let domain = args[0];
        let diff = args.contains(&"--diff");
        let record = args.contains(&"--record");
        let spinner = Spinner::new(&format!("Enumerating subdomains for {}", domain));

        if diff || record {
            // Same baseline semantics as the CLI `subdomains --diff/--record`
            // — shared via ops::subdomain_baseline_check so the two surfaces
            // cannot diverge (mirrors execute_drift below).
            match crate::ops::subdomain_baseline_check(domain, record).await {
                Ok(outcome) => {
                    spinner.finish();
                    let formatter = seer_core::output::get_formatter(self.context.output_format);
                    if diff {
                        if outcome.report.baseline_missing {
                            println!(
                                "{} {}",
                                "note:".ctp_yellow(),
                                crate::ops::no_subdomain_baseline_note(
                                    &outcome.result.domain,
                                    record
                                )
                            );
                        }
                        println!(
                            "{}",
                            formatter.format_subdomain_baseline_diff(&outcome.report)
                        );
                    } else {
                        // --record alone: plain listing plus a confirmation.
                        println!("{}", formatter.format_subdomains(&outcome.result));
                        println!(
                            "{} recorded subdomain baseline for {} ({} names)",
                            "note:".ctp_yellow(),
                            outcome.result.domain,
                            outcome.result.count
                        );
                    }
                    self.last_result = Some(crate::payload::Payload::Subdomains(Box::new(
                        outcome.result.clone(),
                    )));
                    return CommandResult::Continue;
                }
                Err(e) => {
                    spinner.finish();
                    return CommandResult::Error(e.to_string());
                }
            }
        }

        let enumerator = seer_core::SubdomainEnumerator::new();
        match enumerator.enumerate(domain).await {
            Ok(result) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_subdomains(&result));
                self.last_result = Some(crate::payload::Payload::Subdomains(Box::new(
                    result.clone(),
                )));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_diff(&mut self, args: &[&str]) -> CommandResult {
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
                self.last_result = Some(crate::payload::Payload::Diff(Box::new(diff.clone())));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_drift(&mut self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: drift <domain> [--record]".to_string());
        }
        let domain = args[0];
        let record = args.contains(&"--record");
        let spinner = Spinner::new(&format!("Looking up {}", domain));
        // Same history-snapshot semantics as the CLI `drift` subcommand —
        // shared via ops::drift_check so the two surfaces cannot diverge.
        let lookup = seer_core::SmartLookup::from_config(&self.context.config);
        match crate::ops::drift_check(&lookup, domain, record).await {
            Ok(outcome) => {
                spinner.finish();
                if !outcome.had_previous {
                    println!(
                        "{} {}",
                        "note:".ctp_yellow(),
                        crate::ops::no_baseline_note(domain, record)
                    );
                }
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_drift(&outcome.report));
                self.last_result = Some(crate::payload::Payload::Drift(Box::new(
                    outcome.report.clone(),
                )));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_caa(&mut self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: caa <domain>".to_string());
        }
        // Normalize first so `caa HTTPS://WWW.EXAMPLE.COM` behaves like the
        // CLI subcommand and an invalid domain surfaces a clean error.
        match seer_core::normalize_domain(args[0]) {
            Ok(domain) => {
                let spinner = Spinner::new(&format!("Looking up CAA policy for {}", domain));
                let policy = seer_core::caa::lookup_caa(&self.dns_resolver, &domain).await;
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_caa(&policy));
                self.last_result = Some(crate::payload::Payload::Caa(Box::new(policy.clone())));
                CommandResult::Continue
            }
            Err(e) => CommandResult::Error(e.to_string()),
        }
    }

    async fn execute_posture(&mut self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: posture <domain>".to_string());
        }
        let domain = args[0];
        let spinner = Spinner::new(&format!("Inspecting email posture for {}", domain));
        match seer_core::lookup_email_posture(&self.dns_resolver, domain).await {
            Ok(posture) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_posture(&posture));
                self.last_result =
                    Some(crate::payload::Payload::Posture(Box::new(posture.clone())));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_confusables(&mut self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: confusables <domain>".to_string());
        }
        let domain = args[0];
        let spinner = Spinner::new(&format!("Scanning look-alikes for {}", domain));
        let lookup = seer_core::SmartLookup::from_config(&self.context.config);
        match seer_core::find_confusables(&lookup, domain, self.context.config.bulk.concurrency)
            .await
        {
            Ok(report) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_confusables(&report));
                self.last_result = Some(crate::payload::Payload::Confusables(Box::new(
                    report.clone(),
                )));
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
                let mut watchlist = match load_watchlist_async().await {
                    Ok(w) => w,
                    Err(e) => return CommandResult::Error(e),
                };
                match watchlist.add(domain) {
                    Ok(true) => {
                        if let Err(e) = save_watchlist_async(watchlist).await {
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
                let mut watchlist = match load_watchlist_async().await {
                    Ok(w) => w,
                    Err(e) => return CommandResult::Error(e),
                };
                if watchlist.remove(domain) {
                    if let Err(e) = save_watchlist_async(watchlist).await {
                        return CommandResult::Error(format!("Failed to save: {}", e));
                    }
                    println!("Removed {} from watchlist", domain);
                } else {
                    println!("{} was not in the watchlist", domain);
                }
                CommandResult::Continue
            }
            Some("list") => {
                let watchlist = match load_watchlist_async().await {
                    Ok(w) => w,
                    Err(e) => return CommandResult::Error(e),
                };
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
                let watchlist = match load_watchlist_async().await {
                    Ok(w) => w,
                    Err(e) => return CommandResult::Error(e),
                };
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
                self.last_result = Some(crate::payload::Payload::Watch(Box::new(report.clone())));
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

    /// Pure part of `copy`: pick the format, serialize the last result.
    /// Returns (text to place on the clipboard, confirmation message).
    fn render_copy(&self, args: &[&str]) -> Result<(String, String), String> {
        let arg = args.first().map(|s| s.to_lowercase());
        let format = match arg.as_deref() {
            None => seer_core::output::OutputFormat::Markdown,
            Some("markdown") | Some("md") => seer_core::output::OutputFormat::Markdown,
            Some("json") => seer_core::output::OutputFormat::Json,
            Some("yaml") | Some("yml") => seer_core::output::OutputFormat::Yaml,
            Some(other) => {
                return Err(format!(
                    "Unknown format '{other}'. Usage: copy [markdown|json|yaml]"
                ))
            }
        };
        let Some(payload) = &self.last_result else {
            return Err("Nothing to copy yet — run a lookup first".to_string());
        };
        let text = crate::payload::serialize(payload, format);
        let msg = format!(
            "Copied {} result as {}",
            payload.kind(),
            format!("{format:?}").to_lowercase()
        );
        Ok((text, msg))
    }

    fn execute_copy(&self, args: &[&str]) -> CommandResult {
        match self.render_copy(args) {
            Ok((text, msg)) => {
                if let Err(e) = crate::clipboard::copy(&text) {
                    return CommandResult::Error(format!("Clipboard write failed: {e}"));
                }
                println!("{}", msg.green());
                CommandResult::Continue
            }
            Err(msg) => {
                // "Nothing to copy" is guidance, not an error; usage/format
                // problems go through the error path like other commands.
                if msg.starts_with("Nothing to copy") {
                    println!("{}", msg.yellow());
                    CommandResult::Continue
                } else {
                    CommandResult::Error(msg)
                }
            }
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
                Err(_) => CommandResult::Error(
                    "Invalid format. Use: human, json, yaml, markdown".to_string(),
                ),
            },
            _ => CommandResult::Error(format!("Unknown setting: {}", args[0])),
        }
    }
}

/// Load the watchlist off the Tokio worker. The file read + TOML parse are
/// blocking; offloading keeps the REPL responsive to other in-flight tasks
/// (mirrors the history I/O handling in `execute_history`).
async fn load_watchlist_async() -> Result<seer_core::Watchlist, String> {
    tokio::task::spawn_blocking(seer_core::Watchlist::load)
        .await
        .map_err(|e| format!("Failed to load watchlist: {}", e))
}

/// Save the watchlist off the Tokio worker. Flattens the `spawn_blocking` join
/// error and the inner save error into a single message.
async fn save_watchlist_async(watchlist: seer_core::Watchlist) -> Result<(), String> {
    match tokio::task::spawn_blocking(move || watchlist.save()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod copy_tests {
    use super::*;
    use seer_core::dns::{RecordData, RecordType};

    fn repl_with_result() -> Repl {
        let mut repl = Repl::new().expect("repl construction is offline");
        repl.last_result = Some(crate::payload::Payload::Dns(vec![seer_core::DnsRecord {
            name: "example.com".into(),
            record_type: RecordType::A,
            ttl: 300,
            data: RecordData::A {
                address: "1.2.3.4".into(),
            },
        }]));
        repl
    }

    #[test]
    fn copy_with_no_result_is_friendly() {
        let repl = Repl::new().expect("repl construction is offline");
        let err = repl.render_copy(&[]).unwrap_err();
        assert!(err.contains("Nothing to copy"));
    }

    #[test]
    fn copy_defaults_to_markdown() {
        let repl = repl_with_result();
        let (text, msg) = repl.render_copy(&[]).expect("copyable");
        assert!(text.contains("1.2.3.4"));
        assert!(msg.contains("dns") && msg.contains("markdown"));
    }

    #[test]
    fn copy_accepts_explicit_formats() {
        let repl = repl_with_result();
        let (json, _) = repl.render_copy(&["json"]).expect("json");
        assert!(json.trim_start().starts_with('['));
        let (yaml, _) = repl.render_copy(&["yaml"]).expect("yaml");
        assert!(!yaml.is_empty());
        let (md, _) = repl.render_copy(&["markdown"]).expect("markdown");
        assert!(md.contains("1.2.3.4"));
        let (json_upper, _) = repl.render_copy(&["JSON"]).expect("JSON");
        assert!(json_upper.trim_start().starts_with('['));
        let (yml, _) = repl.render_copy(&["yml"]).expect("yml");
        assert!(!yml.is_empty());
    }

    #[test]
    fn copy_rejects_unknown_format() {
        let repl = repl_with_result();
        let err = repl.render_copy(&["bogus"]).unwrap_err();
        assert!(err.contains("Usage: copy"));
    }

    // `tld` looks offline (static WHOIS-server/registry-URL tables), but
    // `seer_core::lookup_tld` also calls `RdapClient::get_rdap_base_url_for_tld`,
    // which fetches/refreshes the IANA RDAP bootstrap data over the network
    // when the process-global cache is cold — so this is a live-network test
    // by the project's convention (see e.g. seer-core/src/rdap/client.rs).
    #[tokio::test]
    #[ignore = "live network; run with --ignored or SEER_LIVE_TESTS=1"]
    async fn tld_command_populates_last_result() {
        let mut repl = Repl::new().expect("repl construction is offline");
        let _ = repl.execute_line("tld com").await;
        assert!(
            matches!(repl.last_result, Some(crate::payload::Payload::Tld(_))),
            "tld should store a copyable payload"
        );
    }
}

// Hermetic arg-validation tests for the delegation command: both the usage
// error and the invalid-domain error surface before any network I/O.
#[cfg(test)]
mod delegation_repl_tests {
    use super::*;

    #[tokio::test]
    async fn delegation_requires_a_domain() {
        let mut repl = Repl::new().expect("repl construction is offline");
        let result = repl.execute_delegation(&[]).await;
        let CommandResult::Error(msg) = result else {
            panic!("expected usage error, got {result:?}");
        };
        assert!(msg.contains("Usage: delegation"), "got: {msg}");
    }

    #[tokio::test]
    async fn delegation_rejects_invalid_domain_before_network() {
        let mut repl = Repl::new().expect("repl construction is offline");
        // Consecutive dots fail normalize_domain inside check() before any
        // network I/O, so this stays hermetic.
        let result = repl.execute_delegation(&["bad..domain"]).await;
        let CommandResult::Error(msg) = result else {
            panic!("expected invalid-domain error, got {result:?}");
        };
        assert!(
            msg.to_lowercase().contains("invalid") && msg.contains("bad..domain"),
            "error should name the invalid input: {msg}"
        );
    }
}

// A typo'd record type previously fell back to A silently, so `dig example.com
// MXX` returned A answers while the user believed they queried MX. Validation
// now rejects the input before any network I/O, keeping these tests hermetic.
#[cfg(test)]
mod record_type_tests {
    use super::*;

    fn assert_rejects(result: &CommandResult) {
        let CommandResult::Error(msg) = result else {
            panic!("expected error for invalid record type, got {result:?}");
        };
        assert!(msg.contains("BOGUS"), "error should name the input: {msg}");
        assert!(
            msg.contains("MX") && msg.contains("SSHFP"),
            "error should list valid types: {msg}"
        );
    }

    #[tokio::test]
    async fn dig_rejects_invalid_record_type() {
        let mut repl = Repl::new().expect("repl construction is offline");
        let result = repl.execute_dig(&["example.com", "BOGUS"]).await;
        assert_rejects(&result);
    }

    #[tokio::test]
    async fn propagation_rejects_invalid_record_type() {
        let mut repl = Repl::new().expect("repl construction is offline");
        let result = repl.execute_propagation(&["example.com", "BOGUS"]).await;
        assert_rejects(&result);
    }

    #[tokio::test]
    async fn compare_rejects_invalid_record_type() {
        let mut repl = Repl::new().expect("repl construction is offline");
        let result = repl
            .execute_compare(&["example.com", "BOGUS", "@8.8.8.8", "@1.1.1.1"])
            .await;
        assert_rejects(&result);
    }
}
