//! Interactive REPL, launched when `seer` runs without a subcommand.
//!
//! A rustyline loop with tab completion ([`SeerCompleter`]) and history in
//! `~/.seer_history` (a line typed with a leading space is not recorded).
//! [`CommandContext`] holds the session state: the output format (`set
//! output`) and the user config the clients are built from. `copy` puts the
//! last result on the clipboard.

mod commands;
mod completer;

pub use commands::{CommandContext, CommandResult};
pub use completer::SeerCompleter;

use std::io::Write;
use std::sync::Arc;

use colored::Colorize;
use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;
use rustyline::{CompletionType, Editor};
use seer_core::colors::CatppuccinExt;

use crate::display::Spinner;

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

/// The line editor configuration. `history_ignore_space` lets a user keep a
/// sensitive query out of `~/.seer_history` by typing a leading space.
fn editor_config() -> rustyline::Config {
    rustyline::Config::builder()
        .history_ignore_space(true)
        .completion_type(CompletionType::List)
        .edit_mode(rustyline::EditMode::Emacs)
        .build()
}

/// The text recorded in history for a raw input line: trailing whitespace is
/// dropped, but LEADING whitespace must survive — rustyline decides whether to
/// honor `history_ignore_space` by looking at it. Adding the fully trimmed
/// line (as the loop used to) saved ` whois secret.com` anyway.
fn history_entry(line: &str) -> &str {
    line.trim_end()
}

impl Repl {
    pub fn new() -> anyhow::Result<Self> {
        let completer = SeerCompleter::new();
        let mut editor = Editor::with_config(editor_config())?;
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
            // Honor the config file's DNS timeout like `dig` does.
            dns_follower: seer_core::DnsFollower::with_resolver(
                seer_core::DnsResolver::from_config(cfg),
            ),
            last_result: None,
            context,
        })
    }

    /// Sets the session's output format, as `set output <fmt>` does. Used to
    /// carry an explicit `seer --format <fmt>` into the REPL.
    pub fn set_output_format(&mut self, format: seer_core::output::OutputFormat) {
        self.context.output_format = format;
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        self.print_banner();

        let mut last_ctrl_c: Option<std::time::Instant> = None;

        loop {
            let prompt = self.get_prompt();

            match self.editor.readline(&prompt) {
                Ok(line) => {
                    last_ctrl_c = None;
                    let command_line = line.trim();
                    if command_line.is_empty() {
                        continue;
                    }

                    self.editor.add_history_entry(history_entry(&line))?;

                    match self.execute_line(command_line).await {
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
        let result = self.dispatch(&command, &parts).await;

        // A failed command must not leave the PREVIOUS result behind for
        // `copy` to hand out as if it were this command's output. `copy` and
        // `set` only act on session state, so their errors (bad format name)
        // keep the buffer.
        if matches!(result, CommandResult::Error(_)) && !matches!(command.as_str(), "copy" | "set")
        {
            self.last_result = None;
        }
        result
    }

    /// Routes a tokenized line (`parts[0]` is the command as typed, `command`
    /// its lowercased form) to its handler.
    async fn dispatch(&mut self, command: &str, parts: &[&str]) -> CommandResult {
        let args = &parts[1..];

        match command {
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
            "headers" => self.execute_headers(args).await,
            "takeover" => self.execute_takeover(args).await,
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
                    self.execute_lookup(parts).await
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
            "  {:<34} ...and classify live/dead + dangling CNAMEs",
            "subdomains <domain> --resolve".bright_cyan()
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
            "  {:<34} Audit HTTP security headers + cookie flags",
            "headers <domain>".bright_cyan()
        );
        println!(
            "  {:<34} Scan subdomains for takeover exposure",
            "takeover <domain> [--host <h>]...".bright_cyan()
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
            format!("Operations: {}", *crate::ops::BULK_OPS_SUMMARY).dimmed()
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
        for (op, about) in crate::ops::BULK_OPS {
            println!("  {:<12} {}", op.bright_green(), about);
        }
        println!();
        println!("{}", "Input File Formats:".bright_cyan());
        println!("{}", crate::ops::BULK_INPUT_FORMATS);
        println!("{}", "Output:".bright_cyan());
        println!("  Results are written to CSV file (default: <input>_results.csv)");
        println!("  Use -o to specify custom output path");
        println!("  Each operation's CSV columns: see `seer bulk --help`");
        println!();
        println!("{}", "Examples:".bright_cyan());
        println!("  bulk status domains.txt");
        println!("  bulk lookup domains.csv -o results.csv");
        println!("  bulk dig domains.txt MX");
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
                self.last_result = Some(crate::payload::Payload::Delegation(Box::new(report)));
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
        self.last_result = Some(crate::payload::Payload::Doctor(Box::new(report)));
        CommandResult::Continue
    }

    async fn execute_reverse(&mut self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: reverse <ip>".to_string());
        }

        let ip = args[0];
        let spinner = Spinner::new(&format!("Looking up PTR for {}", ip));

        // Honor the configured nameserver, like `dig`.
        match self
            .dns_resolver
            .resolve(
                ip,
                seer_core::RecordType::PTR,
                self.context.config.nameserver.as_deref(),
            )
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
            "{}",
            crate::ops::bulk_banner(domains.len(), &parsed.operation)
        );

        let bar = crate::ops::bulk_bar(operations.len());
        let executor = seer_core::BulkExecutor::from_config(&self.context.config);
        let callback = crate::ops::bar_progress_callback(&bar);
        let results = executor.execute(operations, Some(callback)).await;
        crate::ops::finish_bulk_bar(&bar);

        if let Err(e) = crate::ops::write_bulk_csv(&results, &parsed.operation, &output_path) {
            return CommandResult::Error(e);
        }

        println!("\n");
        println!("Results written to: {}", output_path.ctp_green());
        println!("{}", crate::ops::bulk_summary(&results));

        if results.iter().any(|r| !r.success) {
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

        // In raw mode Ctrl+C arrives as a key, so no SIGINT handler here.
        let result = crate::ops::run_live_follow(
            &self.dns_follower,
            &domain,
            record_type,
            nameserver.as_deref(),
            config,
            self.context.output_format,
            false,
        )
        .await;

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
        let commands::SubdomainsArgs {
            domain,
            resolve,
            diff,
            record,
        } = match commands::parse_subdomains_args(args) {
            Ok(p) => p,
            Err(e) => return CommandResult::Error(e),
        };
        let domain = domain.as_str();
        let spinner = Spinner::new(&format!("Enumerating subdomains for {}", domain));

        if diff || record {
            // Same baseline semantics as the CLI `subdomains --diff/--record`
            // — shared via ops::subdomain_baseline_check so the two surfaces
            // cannot diverge (mirrors execute_drift below).
            match crate::ops::subdomain_baseline_check(domain, record).await {
                Ok(outcome) => {
                    spinner.finish();
                    let formatter = seer_core::output::get_formatter(self.context.output_format);
                    // Advisory notes go to stderr, as in the CLI, so stdout
                    // carries only the formatted result.
                    if diff {
                        if outcome.report.baseline_missing {
                            eprintln!(
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
                        eprintln!(
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
            Ok(result) if resolve => {
                // Same pipeline as the CLI's `subdomains --resolve`.
                spinner.set_message("Resolving and classifying discovered names");
                let classification = seer_core::classify_subdomains(
                    &self.dns_resolver,
                    &result.domain,
                    result.subdomains.clone(),
                    self.context.config.bulk.concurrency,
                )
                .await;
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!(
                    "{}",
                    formatter.format_subdomain_classification(&classification)
                );
                self.last_result = Some(crate::payload::Payload::SubdomainClassification(
                    Box::new(classification),
                ));
                CommandResult::Continue
            }
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
        let commands::DriftArgs { domain, record } = match commands::parse_drift_args(args) {
            Ok(p) => p,
            Err(e) => return CommandResult::Error(e),
        };
        let domain = domain.as_str();
        let spinner = Spinner::new(&format!("Looking up {}", domain));
        // Same history-snapshot semantics as the CLI `drift` subcommand —
        // shared via ops::drift_check so the two surfaces cannot diverge.
        let lookup = seer_core::SmartLookup::from_config(&self.context.config);
        match crate::ops::drift_check(&lookup, domain, record).await {
            Ok(outcome) => {
                spinner.finish();
                if !outcome.had_previous {
                    // Advisory note on stderr, as in the CLI.
                    eprintln!(
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

    async fn execute_headers(&mut self, args: &[&str]) -> CommandResult {
        if args.is_empty() {
            return CommandResult::Error("Usage: headers <domain>".to_string());
        }
        let domain = args[0];
        let spinner = Spinner::new(&format!("Auditing HTTP security headers for {}", domain));
        match seer_core::audit_headers(domain, self.context.config.http_timeout()).await {
            Ok(report) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_headers(&report));
                self.last_result = Some(crate::payload::Payload::Headers(Box::new(report)));
                CommandResult::Continue
            }
            Err(e) => {
                spinner.finish();
                CommandResult::Error(e.to_string())
            }
        }
    }

    async fn execute_takeover(&mut self, args: &[&str]) -> CommandResult {
        let commands::TakeoverArgs { domain, hosts } = match commands::parse_takeover_args(args) {
            Ok(p) => p,
            Err(e) => return CommandResult::Error(e),
        };
        let domain = domain.as_str();
        let spinner = Spinner::new(&format!("Scanning {} for takeover exposure", domain));
        // `--host` skips CT enumeration entirely, as in the CLI.
        let hosts = if hosts.is_empty() {
            spinner.set_message(&format!("Enumerating subdomains for {}", domain));
            match seer_core::SubdomainEnumerator::new()
                .enumerate(domain)
                .await
            {
                Ok(result) => result.subdomains,
                Err(e) => {
                    spinner.finish();
                    return CommandResult::Error(e.to_string());
                }
            }
        } else {
            hosts
        };

        spinner.set_message(&format!("Checking {} host(s) for takeover", hosts.len()));
        match seer_core::scan_takeover(
            &self.dns_resolver,
            domain,
            hosts,
            self.context.config.bulk.concurrency,
        )
        .await
        {
            Ok(report) => {
                spinner.finish();
                let formatter = seer_core::output::get_formatter(self.context.output_format);
                println!("{}", formatter.format_takeover(&report));
                self.last_result = Some(crate::payload::Payload::Takeover(Box::new(report)));
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
        if let Some(action) = args.first() {
            return match crate::ops::watch_edit(action, args.get(1).copied(), "watch").await {
                Ok(message) => {
                    println!("{}", message);
                    CommandResult::Continue
                }
                Err(e) => CommandResult::Error(e),
            };
        }
        let watchlist = match crate::ops::load_watchlist().await {
            Ok(w) => w,
            Err(e) => return CommandResult::Error(e),
        };
        if watchlist.domains.is_empty() {
            println!("{}", crate::ops::watchlist_listing(&watchlist, "watch"));
            return CommandResult::Continue;
        }
        let spinner = Spinner::new(&format!("Checking {} domains", watchlist.domains.len()));
        let report =
            seer_core::check_watchlist_with_config(&watchlist.domains, &self.context.config).await;
        spinner.finish();
        let formatter = seer_core::output::get_formatter(self.context.output_format);
        println!("{}", formatter.format_watch(&report));
        self.last_result = Some(crate::payload::Payload::Watch(Box::new(report)));
        CommandResult::Continue
    }

    async fn execute_history(&self, args: &[&str]) -> CommandResult {
        let result = if args.contains(&"--clear") {
            crate::ops::clear_history()
                .await
                .map(|()| "Lookup history cleared".to_string())
        } else {
            crate::ops::load_history().await.map(|history| {
                crate::ops::history_listing(&history, args.first().copied(), "lookup")
            })
        };
        match result {
            Ok(text) => {
                println!("{}", text);
                CommandResult::Continue
            }
            Err(e) => CommandResult::Error(e),
        }
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
    /// The `doctor` command previously rendered its report without touching
    /// `last_result`, so a following `copy` silently copied whatever ran
    /// BEFORE it — wrong output, no error. Seed a DNS result (the stale value
    /// the bug would have surfaced), then confirm a doctor payload wins.
    #[test]
    fn copy_after_doctor_copies_the_doctor_report_not_the_previous_result() {
        use seer_core::doctor::{CheckStatus, DoctorCheck, DoctorReport};

        let mut repl = repl_with_result();
        // Pre-condition: the stale payload the bug would have copied.
        assert_eq!(repl.last_result.as_ref().expect("seeded").kind(), "dns");

        repl.last_result = Some(crate::payload::Payload::Doctor(Box::new(
            DoctorReport::from_checks(vec![DoctorCheck {
                name: "dns".into(),
                status: CheckStatus::Pass,
                detail: "resolved example.com".into(),
                latency_ms: Some(12),
            }]),
        )));

        let (text, msg) = repl.render_copy(&[]).expect("doctor payload is copyable");
        assert!(
            msg.contains("doctor"),
            "confirmation should name doctor: {msg}"
        );
        assert!(
            text.contains("resolved example.com"),
            "copied text should be the doctor report: {text}"
        );
        assert!(
            !text.contains("1.2.3.4"),
            "must not copy the stale DNS result: {text}"
        );
    }

    /// Every copy format must render a doctor payload — `copy` offers
    /// markdown/json/yaml, and doctor is the one payload with no
    /// `OutputFormatter` method behind it.
    #[test]
    fn doctor_payload_serializes_in_every_copy_format() {
        use seer_core::doctor::{CheckStatus, DoctorCheck, DoctorReport};
        use seer_core::output::OutputFormat;

        let payload = crate::payload::Payload::Doctor(Box::new(DoctorReport::from_checks(vec![
            DoctorCheck {
                name: "whois".into(),
                status: CheckStatus::Warn,
                detail: "port 43 slow".into(),
                latency_ms: Some(4200),
            },
        ])));
        for format in [
            OutputFormat::Markdown,
            OutputFormat::Json,
            OutputFormat::Yaml,
        ] {
            let out = crate::payload::serialize(&payload, format);
            assert!(
                out.contains("whois"),
                "{format:?} output missing check name: {out}"
            );
        }
    }

    /// `delegation` previously never stored a payload, so `copy` after it
    /// silently copied whatever ran before.
    #[test]
    fn delegation_payload_is_copyable() {
        let mut repl = repl_with_result();
        repl.last_result = Some(crate::payload::Payload::Delegation(Box::new(
            seer_core::dns::DelegationReport {
                domain: "example.com".into(),
                parent_zone: "com".into(),
                parent_server_queried: vec!["a.gtld-servers.net".into()],
                delegated_ns: vec!["a.iana-servers.net".into()],
                zone_ns: vec!["a.iana-servers.net".into()],
                in_sync: true,
                missing_from_zone: vec![],
                missing_from_parent: vec![],
                lame: vec![],
                warnings: vec![],
            },
        )));
        let (text, msg) = repl.render_copy(&["json"]).expect("copyable");
        assert!(msg.contains("delegation"), "got: {msg}");
        assert!(text.contains("a.iana-servers.net"), "got: {text}");
        assert!(!text.contains("1.2.3.4"), "must not copy the stale result");
    }

    /// A failed command must not leave the previous result for `copy` to
    /// hand out as if it were this command's output. The usage error fires
    /// before any network I/O, so this stays hermetic.
    #[tokio::test]
    async fn failed_command_clears_the_copy_buffer() {
        let mut repl = repl_with_result();
        let result = repl.execute_line("delegation").await;
        assert!(matches!(result, CommandResult::Error(_)), "got {result:?}");
        assert!(repl.last_result.is_none(), "stale payload must be dropped");
        let err = repl.render_copy(&[]).unwrap_err();
        assert!(err.contains("Nothing to copy"), "got: {err}");
    }

    /// `copy`/`set` errors are about the request itself (bad format name),
    /// not a failed lookup, so they keep the buffer.
    #[tokio::test]
    async fn copy_and_set_errors_keep_the_copy_buffer() {
        let mut repl = repl_with_result();
        let result = repl.execute_line("copy bogus").await;
        assert!(matches!(result, CommandResult::Error(_)), "got {result:?}");
        assert!(repl.last_result.is_some());
        let result = repl.execute_line("set output bogus").await;
        assert!(matches!(result, CommandResult::Error(_)), "got {result:?}");
        assert!(repl.last_result.is_some());
    }

    #[tokio::test]
    #[ignore = "live network; run with --ignored or SEER_LIVE_TESTS=1"]
    async fn doctor_command_populates_last_result() {
        let mut repl = Repl::new().expect("repl construction is offline");
        let _ = repl.execute_line("doctor").await;
        assert!(
            matches!(repl.last_result, Some(crate::payload::Payload::Doctor(_))),
            "doctor should store a copyable payload"
        );
    }

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

#[cfg(test)]
mod session_tests {
    use super::*;
    use rustyline::history::History;

    /// The loop trimmed the line before `add_history_entry`, so rustyline
    /// never saw the leading space that `history_ignore_space` keys on and
    /// ` whois secret.com` was persisted to ~/.seer_history anyway.
    #[test]
    fn leading_space_line_is_kept_out_of_history() {
        let mut history = DefaultHistory::with_config(&editor_config());
        history
            .add(history_entry(" whois secret.com"))
            .expect("history add");
        assert!(history.is_empty(), "leading-space line must not be saved");
        history
            .add(history_entry("whois public.com  "))
            .expect("history add");
        assert_eq!(history.len(), 1);
    }

    /// `seer --format json` with no subcommand used to start the REPL in the
    /// config default, discarding the flag.
    #[test]
    fn explicit_format_carries_into_the_repl() {
        let mut repl = Repl::new().expect("repl construction is offline");
        repl.set_output_format(seer_core::output::OutputFormat::Json);
        assert_eq!(
            repl.context.output_format,
            seer_core::output::OutputFormat::Json
        );
        assert!(repl.get_prompt().contains("[json]"));
    }

    /// Mistyped flags used to be silently ignored (`drift x --recrod` ran a
    /// non-recording check). They now fail before any network I/O.
    #[tokio::test]
    async fn repl_rejects_unknown_flags_before_network() {
        let mut repl = Repl::new().expect("repl construction is offline");
        for line in [
            "drift example.com --recrod",
            "subdomains example.com --reslove",
            "takeover example.com --hots a.example.com",
            "follow example.com 5 MXX",
        ] {
            let result = repl.execute_line(line).await;
            let CommandResult::Error(msg) = result else {
                panic!("{line:?} should be rejected, got {result:?}");
            };
            assert!(
                msg.contains("--recrod")
                    || msg.contains("--reslove")
                    || msg.contains("--hots")
                    || msg.contains("MXX"),
                "{line:?}: error should name the bad token: {msg}"
            );
        }
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
