//! Interactive REPL, launched when `seer` runs without a subcommand.
//!
//! A rustyline loop with tab completion ([`SeerCompleter`]) and history in
//! `~/.seer_history`, appended after every command (a line typed with a
//! leading space is not recorded). Ctrl-C cancels the running command and
//! returns to the prompt. [`CommandContext`] holds the session state: the
//! output format (`set output`) and the user config the clients are built
//! from. `copy` puts the last result on the clipboard.

mod catalog;
mod commands;
mod completer;

pub use commands::{CommandContext, CommandResult};
pub use completer::SeerCompleter;

use std::io::Write;

use colored::Colorize;
use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;
use rustyline::{CompletionType, Editor};
use seer_core::colors::CatppuccinExt;

use crate::query::{Clients, Query};

const HISTORY_FILE: &str = ".seer_history";

pub struct Repl {
    editor: Editor<SeerCompleter, DefaultHistory>,
    history_path: std::path::PathBuf,
    /// Set once a history write failed, so the warning is printed once.
    history_warned: bool,
    context: CommandContext,
    /// Built once from the user config and kept for the session.
    clients: Clients,
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

        // Load history (a missing file is a first run).
        let history_path = std::env::home_dir()
            .map(|p| p.join(HISTORY_FILE))
            .unwrap_or_else(|| HISTORY_FILE.into());

        let _ = editor.load_history(&history_path);

        // Build clients from the user config so the REPL honors per-protocol
        // timeouts / nameserver / bulk concurrency.
        let context = CommandContext::new();
        let cfg = &context.config;

        Ok(Self {
            editor,
            history_path,
            history_warned: false,
            clients: Clients::from_config(cfg),
            // Honor the config file's DNS timeout like `dig` does.
            dns_follower: seer_core::DnsFollower::from_config(cfg),
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
                    self.append_history();

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

        Ok(())
    }

    /// Appends the new history entries to `~/.seer_history` right away, so
    /// a crash or kill loses nothing, and with append semantics, so two
    /// concurrent sessions add to the file instead of the last one to exit
    /// overwriting it. rustyline creates and rewrites the file owner-only
    /// (0600) itself — it records every queried domain/IP/ASN.
    fn append_history(&mut self) {
        if let Err(e) = self.editor.append_history(&self.history_path) {
            if !std::mem::replace(&mut self.history_warned, true) {
                eprintln!(
                    "{} could not write {}: {}",
                    "Warning:".ctp_yellow(),
                    self.history_path.display(),
                    e
                );
            }
        }
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
        let canonical = catalog::canonical(&command);

        // Only a command that produced a result may leave one for `copy`: a
        // failed command, or one with no single result (bulk, follow,
        // history, watch add/remove), must not leave the PREVIOUS result to
        // be handed out as if it were its own. The session commands keep it.
        if !matches!(canonical, "copy" | "set" | "help" | "clear" | "exit") {
            self.last_result = None;
        }

        // Ctrl-C cancels the running command (dropping it clears its spinner
        // or progress bar) and returns to the prompt; without a handler the
        // signal killed the whole session. `follow` handles Ctrl-C itself,
        // to stop early and still print its summary.
        if canonical == "follow" {
            return self.dispatch(&command, &parts).await;
        }
        match until_interrupted(self.dispatch(&command, &parts), ctrl_c()).await {
            Some(result) => result,
            None => CommandResult::Error("Interrupted".to_string()),
        }
    }

    /// Routes a tokenized line (`parts[0]` is the command as typed, `command`
    /// its lowercased form) to its handler. Everything that is not a session
    /// or multi-step command is a single-shot query (see `crate::query`).
    async fn dispatch(&mut self, command: &str, parts: &[&str]) -> CommandResult {
        let args = &parts[1..];

        match catalog::canonical(command) {
            "help" => {
                self.print_help();
                CommandResult::Continue
            }
            "exit" => CommandResult::Exit,
            "bulk" => self.execute_bulk(args).await,
            "follow" => self.execute_follow(args).await,
            "watch" => self.execute_watch(args).await,
            "history" => self.execute_history(args).await,
            "set" => self.execute_set(args),
            "copy" => self.execute_copy(args),
            "clear" => {
                print!("\x1B[2J\x1B[1;1H");
                let _ = std::io::stdout().flush();
                CommandResult::Continue
            }
            _ => match commands::parse_query(command, parts) {
                Ok(query) => self.execute_query(query).await,
                Err(e) => CommandResult::Error(e),
            },
        }
    }

    fn print_help(&self) {
        println!();
        for section in catalog::SECTIONS {
            println!("{}", section.title.bright_purple().bold());
            for command in section.commands {
                let invocation = format!("{} {}", command.name, command.usage);
                println!(
                    "  {:<34} {}",
                    invocation.trim_end().bright_cyan(),
                    command.about
                );
            }
            if let Some(note) = section.note {
                println!("  {}", note().dimmed());
            }
            println!();
        }
    }
    fn print_bulk_help(&self) {
        println!();
        println!("{}", "BULK OPERATIONS".bright_purple().bold());
        println!();
        println!("{}", "Usage:".bright_cyan());
        println!("  {}", catalog::usage("bulk").trim_start_matches("Usage: "));
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
        println!("  Use -o to specify custom output path; with `set output json|yaml`");
        println!("  the results print instead (and -o still writes the CSV)");
        println!("  --progress bar|verbose|failures|none picks the progress display");
        println!("  Each operation's CSV columns: see `seer bulk --help`");
        println!();
        println!("{}", "Examples:".bright_cyan());
        println!("  bulk status domains.txt");
        println!("  bulk lookup domains.csv -o results.csv");
        println!("  bulk dig domains.txt MX --progress failures");
        println!();
    }

    /// Runs a single-shot query, prints it in the session's output format
    /// (advisory notes on stderr, as in the CLI), and keeps it for `copy`.
    async fn execute_query(&mut self, query: Query) -> CommandResult {
        match crate::query::run(query, &self.clients, &self.context.config, true).await {
            Ok(outcome) => {
                let format = self.context.output_format;
                outcome.present(format, |payload| {
                    println!("{}", crate::payload::serialize(payload, format));
                });
                self.last_result = Some(outcome.payload);
                CommandResult::Continue
            }
            Err(e) => CommandResult::Error(e.to_string()),
        }
    }
    /// `bulk`: the same run as `seer bulk` ([`crate::bulk::run_bulk`]).
    async fn execute_bulk(&mut self, args: &[&str]) -> CommandResult {
        if args.is_empty()
            || args
                .iter()
                .any(|a| *a == "-h" || *a == "--help" || *a == "help")
        {
            self.print_bulk_help();
            return CommandResult::Continue;
        }
        let request = match commands::parse_bulk_args(args) {
            Ok(request) => request,
            Err(e) => return CommandResult::Error(e),
        };
        // The REPL has no exit code; a failed batch shows in its summary.
        match crate::bulk::run_bulk(request, self.context.output_format, &self.context.config).await
        {
            Ok(_) => CommandResult::Continue,
            Err(e) => CommandResult::Error(e),
        }
    }

    /// `follow`: the same run as `seer follow` ([`crate::ops::follow_command`]).
    async fn execute_follow(&self, args: &[&str]) -> CommandResult {
        let args = match commands::parse_follow_args(args) {
            Ok(args) => args,
            Err(e) => return CommandResult::Error(e),
        };
        match crate::ops::follow_command(
            &self.dns_follower,
            args,
            &self.context.config,
            self.context.output_format,
        )
        .await
        {
            Ok(()) => CommandResult::Continue,
            Err(e) => CommandResult::Error(e),
        }
    }

    async fn execute_watch(&mut self, args: &[&str]) -> CommandResult {
        let format = self.context.output_format;
        if let Some((action, domains)) = args.split_first() {
            let domains: Vec<String> = domains.iter().map(|d| d.to_string()).collect();
            return match crate::manage::watch_edit(action, &domains, "watch").await {
                Ok(listing) => {
                    println!("{}", listing.render(format));
                    CommandResult::Continue
                }
                Err(e) => CommandResult::Error(e),
            };
        }
        match crate::manage::watch_check(&self.context.config, "watch").await {
            Ok(crate::manage::WatchCheck::Empty(listing)) => {
                println!("{}", listing.render(format));
                CommandResult::Continue
            }
            Ok(crate::manage::WatchCheck::Report(report)) => {
                let payload = crate::payload::Payload::Watch(report);
                println!("{}", crate::payload::serialize(&payload, format));
                self.last_result = Some(payload);
                CommandResult::Continue
            }
            Err(e) => CommandResult::Error(e),
        }
    }

    async fn execute_history(&self, args: &[&str]) -> CommandResult {
        let (domain, clear) = match commands::parse_history_args(args) {
            Ok(parsed) => parsed,
            Err(e) => return CommandResult::Error(e),
        };
        match crate::manage::history(domain.as_deref(), clear, "lookup").await {
            Ok(listing) => {
                println!("{}", listing.render(self.context.output_format));
                CommandResult::Continue
            }
            Err(e) => CommandResult::Error(e),
        }
    }

    /// Pure part of `copy`: pick the format, serialize the last result.
    /// Returns (text to place on the clipboard, confirmation message).
    fn render_copy(&self, args: &[&str]) -> Result<(String, String), String> {
        if let Some(extra) = args.get(1) {
            return Err(format!(
                "Unexpected argument: {extra}\n{}",
                catalog::usage("copy")
            ));
        }
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
        if args.len() != 2 {
            return CommandResult::Error(catalog::usage("set"));
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

/// Runs `work` until it finishes — `Some(output)` — or until `interrupt`
/// fires first, dropping `work` (its spinner or progress bar clears on drop)
/// and returning `None`.
async fn until_interrupted<F: std::future::Future>(
    work: F,
    interrupt: impl std::future::Future<Output = ()>,
) -> Option<F::Output> {
    tokio::select! {
        output = work => Some(output),
        () = interrupt => None,
    }
}

/// Resolves on Ctrl-C (SIGINT). If the handler cannot be installed it never
/// resolves — a command must not be cancelled by a failure to listen.
async fn ctrl_c() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod copy_tests {
    use super::*;
    use crate::payload::fixtures;
    use seer_core::dns::RecordType;

    fn repl_with_result() -> Repl {
        let mut repl = Repl::new().expect("repl construction is offline");
        let dig = fixtures::dig(RecordType::A, vec![fixtures::a("example.com", "1.2.3.4")]);
        repl.last_result = Some(crate::payload::Payload::Dig(Box::new(dig)));
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
        assert!(msg.contains("dig") && msg.contains("markdown"));
    }

    #[test]
    fn copy_accepts_explicit_formats() {
        let repl = repl_with_result();
        let (json, _) = repl.render_copy(&["json"]).expect("json");
        assert!(json.trim_start().starts_with('{'));
        let (yaml, _) = repl.render_copy(&["yaml"]).expect("yaml");
        assert!(!yaml.is_empty());
        let (md, _) = repl.render_copy(&["markdown"]).expect("markdown");
        assert!(md.contains("1.2.3.4"));
        let (json_upper, _) = repl.render_copy(&["JSON"]).expect("JSON");
        assert!(json_upper.trim_start().starts_with('{'));
        let (yml, _) = repl.render_copy(&["yml"]).expect("yml");
        assert!(!yml.is_empty());
    }

    #[test]
    fn copy_rejects_unknown_format_and_extra_arguments() {
        let repl = repl_with_result();
        let err = repl.render_copy(&["bogus"]).unwrap_err();
        assert!(err.contains("Usage: copy"));
        let err = repl.render_copy(&["json", "yaml"]).unwrap_err();
        assert!(err.starts_with("Unexpected argument: yaml"), "{err}");
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
        assert_eq!(repl.last_result.as_ref().expect("seeded").kind(), "dig");

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

    /// `copy` after `dig`: one type copies the result object, several the
    /// array, and a trace its hops — in every copy format.
    #[test]
    fn dig_and_trace_payloads_are_copyable() {
        use crate::payload::Payload;
        let mut repl = repl_with_result();
        let chained = fixtures::dig(
            RecordType::A,
            vec![
                fixtures::cname("www.seer.test", "edge.cdn.test."),
                fixtures::a("edge.cdn.test", "192.0.2.7"),
            ],
        );
        let mx = fixtures::dig(
            RecordType::MX,
            vec![fixtures::mx("www.seer.test", "mail.seer.test.")],
        );

        repl.last_result = Some(Payload::Dig(Box::new(chained.clone())));
        let (json, msg) = repl.render_copy(&["json"]).expect("copyable");
        assert!(msg.contains("dig"), "got: {msg}");
        assert!(json.trim_start().starts_with('{'), "an object: {json}");
        assert!(json.contains("edge.cdn.test") && !json.contains("1.2.3.4"));
        let (md, _) = repl.render_copy(&[]).expect("markdown");
        assert!(md.contains("## DNS A Records: www.seer.test"), "{md}");

        repl.last_result = Some(Payload::DigMany(vec![chained, mx]));
        let (json, _) = repl.render_copy(&["json"]).expect("copyable");
        assert!(json.trim_start().starts_with('['), "an array: {json}");
        let (md, _) = repl.render_copy(&["markdown"]).expect("markdown");
        assert!(md.contains("## DNS MX Records"), "{md}");
        let (yaml, _) = repl.render_copy(&["yaml"]).expect("yaml");
        assert!(yaml.contains("mail.seer.test."), "{yaml}");

        repl.last_result = Some(Payload::Trace(Box::new(fixtures::trace(
            vec![fixtures::a("www.seer.test", "192.0.2.7")],
            None,
        ))));
        let (md, msg) = repl.render_copy(&[]).expect("copyable");
        assert!(msg.contains("trace"), "got: {msg}");
        assert!(md.contains("a.root-servers.net."), "{md}");
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

    /// `copy` after a command with no single result (bulk, follow,
    /// history, watch add/remove) copied the result BEFORE it. These fail
    /// before any I/O but, like a success, must not leave the old payload.
    #[tokio::test]
    async fn commands_without_a_result_clear_the_copy_buffer() {
        for line in ["bulk status", "follow", "history a.com b.com", "watch add"] {
            let mut repl = repl_with_result();
            let _ = repl.execute_line(line).await;
            assert!(repl.last_result.is_none(), "{line:?} kept the old payload");
        }
        // Session commands keep it.
        for line in ["help", "set output json", "copy bogus"] {
            let mut repl = repl_with_result();
            let _ = repl.execute_line(line).await;
            assert!(repl.last_result.is_some(), "{line:?} dropped the payload");
        }
    }

    /// Ctrl-C used to kill the whole REPL (and lose its history) mid-command;
    /// it now cancels just the command.
    #[tokio::test]
    async fn an_interrupt_cancels_the_running_command() {
        let pending = std::future::pending::<CommandResult>();
        assert!(until_interrupted(pending, async {}).await.is_none());
        let done = async { CommandResult::Continue };
        let never = std::future::pending::<()>();
        assert!(matches!(
            until_interrupted(done, never).await,
            Some(CommandResult::Continue)
        ));
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
        let result = repl.execute_line("delegation").await;
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
        let result = repl.execute_line("delegation bad..domain").await;
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
        let result = repl.execute_line("dig example.com BOGUS").await;
        assert_rejects(&result);
        // In any position: dig-style arguments come in any order.
        let result = repl.execute_line("dig BOGUS @8.8.8.8 example.com").await;
        assert_rejects(&result);
    }

    /// dig's other usage errors surface before any network I/O too.
    #[tokio::test]
    async fn dig_rejects_bad_arguments_before_network() {
        let mut repl = Repl::new().expect("repl construction is offline");
        for (line, problem) in [
            ("dig", "Usage: dig [@server] <name>"),
            ("dns +short", "no name to query"),
            ("dig example.com +bogus", "+bogus"),
            ("dig example.com @8.8.8.8 +trace", "root servers"),
            ("dig -x example.com", "-x needs an IP address"),
        ] {
            let result = repl.execute_line(line).await;
            let CommandResult::Error(msg) = result else {
                panic!("{line:?} should be rejected, got {result:?}");
            };
            assert!(msg.contains(problem), "{line:?}: {msg}");
        }
    }

    #[tokio::test]
    async fn propagation_rejects_invalid_record_type() {
        let mut repl = Repl::new().expect("repl construction is offline");
        let result = repl.execute_line("propagation example.com BOGUS").await;
        assert_rejects(&result);
    }

    #[tokio::test]
    async fn compare_rejects_invalid_record_type() {
        let mut repl = Repl::new().expect("repl construction is offline");
        let result = repl
            .execute_line("compare example.com BOGUS @8.8.8.8 @1.1.1.1")
            .await;
        assert_rejects(&result);
    }
}
