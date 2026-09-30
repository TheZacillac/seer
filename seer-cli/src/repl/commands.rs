use seer_core::output::OutputFormat;
use seer_core::{RecordType, SeerConfig};

use super::catalog;
use crate::query::Query;

#[derive(Debug, Clone)]
pub struct CommandContext {
    pub output_format: OutputFormat,
    /// User config (`~/.seer/config.toml`) — threaded into client construction
    /// so the REPL honors per-protocol timeouts, nameserver, and bulk
    /// concurrency instead of silently using library defaults.
    pub config: SeerConfig,
}

impl CommandContext {
    pub fn new() -> Self {
        let config = SeerConfig::load();
        let output_format = crate::config_output_format(&config.output_format);
        Self {
            output_format,
            config,
        }
    }
}

impl Default for CommandContext {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum CommandResult {
    Continue,
    Exit,
    Error(String),
}

const UNBALANCED_QUOTE: &str = "Unbalanced quote in command line (close the \" or ' )";

/// Splits a REPL input line into tokens, honoring shell-style single/double
/// quotes so arguments containing spaces (e.g. `bulk lookup "Domain
/// Lists/prod.txt"`) survive intact — the CLI gets this for free from the OS
/// shell, but the REPL tokenizes its own input. Errors on unbalanced quotes
/// instead of silently producing garbage tokens.
///
/// On Windows, backslash is the path separator, so POSIX shell escaping
/// (which `shlex` implements) would eat it: `C:\Users\me\d.txt` became
/// `C:Usersmed.txt`. There the line is split by [`split_quoted_literal`],
/// which honors quotes but keeps every backslash literally.
pub fn tokenize_line(line: &str) -> Result<Vec<String>, String> {
    if cfg!(windows) {
        split_quoted_literal(line)
    } else {
        shlex::split(line).ok_or_else(|| UNBALANCED_QUOTE.to_string())
    }
}

/// Splits `line` on whitespace, grouping text inside single or double quotes
/// into one token (quotes removed; adjacent quoted/unquoted runs join, and
/// `""` yields an empty token). Backslash has no special meaning. This is the
/// Windows REPL tokenizer; it is a plain function so every platform tests it.
pub fn split_quoted_literal(line: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    // True once the current token has started — distinguishes an explicit
    // empty token (`""`) from no token at all.
    let mut in_token = false;
    let mut quote: Option<char> = None;

    for c in line.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => current.push(c),
            None if c == '"' || c == '\'' => {
                quote = Some(c);
                in_token = true;
            }
            None if c.is_whitespace() => {
                if in_token {
                    tokens.push(std::mem::take(&mut current));
                    in_token = false;
                }
            }
            None => {
                current.push(c);
                in_token = true;
            }
        }
    }

    if quote.is_some() {
        return Err(UNBALANCED_QUOTE.to_string());
    }
    if in_token {
        tokens.push(current);
    }
    Ok(tokens)
}

/// Parses a tokenized REPL line into a single-shot [`Query`]. `command` is
/// the lowercased first token and `parts` the whole line; a first token with
/// a dot is a bare domain (`example.com` means `lookup example.com`).
/// Everything is validated here, before any network I/O.
pub fn parse_query(command: &str, parts: &[&str]) -> Result<Query, String> {
    let args = &parts[1..];
    // The one argument, or the command's usage line.
    let arg = || only_arg(command, args);
    Ok(match catalog::canonical(command) {
        "lookup" => Query::Lookup(arg()?),
        "info" => Query::Info(arg()?),
        "whois" => Query::Whois(arg()?),
        "rdap" => Query::Rdap(arg()?),
        "dig" => {
            if args.is_empty() {
                return Err(catalog::usage(command));
            }
            // `-x`/`-s`/`--short`/`--trace` stay in the tokens: the shared
            // parser reads the REPL's flag spellings itself.
            crate::dig_args::parse(args, crate::dig_args::DigFlags::default())
                .map_err(|e| format!("{e}\n{}", catalog::usage(command)))?
                .into_query()
        }
        "prop" => {
            let usage = catalog::usage(command);
            reject_flags(args, &usage)?;
            let (domain, record_type) = match args {
                [domain] => (domain, RecordType::A),
                [domain, name] => (domain, crate::try_parse_record_type(name)?),
                [] => return Err(usage),
                [_, _, extra, ..] => return Err(unexpected(extra, &usage)),
            };
            Query::Prop {
                domain: domain.to_string(),
                record_type,
            }
        }
        "status" => Query::Status(arg()?),
        "reverse" => Query::Reverse(arg()?),
        "avail" => Query::Avail(arg()?),
        "dnssec" => Query::Dnssec(arg()?),
        "ssl" => Query::Ssl(arg()?),
        "tld" => Query::Tld(arg()?),
        "compare" => {
            if args.is_empty() {
                return Err(catalog::usage(command));
            }
            crate::dns_args::parse_compare(args)
                .map_err(|e| format!("{e}\n{}", catalog::usage(command)))?
                .into_query()
        }
        "subdomains" => {
            let SubdomainsArgs {
                domain,
                resolve,
                diff,
                record,
            } = parse_subdomains_args(args)?;
            Query::Subdomains {
                domain,
                resolve,
                diff,
                record,
            }
        }
        "diff" => {
            let usage = catalog::usage(command);
            reject_flags(args, &usage)?;
            match args {
                [a, b] => Query::Diff(a.to_string(), b.to_string()),
                [_, _, extra, ..] => return Err(unexpected(extra, &usage)),
                _ => return Err(usage),
            }
        }
        "drift" => {
            let DriftArgs { domain, record } = parse_drift_args(args)?;
            Query::Drift { domain, record }
        }
        "caa" => Query::Caa(arg()?),
        "posture" => Query::Posture(arg()?),
        "headers" => Query::Headers(arg()?),
        "takeover" => {
            let TakeoverArgs { domain, hosts } = parse_takeover_args(args)?;
            Query::Takeover { domain, hosts }
        }
        "confusables" => Query::Confusables(arg()?),
        "doctor" => {
            no_args(command, args)?;
            Query::Doctor
        }
        "delegation" => Query::Delegation(arg()?),
        // A bare domain is `lookup <domain>`, with the same arity.
        _ if command.contains('.') => {
            if let Some(extra) = args.first() {
                let usage = catalog::usage("lookup");
                reject_unknown_flag(extra, &usage)?;
                return Err(unexpected(extra, &usage));
            }
            Query::Lookup(parts[0].to_string())
        }
        _ => {
            return Err(format!(
                "Unknown command: {}. Type 'help' for available commands.",
                command
            ))
        }
    })
}

/// Returns a usage error for an unrecognized `--flag` / `-f` token, so a typo
/// like `--recrod` fails loudly instead of being silently ignored.
fn reject_unknown_flag(token: &str, usage: &str) -> Result<(), String> {
    if token.starts_with('-') {
        return Err(format!("Unknown option: {token}\n{usage}"));
    }
    Ok(())
}

/// [`reject_unknown_flag`] for every token of a command that takes no flags.
fn reject_flags(args: &[&str], usage: &str) -> Result<(), String> {
    args.iter()
        .try_for_each(|arg| reject_unknown_flag(arg, usage))
}

fn unexpected(extra: &str, usage: &str) -> String {
    format!("Unexpected argument: {extra}\n{usage}")
}

/// The single argument of a one-argument command. Extra arguments and flags
/// are usage errors: they used to be dropped silently, so `whois example.com
/// --raw` ran a plain lookup and `diff a b c` ignored `c`.
fn only_arg(command: &str, args: &[&str]) -> Result<String, String> {
    let usage = catalog::usage(command);
    reject_flags(args, &usage)?;
    match args {
        [arg] => Ok(arg.to_string()),
        [] => Err(usage),
        [_, extra, ..] => Err(unexpected(extra, &usage)),
    }
}

/// A command that takes no arguments at all.
pub fn no_args(command: &str, args: &[&str]) -> Result<(), String> {
    match args.first() {
        Some(extra) => {
            let usage = catalog::usage(command);
            reject_unknown_flag(extra, &usage)?;
            Err(unexpected(extra, &usage))
        }
        None => Ok(()),
    }
}

/// Parses `history [domain] [--clear]`; unknown flags and a second domain
/// are errors (`manage::history` rejects a domain with `--clear`).
pub fn parse_history_args(args: &[&str]) -> Result<(Option<String>, bool), String> {
    let usage = catalog::usage("history");
    let (mut domain, mut clear) = (None, false);
    for arg in args {
        if *arg == "--clear" {
            clear = true;
            continue;
        }
        reject_unknown_flag(arg, &usage)?;
        if domain.is_some() {
            return Err(unexpected(arg, &usage));
        }
        domain = Some(arg.to_string());
    }
    Ok((domain, clear))
}

/// Parsed arguments for the REPL `subdomains` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubdomainsArgs {
    pub domain: String,
    /// Resolve and classify each discovered name (live/dead, dangling CNAME).
    pub resolve: bool,
    /// Diff against the stored baseline.
    pub diff: bool,
    /// Record the fresh enumeration as the new baseline.
    pub record: bool,
}

/// Parses `subdomains <domain> [--resolve] [--diff] [--record]`, mirroring
/// the CLI: `--resolve` conflicts with `--diff`/`--record`, and unknown
/// flags or extra arguments are usage errors.
pub fn parse_subdomains_args(args: &[&str]) -> Result<SubdomainsArgs, String> {
    let usage = catalog::usage("subdomains");
    let mut domain: Option<String> = None;
    let (mut resolve, mut diff, mut record) = (false, false, false);
    for arg in args {
        match *arg {
            "--resolve" => resolve = true,
            "--diff" => diff = true,
            "--record" => record = true,
            other => {
                reject_unknown_flag(other, &usage)?;
                if domain.is_some() {
                    return Err(format!("Unexpected argument: {other}\n{usage}"));
                }
                domain = Some(other.to_string());
            }
        }
    }
    let Some(domain) = domain else {
        return Err(usage);
    };
    if resolve && (diff || record) {
        return Err(format!(
            "--resolve cannot be combined with --diff or --record\n{usage}"
        ));
    }
    Ok(SubdomainsArgs {
        domain,
        resolve,
        diff,
        record,
    })
}

/// Parsed arguments for the REPL `takeover` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TakeoverArgs {
    pub domain: String,
    /// Hosts from repeatable `--host <HOST>`; non-empty skips CT enumeration.
    pub hosts: Vec<String>,
}

/// Parses `takeover <domain> [--host <HOST>]...` (also `--host=HOST`),
/// mirroring the CLI's repeatable `--host`.
pub fn parse_takeover_args(args: &[&str]) -> Result<TakeoverArgs, String> {
    let usage = catalog::usage("takeover");
    let mut domain: Option<String> = None;
    let mut hosts = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "--host" {
            let Some(host) = args.get(i + 1) else {
                return Err(format!("Missing value after --host\n{usage}"));
            };
            hosts.push(host.to_string());
            i += 2;
            continue;
        }
        if let Some(host) = arg.strip_prefix("--host=") {
            if host.is_empty() {
                return Err(format!("Missing value after --host\n{usage}"));
            }
            hosts.push(host.to_string());
        } else {
            reject_unknown_flag(arg, &usage)?;
            if domain.is_some() {
                return Err(format!("Unexpected argument: {arg}\n{usage}"));
            }
            domain = Some(arg.to_string());
        }
        i += 1;
    }
    let Some(domain) = domain else {
        return Err(usage);
    };
    Ok(TakeoverArgs { domain, hosts })
}

/// Parsed arguments for the REPL `drift` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftArgs {
    pub domain: String,
    /// Record the fresh lookup as the new baseline.
    pub record: bool,
}

/// Parses `drift <domain> [--record]`; unknown flags (e.g. the typo
/// `--recrod`, which previously silently skipped recording) are errors.
pub fn parse_drift_args(args: &[&str]) -> Result<DriftArgs, String> {
    let usage = catalog::usage("drift");
    let mut domain: Option<String> = None;
    let mut record = false;
    for arg in args {
        if *arg == "--record" {
            record = true;
            continue;
        }
        reject_unknown_flag(arg, &usage)?;
        if domain.is_some() {
            return Err(format!("Unexpected argument: {arg}\n{usage}"));
        }
        domain = Some(arg.to_string());
    }
    let Some(domain) = domain else {
        return Err(usage);
    };
    Ok(DriftArgs { domain, record })
}

/// Parses `bulk <operation> <file> [type] [-o output.csv] [--progress
/// <mode>]` into the request [`crate::bulk::run_bulk`] runs for both
/// surfaces. Paths stay as typed (`run_bulk` expands `~`).
///
/// Errors with a usage message when fewer than two positionals are given,
/// when `-o`/`--output` or `--progress` trails without a value (previously
/// `-o` was silently ignored, quietly writing the default path), on an
/// unknown flag or a second type, and on `-` as the file: the REPL's stdin
/// is the terminal it reads commands from, so a domain list can only be
/// piped into `seer bulk … -`.
pub fn parse_bulk_args(args: &[&str]) -> Result<crate::bulk::BulkRequest, String> {
    let usage = catalog::usage("bulk");
    let (operation, file) = match args {
        [operation, file, ..] => (operation.to_string(), file.to_string()),
        _ => return Err(format!("{usage}\nType 'bulk -h' for detailed help.")),
    };
    if file == "-" {
        return Err(
            "The REPL cannot read a domain list from stdin; give a file, or pipe the list \
             into `seer bulk <operation> -`"
                .to_string(),
        );
    }
    let mut record_type: Option<RecordType> = None;
    let mut output: Option<String> = None;
    let mut progress: Option<crate::bulk::ProgressMode> = None;

    let mut rest = args[2..].iter();
    while let Some(arg) = rest.next() {
        match *arg {
            "-o" | "--output" => {
                let Some(value) = rest.next() else {
                    return Err("Missing value after -o/--output".to_string());
                };
                output = Some(value.to_string());
            }
            "--progress" => {
                let Some(value) = rest.next() else {
                    return Err("Missing value after --progress".to_string());
                };
                let mode = <crate::bulk::ProgressMode as clap::ValueEnum>::from_str(value, true)
                    .map_err(|_| {
                        format!("Unknown progress mode: {value}. Use: bar, verbose, failures, none")
                    })?;
                progress = Some(mode);
            }
            other => {
                reject_unknown_flag(other, &usage)?;
                if record_type.is_some() {
                    return Err(unexpected(other, &usage));
                }
                record_type = Some(crate::try_parse_record_type(other)?);
            }
        }
    }

    Ok(crate::bulk::BulkRequest {
        operation,
        input: file,
        record_type: record_type.unwrap_or(RecordType::A),
        output,
        progress,
    })
}

/// Parses `follow` through the grammar `seer follow` shares
/// ([`crate::dns_args::parse_follow`]); errors end with the usage line.
pub fn parse_follow_args(args: &[&str]) -> Result<crate::dns_args::FollowArgs, String> {
    let usage = catalog::usage("follow");
    if args.is_empty() {
        return Err(usage);
    }
    crate::dns_args::parse_follow(args, crate::dns_args::FollowFlags::default())
        .map_err(|e| format!("{e}\n{usage}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bulk(args: &[&str]) -> crate::bulk::BulkRequest {
        parse_bulk_args(args).unwrap_or_else(|e| panic!("{args:?}: {e}"))
    }

    #[test]
    fn bulk_requires_operation_and_file() {
        assert!(parse_bulk_args(&[]).is_err());
        assert!(parse_bulk_args(&["status"]).is_err());
    }

    #[test]
    fn bulk_minimal_defaults() {
        let got = bulk(&["status", "domains.txt"]);
        assert_eq!(got.operation, "status");
        assert_eq!(got.input, "domains.txt");
        assert_eq!(got.record_type, RecordType::A);
        assert_eq!(got.output, None);
        assert_eq!(got.progress, None);
    }

    #[test]
    fn bulk_parses_record_type_positional() {
        assert_eq!(
            bulk(&["dig", "domains.txt", "MX"]).record_type,
            RecordType::MX
        );
        // Unparseable type tokens error instead of silently falling back to A.
        let err = parse_bulk_args(&["dig", "domains.txt", "NOTATYPE"])
            .err()
            .expect("must error");
        assert!(err.contains("NOTATYPE"));
        assert!(err.contains("valid types"));
        // A second type used to replace the first silently.
        let err = parse_bulk_args(&["dig", "d.txt", "MX", "TXT"])
            .err()
            .expect("two types");
        assert!(err.starts_with("Unexpected argument: TXT"), "{err}");
    }

    #[test]
    fn bulk_parses_output_and_progress_in_any_order() {
        for flag in ["-o", "--output"] {
            assert_eq!(
                bulk(&["lookup", "d.txt", flag, "out.csv"])
                    .output
                    .as_deref(),
                Some("out.csv")
            );
        }
        for args in [
            &[
                "dig",
                "d.txt",
                "-o",
                "out.csv",
                "TXT",
                "--progress",
                "failures",
            ][..],
            &[
                "dig",
                "d.txt",
                "--progress",
                "Failures",
                "TXT",
                "-o",
                "out.csv",
            ],
        ] {
            let got = bulk(args);
            assert_eq!(got.record_type, RecordType::TXT);
            assert_eq!(got.output.as_deref(), Some("out.csv"));
            assert_eq!(got.progress, Some(crate::bulk::ProgressMode::Failures));
        }
    }

    #[test]
    fn bulk_rejects_dangling_values_unknown_flags_and_stdin() {
        let err = parse_bulk_args(&["lookup", "d.txt", "-o"])
            .err()
            .expect("must error");
        assert!(err.contains("-o/--output"), "got: {err}");
        let err = parse_bulk_args(&["lookup", "d.txt", "--progress"])
            .err()
            .expect("dangling");
        assert!(err.contains("--progress"), "got: {err}");
        let err = parse_bulk_args(&["lookup", "d.txt", "--progress", "loud"])
            .err()
            .expect("mode");
        assert!(err.contains("Unknown progress mode: loud"), "got: {err}");
        let err = parse_bulk_args(&["lookup", "d.txt", "--ouput", "x.csv"])
            .err()
            .expect("typo");
        assert!(err.starts_with("Unknown option: --ouput"), "got: {err}");
        let err = parse_bulk_args(&["lookup", "-"]).err().expect("stdin");
        assert!(err.contains("stdin"), "got: {err}");
    }

    #[test]
    fn follow_errors_end_with_the_usage_line() {
        assert_eq!(parse_follow_args(&[]).err(), Some(catalog::usage("follow")));
        for args in [
            &["example.com", "--chnages-only"][..],
            &["example.com", "5", "MXX"],
            &["example.com", "1", "2", "3"],
        ] {
            let err = parse_follow_args(args).expect_err("must error");
            assert!(err.ends_with(&catalog::usage("follow")), "{args:?}: {err}");
        }
        let got =
            parse_follow_args(&["example.com", "MX", "@8.8.8.8", "--changes-only"]).expect("valid");
        assert_eq!(got.record_type, RecordType::MX);
        assert_eq!(got.nameserver.as_deref(), Some("8.8.8.8"));
        assert!(got.changes_only);
    }

    /// Extra arguments and flags on one-argument commands were dropped
    /// silently; they are usage errors now.
    #[test]
    fn single_argument_commands_reject_extras_and_flags() {
        for (line, problem) in [
            (
                &["whois", "example.com", "--raw"][..],
                "Unknown option: --raw",
            ),
            (&["whois", "--raw", "example.com"], "Unknown option: --raw"),
            (&["lookup", "a.com", "b.com"], "Unexpected argument: b.com"),
            (
                &["diff", "a.com", "b.com", "c.com"],
                "Unexpected argument: c.com",
            ),
            (
                &["prop", "a.com", "MX", "extra"],
                "Unexpected argument: extra",
            ),
            (&["doctor", "now"], "Unexpected argument: now"),
            (&["example.com", "--raw"], "Unknown option: --raw"),
            (&["example.com", "extra"], "Unexpected argument: extra"),
        ] {
            let err = parse_query(&line[0].to_lowercase(), line)
                .err()
                .expect("must be rejected");
            assert!(err.starts_with(problem), "{line:?}: {err}");
        }
        assert!(matches!(
            parse_query("diff", &["diff", "a.com", "b.com"]),
            Ok(Query::Diff(..))
        ));
    }

    #[test]
    fn history_args_accept_a_domain_or_clear_and_reject_the_rest() {
        assert_eq!(parse_history_args(&[]), Ok((None, false)));
        assert_eq!(
            parse_history_args(&["a.com"]),
            Ok((Some("a.com".to_string()), false))
        );
        assert_eq!(parse_history_args(&["--clear"]), Ok((None, true)));
        let err = parse_history_args(&["a.com", "b.com"]).expect_err("two domains");
        assert!(err.starts_with("Unexpected argument: b.com"), "{err}");
        let err = parse_history_args(&["--clera"]).expect_err("typo");
        assert!(err.starts_with("Unknown option: --clera"), "{err}");
    }

    // ---------------- parse_query ----------------

    /// Every catalog command that is not a session/multi-step built-in must
    /// be a query: with no arguments it parses (doctor) or reports exactly
    /// its catalog usage — never "Unknown command".
    #[test]
    fn every_query_command_parses_or_reports_its_usage() {
        let builtins = [
            "help", "exit", "bulk", "follow", "watch", "history", "set", "copy", "clear",
        ];
        for command in catalog::commands().filter(|c| !builtins.contains(&c.name)) {
            if let Err(e) = parse_query(command.name, &[command.name]) {
                assert!(
                    e.starts_with(&catalog::usage(command.name)),
                    "{}: {e}",
                    command.name
                );
            }
        }
        assert!(matches!(
            parse_query("doctor", &["doctor"]),
            Ok(Query::Doctor)
        ));
    }

    #[test]
    fn parse_query_handles_aliases_servers_and_bare_domains() {
        assert!(matches!(
            parse_query("dns", &["DNS", "example.com", "MX", "@1.1.1.1"]),
            Ok(Query::Dig { ref types, server: Some(ref s), .. })
                if types == &[RecordType::MX] && s == "1.1.1.1"
        ));
        // compare takes the CLI's positional form too (one grammar).
        for line in [
            &["compare", "example.com", "@8.8.8.8", "@1.1.1.1"][..],
            &["compare", "example.com", "8.8.8.8", "1.1.1.1"],
        ] {
            assert!(matches!(
                parse_query("compare", line),
                Ok(Query::Compare { ref server_a, ref server_b, .. })
                    if server_a == "8.8.8.8" && server_b == "1.1.1.1"
            ));
        }
        let err = parse_query("compare", &["compare", "example.com", "MX", "@8.8.8.8"])
            .err()
            .expect("one server");
        assert!(
            err.starts_with("compare needs two nameservers"),
            "got: {err}"
        );
        assert!(err.ends_with(&catalog::usage("compare")), "got: {err}");
        assert!(matches!(
            parse_query("example.com", &["Example.COM"]),
            Ok(Query::Lookup(ref d)) if d == "Example.COM"
        ));
        let err = parse_query("bogus", &["bogus"]).err().expect("unknown");
        assert!(err.starts_with("Unknown command: bogus"), "got: {err}");
    }

    /// The REPL `dig` takes the same dig-style arguments as `seer dig`,
    /// through the shared parser, including the flag spellings clap would
    /// parse on the command line.
    #[test]
    fn dig_parses_dig_style_arguments() {
        let Ok(Query::Dig {
            name,
            types,
            server,
            short,
        }) = parse_query(
            "dig",
            &["dig", "@1.1.1.1", "example.com", "A", "AAAA", "a", "+short"],
        )
        else {
            panic!("expected a dig query");
        };
        assert_eq!(name, "example.com");
        assert_eq!(types, vec![RecordType::A, RecordType::AAAA]);
        assert_eq!(server.as_deref(), Some("1.1.1.1"));
        assert!(short);

        assert!(matches!(
            parse_query("dig", &["dig", "-x", "8.8.8.8"]),
            Ok(Query::Dig { ref name, ref types, short: false, .. })
                if name == "8.8.8.8" && types == &[RecordType::PTR]
        ));
        assert!(matches!(
            parse_query("dig", &["dig", "example.com", "--short", "-s", "9.9.9.9"]),
            Ok(Query::Dig { server: Some(ref s), short: true, .. }) if s == "9.9.9.9"
        ));
        assert!(matches!(
            parse_query("dig", &["dig", "example.com", "NS", "+trace"]),
            Ok(Query::Trace { ref name, record_type: RecordType::NS, short: false })
                if name == "example.com"
        ));
    }

    /// Parser errors keep the REPL convention: the problem, then the usage.
    #[test]
    fn dig_errors_end_with_the_usage_line() {
        for (line, problem) in [
            (&["dig", "@8.8.8.8"][..], "no name to query"),
            (
                &["dig", "example.com", "+nocmd"],
                "unknown dig option '+nocmd'",
            ),
            (
                &["dig", "example.com", "--shrot"],
                "unknown option '--shrot'",
            ),
            (
                &["dig", "example.com", "@8.8.8.8", "+trace"],
                "root servers",
            ),
            (&["dig", "-x", "8.8.8.8", "MX"], "-x looks up PTR"),
            (&["dig", "a.example", "b.example"], "one name"),
        ] {
            let err = parse_query("dig", line).err().expect("must be rejected");
            assert!(err.contains(problem), "{line:?}: {err}");
            assert!(err.ends_with(&catalog::usage("dig")), "{line:?}: {err}");
        }
    }

    // ---------------- subdomains / takeover / drift ----------------

    #[test]
    fn subdomains_parses_flags_in_any_position() {
        let got = parse_subdomains_args(&["--diff", "example.com", "--record"]).expect("valid");
        assert_eq!(
            got,
            SubdomainsArgs {
                domain: "example.com".into(),
                resolve: false,
                diff: true,
                record: true,
            }
        );
        let got = parse_subdomains_args(&["example.com", "--resolve"]).expect("valid");
        assert!(got.resolve && !got.diff && !got.record);
    }

    #[test]
    fn subdomains_rejects_unknown_flags_conflicts_and_missing_domain() {
        assert!(parse_subdomains_args(&[]).is_err());
        assert!(parse_subdomains_args(&["--diff"]).is_err());
        let err = parse_subdomains_args(&["example.com", "--reslove"]).expect_err("typo");
        assert!(err.contains("--reslove"), "got: {err}");
        let err = parse_subdomains_args(&["example.com", "--resolve", "--diff"])
            .expect_err("conflict, as in the CLI");
        assert!(err.contains("--resolve"), "got: {err}");
        assert!(parse_subdomains_args(&["a.com", "b.com"]).is_err());
    }

    #[test]
    fn takeover_collects_repeatable_host_flags() {
        let got = parse_takeover_args(&[
            "example.com",
            "--host",
            "a.example.com",
            "--host=b.example.com",
        ])
        .expect("valid");
        assert_eq!(got.domain, "example.com");
        assert_eq!(got.hosts, vec!["a.example.com", "b.example.com"]);
        assert!(parse_takeover_args(&["example.com"])
            .expect("valid")
            .hosts
            .is_empty());
    }

    #[test]
    fn takeover_rejects_dangling_host_and_unknown_flags() {
        let err = parse_takeover_args(&["example.com", "--host"]).expect_err("dangling");
        assert!(err.contains("--host"), "got: {err}");
        let err = parse_takeover_args(&["example.com", "--hots", "a.x"]).expect_err("typo");
        assert!(err.contains("--hots"), "got: {err}");
        assert!(parse_takeover_args(&[]).is_err());
    }

    #[test]
    fn drift_accepts_record_and_rejects_typos() {
        let got = parse_drift_args(&["example.com", "--record"]).expect("valid");
        assert_eq!(
            got,
            DriftArgs {
                domain: "example.com".into(),
                record: true,
            }
        );
        // `--recrod` previously ran a non-recording drift check silently.
        let err = parse_drift_args(&["example.com", "--recrod"]).expect_err("typo");
        assert!(err.contains("--recrod"), "got: {err}");
        assert!(parse_drift_args(&[]).is_err());
    }

    // ---------------- split_quoted_literal (Windows tokenizer) ----------------

    #[test]
    fn literal_splitter_keeps_windows_backslashes() {
        let got = split_quoted_literal(r"bulk lookup C:\Users\me\d.txt -o C:\Reports\out.csv")
            .expect("valid");
        assert_eq!(
            got,
            vec![
                "bulk",
                "lookup",
                r"C:\Users\me\d.txt",
                "-o",
                r"C:\Reports\out.csv"
            ]
        );
    }

    #[test]
    fn literal_splitter_honors_quotes_around_paths_with_spaces() {
        let got = split_quoted_literal(r#"bulk lookup "C:\My Lists\d.txt" -o 'D:\out dir\r.csv'"#)
            .expect("valid");
        assert_eq!(
            got,
            vec![
                "bulk",
                "lookup",
                r"C:\My Lists\d.txt",
                "-o",
                r"D:\out dir\r.csv"
            ]
        );
        // A trailing backslash inside quotes must not escape the closing quote.
        let got = split_quoted_literal(r#"bulk lookup "C:\dir\""#).expect("valid");
        assert_eq!(got, vec!["bulk", "lookup", r"C:\dir\"]);
    }

    #[test]
    fn literal_splitter_joins_adjacent_runs_and_keeps_empty_quotes() {
        assert_eq!(
            split_quoted_literal(r#"a"b c"d '' e"#).expect("valid"),
            vec!["ab cd", "", "e"]
        );
        assert_eq!(
            split_quoted_literal("  \t ").expect("valid"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn literal_splitter_rejects_unbalanced_quote() {
        let err = split_quoted_literal(r#"bulk lookup "C:\unterminated"#).unwrap_err();
        assert!(err.to_lowercase().contains("quote"), "got: {err}");
    }

    // ---------------- tokenize_line ----------------

    #[test]
    fn tokenize_splits_plain_words_like_whitespace_split() {
        let got = tokenize_line("bulk lookup domains.txt").expect("valid");
        assert_eq!(got, vec!["bulk", "lookup", "domains.txt"]);
    }

    #[test]
    fn tokenize_keeps_quoted_path_with_spaces_intact() {
        // The REPL previously split purely on whitespace, so a bulk file at
        // "Domain Lists/prod.txt" was mangled into two garbage tokens with a
        // literal quote character (2026-07-11 review).
        let got = tokenize_line("bulk lookup \"Domain Lists/prod.txt\"").expect("valid");
        assert_eq!(got, vec!["bulk", "lookup", "Domain Lists/prod.txt"]);
    }

    #[test]
    fn tokenize_supports_single_quotes() {
        let got = tokenize_line("bulk lookup 'my domains.txt' -o 'out dir/r.csv'").expect("valid");
        assert_eq!(
            got,
            vec!["bulk", "lookup", "my domains.txt", "-o", "out dir/r.csv"]
        );
    }

    #[test]
    fn tokenize_rejects_unbalanced_quote_with_usage_hint() {
        let err = tokenize_line("bulk lookup \"unterminated").unwrap_err();
        assert!(
            err.to_lowercase().contains("quote"),
            "error should mention quoting: {err}"
        );
    }

    #[test]
    fn tokenize_empty_line_yields_no_tokens() {
        assert_eq!(tokenize_line("   ").expect("valid"), Vec::<String>::new());
    }
}
