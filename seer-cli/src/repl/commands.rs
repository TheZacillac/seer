use seer_core::output::OutputFormat;
use seer_core::SeerConfig;

use super::catalog;

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
        let output_format = config.output_format.parse().unwrap_or_default();
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

/// Returns a usage error for an unrecognized `--flag` / `-f` token, so a typo
/// like `--recrod` fails loudly instead of being silently ignored.
fn reject_unknown_flag(token: &str, usage: &str) -> Result<(), String> {
    if token.starts_with('-') {
        return Err(format!("Unknown option: {token}\n{usage}"));
    }
    Ok(())
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

/// Parsed arguments for the REPL `bulk` command.
///
/// Paths are returned exactly as typed — tilde expansion is the caller's
/// responsibility so this parser stays pure and unit-testable.
#[derive(Debug, Clone, PartialEq)]
pub struct BulkArgs {
    /// Operation name as typed (validated later by `ops::build_bulk_operations`).
    pub operation: String,
    /// Input file path as typed.
    pub file: String,
    /// Record type for dig/prop operations (defaults to A).
    pub record_type: seer_core::RecordType,
    /// Output CSV path from `-o`/`--output`, if given.
    pub output: Option<String>,
}

/// Parses `bulk <operation> <file> [type] [-o output.csv]` arguments.
///
/// Errors with a usage message when fewer than two positionals are given, or
/// when `-o`/`--output` trails without a value (previously that flag was
/// silently ignored, quietly overwriting the default output path).
pub fn parse_bulk_args(args: &[&str]) -> Result<BulkArgs, String> {
    if args.len() < 2 {
        return Err(format!(
            "{}\nType 'bulk -h' for detailed help.",
            catalog::usage("bulk")
        ));
    }

    let operation = args[0].to_string();
    let file = args[1].to_string();
    let mut record_type = seer_core::RecordType::A;
    let mut output: Option<String> = None;

    let mut i = 2;
    while i < args.len() {
        match args[i] {
            "-o" | "--output" => {
                let Some(value) = args.get(i + 1) else {
                    return Err("Missing value after -o/--output".to_string());
                };
                output = Some(value.to_string());
                i += 2;
            }
            other => {
                record_type = crate::try_parse_record_type(other)?;
                i += 1;
            }
        }
    }

    Ok(BulkArgs {
        operation,
        file,
        record_type,
        output,
    })
}

/// Parsed arguments for the REPL `follow` command.
#[derive(Debug, Clone, PartialEq)]
pub struct FollowArgs {
    pub domain: String,
    /// Number of checks to perform (defaults to 10).
    pub iterations: usize,
    /// Minutes between checks; may be fractional (defaults to 1.0).
    pub interval_minutes: f64,
    /// Record type to monitor (defaults to A).
    pub record_type: seer_core::RecordType,
    /// Nameserver from an inline `@server` argument.
    pub nameserver: Option<String>,
    /// Only print iterations whose records changed.
    pub changes_only: bool,
}

/// Parses `follow <domain> [iterations] [interval_minutes] [type] [@server]
/// [--changes-only]` arguments.
///
/// Positional numbers are order-sensitive: the first integer is the iteration
/// count, any later number (integer or float) the interval in minutes. A bare
/// float is always the interval. Any other token must be a record type — a
/// typo (`MXX`) or unknown `--flag` is an error, matching the CLI and the
/// REPL's other DNS commands, rather than silently following A records.
pub fn parse_follow_args(args: &[&str]) -> Result<FollowArgs, String> {
    let usage = catalog::usage("follow");
    let Some(domain) = args.first() else {
        return Err(usage);
    };

    let mut parsed = FollowArgs {
        domain: domain.to_string(),
        iterations: 10,
        interval_minutes: 1.0,
        record_type: seer_core::RecordType::A,
        nameserver: None,
        changes_only: false,
    };

    // Track whether the first numeric positional (iterations) has been
    // consumed. Comparing against the default `10` would be wrong because
    // `follow x 10 5` must treat the explicit `10` as already set.
    let mut iterations_set = false;

    for arg in &args[1..] {
        if let Some(ns) = arg.strip_prefix('@') {
            parsed.nameserver = Some(ns.to_string());
        } else if *arg == "--changes-only" {
            parsed.changes_only = true;
        } else if arg.starts_with("--") {
            return Err(format!("Unknown option: {arg}\n{usage}"));
        } else if let Ok(n) = arg.parse::<usize>() {
            // First number is iterations, second is interval
            if !iterations_set {
                parsed.iterations = n;
                iterations_set = true;
            } else {
                parsed.interval_minutes = n as f64;
            }
        } else if let Ok(mins) = arg.parse::<f64>() {
            parsed.interval_minutes = mins;
        } else {
            parsed.record_type = crate::try_parse_record_type(arg)?;
        }
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seer_core::RecordType;

    #[test]
    fn bulk_requires_operation_and_file() {
        assert!(parse_bulk_args(&[]).is_err());
        assert!(parse_bulk_args(&["status"]).is_err());
    }

    #[test]
    fn bulk_minimal_defaults() {
        let got = parse_bulk_args(&["status", "domains.txt"]).expect("valid");
        assert_eq!(
            got,
            BulkArgs {
                operation: "status".into(),
                file: "domains.txt".into(),
                record_type: RecordType::A,
                output: None,
            }
        );
    }

    #[test]
    fn bulk_parses_record_type_positional() {
        let got = parse_bulk_args(&["dig", "domains.txt", "MX"]).expect("valid");
        assert_eq!(got.record_type, RecordType::MX);
        // Unparseable type tokens error instead of silently falling back to A.
        let err = parse_bulk_args(&["dig", "domains.txt", "NOTATYPE"]).expect_err("must error");
        assert!(err.contains("NOTATYPE"));
        assert!(err.contains("valid types"));
    }

    #[test]
    fn bulk_parses_output_flag_variants() {
        for flag in ["-o", "--output"] {
            let got = parse_bulk_args(&["lookup", "d.txt", flag, "out.csv"]).expect("valid");
            assert_eq!(got.output.as_deref(), Some("out.csv"));
        }
    }

    #[test]
    fn bulk_output_flag_and_type_combine_in_any_order() {
        let got = parse_bulk_args(&["dig", "d.txt", "-o", "out.csv", "TXT"]).expect("valid");
        assert_eq!(got.record_type, RecordType::TXT);
        assert_eq!(got.output.as_deref(), Some("out.csv"));

        let got = parse_bulk_args(&["dig", "d.txt", "TXT", "-o", "out.csv"]).expect("valid");
        assert_eq!(got.record_type, RecordType::TXT);
        assert_eq!(got.output.as_deref(), Some("out.csv"));
    }

    #[test]
    fn bulk_dangling_output_flag_errors() {
        let err = parse_bulk_args(&["lookup", "d.txt", "-o"]).expect_err("must error");
        assert!(err.contains("-o/--output"), "got: {err}");
    }

    #[test]
    fn follow_requires_domain() {
        assert!(parse_follow_args(&[]).is_err());
    }

    #[test]
    fn follow_defaults() {
        let got = parse_follow_args(&["example.com"]).expect("valid");
        assert_eq!(
            got,
            FollowArgs {
                domain: "example.com".into(),
                iterations: 10,
                interval_minutes: 1.0,
                record_type: RecordType::A,
                nameserver: None,
                changes_only: false,
            }
        );
    }

    #[test]
    fn follow_first_int_is_iterations_second_is_interval() {
        let got = parse_follow_args(&["example.com", "5", "2"]).expect("valid");
        assert_eq!(got.iterations, 5);
        assert_eq!(got.interval_minutes, 2.0);
    }

    #[test]
    fn follow_explicit_default_iterations_still_consumes_slot() {
        // `follow x 10 5` — the explicit `10` matches the default but must
        // still claim the iterations slot, making `5` the interval.
        let got = parse_follow_args(&["example.com", "10", "5"]).expect("valid");
        assert_eq!(got.iterations, 10);
        assert_eq!(got.interval_minutes, 5.0);
    }

    #[test]
    fn follow_float_is_always_interval() {
        // A float can't be iterations, so it sets the interval even first.
        let got = parse_follow_args(&["example.com", "0.5"]).expect("valid");
        assert_eq!(got.iterations, 10);
        assert_eq!(got.interval_minutes, 0.5);
    }

    #[test]
    fn follow_parses_type_server_and_changes_only() {
        let got =
            parse_follow_args(&["example.com", "MX", "@8.8.8.8", "--changes-only"]).expect("valid");
        assert_eq!(got.record_type, RecordType::MX);
        assert_eq!(got.nameserver.as_deref(), Some("8.8.8.8"));
        assert!(got.changes_only);
    }

    #[test]
    fn follow_full_argument_soup() {
        let got =
            parse_follow_args(&["example.com", "20", "0.5", "AAAA", "@1.1.1.1"]).expect("valid");
        assert_eq!(got.iterations, 20);
        assert_eq!(got.interval_minutes, 0.5);
        assert_eq!(got.record_type, RecordType::AAAA);
        assert_eq!(got.nameserver.as_deref(), Some("1.1.1.1"));
        assert!(!got.changes_only);
    }

    #[test]
    fn follow_rejects_mistyped_record_type() {
        // `follow example.com 5 MXX` previously ignored the typo and watched
        // A records.
        let err = parse_follow_args(&["example.com", "5", "MXX"]).expect_err("must error");
        assert!(err.contains("MXX"), "error should name the input: {err}");
        assert!(err.contains("valid types"), "got: {err}");
    }

    #[test]
    fn follow_rejects_unknown_long_flag() {
        let err =
            parse_follow_args(&["example.com", "--chnages-only"]).expect_err("typo'd flag errors");
        assert!(err.contains("--chnages-only"), "got: {err}");
        assert!(err.contains("Usage: follow"), "got: {err}");
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
