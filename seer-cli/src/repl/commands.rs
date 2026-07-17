use seer_core::output::OutputFormat;
use seer_core::SeerConfig;

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

/// Splits a REPL input line into tokens, honoring shell-style single/double
/// quotes so arguments containing spaces (e.g. `bulk lookup "Domain
/// Lists/prod.txt"`) survive intact — the CLI gets this for free from the OS
/// shell, but the REPL tokenizes its own input. Errors on unbalanced quotes
/// instead of silently producing garbage tokens.
pub fn tokenize_line(line: &str) -> Result<Vec<String>, String> {
    shlex::split(line)
        .ok_or_else(|| "Unbalanced quote in command line (close the \" or ' )".to_string())
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
        return Err(
            "Usage: bulk <operation> <file> [type] [-o output.csv]\nType 'bulk -h' for detailed help."
                .to_string(),
        );
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
/// float is always the interval. Non-numeric tokens are tried as record types.
pub fn parse_follow_args(args: &[&str]) -> Result<FollowArgs, String> {
    let Some(domain) = args.first() else {
        return Err(
            "Usage: follow <domain> [iterations] [interval_minutes] [type] [@server] [--changes-only]"
                .to_string(),
        );
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
        } else if let Ok(rt) = arg.parse() {
            parsed.record_type = rt;
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
