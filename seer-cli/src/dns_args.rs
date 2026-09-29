//! The `compare` and `follow` grammars, parsed once for the clap subcommands
//! and the REPL — as [`crate::dig_args`] is for `dig` — so both surfaces
//! accept the same arguments and fail with the same errors.
//!
//! Tokens come in any order and are read by their shape, as in dig: `@server`
//! is a nameserver, a dotless token that names a record type is the type, a
//! number is a count or an interval (`follow`), and anything else is the
//! domain. The flag spellings clap parses for `seer follow` (`-s/--server`,
//! `--changes-only`) arrive as [`FollowFlags`]; the REPL leaves them in the
//! token list for [`parse_follow`] to read. Errors are complete sentences
//! naming the offending token; nothing touches the network.

use std::net::IpAddr;

use seer_core::RecordType;

use crate::dig_args::{flag_with_value, quoted_list, record_type_token, strip_at, type_list, Flag};
use crate::query::Query;

/// The arguments after `compare`, as the REPL usage line and `seer compare
/// --help` show them.
pub const COMPARE_USAGE: &str = "<domain> [@]<server1> [@]<server2> [type]";

/// The arguments after `follow`, as the REPL usage line and `seer follow
/// --help` show them.
pub const FOLLOW_USAGE: &str =
    "<domain> [iterations] [interval_minutes] [type] [@server] [--changes-only]";

/// `follow`'s number of checks when none is given.
pub const DEFAULT_ITERATIONS: usize = 10;
/// `follow`'s minutes between checks when none is given.
pub const DEFAULT_INTERVAL_MINUTES: f64 = 1.0;

/// A parsed `compare` command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareArgs {
    pub domain: String,
    /// A by default.
    pub record_type: RecordType,
    /// The two nameserver specs, without their `@`, in the order given.
    pub server_a: String,
    pub server_b: String,
}

impl CompareArgs {
    pub fn into_query(self) -> Query {
        Query::Compare {
            domain: self.domain,
            record_type: self.record_type,
            server_a: self.server_a,
            server_b: self.server_b,
        }
    }
}

/// Parses `compare` tokens: one domain (the first bare token), exactly two
/// nameservers (`@server`, or bare tokens after the domain — so the older
/// `compare <domain> <server1> <server2> [type]` form still parses), and at
/// most one record type.
pub fn parse_compare<S: AsRef<str>>(tokens: &[S]) -> Result<CompareArgs, String> {
    let mut domain: Option<&str> = None;
    // Bare server tokens are kept apart: one of them may be a mistyped type.
    let mut servers: Vec<(String, bool)> = Vec::new();
    let mut types: Vec<RecordType> = Vec::new();
    for token in tokens.iter().map(AsRef::as_ref) {
        if token.starts_with('-') {
            return Err(format!(
                "unknown option '{token}' (compare takes a domain, two nameservers and a type)"
            ));
        } else if let Some(server) = token.strip_prefix('@') {
            if server.is_empty() {
                return Err("'@' needs a nameserver, e.g. @8.8.8.8".to_string());
            }
            servers.push((server.to_string(), false));
        } else if let Some(record_type) = record_type_token(token) {
            if !types.contains(&record_type) {
                types.push(record_type);
            }
        } else if domain.is_none() {
            domain = Some(token);
        } else {
            servers.push((token.to_string(), true));
        }
    }

    let Some(domain) = domain else {
        return Err("no domain to compare".to_string());
    };
    let record_type = one_type("compare", types)?;
    let names: Vec<String> = servers.iter().map(|(s, _)| s.clone()).collect();
    match names.as_slice() {
        [server_a, server_b] => Ok(CompareArgs {
            domain: domain.to_string(),
            record_type,
            server_a: server_a.clone(),
            server_b: server_b.clone(),
        }),
        [] => Err("compare needs two nameservers, got none".to_string()),
        [only] => Err(format!("compare needs two nameservers, got only '{only}'")),
        _ => {
            let mut message = format!("compare takes two nameservers, got {}", quoted_list(&names));
            let bare: Vec<&str> = servers
                .iter()
                .filter(|(_, bare)| *bare)
                .map(|(s, _)| s.as_str())
                .collect();
            push_type_typo_hint(&mut message, &bare);
            Err(message)
        }
    }
}

/// The options `seer follow` takes as clap flags. The REPL passes the
/// default and leaves any flags in the token list instead.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FollowFlags {
    /// `-s/--server`; a leading `@` is accepted and dropped.
    pub server: Option<String>,
    /// `--changes-only`.
    pub changes_only: bool,
}

/// A parsed `follow` command line.
#[derive(Debug, Clone, PartialEq)]
pub struct FollowArgs {
    pub domain: String,
    /// Number of checks ([`DEFAULT_ITERATIONS`] unless given).
    pub iterations: usize,
    /// Minutes between checks; may be fractional
    /// ([`DEFAULT_INTERVAL_MINUTES`] unless given).
    pub interval_minutes: f64,
    /// A by default.
    pub record_type: RecordType,
    /// The nameserver spec, without its `@`.
    pub nameserver: Option<String>,
    /// Only print iterations whose records changed.
    pub changes_only: bool,
}

/// Parses `follow` tokens with the options already parsed as `flags`.
///
/// Numbers are read in order: the first integer is the iteration count and
/// the next number the interval in minutes; a fractional number is always
/// the interval (`follow x 0.5` keeps 10 iterations). A third number, a
/// second type, nameserver or domain is an error rather than silently
/// replacing the first.
pub fn parse_follow<S: AsRef<str>>(tokens: &[S], flags: FollowFlags) -> Result<FollowArgs, String> {
    let FollowFlags {
        server,
        mut changes_only,
    } = flags;
    let mut servers: Vec<String> = server.iter().map(|s| strip_at(s).to_string()).collect();
    let mut names: Vec<&str> = Vec::new();
    let mut types: Vec<RecordType> = Vec::new();
    let mut iterations: Option<usize> = None;
    let mut interval: Option<f64> = None;

    let mut tokens = tokens.iter().map(AsRef::as_ref);
    while let Some(token) = tokens.next() {
        if let Some((Flag::Server, spelling, inline)) = flag_with_value(token) {
            let value = match inline {
                Some(value) => value,
                None => tokens.next().unwrap_or_default(),
            };
            if value.is_empty() {
                return Err(format!(
                    "{spelling} needs a nameserver, e.g. {spelling} 8.8.8.8"
                ));
            }
            servers.push(strip_at(value).to_string());
        } else if token == "--changes-only" {
            changes_only = true;
        } else if token.starts_with('-') {
            return Err(format!(
                "unknown option '{token}' (follow takes -s/--server and --changes-only)"
            ));
        } else if let Some(server) = token.strip_prefix('@') {
            if server.is_empty() {
                return Err("'@' needs a nameserver, e.g. @8.8.8.8".to_string());
            }
            servers.push(server.to_string());
        } else if let Ok(count) = token.parse::<usize>() {
            match (iterations, interval) {
                (None, _) => iterations = Some(count),
                (Some(_), None) => interval = Some(count as f64),
                (Some(_), Some(_)) => return Err(extra_number(token)),
            }
        } else if let Some(minutes) = token.parse::<f64>().ok().filter(|m| m.is_finite()) {
            if interval.is_some() {
                return Err(extra_number(token));
            }
            interval = Some(minutes);
        } else if let Some(record_type) = record_type_token(token) {
            if !types.contains(&record_type) {
                types.push(record_type);
            }
        } else {
            names.push(token);
        }
    }

    let domain = match names.as_slice() {
        [] => return Err("no domain to follow".to_string()),
        [domain] => domain.to_string(),
        _ => {
            let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
            let mut message = format!("follow watches one domain, got {}", quoted_list(&names));
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            push_type_typo_hint(&mut message, &names);
            return Err(message);
        }
    };
    let nameserver = match servers.as_slice() {
        [] => None,
        [server] => Some(server.clone()),
        _ => {
            return Err(format!(
                "follow queries one nameserver, got {}",
                quoted_list(&servers)
            ))
        }
    };
    Ok(FollowArgs {
        domain,
        iterations: iterations.unwrap_or(DEFAULT_ITERATIONS),
        interval_minutes: interval.unwrap_or(DEFAULT_INTERVAL_MINUTES),
        record_type: one_type("follow", types)?,
        nameserver,
        changes_only,
    })
}

fn extra_number(token: &str) -> String {
    format!(
        "follow takes at most two numbers (iterations, then interval minutes); \
         '{token}' is one too many"
    )
}

/// The single record type of a command that queries one (A when none).
fn one_type(command: &str, types: Vec<RecordType>) -> Result<RecordType, String> {
    match types.as_slice() {
        [] => Ok(RecordType::A),
        [record_type] => Ok(*record_type),
        _ => Err(format!(
            "{command} takes one record type, got {}",
            type_list(&types)
        )),
    }
}

/// Appends a hint when one of `candidates` (tokens read as names or
/// servers) looks like a mistyped record type: dotless and not an address.
fn push_type_typo_hint(message: &mut String, candidates: &[&str]) {
    let typo = candidates
        .iter()
        .rev()
        .find(|token| !token.contains(['.', ':']) && token.parse::<IpAddr>().is_err());
    if let Some(typo) = typo {
        message.push_str(&format!(
            " ('{typo}' is not a record type; valid types: {})",
            *crate::VALID_RECORD_TYPES
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compare(tokens: &[&str]) -> Result<CompareArgs, String> {
        parse_compare(tokens)
    }

    fn compared(record_type: RecordType) -> CompareArgs {
        CompareArgs {
            domain: "example.com".into(),
            record_type,
            server_a: "8.8.8.8".into(),
            server_b: "1.1.1.1".into(),
        }
    }

    /// The CLI's positional form and the REPL's `@` form used to be two
    /// grammars; every spelling of either now parses the same way.
    #[test]
    fn compare_accepts_both_historic_forms_in_any_order() {
        for tokens in [
            &["example.com", "8.8.8.8", "1.1.1.1"][..],
            &["example.com", "@8.8.8.8", "@1.1.1.1"],
            &["@8.8.8.8", "example.com", "1.1.1.1"],
            &["@8.8.8.8", "@1.1.1.1", "example.com"],
        ] {
            assert_eq!(compare(tokens), Ok(compared(RecordType::A)), "{tokens:?}");
        }
        for tokens in [
            &["example.com", "8.8.8.8", "1.1.1.1", "MX"][..],
            &["example.com", "MX", "@8.8.8.8", "@1.1.1.1"],
            &["mx", "example.com", "@8.8.8.8", "1.1.1.1"],
        ] {
            assert_eq!(compare(tokens), Ok(compared(RecordType::MX)), "{tokens:?}");
        }
        let got = compare(&[
            "example.com",
            "tls://1.1.1.1",
            "@https://dns.google/dns-query",
        ])
        .expect("valid");
        assert_eq!(got.server_a, "tls://1.1.1.1");
        assert_eq!(got.server_b, "https://dns.google/dns-query");
    }

    #[test]
    fn compare_needs_exactly_two_servers_and_one_type() {
        assert!(compare(&[]).unwrap_err().starts_with("no domain"));
        assert!(compare(&["@8.8.8.8", "@1.1.1.1"])
            .unwrap_err()
            .starts_with("no domain"));
        assert_eq!(
            compare(&["example.com", "@8.8.8.8"]).unwrap_err(),
            "compare needs two nameservers, got only '8.8.8.8'"
        );
        let e = compare(&["example.com", "@8.8.8.8", "@1.1.1.1", "9.9.9.9"]).unwrap_err();
        assert!(
            e.contains("got '8.8.8.8', '1.1.1.1' and '9.9.9.9'") && !e.contains("record type"),
            "{e}"
        );
        let e = compare(&["example.com", "A", "MX", "@8.8.8.8", "@1.1.1.1"]).unwrap_err();
        assert_eq!(e, "compare takes one record type, got A and MX");
        let e = compare(&["example.com", "@8.8.8.8", "@1.1.1.1", "--type"]).unwrap_err();
        assert!(e.contains("unknown option '--type'"), "{e}");
    }

    /// A typo'd type lands among the servers; the error says so.
    #[test]
    fn compare_names_a_mistyped_type() {
        let e = compare(&["example.com", "BOGUS", "@8.8.8.8", "@1.1.1.1"]).unwrap_err();
        assert!(e.contains("'BOGUS' is not a record type"), "{e}");
        assert!(e.contains("valid types: A, AAAA"), "{e}");
    }

    fn follow(tokens: &[&str]) -> Result<FollowArgs, String> {
        parse_follow(tokens, FollowFlags::default())
    }

    #[test]
    fn follow_defaults() {
        assert_eq!(
            follow(&["example.com"]),
            Ok(FollowArgs {
                domain: "example.com".into(),
                iterations: DEFAULT_ITERATIONS,
                interval_minutes: DEFAULT_INTERVAL_MINUTES,
                record_type: RecordType::A,
                nameserver: None,
                changes_only: false,
            })
        );
    }

    /// The CLI's positional order (`<domain> [iterations] [interval]
    /// [type]`) and the REPL's free order read the same.
    #[test]
    fn follow_reads_numbers_in_order_and_everything_else_by_shape() {
        for tokens in [
            &["example.com", "20", "0.5", "AAAA", "@1.1.1.1"][..],
            &["AAAA", "example.com", "-s", "1.1.1.1", "20", "0.5"],
            &["@1.1.1.1", "20", "example.com", "0.5", "aaaa"],
        ] {
            let got = follow(tokens).expect("valid");
            assert_eq!(got.domain, "example.com", "{tokens:?}");
            assert_eq!(got.iterations, 20, "{tokens:?}");
            assert_eq!(got.interval_minutes, 0.5, "{tokens:?}");
            assert_eq!(got.record_type, RecordType::AAAA, "{tokens:?}");
            assert_eq!(got.nameserver.as_deref(), Some("1.1.1.1"), "{tokens:?}");
        }
        // An explicit default still claims the iterations slot.
        let got = follow(&["example.com", "10", "5"]).expect("valid");
        assert_eq!((got.iterations, got.interval_minutes), (10, 5.0));
        // A fraction is always the interval.
        let got = follow(&["example.com", "0.5"]).expect("valid");
        assert_eq!((got.iterations, got.interval_minutes), (10, 0.5));
        let got = follow(&["example.com", "0.5", "3"]).expect("valid");
        assert_eq!((got.iterations, got.interval_minutes), (3, 0.5));
    }

    #[test]
    fn follow_merges_clap_flags_with_token_spellings() {
        let got = parse_follow(
            &["example.com"],
            FollowFlags {
                server: Some("@8.8.8.8".into()),
                changes_only: true,
            },
        )
        .expect("valid");
        assert_eq!(got.nameserver.as_deref(), Some("8.8.8.8"));
        assert!(got.changes_only);
        let got = follow(&["example.com", "--server=9.9.9.9", "--changes-only"]).expect("valid");
        assert_eq!(got.nameserver.as_deref(), Some("9.9.9.9"));
        assert!(got.changes_only);
    }

    #[test]
    fn follow_rejects_extras_instead_of_overwriting() {
        for (tokens, problem) in [
            (&[][..], "no domain to follow"),
            (&["example.com", "5", "2", "3"], "'3' is one too many"),
            (&["example.com", "0.5", "0.25"], "'0.25' is one too many"),
            (&["example.com", "A", "MX"], "one record type, got A and MX"),
            (
                &["example.com", "@8.8.8.8", "-s", "1.1.1.1"],
                "one nameserver, got '8.8.8.8' and '1.1.1.1'",
            ),
            (&["a.example", "b.example"], "one domain, got"),
            (&["example.com", "--chnages-only"], "'--chnages-only'"),
            (&["example.com", "-x", "8.8.8.8"], "unknown option '-x'"),
            (&["example.com", "-s"], "-s needs a nameserver"),
        ] {
            let e = follow(tokens).expect_err("must be rejected");
            assert!(e.contains(problem), "{tokens:?}: {e}");
        }
    }

    /// `follow example.com 5 MXX` watched A records while the user believed
    /// it was MX; the typo is now named as a would-be type.
    #[test]
    fn follow_names_a_mistyped_type() {
        let e = follow(&["example.com", "5", "MXX"]).unwrap_err();
        assert!(e.contains("'MXX' is not a record type"), "{e}");
        assert!(e.contains("valid types"), "{e}");
    }
}
