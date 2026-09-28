//! dig-style arguments, parsed once for both `seer dig` and the REPL `dig`,
//! so the two accept the same syntax and fail with the same errors.
//!
//! As in dig, the arguments come in any order, and each token is read by its
//! shape:
//! - `@server` names the nameserver — at most one, from any source;
//! - `+short` / `+trace` switch those modes on; any other `+option` is an
//!   error rather than silently ignored;
//! - a record type (`A`, `mx`, `*` for ANY) with no dot in it is a type;
//!   several may be given, repeats are dropped and the order kept;
//! - anything else is the name to query, and there must be exactly one
//!   (`-x <ip>` supplies it for a reverse lookup).
//!
//! The flag spellings — `-s`/`--server`, `--short`, `--trace` and
//! `-x`/`--reverse <ip>` — merge into the same [`DigArgs`]. clap parses them
//! for `seer dig` and passes them in as [`DigFlags`]; the REPL, which
//! tokenizes its own line, leaves them in the token list for [`parse`] to
//! pick out.

use std::net::IpAddr;

use seer_core::RecordType;

use crate::query::Query;

/// The arguments after `dig`, as the REPL usage line and `seer dig --help`
/// show them.
pub const USAGE: &str = "[@server] <name> [type...] [+short] [+trace]";

/// The `+options` [`parse`] understands.
pub const PLUS_OPTIONS: &[&str] = &["+short", "+trace"];

/// A parsed `dig` command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigArgs {
    /// The name to query; for `-x`, the IP address.
    pub name: String,
    /// The record types in the order given, without repeats. Never empty:
    /// A by default, PTR for `-x`, and exactly one with `trace`.
    pub types: Vec<RecordType>,
    /// The nameserver spec, without its `@`. Never set with `trace`.
    pub server: Option<String>,
    /// `+short`: print only the record values, one per line.
    pub short: bool,
    /// `+trace`: walk the delegation down from the root servers.
    pub trace: bool,
}

/// The options `seer dig` takes as clap flags. The REPL passes the default
/// and leaves any flags in the token list instead.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DigFlags {
    /// `-s/--server`; a leading `@` is accepted and dropped.
    pub server: Option<String>,
    /// `--short`.
    pub short: bool,
    /// `--trace`.
    pub trace: bool,
    /// `-x/--reverse <ip>`.
    pub reverse: Option<String>,
}

/// Parses dig-style `tokens` (the arguments after `dig`) together with the
/// options already parsed as `flags`. Errors are complete sentences naming
/// the offending token; nothing touches the network.
pub fn parse<S: AsRef<str>>(tokens: &[S], flags: DigFlags) -> Result<DigArgs, String> {
    let mut servers: Vec<String> = Vec::new();
    let mut reverse: Vec<String> = Vec::new();
    let mut names: Vec<&str> = Vec::new();
    let mut types: Vec<RecordType> = Vec::new();
    let DigFlags {
        server,
        mut short,
        mut trace,
        reverse: reverse_flag,
    } = flags;
    servers.extend(server.map(|s| strip_at(&s).to_string()));
    reverse.extend(reverse_flag);

    let mut tokens = tokens.iter().map(AsRef::as_ref);
    while let Some(token) = tokens.next() {
        // The REPL's flag spellings; clap consumes these before `parse`
        // sees the CLI's tokens.
        if let Some((flag, spelling, inline)) = flag_with_value(token) {
            let value = match inline {
                Some(value) => value,
                None => tokens.next().unwrap_or_default(),
            };
            if value.is_empty() {
                let wanted = match flag {
                    Flag::Server => "a nameserver",
                    Flag::Reverse => "an IP address",
                };
                return Err(format!(
                    "{spelling} needs {wanted}, e.g. {spelling} 8.8.8.8"
                ));
            }
            match flag {
                Flag::Server => servers.push(strip_at(value).to_string()),
                Flag::Reverse => reverse.push(value.to_string()),
            }
        } else if token == "--short" {
            short = true;
        } else if token == "--trace" {
            trace = true;
        } else if token.starts_with('-') {
            return Err(format!(
                "unknown option '{token}' (dig takes -s/--server, --short, --trace and -x/--reverse)"
            ));
        } else if let Some(server) = token.strip_prefix('@') {
            if server.is_empty() {
                return Err("'@' needs a nameserver, e.g. @8.8.8.8".to_string());
            }
            servers.push(server.to_string());
        } else if let Some(option) = token.strip_prefix('+') {
            match option.to_ascii_lowercase().as_str() {
                "short" => short = true,
                "trace" => trace = true,
                _ => {
                    return Err(format!(
                        "unknown dig option '{token}' (supported: {})",
                        PLUS_OPTIONS.join(", ")
                    ))
                }
            }
        } else if let Some(record_type) = record_type_token(token) {
            if !types.contains(&record_type) {
                types.push(record_type);
            }
        } else {
            names.push(token);
        }
    }

    let server = match servers.as_slice() {
        [] => None,
        [server] => Some(server.clone()),
        [first, second, ..] => {
            return Err(format!(
                "dig queries one nameserver, got '{first}' and '{second}'"
            ))
        }
    };
    let name = the_name(&reverse, &names)?;
    let types = if reverse.is_empty() {
        if types.is_empty() {
            vec![RecordType::A]
        } else {
            types
        }
    } else {
        reverse_types(types)?
    };

    if trace {
        if let Some(server) = &server {
            return Err(format!(
                "+trace/--trace starts at the root servers, so it cannot be combined with a \
                 nameserver ('{server}')"
            ));
        }
        if types.len() > 1 {
            return Err(format!(
                "+trace/--trace follows one record type, got {}",
                type_list(&types)
            ));
        }
    }

    Ok(DigArgs {
        name,
        types,
        server,
        short,
        trace,
    })
}

/// Whether `tokens` — a partly typed REPL line after `dig` — already name
/// the query, with a name or `-x <ip>`. Completion offers record types only
/// after that: before it, a word is more likely the name.
pub fn has_name<S: AsRef<str>>(tokens: &[S]) -> bool {
    let mut tokens = tokens.iter().map(AsRef::as_ref);
    while let Some(token) = tokens.next() {
        if let Some((flag, _, inline)) = flag_with_value(token) {
            let value = inline.or_else(|| tokens.next());
            if matches!(flag, Flag::Reverse) && value.is_some() {
                return true;
            }
        } else if !token.starts_with(['-', '@', '+']) && record_type_token(token).is_none() {
            return true;
        }
    }
    false
}

impl DigArgs {
    /// The single-shot query this command line asks for: a trace, or a
    /// query per record type.
    pub fn into_query(self) -> Query {
        match (self.trace, self.types.as_slice()) {
            // `parse` allows `trace` with exactly one type.
            (true, &[record_type]) => Query::Trace {
                name: self.name,
                record_type,
                short: self.short,
            },
            _ => Query::Dig {
                name: self.name,
                types: self.types,
                server: self.server,
                short: self.short,
            },
        }
    }
}

/// A REPL flag that takes a value.
#[derive(Clone, Copy)]
enum Flag {
    Server,
    Reverse,
}

/// Recognizes `-s`/`--server`/`-x`/`--reverse`: the flag, its spelling, and
/// its value when given inline (`--server=8.8.8.8`).
fn flag_with_value(token: &str) -> Option<(Flag, &str, Option<&str>)> {
    let (name, inline) = match token.split_once('=') {
        Some((name, value)) if name.starts_with("--") => (name, Some(value)),
        _ => (token, None),
    };
    let flag = match name {
        "-s" | "--server" => Flag::Server,
        "-x" | "--reverse" => Flag::Reverse,
        _ => return None,
    };
    Some((flag, name, inline))
}

/// The record type a token names, if it is one. A token with a dot is always
/// a name, so a type is never mistaken for part of a domain.
fn record_type_token(token: &str) -> Option<RecordType> {
    if token.contains('.') {
        return None;
    }
    token.parse().ok()
}

/// A nameserver spec without the `@` dig puts in front of it.
fn strip_at(server: &str) -> &str {
    server.strip_prefix('@').unwrap_or(server)
}

/// The one name to query, from `-x` or the positional names.
fn the_name(reverse: &[String], names: &[&str]) -> Result<String, String> {
    let mut given: Vec<String> = reverse.iter().map(|ip| format!("-x {ip}")).collect();
    given.extend(names.iter().map(|name| name.to_string()));
    if given.len() > 1 {
        let mut message = format!("dig queries one name, but got {}", quoted_list(&given));
        // A dotless extra is most likely a mistyped record type.
        if let Some(typo) = names.iter().rev().find(|name| !name.contains('.')) {
            message.push_str(&format!(
                " ('{typo}' is not a record type; valid types: {})",
                *crate::VALID_RECORD_TYPES
            ));
        }
        return Err(message);
    }
    match (reverse.first(), names.first()) {
        (Some(ip), _) => match ip.parse::<IpAddr>() {
            Ok(_) => Ok(ip.clone()),
            Err(_) => Err(format!("-x needs an IP address, got '{ip}'")),
        },
        (None, Some(name)) => Ok(name.to_string()),
        (None, None) => Err("no name to query (give a domain, or -x <ip>)".to_string()),
    }
}

/// The types of a `-x` lookup: PTR, which may be spelled out but not
/// combined with anything else.
fn reverse_types(types: Vec<RecordType>) -> Result<Vec<RecordType>, String> {
    let others: Vec<RecordType> = types
        .into_iter()
        .filter(|&t| t != RecordType::PTR)
        .collect();
    if others.is_empty() {
        Ok(vec![RecordType::PTR])
    } else {
        Err(format!(
            "-x looks up PTR records, so it cannot be combined with {}",
            type_list(&others)
        ))
    }
}

/// `A, AAAA and MX`.
fn type_list(types: &[RecordType]) -> String {
    and_list(types.iter().map(ToString::to_string).collect())
}

/// `'a', 'b' and 'c'`.
fn quoted_list(items: &[String]) -> String {
    and_list(items.iter().map(|item| format!("'{item}'")).collect())
}

fn and_list(mut items: Vec<String>) -> String {
    match items.pop() {
        None => String::new(),
        Some(last) if items.is_empty() => last,
        Some(last) => format!("{} and {last}", items.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dig(tokens: &[&str]) -> Result<DigArgs, String> {
        parse(tokens, DigFlags::default())
    }

    fn args(name: &str, types: &[RecordType]) -> DigArgs {
        DigArgs {
            name: name.to_string(),
            types: types.to_vec(),
            server: None,
            short: false,
            trace: false,
        }
    }

    fn err(tokens: &[&str]) -> String {
        dig(tokens).expect_err("must be rejected")
    }

    #[test]
    fn a_bare_name_queries_a_records() {
        assert_eq!(
            dig(&["example.com"]),
            Ok(args("example.com", &[RecordType::A]))
        );
    }

    #[test]
    fn server_may_come_anywhere_including_first() {
        for tokens in [
            ["@1.1.1.1", "example.com", "MX"],
            ["example.com", "@1.1.1.1", "MX"],
            ["example.com", "MX", "@1.1.1.1"],
            ["MX", "example.com", "@1.1.1.1"],
        ] {
            let got = dig(&tokens).expect("valid");
            assert_eq!(got.name, "example.com", "{tokens:?}");
            assert_eq!(got.types, vec![RecordType::MX], "{tokens:?}");
            assert_eq!(got.server.as_deref(), Some("1.1.1.1"), "{tokens:?}");
        }
        // Every nameserver spec form passes through as given.
        for spec in [
            "tls://1.1.1.1",
            "https://dns.google/dns-query",
            "ns1.example.net:5353",
        ] {
            let at = format!("@{spec}");
            let got = dig(&[at.as_str(), "example.com"]).expect("valid");
            assert_eq!(got.server.as_deref(), Some(spec));
        }
    }

    #[test]
    fn one_nameserver_at_most_from_any_source() {
        let e = err(&["example.com", "@8.8.8.8", "@1.1.1.1"]);
        assert!(e.contains("one nameserver") && e.contains("8.8.8.8") && e.contains("1.1.1.1"));
        let e = parse(
            &["@1.1.1.1", "example.com"],
            DigFlags {
                server: Some("8.8.8.8".into()),
                ..DigFlags::default()
            },
        )
        .expect_err("-s plus @server");
        assert!(e.contains("one nameserver"), "{e}");
        let e = err(&["example.com", "-s", "8.8.8.8", "@1.1.1.1"]);
        assert!(e.contains("one nameserver"), "{e}");
        let e = err(&["example.com", "@"]);
        assert!(e.contains("'@' needs a nameserver"), "{e}");
    }

    #[test]
    fn server_flag_merges_and_drops_a_leading_at() {
        let flags = |server: &str| DigFlags {
            server: Some(server.into()),
            ..DigFlags::default()
        };
        for server in ["8.8.8.8", "@8.8.8.8"] {
            let got = parse(&["example.com"], flags(server)).expect("valid");
            assert_eq!(got.server.as_deref(), Some("8.8.8.8"));
        }
        // The REPL spellings of the same flag.
        for tokens in [
            &["-s", "8.8.8.8", "example.com"][..],
            &["example.com", "--server", "@8.8.8.8"],
            &["--server=8.8.8.8", "example.com"],
        ] {
            let got = dig(tokens).expect("valid");
            assert_eq!(got.server.as_deref(), Some("8.8.8.8"), "{tokens:?}");
            assert_eq!(got.name, "example.com", "{tokens:?}");
        }
        for tokens in [&["example.com", "-s"][..], &["example.com", "--server="]] {
            assert!(err(tokens).contains("needs a nameserver"), "{tokens:?}");
        }
    }

    #[test]
    fn several_types_are_deduplicated_in_order() {
        let got = dig(&["example.com", "a", "AAAA", "MX", "A", "mx", "TXT"]).expect("valid");
        assert_eq!(
            got.types,
            vec![
                RecordType::A,
                RecordType::AAAA,
                RecordType::MX,
                RecordType::TXT
            ]
        );
    }

    #[test]
    fn star_and_any_are_the_any_type() {
        for token in ["*", "ANY", "any"] {
            assert_eq!(
                dig(&["example.com", token]).expect("valid").types,
                vec![RecordType::ANY]
            );
        }
        // `*` and ANY are the same type, so the second is a repeat.
        assert_eq!(
            dig(&["example.com", "*", "ANY"]).expect("valid").types,
            vec![RecordType::ANY]
        );
    }

    #[test]
    fn every_core_record_type_parses_as_a_type() {
        for name in RecordType::ALL_NAMES {
            let got = dig(&["example.com", name]).expect("valid");
            assert_eq!(got.types.len(), 1, "{name}");
            assert_eq!(got.types[0].to_string(), *name);
        }
    }

    /// A dotted token is always the name, even when a label spells a type;
    /// a wildcard owner name is a name, not ANY.
    #[test]
    fn dotted_tokens_are_names() {
        assert_eq!(
            dig(&["mx.example.com", "MX"]),
            Ok(args("mx.example.com", &[RecordType::MX]))
        );
        assert_eq!(
            dig(&["*.example.com"]),
            Ok(args("*.example.com", &[RecordType::A]))
        );
        assert_eq!(
            dig(&["_sip._tcp.example.com", "SRV"]),
            Ok(args("_sip._tcp.example.com", &[RecordType::SRV]))
        );
    }

    #[test]
    fn plus_options_set_short_and_trace() {
        let got = dig(&["example.com", "+short"]).expect("valid");
        assert!(got.short && !got.trace);
        let got = dig(&["+trace", "example.com"]).expect("valid");
        assert!(got.trace && !got.short);
        let got = dig(&["+SHORT", "example.com", "+Trace", "+short"]).expect("valid");
        assert!(got.short && got.trace);
        // The REPL's flag spellings.
        let got = dig(&["--short", "example.com", "--trace"]).expect("valid");
        assert!(got.short && got.trace);
    }

    #[test]
    fn unknown_plus_options_are_rejected_with_the_supported_list() {
        for option in ["+shrot", "+nocmd", "+"] {
            let e = err(&["example.com", option]);
            assert!(e.contains(&format!("'{option}'")), "{e}");
            assert!(e.contains("+short, +trace"), "{e}");
        }
    }

    #[test]
    fn unknown_dash_options_are_rejected() {
        for option in ["--shrot", "-t", "--reverse-lookup"] {
            let e = err(&["example.com", option]);
            assert!(e.contains(&format!("unknown option '{option}'")), "{e}");
        }
    }

    #[test]
    fn short_and_trace_flags_merge_with_tokens() {
        let got = parse(
            &["example.com"],
            DigFlags {
                short: true,
                trace: true,
                ..DigFlags::default()
            },
        )
        .expect("valid");
        assert!(got.short && got.trace);
        let got = parse(
            &["example.com", "+short"],
            DigFlags {
                short: true,
                ..DigFlags::default()
            },
        )
        .expect("repeating a mode is harmless");
        assert!(got.short);
    }

    #[test]
    fn reverse_queries_the_ptr_of_an_ip() {
        let reverse = |ip: &str| DigFlags {
            reverse: Some(ip.into()),
            ..DigFlags::default()
        };
        for ip in ["8.8.8.8", "2001:4860:4860::8888"] {
            let got = parse::<&str>(&[], reverse(ip)).expect("valid");
            assert_eq!(got, args(ip, &[RecordType::PTR]));
        }
        // PTR may be spelled out; the REPL spells -x in its tokens.
        assert_eq!(
            parse(&["PTR"], reverse("8.8.8.8")),
            Ok(args("8.8.8.8", &[RecordType::PTR]))
        );
        for tokens in [
            &["-x", "8.8.8.8"][..],
            &["--reverse", "8.8.8.8", "ptr"],
            &["--reverse=8.8.8.8"],
        ] {
            assert_eq!(
                dig(tokens),
                Ok(args("8.8.8.8", &[RecordType::PTR])),
                "{tokens:?}"
            );
        }
        let got = dig(&["@1.1.1.1", "-x", "8.8.8.8", "+short"]).expect("valid");
        assert_eq!(got.server.as_deref(), Some("1.1.1.1"));
        assert!(got.short);
    }

    #[test]
    fn reverse_rejects_other_types_names_and_non_ips() {
        let e = err(&["-x", "8.8.8.8", "MX", "PTR", "A"]);
        assert!(
            e.contains("-x looks up PTR") && e.contains("MX and A"),
            "{e}"
        );
        let e = err(&["-x", "8.8.8.8", "example.com"]);
        assert!(
            e.contains("one name") && e.contains("'-x 8.8.8.8' and 'example.com'"),
            "{e}"
        );
        let e = err(&["-x", "8.8.8.8", "-x", "1.1.1.1"]);
        assert!(e.contains("one name"), "{e}");
        let e = err(&["-x", "example.com"]);
        assert!(
            e.contains("-x needs an IP address, got 'example.com'"),
            "{e}"
        );
        let e = err(&["-x"]);
        assert!(e.contains("-x needs an IP address"), "{e}");
    }

    #[test]
    fn exactly_one_name_is_required() {
        let e = err(&[]);
        assert!(e.starts_with("no name to query"), "{e}");
        let e = err(&["@8.8.8.8", "MX", "+short"]);
        assert!(e.starts_with("no name to query"), "{e}");
        let e = err(&["example.com", "example.org"]);
        assert!(e.contains("'example.com' and 'example.org'"), "{e}");
        assert!(
            !e.contains("not a record type"),
            "both are dotted names: {e}"
        );
    }

    /// A typo'd type must not silently query A records (or a second name):
    /// the error names it as a would-be type and lists the valid ones.
    #[test]
    fn a_mistyped_type_is_reported_as_one() {
        for tokens in [["example.com", "MXX"], ["MXX", "example.com"]] {
            let e = err(&tokens);
            assert!(e.contains("'MXX' is not a record type"), "{e}");
            assert!(e.contains("valid types: A, AAAA"), "{e}");
        }
    }

    #[test]
    fn trace_takes_one_type_and_no_server() {
        let got = dig(&["example.com", "+trace", "AAAA"]).expect("valid");
        assert_eq!(got.types, vec![RecordType::AAAA]);
        let e = err(&["@8.8.8.8", "example.com", "+trace"]);
        assert!(e.contains("root servers") && e.contains("8.8.8.8"), "{e}");
        let e = parse(
            &["example.com"],
            DigFlags {
                server: Some("1.1.1.1".into()),
                trace: true,
                ..DigFlags::default()
            },
        )
        .expect_err("--trace with -s");
        assert!(e.contains("root servers"), "{e}");
        let e = err(&["example.com", "A", "MX", "+trace"]);
        assert!(e.contains("one record type, got A and MX"), "{e}");
        // A repeated type is still one type.
        assert!(dig(&["example.com", "A", "a", "+trace"]).is_ok());
    }

    #[test]
    fn into_query_builds_a_dig_or_a_trace() {
        let query = dig(&["@1.1.1.1", "example.com", "A", "MX", "+short"])
            .expect("valid")
            .into_query();
        let Query::Dig {
            name,
            types,
            server,
            short,
        } = query
        else {
            panic!("expected a dig query");
        };
        assert_eq!(name, "example.com");
        assert_eq!(types, vec![RecordType::A, RecordType::MX]);
        assert_eq!(server.as_deref(), Some("1.1.1.1"));
        assert!(short);

        let query = dig(&["example.com", "NS", "+trace", "+short"])
            .expect("valid")
            .into_query();
        let Query::Trace {
            name,
            record_type,
            short,
        } = query
        else {
            panic!("expected a trace query");
        };
        assert_eq!(name, "example.com");
        assert_eq!(record_type, RecordType::NS);
        assert!(short);
    }

    #[test]
    fn has_name_skips_servers_options_and_types() {
        assert!(!has_name::<&str>(&[]));
        assert!(!has_name(&["@1.1.1.1", "+short", "MX", "a"]));
        assert!(!has_name(&["-s", "8.8.8.8", "--server=1.1.1.1", "--short"]));
        assert!(!has_name(&["-x"]), "-x still waits for its address");
        assert!(has_name(&["example.com"]));
        assert!(has_name(&["@1.1.1.1", "MX", "example.com"]));
        assert!(has_name(&["-x", "8.8.8.8"]));
        assert!(has_name(&["--reverse=8.8.8.8"]));
    }

    #[test]
    fn lists_read_naturally() {
        assert_eq!(type_list(&[RecordType::A]), "A");
        assert_eq!(type_list(&[RecordType::A, RecordType::MX]), "A and MX");
        assert_eq!(
            quoted_list(&["a".into(), "b".into(), "c".into()]),
            "'a', 'b' and 'c'"
        );
    }
}
