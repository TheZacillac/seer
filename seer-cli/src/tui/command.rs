//! Parser for the `:` command line. Pure — returns a `CmdOutcome` the App
//! interprets. Mirrors the CLI/REPL command surface.

use crate::tui::lenses;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmdOutcome {
    Noop,
    Quit,
    Help,
    Copy,
    SetFormat(String),
    BadFormat,
    /// Switch to a lens (by cmd alias / key), optionally looking up a target.
    Lens {
        lens: String,
        target: Option<String>,
    },
    /// `lookup <domain>` or a bare domain.
    Lookup(String),
    /// `diff a.com b.com` — compare two domains.
    Diff {
        a: String,
        b: String,
    },
    /// `compare domain.com ns-a ns-b` — compare DNS between two nameservers.
    Compare {
        domain: String,
        a: String,
        b: String,
    },
    Unknown(String),
}

pub fn parse(raw: &str) -> CmdOutcome {
    let line = raw.trim();
    if line.is_empty() {
        return CmdOutcome::Noop;
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    let head = parts[0].to_lowercase();

    match head.as_str() {
        "q" | "quit" | "exit" => return CmdOutcome::Quit,
        "help" | "h" | "?" => return CmdOutcome::Help,
        "copy" | "yank" | "y" => return CmdOutcome::Copy,
        "set" => {
            let what = parts.get(1).map(|s| s.to_lowercase()).unwrap_or_default();
            let val = parts.get(2).map(|s| s.to_lowercase()).unwrap_or_default();
            if what == "output" || what == "format" {
                if matches!(val.as_str(), "human" | "json" | "yaml" | "markdown") {
                    return CmdOutcome::SetFormat(val);
                }
                return CmdOutcome::BadFormat;
            }
            return CmdOutcome::Unknown(line.to_string());
        }
        "lookup" | "info" => {
            return match parts.get(1) {
                Some(t) => CmdOutcome::Lookup((*t).to_string()),
                None => CmdOutcome::Unknown(line.to_string()),
            };
        }
        _ => {}
    }

    if head == "diff" {
        return match (parts.get(1), parts.get(2)) {
            (Some(a), Some(b)) => CmdOutcome::Diff {
                a: a.to_string(),
                b: b.to_string(),
            },
            _ => CmdOutcome::Unknown(line.to_string()),
        };
    }
    if head == "compare" {
        return match (parts.get(1), parts.get(2), parts.get(3)) {
            (Some(d), Some(a), Some(b)) => CmdOutcome::Compare {
                domain: d.to_string(),
                a: a.to_string(),
                b: b.to_string(),
            },
            _ => CmdOutcome::Unknown(line.to_string()),
        };
    }

    // A known lens command (whois, dig, ssl, status, prop, rdap, ...).
    if lenses::find_by_cmd_or_key(&head).is_some() {
        return CmdOutcome::Lens {
            lens: head,
            target: parts.get(1).map(|s| s.to_string()),
        };
    }

    // A bare domain (contains a dot).
    if head.contains('.') {
        return CmdOutcome::Lookup(head);
    }

    CmdOutcome::Unknown(line.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quit() {
        assert_eq!(parse("q"), CmdOutcome::Quit);
        assert_eq!(parse("quit"), CmdOutcome::Quit);
        assert_eq!(parse("exit"), CmdOutcome::Quit);
    }

    #[test]
    fn parses_help_and_copy() {
        assert_eq!(parse("help"), CmdOutcome::Help);
        assert_eq!(parse("?"), CmdOutcome::Help);
        assert_eq!(parse("copy"), CmdOutcome::Copy);
        assert_eq!(parse("yank"), CmdOutcome::Copy);
    }

    #[test]
    fn parses_set_output() {
        assert_eq!(
            parse("set output json"),
            CmdOutcome::SetFormat("json".into())
        );
        assert_eq!(
            parse("set format yaml"),
            CmdOutcome::SetFormat("yaml".into())
        );
        assert_eq!(parse("set output bogus"), CmdOutcome::BadFormat);
    }

    #[test]
    fn parses_lens_with_and_without_target() {
        assert_eq!(
            parse("whois"),
            CmdOutcome::Lens {
                lens: "whois".into(),
                target: None
            }
        );
        assert_eq!(
            parse("dig example.com"),
            CmdOutcome::Lens {
                lens: "dig".into(),
                target: Some("example.com".into())
            }
        );
    }

    #[test]
    fn parses_bare_domain_and_lookup() {
        assert_eq!(
            parse("example.com"),
            CmdOutcome::Lookup("example.com".into())
        );
        assert_eq!(
            parse("lookup acme.io"),
            CmdOutcome::Lookup("acme.io".into())
        );
    }

    #[test]
    fn empty_is_noop_unknown_is_error() {
        assert_eq!(parse("   "), CmdOutcome::Noop);
        assert_eq!(
            parse("frobnicate"),
            CmdOutcome::Unknown("frobnicate".into())
        );
    }

    #[test]
    fn parses_new_lens_commands() {
        assert_eq!(
            parse("reverse 8.8.8.8"),
            CmdOutcome::Lens {
                lens: "reverse".into(),
                target: Some("8.8.8.8".into())
            }
        );
        assert_eq!(
            parse("tld .com"),
            CmdOutcome::Lens {
                lens: "tld".into(),
                target: Some(".com".into())
            }
        );
        assert_eq!(
            parse("diff a.com b.com"),
            CmdOutcome::Diff {
                a: "a.com".into(),
                b: "b.com".into()
            }
        );
        assert_eq!(
            parse("compare ex.com 8.8.8.8 1.1.1.1"),
            CmdOutcome::Compare {
                domain: "ex.com".into(),
                a: "8.8.8.8".into(),
                b: "1.1.1.1".into()
            }
        );
    }
}
