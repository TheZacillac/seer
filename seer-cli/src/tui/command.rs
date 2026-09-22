//! Parser for the `:` command line. Pure — returns a `CmdOutcome` the App
//! interprets. Mirrors the CLI/REPL command surface.

use seer_core::RecordType;

use crate::tui::lenses;
use crate::tui::theme::Theme;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmdOutcome {
    Noop,
    Quit,
    Help,
    Copy,
    SetFormat(String),
    BadFormat,
    /// `theme <name>` with a name `Theme::from_name` accepts.
    SetTheme(String),
    /// `theme` with a missing or unknown name.
    BadTheme,
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
    /// `dig <domain> [type]` — DNS records of one type (default `A`).
    Dig {
        domain: String,
        record_type: RecordType,
    },
    /// `watch add <domain>` / `watch remove <domain>` — edit the watchlist.
    WatchMutate {
        add: Option<String>,
        remove: Option<String>,
    },
    /// A recognized command with bad arguments; the message is shown as-is.
    Invalid(String),
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
        "theme" => {
            let val = parts.get(1).map(|s| s.to_lowercase()).unwrap_or_default();
            if Theme::from_name(&val).is_some() {
                return CmdOutcome::SetTheme(val);
            }
            return CmdOutcome::BadTheme;
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
    if head == "dig" || head == "dns" {
        return match parts.as_slice() {
            [_] => CmdOutcome::Lens {
                lens: head,
                target: None,
            },
            [_, domain] => CmdOutcome::Dig {
                domain: domain.to_string(),
                record_type: RecordType::A,
            },
            [_, domain, rt] => match rt.parse::<RecordType>() {
                Ok(record_type) => CmdOutcome::Dig {
                    domain: domain.to_string(),
                    record_type,
                },
                Err(_) => CmdOutcome::Invalid(format!("unknown record type: {rt}")),
            },
            _ => CmdOutcome::Invalid("usage: dig <domain> [type]".to_string()),
        };
    }

    // Global lenses (no target domain): their arguments are subcommands, and
    // must never be mistaken for a domain — that would clobber the session
    // target with e.g. "add".
    if head == "watch" {
        let sub = parts.get(1).map(|s| s.to_lowercase());
        return match (sub.as_deref(), parts.get(2), parts.len()) {
            (None, _, _) | (Some("list"), None, 2) => CmdOutcome::Lens {
                lens: head,
                target: None,
            },
            (Some("add"), Some(d), 3) => CmdOutcome::WatchMutate {
                add: Some(d.to_string()),
                remove: None,
            },
            (Some("remove" | "rm"), Some(d), 3) => CmdOutcome::WatchMutate {
                add: None,
                remove: Some(d.to_string()),
            },
            _ => CmdOutcome::Invalid("usage: watch [list] · watch add|remove <domain>".to_string()),
        };
    }
    if head == "history" || head == "bulk" {
        if parts.len() > 1 {
            let usage = if head == "history" {
                "usage: history (in the pane: ↵ replay · c clear)"
            } else {
                "usage: bulk (in the pane: d domains · f file · r run)"
            };
            return CmdOutcome::Invalid(usage.to_string());
        }
        return CmdOutcome::Lens {
            lens: head,
            target: None,
        };
    }

    // A known lens command (whois, ssl, status, prop, rdap, ...).
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
    fn parses_theme_command() {
        assert_eq!(parse("theme latte"), CmdOutcome::SetTheme("latte".into()));
        assert_eq!(parse("theme frappe"), CmdOutcome::SetTheme("frappe".into()));
        // Args are lowercased before validation, so mixed case parses.
        assert_eq!(parse("theme LATTE"), CmdOutcome::SetTheme("latte".into()));
        assert_eq!(parse("theme Frappé"), CmdOutcome::SetTheme("frappé".into()));
        // Missing or unknown names both surface the standard error.
        assert_eq!(parse("theme"), CmdOutcome::BadTheme);
        assert_eq!(parse("theme mocha"), CmdOutcome::BadTheme);
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
            parse("ssl example.com"),
            CmdOutcome::Lens {
                lens: "ssl".into(),
                target: Some("example.com".into())
            }
        );
    }

    #[test]
    fn dig_parses_an_optional_record_type() {
        assert_eq!(
            parse("dig"),
            CmdOutcome::Lens {
                lens: "dig".into(),
                target: None
            }
        );
        assert_eq!(
            parse("dig example.com"),
            CmdOutcome::Dig {
                domain: "example.com".into(),
                record_type: RecordType::A
            }
        );
        // The type was previously dropped silently (always A).
        assert_eq!(
            parse("dig example.com mx"),
            CmdOutcome::Dig {
                domain: "example.com".into(),
                record_type: RecordType::MX
            }
        );
        assert!(
            matches!(parse("dig example.com BOGUS"), CmdOutcome::Invalid(m) if m.contains("BOGUS"))
        );
        assert!(matches!(
            parse("dig example.com MX extra"),
            CmdOutcome::Invalid(_)
        ));
    }

    #[test]
    fn global_lens_arguments_are_subcommands_not_domains() {
        assert_eq!(
            parse("watch add example.org"),
            CmdOutcome::WatchMutate {
                add: Some("example.org".into()),
                remove: None
            }
        );
        assert_eq!(
            parse("watch remove example.org"),
            CmdOutcome::WatchMutate {
                add: None,
                remove: Some("example.org".into())
            }
        );
        for line in ["watch", "watch list"] {
            assert_eq!(
                parse(line),
                CmdOutcome::Lens {
                    lens: "watch".into(),
                    target: None
                },
                "{line}"
            );
        }
        for line in [
            "watch add",
            "watch frob x.com",
            "history clear",
            "bulk file.txt",
        ] {
            assert!(
                matches!(parse(line), CmdOutcome::Invalid(_)),
                "{line} must be rejected, not treated as a domain"
            );
        }
        assert_eq!(
            parse("history"),
            CmdOutcome::Lens {
                lens: "history".into(),
                target: None
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
