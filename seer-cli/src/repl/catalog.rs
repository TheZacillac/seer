//! The REPL's command catalog: every command's name, aliases, argument usage,
//! and help line in one table. Tab completion, typing hints, `help`, and
//! usage errors all read from it, so they cannot drift from one another.

/// One REPL command.
pub struct ReplCommand {
    pub name: &'static str,
    /// Arguments after the name — the typing hint, the `help` row, and the
    /// usage error all show this.
    pub usage: &'static str,
    pub about: &'static str,
}

const fn cmd(name: &'static str, usage: &'static str, about: &'static str) -> ReplCommand {
    ReplCommand { name, usage, about }
}

/// A `help` section: its title, commands, and an optional dimmed note line.
pub struct Section {
    pub title: &'static str,
    pub commands: &'static [ReplCommand],
    pub note: Option<fn() -> String>,
}

/// Every command, grouped as `help` shows them.
pub const SECTIONS: &[Section] = &[
    Section {
        title: "LOOKUP COMMANDS",
        commands: &[
            cmd(
                "lookup",
                "<domain>",
                "Smart lookup (or just type a domain directly)",
            ),
            cmd(
                "info",
                "<domain>",
                "Comprehensive domain info (RDAP + WHOIS merged)",
            ),
            cmd("whois", "<domain>", "Query WHOIS information"),
            cmd("rdap", "<domain|ip|asn>", "Query RDAP registry data"),
        ],
        note: None,
    },
    Section {
        title: "DNS COMMANDS",
        commands: &[
            cmd("dig", "<domain> [type] [@server]", "Query DNS records"),
            cmd("prop", "<domain> [type]", "Check DNS propagation globally"),
            cmd(
                "follow",
                "<domain> [iterations] [interval_minutes] [type] [@server] [--changes-only]",
                "Monitor DNS records over time",
            ),
            cmd(
                "compare",
                "<domain> [type] @<server1> @<server2>",
                "Compare DNS records across nameservers",
            ),
            cmd(
                "delegation",
                "<domain>",
                "Check NS delegation health (parent vs zone, lameness)",
            ),
        ],
        note: Some(|| format!("Record types: {}", *crate::VALID_RECORD_TYPES)),
    },
    Section {
        title: "UTILITY COMMANDS",
        commands: &[
            cmd("reverse", "<ip>", "Reverse DNS lookup for an IP"),
            cmd(
                "avail",
                "<domain>",
                "Check domain registration availability",
            ),
            cmd("dnssec", "<domain>", "Check DNSSEC configuration"),
            cmd(
                "tld",
                "<tld>",
                "Look up TLD info (WHOIS server, RDAP, registry)",
            ),
            cmd(
                "subdomains",
                "<domain> [--resolve | --diff] [--record]",
                "Enumerate subdomains via CT logs (classify, baseline diff)",
            ),
            cmd(
                "doctor",
                "",
                "Diagnose seer environment (config, DNS, WHOIS, RDAP)",
            ),
        ],
        note: None,
    },
    Section {
        title: "STATUS & SSL",
        commands: &[
            cmd(
                "status",
                "<domain>",
                "Check HTTP, SSL, and domain expiration",
            ),
            cmd("ssl", "<domain>", "Inspect SSL certificate chain and SANs"),
        ],
        note: None,
    },
    Section {
        title: "SECURITY",
        commands: &[
            cmd("caa", "<domain>", "Look up CAA (cert authority) policy"),
            cmd(
                "posture",
                "<domain>",
                "Email/DNS posture (SPF, DMARC, MTA-STS, BIMI, DANE)",
            ),
            cmd(
                "headers",
                "<domain>",
                "Audit HTTP security headers + cookie flags",
            ),
            cmd(
                "takeover",
                "<domain> [--host <host>]...",
                "Scan subdomains for takeover exposure",
            ),
            cmd(
                "confusables",
                "<domain>",
                "Find registered look-alike domains",
            ),
        ],
        note: None,
    },
    Section {
        title: "COMPARISON",
        commands: &[cmd(
            "diff",
            "<domain1> <domain2>",
            "Compare two domains side-by-side",
        )],
        note: None,
    },
    Section {
        title: "MONITORING",
        commands: &[
            cmd(
                "watch",
                "[add|remove|list] [domain]",
                "Check watchlist / add / remove / list",
            ),
            cmd("history", "[domain] [--clear]", "View lookup history"),
            cmd(
                "drift",
                "<domain> [--record]",
                "Detect drift vs the last stored lookup",
            ),
        ],
        note: None,
    },
    Section {
        title: "BULK OPERATIONS",
        commands: &[cmd(
            "bulk",
            "<operation> <file> [type] [-o output.csv]",
            "Run bulk operations from file (bulk -h for details)",
        )],
        note: Some(|| format!("Operations: {}", *crate::ops::BULK_OPS_SUMMARY)),
    },
    Section {
        title: "SETTINGS",
        commands: &[
            cmd(
                "set",
                "output <human|json|yaml|markdown>",
                "Change output format",
            ),
            cmd(
                "copy",
                "[markdown|json|yaml]",
                "Copy last result to clipboard (default: markdown)",
            ),
            cmd("clear", "", "Clear screen"),
            cmd("help", "", "Show this help"),
            cmd("exit", "", "Exit the program"),
        ],
        note: None,
    },
];

/// Alternate spellings and the command each one means.
pub const ALIASES: &[(&str, &str)] = &[
    ("dns", "dig"),
    ("propagation", "prop"),
    ("subs", "subdomains"),
    ("?", "help"),
    ("quit", "exit"),
    ("q", "exit"),
];

/// Every command in catalog order.
pub fn commands() -> impl Iterator<Item = &'static ReplCommand> {
    SECTIONS.iter().flat_map(|section| section.commands)
}

/// The canonical name for `word` (already lowercased): aliases resolve to
/// their command, anything else is returned unchanged.
pub fn canonical(word: &str) -> &str {
    ALIASES
        .iter()
        .find(|(alias, _)| *alias == word)
        .map_or(word, |(_, name)| name)
}

/// The catalog entry for a command name or alias.
pub fn find(word: &str) -> Option<&'static ReplCommand> {
    let name = canonical(word);
    commands().find(|c| c.name == name)
}

/// `Usage: <name> <usage>` for a command name or alias.
pub fn usage(word: &str) -> String {
    match find(word) {
        Some(c) => format!("Usage: {} {}", c.name, c.usage)
            .trim_end()
            .to_string(),
        None => format!("Usage: {}", word),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_aliases_are_unique_and_aliases_resolve() {
        let mut seen = std::collections::HashSet::new();
        for word in commands()
            .map(|c| c.name)
            .chain(ALIASES.iter().map(|(a, _)| *a))
        {
            assert!(seen.insert(word), "{word} is listed twice");
        }
        for (alias, name) in ALIASES {
            assert!(find(alias).is_some_and(|c| c.name == *name), "{alias}");
        }
    }

    #[test]
    fn usage_names_the_canonical_command() {
        assert_eq!(usage("dns"), "Usage: dig <domain> [type] [@server]");
        assert_eq!(usage("whois"), "Usage: whois <domain>");
    }
}
