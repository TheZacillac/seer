use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::Helper;

const COMMANDS: &[&str] = &[
    "help",
    "exit",
    "quit",
    "lookup",
    "info",
    "whois",
    "rdap",
    "dig",
    "dns",
    "prop",
    "follow",
    "reverse",
    "avail",
    "dnssec",
    "bulk",
    "status",
    "ssl",
    "tld",
    "compare",
    "subdomains",
    "subs",
    "diff",
    "drift",
    "caa",
    "posture",
    "confusables",
    "watch",
    "history",
    "set",
    "clear",
];

// Note: "CAA" here is the DNS record type completed after `dig`/`prop`/etc.,
// distinct from the lowercase `caa` policy-lookup command in COMMANDS above.
const RECORD_TYPES: &[&str] = &[
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV", "CAA", "DNSKEY", "DS", "ANY",
];

/// Bulk operation names come from the shared ops module so the completer can
/// never drift from what `bulk` actually accepts.
const BULK_OPERATIONS: &[&str] = crate::ops::BULK_OPS;

const SET_OPTIONS: &[&str] = &["output"];

const OUTPUT_FORMATS: &[&str] = &["human", "json", "yaml", "markdown"];

const WATCH_ACTIONS: &[&str] = &["add", "remove", "list"];

pub struct SeerCompleter;

impl SeerCompleter {
    pub fn new() -> Self {
        Self
    }
}

impl Completer for SeerCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        // `pos` is a byte offset from rustyline; slicing with `&line[..pos]`
        // panics if it lands inside a multibyte char. `get(..pos)` returns
        // None on a non-char-boundary, so fall back to the whole line.
        let line_to_cursor = line.get(..pos).unwrap_or(line);
        let words: Vec<&str> = line_to_cursor.split_whitespace().collect();

        if words.is_empty() || (words.len() == 1 && !line_to_cursor.ends_with(' ')) {
            // Complete command
            let prefix = words.first().copied().unwrap_or("");
            let matches: Vec<Pair> = COMMANDS
                .iter()
                .filter(|cmd| cmd.starts_with(prefix))
                .map(|cmd| Pair {
                    display: cmd.to_string(),
                    replacement: cmd.to_string(),
                })
                .collect();
            let start = line_to_cursor.len() - prefix.len();
            return Ok((start, matches));
        }

        let command = words[0].to_lowercase();
        let current_word = if line_to_cursor.ends_with(' ') {
            ""
        } else {
            words.last().copied().unwrap_or("")
        };

        match command.as_str() {
            "dig" | "dns" | "propagation" | "prop" | "follow" | "compare" if words.len() >= 2 => {
                // Complete record types
                let matches: Vec<Pair> = RECORD_TYPES
                    .iter()
                    .filter(|rt| rt.to_lowercase().starts_with(&current_word.to_lowercase()))
                    .map(|rt| Pair {
                        display: rt.to_string(),
                        replacement: rt.to_string(),
                    })
                    .collect();
                let start = line_to_cursor.len() - current_word.len();
                return Ok((start, matches));
            }
            "bulk" if words.len() == 1 || (words.len() == 2 && !line_to_cursor.ends_with(' ')) => {
                // Complete bulk operation type
                let matches: Vec<Pair> = BULK_OPERATIONS
                    .iter()
                    .filter(|op| op.starts_with(current_word))
                    .map(|op| Pair {
                        display: op.to_string(),
                        replacement: op.to_string(),
                    })
                    .collect();
                let start = line_to_cursor.len() - current_word.len();
                return Ok((start, matches));
            }
            "set" => {
                if words.len() == 1 || (words.len() == 2 && !line_to_cursor.ends_with(' ')) {
                    // Complete setting name
                    let matches: Vec<Pair> = SET_OPTIONS
                        .iter()
                        .filter(|opt| opt.starts_with(current_word))
                        .map(|opt| Pair {
                            display: opt.to_string(),
                            replacement: opt.to_string(),
                        })
                        .collect();
                    let start = line_to_cursor.len() - current_word.len();
                    return Ok((start, matches));
                } else if words.len() >= 2 && words[1] == "output" {
                    // Complete output format
                    let matches: Vec<Pair> = OUTPUT_FORMATS
                        .iter()
                        .filter(|fmt| fmt.starts_with(current_word))
                        .map(|fmt| Pair {
                            display: fmt.to_string(),
                            replacement: fmt.to_string(),
                        })
                        .collect();
                    let start = line_to_cursor.len() - current_word.len();
                    return Ok((start, matches));
                }
            }
            "watch" if words.len() == 1 || (words.len() == 2 && !line_to_cursor.ends_with(' ')) => {
                let matches: Vec<Pair> = WATCH_ACTIONS
                    .iter()
                    .filter(|a| a.starts_with(current_word))
                    .map(|a| Pair {
                        display: a.to_string(),
                        replacement: a.to_string(),
                    })
                    .collect();
                let start = line_to_cursor.len() - current_word.len();
                return Ok((start, matches));
            }
            _ => {}
        }

        Ok((pos, vec![]))
    }
}

impl Hinter for SeerCompleter {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, _ctx: &rustyline::Context<'_>) -> Option<String> {
        if line.is_empty() || pos < line.len() {
            return None;
        }

        let words: Vec<&str> = line.split_whitespace().collect();
        if words.is_empty() {
            return None;
        }

        // Provide usage hints for commands
        match words[0].to_lowercase().as_str() {
            "lookup" if words.len() == 1 && line.ends_with(' ') => Some(" <domain>".to_string()),
            "info" if words.len() == 1 && line.ends_with(' ') => Some(" <domain>".to_string()),
            "whois" if words.len() == 1 && line.ends_with(' ') => Some(" <domain>".to_string()),
            "rdap" if words.len() == 1 && line.ends_with(' ') => {
                Some(" <domain|ip|asn>".to_string())
            }
            "dig" | "dns" if words.len() == 1 && line.ends_with(' ') => {
                Some(" <domain> [type] [@server]".to_string())
            }
            "propagation" | "prop" if words.len() == 1 && line.ends_with(' ') => {
                Some(" <domain> [type]".to_string())
            }
            "bulk" if words.len() == 1 && line.ends_with(' ') => {
                Some(" <operation> <file.txt>".to_string())
            }
            "set" if words.len() == 1 && line.ends_with(' ') => {
                Some(" output <human|json|yaml|markdown>".to_string())
            }
            "reverse" if words.len() == 1 && line.ends_with(' ') => Some(" <ip>".to_string()),
            "avail" if words.len() == 1 && line.ends_with(' ') => Some(" <domain>".to_string()),
            "dnssec" if words.len() == 1 && line.ends_with(' ') => Some(" <domain>".to_string()),
            "status" if words.len() == 1 && line.ends_with(' ') => Some(" <domain>".to_string()),
            "follow" if words.len() == 1 && line.ends_with(' ') => {
                Some(" <domain> [iterations] [interval_minutes] [type] [@server]".to_string())
            }
            "ssl" if words.len() == 1 && line.ends_with(' ') => Some(" <domain>".to_string()),
            "tld" if words.len() == 1 && line.ends_with(' ') => Some(" <tld>".to_string()),
            "compare" if words.len() == 1 && line.ends_with(' ') => {
                Some(" <domain> [type] @<server1> @<server2>".to_string())
            }
            "subdomains" | "subs" if words.len() == 1 && line.ends_with(' ') => {
                Some(" <domain> [--diff] [--record]".to_string())
            }
            "diff" if words.len() == 1 && line.ends_with(' ') => {
                Some(" <domain1> <domain2>".to_string())
            }
            "drift" if words.len() == 1 && line.ends_with(' ') => {
                Some(" <domain> [--record]".to_string())
            }
            "caa" | "posture" | "confusables" if words.len() == 1 && line.ends_with(' ') => {
                Some(" <domain>".to_string())
            }
            "watch" if words.len() == 1 && line.ends_with(' ') => {
                Some(" [add|remove|list] [domain]".to_string())
            }
            "history" if words.len() == 1 && line.ends_with(' ') => {
                Some(" [domain] [--clear]".to_string())
            }
            _ => None,
        }
    }
}

impl Highlighter for SeerCompleter {}
impl Validator for SeerCompleter {}
impl Helper for SeerCompleter {}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyline::history::DefaultHistory;

    #[test]
    fn complete_does_not_panic_on_multibyte_cursor_midchar() {
        // pos lands inside a multibyte char ('é' occupies bytes 3..5), i.e. a
        // non-char-boundary. `&line[..pos]` would panic there; the completer
        // must handle a mid-char cursor gracefully instead of crashing the
        // REPL (a panic drops the terminal out of a usable state).
        let completer = SeerCompleter::new();
        let history = DefaultHistory::new();
        let ctx = rustyline::Context::new(&history);
        let result = completer.complete("café", 4, &ctx);
        assert!(
            result.is_ok(),
            "completer must not panic on a non-char-boundary cursor"
        );
    }

    #[test]
    fn new_commands_are_completable() {
        for cmd in ["drift", "caa", "posture", "confusables"] {
            assert!(COMMANDS.contains(&cmd), "{cmd} should be a known command");
        }
        // The lowercase `caa` command must not displace the CAA record type.
        assert!(RECORD_TYPES.contains(&"CAA"));
    }

    #[test]
    fn bulk_completion_offers_new_operations() {
        let completer = SeerCompleter::new();
        let history = DefaultHistory::new();
        let ctx = rustyline::Context::new(&history);
        let line = "bulk po";
        let (_, candidates) = completer.complete(line, line.len(), &ctx).expect("ok");
        assert!(
            candidates.iter().any(|c| c.replacement == "posture"),
            "bulk completion should offer posture"
        );
    }
}
