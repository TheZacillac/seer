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
    "whois",
    "rdap",
    "dig",
    "dns",
    "propagation",
    "prop",
    "bulk",
    "set",
    "clear",
];

const RECORD_TYPES: &[&str] = &[
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV", "CAA", "ANY",
];

const BULK_OPERATIONS: &[&str] = &["lookup", "whois", "rdap", "dig", "propagation"];

const SET_OPTIONS: &[&str] = &["output"];

const OUTPUT_FORMATS: &[&str] = &["human", "json"];

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
        let line_to_cursor = &line[..pos];
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
            "dig" | "dns" | "propagation" | "prop" => {
                // Complete record types
                if words.len() >= 2 {
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
            }
            "bulk" => {
                if words.len() == 1 || (words.len() == 2 && !line_to_cursor.ends_with(' ')) {
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
            "lookup" if words.len() == 1 && line.ends_with(' ') => {
                Some(" <domain>".to_string())
            }
            "whois" if words.len() == 1 && line.ends_with(' ') => {
                Some(" <domain>".to_string())
            }
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
                Some(" output <human|json>".to_string())
            }
            _ => None,
        }
    }
}

impl Highlighter for SeerCompleter {}
impl Validator for SeerCompleter {}
impl Helper for SeerCompleter {}
