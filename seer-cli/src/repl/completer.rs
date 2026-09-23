use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::Helper;

use super::catalog;

/// Record types come from core so completion can never drift from what
/// `RecordType::from_str` accepts — the hand-mirrored list this replaces had
/// silently lost NAPTR, TLSA, and SSHFP.
const RECORD_TYPES: &[&str] = seer_core::RecordType::ALL_NAMES;

const OUTPUT_FORMATS: &[&str] = &["human", "json", "yaml", "markdown"];

const WATCH_ACTIONS: &[&str] = &["add", "remove", "list"];

pub struct SeerCompleter;

impl SeerCompleter {
    pub fn new() -> Self {
        Self
    }
}

/// The `options` that start with `prefix` (case-insensitively, as commands
/// are), each replacing the prefix that ends `line_to_cursor`.
fn complete_from<'a>(
    options: impl IntoIterator<Item = &'a str>,
    prefix: &str,
    line_to_cursor: &str,
) -> (usize, Vec<Pair>) {
    let prefix_lower = prefix.to_lowercase();
    let matches = options
        .into_iter()
        .filter(|option| option.to_lowercase().starts_with(&prefix_lower))
        .map(|option| Pair {
            display: option.to_string(),
            replacement: option.to_string(),
        })
        .collect();
    (line_to_cursor.len() - prefix.len(), matches)
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
        // The word under the cursor (empty after a space) and its position.
        let (current, index) = match words.last() {
            Some(last) if !line_to_cursor.ends_with(' ') => (*last, words.len() - 1),
            _ => ("", words.len()),
        };
        let command = words.first().map(|w| w.to_lowercase());

        let options: Vec<&str> = match (index, command.as_deref().map(catalog::canonical)) {
            (0, _) => catalog::commands()
                .map(|c| c.name)
                .chain(catalog::ALIASES.iter().map(|(alias, _)| *alias))
                .collect(),
            (1, Some("bulk")) => crate::ops::BULK_OPS.iter().map(|(op, _)| *op).collect(),
            (1, Some("set")) => vec!["output"],
            (1, Some("watch")) => WATCH_ACTIONS.to_vec(),
            (_, Some("set")) if words.get(1) == Some(&"output") => OUTPUT_FORMATS.to_vec(),
            // Record types follow the domain.
            (2.., Some("dig" | "prop" | "follow" | "compare")) => RECORD_TYPES.to_vec(),
            _ => return Ok((pos, Vec::new())),
        };
        Ok(complete_from(options, current, line_to_cursor))
    }
}

impl Hinter for SeerCompleter {
    type Hint = String;

    /// After `<command> `, hints the command's arguments.
    fn hint(&self, line: &str, pos: usize, _ctx: &rustyline::Context<'_>) -> Option<String> {
        if pos < line.len() || !line.ends_with(' ') {
            return None;
        }
        let mut words = line.split_whitespace();
        let (Some(command), None) = (words.next(), words.next()) else {
            return None;
        };
        catalog::find(&command.to_lowercase())
            .filter(|c| !c.usage.is_empty())
            .map(|c| format!(" {}", c.usage))
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

    fn candidates(line: &str) -> Vec<String> {
        let history = DefaultHistory::new();
        let ctx = rustyline::Context::new(&history);
        let (_, pairs) = SeerCompleter::new()
            .complete(line, line.len(), &ctx)
            .expect("ok");
        pairs.into_iter().map(|p| p.replacement).collect()
    }

    fn hint(line: &str) -> Option<String> {
        let history = DefaultHistory::new();
        let ctx = rustyline::Context::new(&history);
        SeerCompleter::new().hint(line, line.len(), &ctx)
    }

    /// `propagation` was dispatched but missing from the hand-kept list.
    #[test]
    fn every_command_and_alias_is_completable() {
        let all = candidates("");
        for word in catalog::commands()
            .map(|c| c.name)
            .chain(catalog::ALIASES.iter().map(|(alias, _)| *alias))
        {
            assert!(all.iter().any(|c| c == word), "{word} is not completable");
        }
        assert_eq!(candidates("propag"), vec!["propagation"]);
    }

    #[test]
    fn arguments_complete_by_position() {
        assert!(candidates("bulk po").contains(&"posture".to_string()));
        assert_eq!(candidates("set o"), vec!["output"]);
        assert_eq!(candidates("set output j"), vec!["json"]);
        assert_eq!(candidates("watch r"), vec!["remove"]);
        // Record types follow the domain, for aliases too; the lowercase
        // `caa` command must not displace the CAA record type.
        assert!(candidates("dns example.com ca").contains(&"CAA".to_string()));
        assert!(
            candidates("dig a").is_empty(),
            "the domain slot has no types"
        );
    }

    /// The follow hint used to omit `--changes-only`, which help showed.
    #[test]
    fn hints_show_the_catalog_usage() {
        assert_eq!(hint("whois "), Some(" <domain>".to_string()));
        assert!(hint("follow ").is_some_and(|h| h.contains("--changes-only")));
        assert_eq!(hint("prop "), hint("propagation "));
        assert_eq!(hint("doctor "), None);
        assert_eq!(hint("whois example.com "), None);
    }
}
