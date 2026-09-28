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
            (1.., Some("dig")) => dig_candidates(&words[1..index], current),
            // Record types follow the domain.
            (2.., Some("prop" | "follow" | "compare")) => RECORD_TYPES.to_vec(),
            _ => return Ok((pos, Vec::new())),
        };
        Ok(complete_from(options, current, line_to_cursor))
    }
}

/// `dig` arguments come in any order (see [`crate::dig_args`]): a `+` word
/// is one of its options wherever it sits, and record types complete once
/// the name has been given — before that, a word is more likely the name.
fn dig_candidates(before: &[&str], current: &str) -> Vec<&'static str> {
    if current.starts_with('+') {
        crate::dig_args::PLUS_OPTIONS.to_vec()
    } else if current.starts_with(['@', '-']) || !crate::dig_args::has_name(before) {
        Vec::new()
    } else {
        RECORD_TYPES.to_vec()
    }
}

impl SeerCompleter {
    /// For a partly typed argument with exactly one completion, the rest of
    /// it (`ort` after `dig example.com +sh`), in the case of the typed part
    /// — record types complete uppercase but parse in any case, so `cnam`
    /// hints `e` and `CNAM` hints `E`.
    fn completion_hint(&self, line: &str, ctx: &rustyline::Context<'_>) -> Option<String> {
        // Only arguments: the word under the cursor is not the command.
        line.split_whitespace().nth(1)?;
        let (start, candidates) = self.complete(line, line.len(), ctx).ok()?;
        let [only] = candidates.as_slice() else {
            return None;
        };
        let typed = line.get(start..)?;
        let rest = only
            .replacement
            .get(typed.len()..)
            .filter(|r| !r.is_empty())?;
        let shouting = typed.chars().any(|c| c.is_ascii_uppercase())
            && !typed.chars().any(|c| c.is_ascii_lowercase());
        Some(if shouting {
            rest.to_ascii_uppercase()
        } else {
            rest.to_ascii_lowercase()
        })
    }
}

impl Hinter for SeerCompleter {
    type Hint = String;

    /// After `<command> `, hints the command's arguments; inside a partly
    /// typed argument with a single completion, hints the rest of it.
    fn hint(&self, line: &str, pos: usize, ctx: &rustyline::Context<'_>) -> Option<String> {
        if pos < line.len() {
            return None;
        }
        if !line.ends_with(' ') {
            return self.completion_hint(line, ctx);
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

    /// dig takes its arguments in any order, so completion goes by what a
    /// word looks like and whether the name has been given yet.
    #[test]
    fn dig_completes_options_anywhere_and_types_after_the_name() {
        assert_eq!(candidates("dig +"), vec!["+short", "+trace"]);
        assert_eq!(candidates("dig example.com MX +t"), vec!["+trace"]);
        assert!(candidates("dig @1.1.1.1 a").is_empty(), "no name yet");
        assert!(candidates("dig A a").is_empty(), "a type is not the name");
        assert!(candidates("dig -s 8.8.8.8 a").is_empty(), "nor a server");
        assert!(candidates("dig @1.1.1.1 example.com ht").contains(&"HTTPS".to_string()));
        assert_eq!(candidates("dig -x 8.8.8.8 pt"), vec!["PTR"]);
        assert!(candidates("dig example.com @").is_empty());
        // Every core type completes, the new ones included.
        let all = candidates("dig example.com MX ");
        for name in seer_core::RecordType::ALL_NAMES {
            assert!(all.iter().any(|c| c == name), "{name} is not completable");
        }
    }

    #[test]
    fn a_unique_argument_completion_is_hinted() {
        assert_eq!(hint("dig example.com +sh"), Some("ort".to_string()));
        assert_eq!(hint("dig +TR"), Some("ACE".to_string()));
        assert_eq!(hint("dig example.com cnam"), Some("e".to_string()));
        assert_eq!(hint("dig example.com CNAM"), Some("E".to_string()));
        assert_eq!(hint("dig example.com CDNS"), Some("KEY".to_string()));
        assert_eq!(hint("set output ya"), Some("ml".to_string()));
        // Ambiguous, complete already, or nothing to complete: no hint.
        assert_eq!(hint("dig example.com a"), None);
        assert_eq!(hint("dig example.com +short"), None);
        assert_eq!(hint("dig exa"), None);
        // Command names are not hinted, only arguments.
        assert_eq!(hint("delega"), None);
    }

    /// The follow hint used to omit `--changes-only`, which help showed.
    #[test]
    fn hints_show_the_catalog_usage() {
        assert_eq!(hint("whois "), Some(" <domain>".to_string()));
        assert!(hint("follow ").is_some_and(|h| h.contains("--changes-only")));
        assert_eq!(
            hint("dig "),
            Some(" [@server] <name> [type...] [+short] [+trace]".to_string())
        );
        assert_eq!(hint("prop "), hint("propagation "));
        assert_eq!(hint("doctor "), None);
        assert_eq!(hint("whois example.com "), None);
    }
}
