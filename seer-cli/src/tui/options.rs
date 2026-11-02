//! The Options section: each lens's option fields, declared as [`OptSpec`]
//! rows on its `LENSES` entry, and the values the user gave them
//! ([`Options`]). An unset value reads as its spec's default, so the store
//! holds only what changed. `App::default_req` is the one place values
//! become a request, so the box and the fetch cannot disagree. Values are
//! per lens; only the session domain is shared.
//!
//! The editing and display half of the API (`cycle`, `commit_text`,
//! `display`, `visible`, the spec labels and bounds) is consumed by the
//! Options box, which is not drawn yet: until it is, those items are
//! exercised by tests only.
#![allow(dead_code)]

use std::collections::HashMap;

use seer_core::output::sanitize_line;
use seer_core::RecordType;

use crate::ops::BULK_OP_NAMES;
use crate::tui::lenses::{self, LensKey};

/// Which option a value belongs to. Unique within a lens (test-enforced).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptId {
    RecordType,
    Server,
    ServerA,
    ServerB,
    Interval,
    Count,
    RdapQuery,
    SecondDomain,
    BulkOp,
    BulkSource,
    BulkDomains,
    BulkFile,
}

/// How a field is edited and what it defaults to.
#[derive(Debug, Clone, Copy)]
pub enum OptKind {
    /// Cycles `RecordType::ALL`.
    RecordType { default: RecordType },
    /// Cycles `presets` (`None` = the system resolver); `↵` types a custom one.
    Nameserver {
        presets: &'static [Option<&'static str>],
        default: Option<&'static str>,
    },
    Choice {
        labels: &'static [&'static str],
        default: usize,
    },
    /// Typed with `↵`; empty shows `placeholder`.
    Text { placeholder: &'static str },
    /// Steps by `step` with ←/→ (clamped, no wrap) or is typed with `↵`.
    Number {
        min: u64,
        max: u64,
        step: u64,
        default: u64,
    },
}

impl OptKind {
    fn default_value(&self) -> OptValue {
        match *self {
            OptKind::RecordType { default } => OptValue::Record(default),
            OptKind::Nameserver { default, .. } => OptValue::Server(default.map(str::to_string)),
            OptKind::Choice { default, .. } => OptValue::Choice(default),
            OptKind::Text { .. } => OptValue::Text(String::new()),
            OptKind::Number { default, .. } => OptValue::Number(default),
        }
    }
}

/// One field of a lens's Options box.
#[derive(Debug, Clone, Copy)]
pub struct OptSpec {
    pub id: OptId,
    pub label: &'static str,
    pub kind: OptKind,
    /// Whether the field shows now. A hidden field keeps its value.
    pub shown: fn(&Options) -> bool,
}

fn always(_: &Options) -> bool {
    true
}

/// A field that always shows; `.shown_when` narrows it.
pub const fn opt(id: OptId, label: &'static str, kind: OptKind) -> OptSpec {
    OptSpec {
        id,
        label,
        kind,
        shown: always,
    }
}

impl OptSpec {
    const fn shown_when(self, shown: fn(&Options) -> bool) -> Self {
        Self { shown, ..self }
    }

    /// Whether `↵` opens a text editor for this field.
    pub fn is_typed(&self) -> bool {
        matches!(
            self.kind,
            OptKind::Text { .. } | OptKind::Number { .. } | OptKind::Nameserver { .. }
        )
    }
}

/// A field's current value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptValue {
    Record(RecordType),
    Server(Option<String>),
    Choice(usize),
    Text(String),
    Number(u64),
}

/// What a Bulk run reads its domains from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BulkInput {
    Domains(String),
    File(String),
}

const RECORD_TYPE: OptSpec = opt(
    OptId::RecordType,
    "Type",
    OptKind::RecordType {
        default: RecordType::A,
    },
);
/// Records' nameserver slots: system, Google, Cloudflare.
const SYSTEM_FIRST: &[Option<&str>] = &[None, Some("8.8.8.8"), Some("1.1.1.1")];
/// Compare's resolver pool (no system slot: both sides name a server).
const RESOLVERS: &[Option<&str>] = &[
    Some("8.8.8.8"),
    Some("1.1.1.1"),
    Some("9.9.9.9"),
    Some("208.67.222.222"),
];

pub const RDAP: &[OptSpec] = &[opt(
    OptId::RdapQuery,
    "Query",
    OptKind::Choice {
        labels: &["Domain", "IP", "ASN"],
        default: 0,
    },
)];
pub const RECORDS: &[OptSpec] = &[
    RECORD_TYPE,
    opt(
        OptId::Server,
        "Server",
        OptKind::Nameserver {
            presets: SYSTEM_FIRST,
            default: None,
        },
    ),
];
pub const COMPARE: &[OptSpec] = &[
    opt(
        OptId::ServerA,
        "Server A",
        OptKind::Nameserver {
            presets: RESOLVERS,
            default: Some("8.8.8.8"),
        },
    ),
    opt(
        OptId::ServerB,
        "Server B",
        OptKind::Nameserver {
            presets: RESOLVERS,
            default: Some("1.1.1.1"),
        },
    ),
];
pub const TRACE: &[OptSpec] = &[RECORD_TYPE];
pub const FOLLOW: &[OptSpec] = &[
    opt(
        OptId::Interval,
        "Interval (s)",
        OptKind::Number {
            min: 1,
            max: seer_core::MAX_FOLLOW_INTERVAL_SECS,
            step: 5,
            default: 30,
        },
    ),
    opt(
        OptId::Count,
        "Count",
        OptKind::Number {
            min: 1,
            max: seer_core::MAX_FOLLOW_ITERATIONS as u64,
            step: 1,
            default: 20,
        },
    ),
];
pub const DIFF: &[OptSpec] = &[opt(
    OptId::SecondDomain,
    "Compare with",
    OptKind::Text {
        placeholder: "second domain",
    },
)];
pub const BULK: &[OptSpec] = &[
    opt(
        OptId::BulkOp,
        "Op",
        OptKind::Choice {
            labels: BULK_OP_NAMES,
            default: 0,
        },
    ),
    opt(
        OptId::BulkSource,
        "Source",
        OptKind::Choice {
            labels: &["domains", "file"],
            default: 0,
        },
    ),
    opt(
        OptId::BulkDomains,
        "Domains",
        OptKind::Text {
            placeholder: "a.com b.com …",
        },
    )
    .shown_when(bulk_from_domains),
    opt(
        OptId::BulkFile,
        "File",
        OptKind::Text {
            placeholder: "path/to/domains.txt",
        },
    )
    .shown_when(bulk_from_file),
];

fn bulk_from_file(o: &Options) -> bool {
    o.choice(LensKey::Bulk, OptId::BulkSource) == Some(1)
}

fn bulk_from_domains(o: &Options) -> bool {
    !bulk_from_file(o)
}

/// The spec of `id` on lens `key`, if the lens declares it.
fn spec(key: LensKey, id: OptId) -> Option<&'static OptSpec> {
    lenses::lenses()[key.index()]
        .options
        .iter()
        .find(|s| s.id == id)
}

/// `i` stepped once through `n` slots, wrapping.
fn step(i: usize, n: usize, forward: bool) -> usize {
    if forward {
        (i + 1) % n
    } else {
        (i + n - 1) % n
    }
}

/// Every lens's option values that differ from (or were set over) the defaults.
#[derive(Debug, Default)]
pub struct Options {
    values: HashMap<(LensKey, OptId), OptValue>,
}

impl Options {
    /// The value of `id` on `key`: the one set, else the spec default.
    /// `None` when the lens does not declare the option.
    fn value(&self, key: LensKey, id: OptId) -> Option<OptValue> {
        match self.values.get(&(key, id)) {
            Some(v) => Some(v.clone()),
            None => spec(key, id).map(|s| s.kind.default_value()),
        }
    }

    pub fn record_type(&self, key: LensKey) -> Option<RecordType> {
        match self.value(key, OptId::RecordType)? {
            OptValue::Record(t) => Some(t),
            _ => None,
        }
    }

    /// The nameserver of `id` on `key` (inner `None` = system resolver);
    /// outer `None` when the lens does not declare it.
    pub fn server(&self, key: LensKey, id: OptId) -> Option<Option<String>> {
        match self.value(key, id)? {
            OptValue::Server(s) => Some(s),
            _ => None,
        }
    }

    pub fn choice(&self, key: LensKey, id: OptId) -> Option<usize> {
        match self.value(key, id)? {
            OptValue::Choice(i) => Some(i),
            _ => None,
        }
    }

    pub fn text(&self, key: LensKey, id: OptId) -> Option<String> {
        match self.value(key, id)? {
            OptValue::Text(t) => Some(t),
            _ => None,
        }
    }

    pub fn number(&self, key: LensKey, id: OptId) -> Option<u64> {
        match self.value(key, id)? {
            OptValue::Number(n) => Some(n),
            _ => None,
        }
    }

    // Setters write the right variant by construction, so a getter never
    // meets a mismatched one. `:` commands use them; keys use `cycle` /
    // `commit_text`.
    pub fn set_record_type(&mut self, key: LensKey, t: RecordType) {
        self.values
            .insert((key, OptId::RecordType), OptValue::Record(t));
    }

    pub fn set_server(&mut self, key: LensKey, id: OptId, server: Option<String>) {
        self.values.insert((key, id), OptValue::Server(server));
    }

    pub fn set_choice(&mut self, key: LensKey, id: OptId, i: usize) {
        self.values.insert((key, id), OptValue::Choice(i));
    }

    pub fn set_text(&mut self, key: LensKey, id: OptId, text: String) {
        self.values.insert((key, id), OptValue::Text(text));
    }

    /// Step the field once (←/→): next or previous choice, record type or
    /// preset (a custom nameserver steps onto the first or last preset),
    /// or ±`step` for a number, clamped. Returns whether the value changed.
    pub fn cycle(&mut self, key: LensKey, id: OptId, forward: bool) -> bool {
        let (Some(spec), Some(cur)) = (spec(key, id), self.value(key, id)) else {
            return false;
        };
        let next = match (spec.kind, &cur) {
            (OptKind::RecordType { .. }, OptValue::Record(t)) => {
                let all = RecordType::ALL;
                let i = all.iter().position(|x| x == t).unwrap_or(0);
                OptValue::Record(all[step(i, all.len(), forward)])
            }
            (OptKind::Nameserver { presets, .. }, OptValue::Server(s)) => {
                let at = presets.iter().position(|p| p.map(str::to_string) == *s);
                let i = match at {
                    Some(i) => step(i, presets.len(), forward),
                    None if forward => 0,
                    None => presets.len() - 1,
                };
                OptValue::Server(presets[i].map(str::to_string))
            }
            (OptKind::Choice { labels, .. }, OptValue::Choice(i)) => {
                OptValue::Choice(step(*i, labels.len(), forward))
            }
            (OptKind::Number { min, max, step, .. }, OptValue::Number(n)) => {
                OptValue::Number(if forward {
                    n.saturating_add(step).min(max)
                } else {
                    n.saturating_sub(step).max(min)
                })
            }
            _ => return false,
        };
        let changed = next != cur;
        self.values.insert((key, id), next);
        changed
    }

    /// Commit typed text to a Text, Number or Nameserver field. A value that
    /// fails validation is refused with a message and nothing changes.
    /// Returns whether the value changed.
    pub fn commit_text(&mut self, key: LensKey, id: OptId, raw: &str) -> Result<bool, String> {
        let spec = spec(key, id).ok_or_else(|| "no such option".to_string())?;
        let raw = raw.trim();
        let next = match spec.kind {
            OptKind::Nameserver { presets, .. } => {
                if raw.is_empty() || raw.eq_ignore_ascii_case("system") {
                    if !presets.contains(&None) {
                        return Err(format!("{} needs a nameserver", spec.label));
                    }
                    OptValue::Server(None)
                } else {
                    seer_core::dns::NameserverSpec::parse(raw)
                        .map_err(|e| sanitize_line(&e.to_string()))?;
                    OptValue::Server(Some(raw.to_string()))
                }
            }
            OptKind::Number { min, max, .. } => {
                let n: u64 = raw
                    .parse()
                    .map_err(|_| format!("{} must be a whole number", spec.label))?;
                OptValue::Number(n.clamp(min, max))
            }
            OptKind::Text { .. } => OptValue::Text(validate_text(id, raw)?),
            OptKind::RecordType { .. } | OptKind::Choice { .. } => {
                return Err(format!("{} is chosen with ← →", spec.label))
            }
        };
        let changed = self.value(key, id).as_ref() != Some(&next);
        self.values.insert((key, id), next);
        Ok(changed)
    }

    /// The field's value as the Options box shows it, and whether that is
    /// the placeholder (drawn dim) rather than a value.
    pub fn display(&self, key: LensKey, spec: &OptSpec) -> (String, bool) {
        match (self.value(key, spec.id), spec.kind) {
            (Some(OptValue::Record(t)), _) => (t.as_str().to_string(), false),
            (Some(OptValue::Server(None)), _) => ("system".to_string(), false),
            (Some(OptValue::Server(Some(s))), _) => (s, false),
            (Some(OptValue::Choice(i)), OptKind::Choice { labels, .. }) => (
                labels.get(i).copied().unwrap_or_default().to_string(),
                false,
            ),
            (Some(OptValue::Text(t)), OptKind::Text { placeholder }) if t.is_empty() => {
                (placeholder.to_string(), true)
            }
            (Some(OptValue::Text(t)), _) => (t, false),
            (Some(OptValue::Number(n)), _) => (n.to_string(), false),
            _ => (String::new(), true),
        }
    }

    /// The lens's fields that show now, in declaration order.
    pub fn visible(&self, key: LensKey) -> Vec<&'static OptSpec> {
        lenses::lenses()[key.index()]
            .options
            .iter()
            .filter(|s| (s.shown)(self))
            .collect()
    }

    /// The next Follow run's `(count, interval_secs)`.
    pub fn follow_run(&self) -> Option<(usize, u64)> {
        let count = self.number(LensKey::Follow, OptId::Count)?;
        let interval = self.number(LensKey::Follow, OptId::Interval)?;
        Some((usize::try_from(count).ok()?, interval))
    }

    /// The next Bulk run's op and input.
    pub fn bulk_run(&self) -> Option<(&'static str, BulkInput)> {
        let op = *BULK_OP_NAMES.get(self.choice(LensKey::Bulk, OptId::BulkOp)?)?;
        let input = if bulk_from_file(self) {
            BulkInput::File(self.text(LensKey::Bulk, OptId::BulkFile)?)
        } else {
            BulkInput::Domains(self.text(LensKey::Bulk, OptId::BulkDomains)?)
        };
        Some((op, input))
    }
}

/// Per-field checks for typed text, in core where core has them.
fn validate_text(id: OptId, raw: &str) -> Result<String, String> {
    match id {
        OptId::SecondDomain if !raw.is_empty() => {
            seer_core::validation::normalize_domain(raw).map_err(|e| sanitize_line(&e.to_string()))
        }
        OptId::BulkDomains => {
            crate::tui::panes::bulk::parse_domains_input(raw).map(|_| raw.to_string())
        }
        _ => Ok(raw.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::lenses;

    #[test]
    fn defaults_match_the_old_pane_defaults() {
        let o = Options::default();
        assert_eq!(o.record_type(LensKey::Dns), Some(RecordType::A));
        assert_eq!(o.server(LensKey::Dns, OptId::Server), Some(None), "system");
        assert_eq!(
            o.server(LensKey::Compare, OptId::ServerA),
            Some(Some("8.8.8.8".into()))
        );
        assert_eq!(
            o.server(LensKey::Compare, OptId::ServerB),
            Some(Some("1.1.1.1".into()))
        );
        assert_eq!(o.follow_run(), Some((20, 30)), "(count, interval_secs)");
        assert_eq!(o.choice(LensKey::Rdap, OptId::RdapQuery), Some(0));
        assert_eq!(
            o.text(LensKey::Diff, OptId::SecondDomain),
            Some(String::new())
        );
    }

    #[test]
    fn undeclared_options_read_as_none() {
        let o = Options::default();
        assert_eq!(o.record_type(LensKey::Whois), None);
        assert_eq!(o.server(LensKey::Trace, OptId::Server), None);
    }

    #[test]
    fn values_are_per_lens() {
        let mut o = Options::default();
        o.set_record_type(LensKey::Dns, RecordType::MX);
        assert_eq!(o.record_type(LensKey::Dns), Some(RecordType::MX));
        assert_eq!(o.record_type(LensKey::Trace), Some(RecordType::A));
    }

    #[test]
    fn cycling_wraps_and_reports_change() {
        let mut o = Options::default();
        assert!(o.cycle(LensKey::Rdap, OptId::RdapQuery, false));
        assert_eq!(
            o.choice(LensKey::Rdap, OptId::RdapQuery),
            Some(2),
            "wraps back"
        );
        assert!(o.cycle(LensKey::Dns, OptId::RecordType, true));
        assert_eq!(o.record_type(LensKey::Dns), Some(RecordType::AAAA));
        // A Number clamps instead of wrapping, so the bound is "no change".
        o.commit_text(LensKey::Follow, OptId::Interval, "3600")
            .unwrap();
        assert!(!o.cycle(LensKey::Follow, OptId::Interval, true));
    }

    #[test]
    fn a_custom_nameserver_cycles_onto_the_presets() {
        let mut o = Options::default();
        o.set_server(LensKey::Dns, OptId::Server, Some("9.9.9.9".into()));
        assert!(o.cycle(LensKey::Dns, OptId::Server, true));
        assert_eq!(
            o.server(LensKey::Dns, OptId::Server),
            Some(None),
            "first preset"
        );
        o.set_server(LensKey::Dns, OptId::Server, Some("9.9.9.9".into()));
        assert!(o.cycle(LensKey::Dns, OptId::Server, false));
        assert_eq!(
            o.server(LensKey::Dns, OptId::Server),
            Some(Some("1.1.1.1".into())),
            "last preset"
        );
    }

    #[test]
    fn typed_values_are_validated_and_clamped() {
        let mut o = Options::default();
        assert_eq!(
            o.commit_text(LensKey::Follow, OptId::Count, "10001"),
            Ok(true)
        );
        assert_eq!(o.number(LensKey::Follow, OptId::Count), Some(10_000));
        assert_eq!(
            o.commit_text(LensKey::Follow, OptId::Interval, "0"),
            Ok(true)
        );
        assert_eq!(o.number(LensKey::Follow, OptId::Interval), Some(1));
        assert!(o.commit_text(LensKey::Follow, OptId::Count, "ten").is_err());
        assert_eq!(
            o.number(LensKey::Follow, OptId::Count),
            Some(10_000),
            "unchanged on error"
        );

        assert!(o
            .commit_text(LensKey::Dns, OptId::Server, "bad host!")
            .is_err());
        assert_eq!(
            o.commit_text(LensKey::Dns, OptId::Server, "tls://1.1.1.1"),
            Ok(true)
        );
        assert_eq!(
            o.commit_text(LensKey::Dns, OptId::Server, "system"),
            Ok(true)
        );
        assert_eq!(o.server(LensKey::Dns, OptId::Server), Some(None));
        // Compare has no system slot: empty is refused, not stored.
        assert!(o.commit_text(LensKey::Compare, OptId::ServerA, "").is_err());

        assert!(o
            .commit_text(LensKey::Diff, OptId::SecondDomain, "not a domain")
            .is_err());
        assert_eq!(
            o.commit_text(LensKey::Diff, OptId::SecondDomain, "Example.ORG"),
            Ok(true)
        );
        assert_eq!(
            o.text(LensKey::Diff, OptId::SecondDomain),
            Some("example.org".into())
        );
        assert!(o
            .commit_text(LensKey::Bulk, OptId::BulkDomains, "nodots")
            .is_err());
    }

    #[test]
    fn bulk_shows_the_input_its_source_names() {
        let mut o = Options::default();
        let ids =
            |o: &Options| -> Vec<OptId> { o.visible(LensKey::Bulk).iter().map(|s| s.id).collect() };
        assert_eq!(
            ids(&o),
            [OptId::BulkOp, OptId::BulkSource, OptId::BulkDomains]
        );
        o.set_choice(LensKey::Bulk, OptId::BulkSource, 1);
        assert_eq!(ids(&o), [OptId::BulkOp, OptId::BulkSource, OptId::BulkFile]);
        o.set_text(LensKey::Bulk, OptId::BulkFile, "list.txt".into());
        assert!(matches!(
            o.bulk_run(),
            Some(("lookup", BulkInput::File(p))) if p == "list.txt"
        ));
    }

    #[test]
    fn display_names_values_and_marks_placeholders() {
        let o = Options::default();
        let spec = |key, id| {
            *lenses::lenses()[LensKey::index(key)]
                .options
                .iter()
                .find(|s| s.id == id)
                .unwrap()
        };
        assert_eq!(
            o.display(LensKey::Dns, &spec(LensKey::Dns, OptId::Server)),
            ("system".to_string(), false)
        );
        let (text, placeholder) =
            o.display(LensKey::Diff, &spec(LensKey::Diff, OptId::SecondDomain));
        assert!(placeholder);
        assert_eq!(text, "second domain");
    }

    #[test]
    fn every_declared_option_has_a_value_and_presets_are_non_empty() {
        let o = Options::default();
        for lens in lenses::lenses() {
            for spec in lens.options {
                let (_, _) = o.display(lens.key, spec);
                match spec.kind {
                    OptKind::Nameserver { presets, .. } => assert!(!presets.is_empty()),
                    OptKind::Choice { labels, default } => {
                        assert!(default < labels.len(), "{} {:?}", lens.label, spec.id);
                    }
                    _ => {}
                }
            }
        }
    }
}
