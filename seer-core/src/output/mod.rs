//! Output formatting for every seer-core result type.
//!
//! [`OutputFormatter`] has one `format_*` method per result type, implemented
//! by the human (colored terminal), JSON, YAML and Markdown formatters. The
//! method list is written once, in `with_report_methods!`, which generates the
//! trait and all four impls.
//! Callers pick one through [`get_formatter`] from an [`OutputFormat`], so the
//! CLI, REPL, TUI raw view and clipboard copy all render identically. Human
//! and Markdown output are pinned by `insta` snapshots in
//! `seer-core/tests/format_snapshots.rs`.
//!
//! [`dig_short`] and [`dig_trace_short`] are the `dig +short` rendering of a
//! query result and a trace: bare values, one per line, sanitized for a
//! terminal — a plain-text mode outside the four formats. [`dig`] also holds
//! the wording of a query's outcome (NXDOMAIN vs NODATA, the wildcard note),
//! shared by the formatters and the TUI's DNS lens, and [`sanitize_line`] is
//! the terminal-safety guard the human formatter applies to remote strings.
//! Wording the formats share — [`availability_label`] (with its
//! [`Emphasis`], also used by the TUI), the expiry phrase, the lookup source,
//! the DNSSEC depth note, the propagation detail and the diff rows — is
//! written once here and in `diff_table`.

// The report-method list and the impl generators below must precede the
// `mod` declarations: `macro_rules!` is textually scoped, and the human and
// markdown modules invoke `impl_forwarding!` where their inherent methods
// are visible.

/// Calls `$mac!` with every report type a formatter renders, one
/// `method(arg: Type);` row each. This list is the single source of truth for
/// [`OutputFormatter`] and all four of its impls: adding a report type is one
/// row here plus the human and markdown inherent methods of the same name.
macro_rules! with_report_methods {
    ($mac:ident!($($prefix:tt)*)) => {
        $mac! {
            $($prefix)*
            format_whois(response: crate::whois::WhoisResponse);
            format_rdap(response: crate::rdap::RdapResponse);
            format_dns(records: [crate::dns::DnsRecord]);
            format_dig(result: crate::dns::DnsQueryResult);
            format_dns_trace(trace: crate::dns::DnsTrace);
            format_propagation(result: crate::dns::PropagationResult);
            format_lookup(result: crate::lookup::LookupResult);
            format_status(response: crate::status::StatusResponse);
            format_follow_iteration(iteration: crate::dns::FollowIteration);
            format_follow(result: crate::dns::FollowResult);
            format_availability(result: crate::availability::AvailabilityResult);
            format_dnssec(report: crate::dns::DnssecReport);
            format_delegation(report: crate::dns::DelegationReport);
            format_tld(info: crate::tld::TldInfo);
            format_dns_comparison(comparison: crate::dns::DnsComparison);
            format_subdomains(result: crate::subdomains::SubdomainResult);
            format_diff(diff: crate::diff::DomainDiff);
            format_ssl(report: crate::ssl::SslReport);
            format_watch(report: crate::watchlist::WatchReport);
            format_domain_info(info: crate::domain_info::DomainInfo);
            format_drift(report: crate::drift::DriftReport);
            format_posture(posture: crate::posture::EmailPosture);
            format_headers(report: crate::headers::HeaderReport);
            format_takeover(report: crate::takeover::TakeoverReport);
            format_caa(policy: crate::caa::CaaPolicy);
            format_confusables(report: crate::confusables::ConfusableReport);
            format_subdomain_classification(result: crate::subdomains::SubdomainClassification);
            format_subdomain_baseline_diff(report: crate::subdomains::SubdomainBaselineDiff);
        }
    };
}

macro_rules! declare_output_formatter {
    ($($method:ident($arg:ident: $ty:ty);)+) => {
        /// Renders every report type in one output format; pick an
        /// implementation with [`get_formatter`].
        pub trait OutputFormatter {
            $(fn $method(&self, $arg: &$ty) -> String;)+
        }
    };
}

/// Implements [`OutputFormatter`] for a data-format formatter by passing every
/// report to one serializing method (`to_json`, `to_yaml_value`).
macro_rules! impl_serializing {
    ($formatter:ty, $render:ident; $($method:ident($arg:ident: $ty:ty);)+) => {
        impl OutputFormatter for $formatter {
            $(fn $method(&self, $arg: &$ty) -> String {
                self.$render($arg)
            })+
        }
    };
}

/// Implements [`OutputFormatter`] by forwarding each method to the inherent
/// method of the same name, defined in the formatter's per-concern
/// submodules. Rust resolves the inherent method first, so this does not
/// recurse; it must be invoked where those inherent methods are visible.
/// A missing inherent method would make the forwarder call itself, so
/// `unconditional_recursion` is denied: a compile error, not a stack overflow.
macro_rules! impl_forwarding {
    ($formatter:ty; $($method:ident($arg:ident: $ty:ty);)+) => {
        #[deny(unconditional_recursion)]
        impl OutputFormatter for $formatter {
            $(fn $method(&self, $arg: &$ty) -> String {
                self.$method($arg)
            })+
        }
    };
}

mod contact;
mod diff_table;
pub mod dig;
mod grouping;
mod human;
mod json;
mod markdown;

pub use dig::{dig_short, dig_trace_short};
pub use human::HumanFormatter;
pub use json::JsonFormatter;
pub use markdown::MarkdownFormatter;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::dns::{AuthenticationTier, PropagationResult, PropagationVerdict};
use crate::lookup::LookupResult;
use crate::subdomains::SubdomainStatus;
use crate::takeover::TakeoverVerdict;

static_regex! {
    /// ANSI escape sequences in untrusted text: CSI, OSC (terminated by BEL
    /// or ST — ESC is excluded from the payload so it can't over-consume
    /// across sequences) and the two-byte forms.
    ANSI_ESCAPE_RE = r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[A-Z@-_]";
}

/// Invisible Unicode format characters that reorder or hide text without
/// being control characters: zero-width space/joiners and LRM/RLM
/// (U+200B–U+200F), the bidi embeddings and overrides (U+202A–U+202E) and
/// isolates (U+2066–U+2069), the Arabic letter mark (U+061C) and the BOM
/// (U+FEFF). A "Trojan Source" override can make remote text read as
/// something it isn't, so every renderer drops them.
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{061C}'
            | '\u{FEFF}'
    )
}

/// Sanitizes untrusted remote text (a WHOIS value, a record's data, a server
/// error) for one line of a terminal: ANSI escape sequences, the remaining
/// C0/C1 control characters (CR, backspace, BEL, stray ESC, DEL…) and
/// invisible bidi/zero-width format characters are removed, and newlines,
/// tabs and the Unicode line/paragraph separators are folded to spaces — so
/// remote data can neither inject terminal escapes nor forge an extra row.
/// The human formatter applies it to every remote value; other terminal
/// renderers (the TUI) use it too.
pub fn sanitize_line(s: &str) -> String {
    ANSI_ESCAPE_RE
        .replace_all(s, "")
        .chars()
        .filter_map(|c| match c {
            '\n' | '\t' | '\u{2028}' | '\u{2029}' => Some(' '),
            c if c.is_control() || is_invisible_format(c) => None,
            c => Some(c),
        })
        .collect()
}

/// Whole days from now until `when` — see [`crate::dates::days_until`]: an
/// expiry any time in the past is negative, so it never renders as
/// "expires in 0 days".
fn days_until(when: DateTime<Utc>) -> i64 {
    crate::dates::days_until(when, Utc::now())
}

/// `1 day` / `N days`.
fn day_count(days: i64) -> String {
    if days == 1 {
        "1 day".to_string()
    } else {
        format!("{days} days")
    }
}

/// The one wording of an expiry `days_until` days away (see [`days_until`]):
/// "expired N days ago" once past, else "expires in N days".
fn expiry_phrase(days_until: i64) -> String {
    if days_until < 0 {
        format!("expired {} ago", day_count(-days_until))
    } else {
        format!("expires in {}", day_count(days_until))
    }
}

/// How a renderer should emphasize a value: the human formatter maps it to a
/// color, the TUI to a theme color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emphasis {
    /// Healthy, or the answer hoped for.
    Good,
    /// A neutral fact.
    Neutral,
    /// Worth attention.
    Caution,
    /// A failure or an urgent problem.
    Bad,
}

/// How urgent an expiry `days_until` days away is: already past or under 30
/// days is [`Emphasis::Bad`], under 90 [`Emphasis::Caution`], else
/// [`Emphasis::Good`].
fn expiry_emphasis(days_until: i64) -> Emphasis {
    match days_until {
        d if d < 30 => Emphasis::Bad,
        d if d < 90 => Emphasis::Caution,
        _ => Emphasis::Good,
    }
}

/// The display label of an availability verdict
/// ([`crate::availability::AvailabilityResult::verdict`]) and how to
/// emphasize it. Any other verdict reads "UNKNOWN".
pub fn availability_label(verdict: &str) -> (&'static str, Emphasis) {
    match verdict {
        "available" => ("AVAILABLE", Emphasis::Good),
        "likely_available" => ("MAY BE AVAILABLE", Emphasis::Caution),
        "registered" => ("REGISTERED", Emphasis::Neutral),
        "likely_registered" => ("LIKELY REGISTERED", Emphasis::Caution),
        _ => ("UNKNOWN", Emphasis::Bad),
    }
}

/// Where a lookup's data came from, as every formatter's "Source" line
/// reads it.
fn lookup_source(result: &LookupResult) -> &'static str {
    match result {
        LookupResult::Rdap { .. } => "RDAP",
        LookupResult::Whois {
            rdap_error: None, ..
        } => "WHOIS",
        LookupResult::Whois { .. }
        | LookupResult::Available {
            whois_data: Some(_),
            ..
        } => "WHOIS (RDAP unavailable)",
        LookupResult::Available { .. } => "availability check (RDAP and WHOIS failed)",
    }
}

/// Formats a [`TimeDelta`] as a compact duration (`Ns` / `Nm Ns` / `Nh Nm`).
fn format_duration(duration: TimeDelta) -> String {
    let total_secs = duration.num_seconds();
    if total_secs < 60 {
        format!("{total_secs}s")
    } else if total_secs < 3600 {
        format!("{}m {}s", total_secs / 60, total_secs % 60)
    } else {
        format!("{}h {}m", total_secs / 3600, (total_secs % 3600) / 60)
    }
}

/// The DNSSEC disclosure (M12) that closes every block of DNS answers:
/// seer's resolver does not validate DNSSEC, and UDP DNS is trivially
/// spoofable. The human formatters print it as is, Markdown as a quote.
const DNSSEC_NOTE: &str = "Note: DNS responses are not DNSSEC-validated";

/// A DNSSEC report's verification depth, and the note saying what that
/// depth does *not* establish (none for an unsigned zone: nothing was
/// checked).
fn dnssec_depth(tier: AuthenticationTier) -> (&'static str, Option<&'static str>) {
    match tier {
        AuthenticationTier::Unsigned => ("unsigned (no DNSSEC records)", None),
        AuthenticationTier::DigestOnly => (
            "digest-only (DS↔DNSKEY consistency)",
            Some(
                "Note: reflects DS/DNSKEY digest consistency only — RRSIG signatures, \
                 validity periods, and the chain to the root are NOT cryptographically \
                 verified.",
            ),
        ),
    }
}

/// The detail after a propagation verdict: how many of the responding
/// servers agree (`all 20 responding servers agree`).
fn propagation_detail(result: &PropagationResult) -> String {
    let responding = result.servers_responding;
    match result.verdict() {
        PropagationVerdict::NoAnswer => {
            format!("none of the {} servers answered", result.servers_checked)
        }
        PropagationVerdict::Full if responding == 1 => {
            "the one responding server answered".to_string()
        }
        PropagationVerdict::Full => format!("all {responding} responding servers agree"),
        _ => format!(
            "{} of {responding} responding servers agree",
            result.servers_agreeing()
        ),
    }
}

/// A takeover finding's verdict as the formatters print it.
fn takeover_label(verdict: TakeoverVerdict) -> &'static str {
    match verdict {
        TakeoverVerdict::Vulnerable => "VULNERABLE",
        TakeoverVerdict::Potential => "potential",
        TakeoverVerdict::Inconclusive => "inconclusive",
        TakeoverVerdict::Safe => "safe",
    }
}

/// A classified subdomain's status as the formatters print it.
fn subdomain_status_label(status: SubdomainStatus) -> &'static str {
    match status {
        SubdomainStatus::Live => "live",
        SubdomainStatus::Dead => "dead",
        SubdomainStatus::Wildcard => "wildcard",
        SubdomainStatus::Unknown => "unknown",
    }
}

/// A differing propagation server's answer as one short line of plain
/// text (the caller escapes it for its format; the TUI through
/// [`sanitize_line`]): the values themselves when
/// the sets are small, else what it lacks and adds against the consensus —
/// a 19-record TXT set is unreadable inline, and the difference is the news.
pub fn propagation_difference(inc: &crate::dns::Inconsistency, empty_label: &str) -> String {
    const INLINE_VALUES: usize = 6;
    if inc.values.is_empty() {
        return format!("no records ({empty_label})");
    }
    if inc.values.len() + inc.consensus.len() <= INLINE_VALUES {
        return inc.values.join(", ");
    }
    let mut parts = Vec::new();
    let missing = inc.missing_count();
    if missing > 0 {
        parts.push(format!("missing {missing} of {}", inc.consensus.len()));
    }
    let extra = inc.extra_values();
    if !extra.is_empty() {
        parts.push(format!("extra: {}", extra.join(", ")));
    }
    parts.join("; ")
}

/// Shown beside a propagation result whose answers look location-dependent
/// ([`crate::dns::PropagationResult::looks_location_dependent`]).
const GEO_NOTE: &str = "Note: answers vary by resolver location, typical of GeoDNS/CDN \
     names rather than a propagation delay";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
    Yaml,
    Markdown,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "human" | "text" | "pretty" => Ok(OutputFormat::Human),
            "json" => Ok(OutputFormat::Json),
            "yaml" | "yml" => Ok(OutputFormat::Yaml),
            "markdown" | "md" => Ok(OutputFormat::Markdown),
            _ => Err(format!(
                "Unknown output format: {}. Use: human, json, yaml, markdown",
                s
            )),
        }
    }
}

with_report_methods!(declare_output_formatter!());

/// YAML output formatter that converts data structures to YAML format.
#[derive(Default)]
pub struct YamlFormatter;

impl YamlFormatter {
    pub fn new() -> Self {
        Self
    }

    /// Formats any serializable value as YAML output.
    pub fn to_yaml_value<T: Serialize + ?Sized>(&self, value: &T) -> String {
        // Convert to JSON value first, then format as YAML-like output
        match serde_json::to_value(value) {
            Ok(v) => format_as_yaml(&v, 0),
            Err(e) => format!("error: {}", yaml_scalar(&e.to_string())),
        }
    }
}

with_report_methods!(impl_serializing!(YamlFormatter, to_yaml_value;));

/// Returns true when a string cannot be emitted as a YAML *plain* scalar and
/// must be double-quoted. Covers the cases the old `contains('\n'|':'|'#')`
/// predicate missed (issue #54): empty strings, leading/trailing whitespace,
/// any control character or YAML line break (U+0085/U+2028/U+2029 — a raw one
/// makes the whole document unparseable), a leading YAML indicator character,
/// an interior `": "` / trailing `:` / `" #"` (which break a plain scalar),
/// and the YAML 1.1 bool/null tokens (`null`, `~`, `true`, `false`, `yes`,
/// `no`, `y`, `n`, `on`, `off`) and special keys (`=` value, `<<` merge)
/// which would otherwise round-trip as the wrong type or fail to load.
///
/// Anything starting with an ASCII digit, `+`, or `.` is quoted too: that is
/// how a YAML 1.1/1.2 resolver comes to read a plain scalar as a number or
/// timestamp (`+1.5555550100` → float, `292` → int, `0123` → octal, `1:20` →
/// sexagesimal, `2024-01-15` → date, `.inf`/`.nan` → float). Only JSON
/// *strings* reach this function (numbers are emitted unquoted by
/// `format_as_yaml`), so such a value must stay a string. The rule
/// over-quotes some harmless values (e.g. IPv4 addresses), which is cheap and
/// keeps it auditable.
fn yaml_needs_quoting(s: &str) -> bool {
    if s.is_empty() || s != s.trim() {
        return true;
    }
    if s.chars()
        .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}'))
    {
        return true;
    }
    if matches!(
        s.to_ascii_lowercase().as_str(),
        "null" | "~" | "true" | "false" | "yes" | "no" | "y" | "n" | "on" | "off" | "=" | "<<"
    ) {
        return true;
    }
    if let Some(first) = s.chars().next() {
        // A leading YAML indicator char makes the whole scalar non-plain.
        if "-?:,[]{}#&*!|>'\"%@`".contains(first) {
            return true;
        }
        // Possible number / timestamp / special float (see doc comment).
        if first.is_ascii_digit() || first == '+' || first == '.' {
            return true;
        }
    }
    s.contains(": ") || s.ends_with(':') || s.contains(" #")
}

/// Emits `s` as a YAML double-quoted scalar, escaping `"`, `\`, control
/// characters, and the YAML line-break characters (so attacker ANSI/control
/// bytes can't reach the terminal or break the document).
fn yaml_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\0' => out.push_str("\\0"),
            // YAML line breaks: next line (a C1 control, so it must precede
            // the generic arm below), line separator, paragraph separator.
            '\u{0085}' => out.push_str("\\N"),
            '\u{2028}' => out.push_str("\\L"),
            '\u{2029}' => out.push_str("\\P"),
            // C0/C1 controls + DEL → YAML \xXX escape (all <= 0x9F, two digits).
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Emits a scalar string as a plain YAML scalar when safe, else double-quoted.
fn yaml_scalar(s: &str) -> String {
    if yaml_needs_quoting(s) {
        yaml_quote(s)
    } else {
        s.to_string()
    }
}

/// True for a non-empty array or object: a value rendered as an indented
/// block rather than inline after its key or dash.
fn is_yaml_block(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(arr) => !arr.is_empty(),
        serde_json::Value::Object(map) => !map.is_empty(),
        _ => false,
    }
}

/// Block-style YAML from a `serde_json::Value`. A scalar or empty collection
/// renders inline (`42`, `[]`); a non-empty collection renders as lines that
/// each start with `indent` levels of two spaces, no leading or trailing
/// blank. A block item's first line goes right after its `- ` (the dash
/// takes the place of that line's own indent), and a key whose value is a
/// block ends its line at the `:`, so no line carries trailing whitespace.
fn format_as_yaml(value: &serde_json::Value, indent: usize) -> String {
    let prefix = "  ".repeat(indent);
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => yaml_scalar(s),
        serde_json::Value::Array(arr) if arr.is_empty() => "[]".to_string(),
        serde_json::Value::Object(map) if map.is_empty() => "{}".to_string(),
        serde_json::Value::Array(arr) => {
            let item_prefix = "  ".repeat(indent + 1);
            arr.iter()
                .map(|item| {
                    let rendered = format_as_yaml(item, indent + 1);
                    let first_line = rendered.strip_prefix(&item_prefix).unwrap_or(&rendered);
                    format!("{prefix}- {first_line}")
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
        serde_json::Value::Object(map) => map
            .iter()
            .map(|(key, val)| {
                // Keys can be attacker-controlled (e.g. RDAP `extra` flattened
                // map), so quote them under the same rules as scalar values.
                let key = yaml_scalar(key);
                if is_yaml_block(val) {
                    format!("{prefix}{key}:\n{}", format_as_yaml(val, indent + 1))
                } else {
                    format!("{prefix}{key}: {}", format_as_yaml(val, indent))
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

pub fn get_formatter(format: OutputFormat) -> Box<dyn OutputFormatter> {
    match format {
        OutputFormat::Human => Box::new(HumanFormatter::new()),
        OutputFormat::Json => Box::new(JsonFormatter::new()),
        OutputFormat::Yaml => Box::new(YamlFormatter::new()),
        OutputFormat::Markdown => Box::new(MarkdownFormatter::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_format_from_str() {
        assert_eq!(
            "human".parse::<OutputFormat>().unwrap(),
            OutputFormat::Human
        );
        assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!("yaml".parse::<OutputFormat>().unwrap(), OutputFormat::Yaml);
        assert_eq!("yml".parse::<OutputFormat>().unwrap(), OutputFormat::Yaml);
        assert_eq!("text".parse::<OutputFormat>().unwrap(), OutputFormat::Human);
        assert_eq!(
            "pretty".parse::<OutputFormat>().unwrap(),
            OutputFormat::Human
        );
        assert!("invalid".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn test_output_format_default() {
        assert_eq!(OutputFormat::default(), OutputFormat::Human);
    }

    #[test]
    fn test_get_formatter_returns_correct_type() {
        // Just verify we can get formatters without panicking
        let _ = get_formatter(OutputFormat::Human);
        let _ = get_formatter(OutputFormat::Json);
        let _ = get_formatter(OutputFormat::Yaml);
    }

    #[test]
    fn test_yaml_formatter_basic() {
        let formatter = YamlFormatter::new();
        let status = crate::status::StatusResponse::new("example.com".to_string());
        let output = formatter.format_status(&status);
        assert!(output.contains("example.com"));
        assert!(output.contains("domain"));
    }

    #[test]
    fn test_format_as_yaml_primitives() {
        assert_eq!(format_as_yaml(&serde_json::json!(null), 0), "null");
        assert_eq!(format_as_yaml(&serde_json::json!(true), 0), "true");
        assert_eq!(format_as_yaml(&serde_json::json!(42), 0), "42");
        assert_eq!(format_as_yaml(&serde_json::json!("hello"), 0), "hello");
    }

    #[test]
    fn test_format_as_yaml_array() {
        let output = format_as_yaml(&serde_json::json!([1, 2, 3]), 0);
        assert!(output.contains("- 1"));
        assert!(output.contains("- 2"));
        assert!(output.contains("- 3"));
    }

    #[test]
    fn yaml_is_clean_block_style_without_blank_or_trailing_space_lines() {
        use serde_json::json;
        // A top-level array used to start with a blank line, and an object
        // inside an array rendered as `- ` (trailing space) then its keys.
        let doc = format_as_yaml(
            &json!([
                {"name": "a", "ttl": 300},
                {"name": "b", "tags": ["x", "z"], "empty": [], "meta": {"k": "v"}},
                [1, 2]
            ]),
            0,
        );
        let expected = "\
- name: a
  ttl: 300
- empty: []
  meta:
    k: v
  name: b
  tags:
    - x
    - z
- - 1
  - 2";
        assert_eq!(doc, expected);
        for line in doc.lines() {
            assert!(!line.ends_with(' '), "trailing space: {line:?}");
        }

        let doc = format_as_yaml(&json!({"domain": "x", "records": [{"a": 1}]}), 0);
        assert_eq!(doc, "domain: x\nrecords:\n  - a: 1");
    }

    #[test]
    fn sanitize_line_strips_controls_and_folds_line_breaks() {
        // Bare C0/C1 controls (CR, backspace, BEL, C1 CSI 0x9B) could
        // overwrite or spoof rendered lines; newline/tab/U+2028 would forge
        // a row.
        assert_eq!(sanitize_line("a\rb\x08c\x07d\u{009b}e"), "abcde");
        assert_eq!(
            sanitize_line("line1\nline2\tcol\u{2028}x"),
            "line1 line2 col x"
        );
        // OSC terminated by ST (ESC \) and classic CSI are removed whole.
        assert_eq!(
            sanitize_line("\x1b]0;malicious title\x1b\\visible"),
            "visible"
        );
        assert_eq!(sanitize_line("\x1b[31mred\x1b[0m"), "red");
    }

    #[test]
    fn sanitize_line_drops_bidi_and_zero_width_format_chars() {
        // A right-to-left override (Trojan Source) or zero-width space
        // passed through, so remote text could read as something else.
        let trojan = "a\u{202E}b\u{2066}c\u{200B}d\u{FEFF}e\u{061C}f\u{200E}g\u{2069}";
        assert_eq!(sanitize_line(trojan), "abcdefg");
        // Ordinary non-ASCII text is kept.
        assert_eq!(sanitize_line("café — ü"), "café — ü");
    }

    #[test]
    fn expiry_phrase_is_one_wording_for_past_and_future() {
        assert_eq!(expiry_phrase(-5), "expired 5 days ago");
        assert_eq!(expiry_phrase(-1), "expired 1 day ago");
        assert_eq!(expiry_phrase(0), "expires in 0 days");
        assert_eq!(expiry_phrase(1), "expires in 1 day");
        assert_eq!(expiry_phrase(29), "expires in 29 days");
        assert_eq!(expiry_emphasis(-1), Emphasis::Bad);
        assert_eq!(expiry_emphasis(29), Emphasis::Bad);
        assert_eq!(expiry_emphasis(30), Emphasis::Caution);
        assert_eq!(expiry_emphasis(90), Emphasis::Good);
    }

    #[test]
    fn availability_label_covers_every_verdict_and_tolerates_others() {
        assert_eq!(availability_label("available").0, "AVAILABLE");
        assert_eq!(availability_label("likely_available").0, "MAY BE AVAILABLE");
        assert_eq!(availability_label("registered").0, "REGISTERED");
        assert_eq!(
            availability_label("likely_registered").0,
            "LIKELY REGISTERED"
        );
        assert_eq!(availability_label("unknown"), ("UNKNOWN", Emphasis::Bad));
        assert_eq!(availability_label("whatever"), ("UNKNOWN", Emphasis::Bad));
    }

    #[test]
    fn propagation_detail_names_a_lone_responder() {
        use crate::dns::{
            ConsensusValue, DnsRecord, DnsServer, DnsStatus, PropagationServerResult, RecordData,
            RecordType,
        };
        let answered = PropagationServerResult {
            server: DnsServer::new("Google", "8.8.8.8", "NA", "Google"),
            records: vec![DnsRecord {
                name: "example.com".into(),
                record_type: RecordType::A,
                ttl: 300,
                data: RecordData::A {
                    address: "1.2.3.4".into(),
                },
            }],
            response_time_ms: 12,
            success: true,
            error: None,
            status: Some(DnsStatus::NoError),
        };
        let result = PropagationResult {
            domain: "example.com".into(),
            record_type: RecordType::A,
            servers_checked: 2,
            servers_responding: 1,
            propagation_percentage: 100.0,
            results: vec![answered],
            consensus_values: vec![ConsensusValue::new(RecordType::A, "1.2.3.4")],
            inconsistencies: vec![],
            unreachable_servers: vec![],
            dnssec_validated: false,
            nameserver_details: None,
        };
        assert_eq!(
            propagation_detail(&result),
            "the one responding server answered"
        );
        // Markdown used to say "all 1 responding servers agree".
        let md = MarkdownFormatter::new().format_propagation(&result);
        assert!(md.contains("the one responding server answered"), "{md}");
    }

    #[test]
    fn dnssec_depth_notes_what_each_tier_does_not_verify() {
        assert_eq!(dnssec_depth(AuthenticationTier::Unsigned).1, None);
        let digest = dnssec_depth(AuthenticationTier::DigestOnly).1.unwrap();
        assert!(digest.contains("RRSIG signatures, validity periods"));
    }

    #[test]
    fn test_format_as_yaml_empty_collections() {
        assert_eq!(format_as_yaml(&serde_json::json!([]), 0), "[]");
        assert_eq!(format_as_yaml(&serde_json::json!({}), 0), "{}");
    }

    // --- #54: YAML scalar quoting hardening ----------------------------

    #[test]
    fn yaml_scalar_quoting_hardened() {
        use serde_json::json;
        let y = |s: &str| format_as_yaml(&json!(s), 0);

        // YAML 1.1 bool/null tokens must be quoted to stay strings.
        assert_eq!(y("No"), "\"No\"");
        assert_eq!(y("true"), "\"true\"");
        assert_eq!(y("null"), "\"null\"");
        assert_eq!(y("~"), "\"~\"");

        // Empty + leading/trailing whitespace.
        assert_eq!(y(""), "\"\"");
        assert_eq!(y(" leading"), "\" leading\"");
        assert_eq!(y("trailing "), "\"trailing \"");

        // Leading YAML indicator characters.
        for s in [
            "- dash", "@at", "*star", "[brk", "{brace", "#hash", "!bang", "&amp", "|pipe", ">gt",
            "%pct", "`tick", "?q", ",comma",
        ] {
            assert_eq!(
                y(s),
                format!("\"{s}\""),
                "must quote leading-indicator {s:?}"
            );
        }

        // Colon-space breaks a plain scalar.
        assert_eq!(y("key: value"), "\"key: value\"");

        // Control chars / ANSI are escaped, never emitted raw.
        assert_eq!(y("a\tb"), "\"a\\tb\"");
        assert_eq!(y("a\rb"), "\"a\\rb\"");
        assert_eq!(y("x\x1b[31m"), "\"x\\x1b[31m\"");

        // Safe plain scalars must NOT be over-quoted.
        assert_eq!(y("plain-value"), "plain-value");
        assert_eq!(y("has internal spaces"), "has internal spaces");
        assert_eq!(y("ns1.example.com"), "ns1.example.com");
    }

    #[test]
    fn yaml_quotes_strings_a_resolver_would_read_as_non_strings() {
        use serde_json::json;
        let y = |s: &str| format_as_yaml(&json!(s), 0);

        for s in [
            "+1.5555550100",        // WHOIS phone → float 1.55555501
            "292",                  // registrar IANA id string → int
            "0123",                 // YAML 1.1 octal → 83
            "1:20",                 // YAML 1.1 sexagesimal → 80
            "2024-01-15",           // date
            "2024-01-15T04:00:00Z", // RFC 3339 timestamp → datetime
            ".inf",
            ".NaN",
            "=",  // YAML 1.1 value key: PyYAML raises ConstructorError
            "<<", // merge key: PyYAML raises ConstructorError
            "y",  // YAML 1.1 single-letter bools, any case
            "N",
        ] {
            assert_eq!(y(s), format!("\"{s}\""), "must quote {s:?}");
        }

        // Hostnames and words stay plain; real JSON numbers are never quoted.
        assert_eq!(y("ns1.example.com"), "ns1.example.com");
        assert_eq!(y("yes-but-longer"), "yes-but-longer");
        assert_eq!(y("a=b"), "a=b");
        assert_eq!(format_as_yaml(&json!(292), 0), "292");
        assert_eq!(format_as_yaml(&json!(1.5), 0), "1.5");
    }

    #[test]
    fn yaml_escapes_unicode_line_breaks() {
        use serde_json::json;
        // U+2028/U+2029 aren't `char::is_control`, so they used to be emitted
        // raw — and a raw one (or U+0085) makes the whole document fail to
        // parse. They must be quoted and escaped with YAML's \L / \P / \N, in
        // values and in keys alike.
        let y = |s: &str| format_as_yaml(&json!(s), 0);
        assert_eq!(y("a\u{2028}b"), "\"a\\Lb\"");
        assert_eq!(y("a\u{2029}b"), "\"a\\Pb\"");
        assert_eq!(y("a\u{0085}b"), "\"a\\Nb\"");

        let doc = format_as_yaml(&json!({ "k\u{2028}ey": "v" }), 0);
        assert_eq!(doc, "\"k\\Ley\": v");
    }

    #[test]
    fn yaml_object_keys_with_significant_chars_are_quoted() {
        // Keys from attacker-controlled flattened maps (e.g. RDAP `extra`) must
        // be quoted too, or a key like "a\ninjected: true" forges structure.
        let doc = format_as_yaml(&serde_json::json!({ "a\nb": "v" }), 0);
        assert!(
            doc.contains("\"a\\nb\""),
            "malicious key must be quoted/escaped: {doc:?}"
        );
        // Normal identifier keys stay unquoted.
        let doc = format_as_yaml(&serde_json::json!({ "domain": "x" }), 0);
        assert!(
            doc.starts_with("domain:"),
            "plain key must not be quoted: {doc:?}"
        );
    }
}
