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
macro_rules! impl_forwarding {
    ($formatter:ty; $($method:ident($arg:ident: $ty:ty);)+) => {
        impl OutputFormatter for $formatter {
            $(fn $method(&self, $arg: &$ty) -> String {
                self.$method($arg)
            })+
        }
    };
}

mod contact;
mod grouping;
mod human;
mod json;
mod markdown;

pub use human::HumanFormatter;
pub use json::JsonFormatter;
pub use markdown::MarkdownFormatter;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Whole days from now until `when` — see [`crate::dates::days_until`]: an
/// expiry any time in the past is negative, so it never renders as
/// "expires in 0 days!".
fn days_until(when: DateTime<Utc>) -> i64 {
    crate::dates::days_until(when, Utc::now())
}

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
            Err(e) => format!("error: {}", e),
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

/// Simple YAML-like formatter from serde_json::Value.
fn format_as_yaml(value: &serde_json::Value, indent: usize) -> String {
    let prefix = "  ".repeat(indent);
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => yaml_scalar(s),
        serde_json::Value::Array(arr) => {
            if arr.is_empty() {
                return "[]".to_string();
            }
            let mut out = String::new();
            for item in arr {
                out.push('\n');
                out.push_str(&prefix);
                out.push_str("- ");
                let formatted = format_as_yaml(item, indent + 1);
                out.push_str(&formatted);
            }
            out
        }
        serde_json::Value::Object(map) => {
            if map.is_empty() {
                return "{}".to_string();
            }
            let mut out = String::new();
            let mut first = indent == 0;
            for (key, val) in map {
                if !first {
                    out.push('\n');
                }
                first = false;
                out.push_str(&prefix);
                // Keys can be attacker-controlled (e.g. RDAP `extra` flattened
                // map), so quote them under the same rules as scalar values.
                out.push_str(&yaml_scalar(key));
                out.push_str(": ");
                match val {
                    serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                        out.push_str(&format_as_yaml(val, indent + 1));
                    }
                    _ => {
                        out.push_str(&format_as_yaml(val, indent));
                    }
                }
            }
            out
        }
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
