mod grouping;
mod human;
mod json;
mod markdown;

pub use human::HumanFormatter;
pub use json::JsonFormatter;
pub use markdown::MarkdownFormatter;

use serde::{Deserialize, Serialize};

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

pub trait OutputFormatter {
    fn format_whois(&self, response: &crate::whois::WhoisResponse) -> String;
    fn format_rdap(&self, response: &crate::rdap::RdapResponse) -> String;
    fn format_dns(&self, records: &[crate::dns::DnsRecord]) -> String;
    fn format_propagation(&self, result: &crate::dns::PropagationResult) -> String;
    fn format_lookup(&self, result: &crate::lookup::LookupResult) -> String;
    fn format_status(&self, response: &crate::status::StatusResponse) -> String;
    fn format_follow_iteration(&self, iteration: &crate::dns::FollowIteration) -> String;
    fn format_follow(&self, result: &crate::dns::FollowResult) -> String;
    fn format_availability(&self, result: &crate::availability::AvailabilityResult) -> String;
    fn format_dnssec(&self, report: &crate::dns::DnssecReport) -> String;
    fn format_tld(&self, info: &crate::tld::TldInfo) -> String;
    fn format_dns_comparison(&self, comparison: &crate::dns::DnsComparison) -> String;
    fn format_subdomains(&self, result: &crate::subdomains::SubdomainResult) -> String;
    fn format_diff(&self, diff: &crate::diff::DomainDiff) -> String;
    fn format_ssl(&self, report: &crate::ssl::SslReport) -> String;
    fn format_watch(&self, report: &crate::watchlist::WatchReport) -> String;
    fn format_domain_info(&self, info: &crate::domain_info::DomainInfo) -> String;
    fn format_drift(&self, report: &crate::drift::DriftReport) -> String;
    fn format_posture(&self, posture: &crate::posture::EmailPosture) -> String;
    fn format_caa(&self, policy: &crate::caa::CaaPolicy) -> String;
    fn format_confusables(&self, report: &crate::confusables::ConfusableReport) -> String;
    fn format_subdomain_classification(
        &self,
        result: &crate::subdomains::SubdomainClassification,
    ) -> String;
}

/// YAML output formatter that converts data structures to YAML format.
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

impl Default for YamlFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputFormatter for YamlFormatter {
    fn format_whois(&self, response: &crate::whois::WhoisResponse) -> String {
        self.to_yaml_value(response)
    }
    fn format_rdap(&self, response: &crate::rdap::RdapResponse) -> String {
        self.to_yaml_value(response)
    }
    fn format_dns(&self, records: &[crate::dns::DnsRecord]) -> String {
        self.to_yaml_value(records)
    }
    fn format_propagation(&self, result: &crate::dns::PropagationResult) -> String {
        self.to_yaml_value(result)
    }
    fn format_lookup(&self, result: &crate::lookup::LookupResult) -> String {
        self.to_yaml_value(result)
    }
    fn format_status(&self, response: &crate::status::StatusResponse) -> String {
        self.to_yaml_value(response)
    }
    fn format_follow_iteration(&self, iteration: &crate::dns::FollowIteration) -> String {
        self.to_yaml_value(iteration)
    }
    fn format_follow(&self, result: &crate::dns::FollowResult) -> String {
        self.to_yaml_value(result)
    }
    fn format_availability(&self, result: &crate::availability::AvailabilityResult) -> String {
        self.to_yaml_value(result)
    }
    fn format_dnssec(&self, report: &crate::dns::DnssecReport) -> String {
        self.to_yaml_value(report)
    }
    fn format_tld(&self, info: &crate::tld::TldInfo) -> String {
        self.to_yaml_value(info)
    }
    fn format_dns_comparison(&self, comparison: &crate::dns::DnsComparison) -> String {
        self.to_yaml_value(comparison)
    }
    fn format_subdomains(&self, result: &crate::subdomains::SubdomainResult) -> String {
        self.to_yaml_value(result)
    }
    fn format_diff(&self, diff: &crate::diff::DomainDiff) -> String {
        self.to_yaml_value(diff)
    }
    fn format_ssl(&self, report: &crate::ssl::SslReport) -> String {
        self.to_yaml_value(report)
    }
    fn format_watch(&self, report: &crate::watchlist::WatchReport) -> String {
        self.to_yaml_value(report)
    }
    fn format_domain_info(&self, info: &crate::domain_info::DomainInfo) -> String {
        self.to_yaml_value(info)
    }
    fn format_drift(&self, report: &crate::drift::DriftReport) -> String {
        self.to_yaml_value(report)
    }
    fn format_posture(&self, posture: &crate::posture::EmailPosture) -> String {
        self.to_yaml_value(posture)
    }
    fn format_caa(&self, policy: &crate::caa::CaaPolicy) -> String {
        self.to_yaml_value(policy)
    }
    fn format_confusables(&self, report: &crate::confusables::ConfusableReport) -> String {
        self.to_yaml_value(report)
    }
    fn format_subdomain_classification(
        &self,
        result: &crate::subdomains::SubdomainClassification,
    ) -> String {
        self.to_yaml_value(result)
    }
}

/// Returns true when a string cannot be emitted as a YAML *plain* scalar and
/// must be double-quoted. Covers the cases the old `contains('\n'|':'|'#')`
/// predicate missed (issue #54): empty strings, leading/trailing whitespace,
/// any control character, a leading YAML indicator character, an interior
/// `": "` / trailing `:` / `" #"` (which break a plain scalar), and the YAML
/// 1.1 bool/null tokens (`null`, `~`, `true`, `false`, `yes`, `no`, `on`,
/// `off`) which would otherwise round-trip as the wrong type.
fn yaml_needs_quoting(s: &str) -> bool {
    if s.is_empty() || s != s.trim() {
        return true;
    }
    if s.chars().any(|c| c.is_control()) {
        return true;
    }
    if matches!(
        s.to_ascii_lowercase().as_str(),
        "null" | "~" | "true" | "false" | "yes" | "no" | "on" | "off"
    ) {
        return true;
    }
    // A leading YAML indicator char makes the whole scalar non-plain.
    if let Some(first) = s.chars().next() {
        if "-?:,[]{}#&*!|>'\"%@`".contains(first) {
            return true;
        }
    }
    s.contains(": ") || s.ends_with(':') || s.contains(" #")
}

/// Emits `s` as a YAML double-quoted scalar, escaping `"`, `\`, and control
/// characters (so attacker ANSI/control bytes can't reach the terminal or
/// break the document).
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
