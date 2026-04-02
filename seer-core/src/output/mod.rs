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
}

/// Simple YAML-like formatter from serde_json::Value.
fn format_as_yaml(value: &serde_json::Value, indent: usize) -> String {
    let prefix = "  ".repeat(indent);
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => {
            if s.contains('\n') || s.contains(':') || s.contains('#') {
                format!("\"{}\"", s.replace('"', "\\\""))
            } else {
                s.clone()
            }
        }
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
                out.push_str(key);
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
}
