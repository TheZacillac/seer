mod human;
mod json;

pub use human::HumanFormatter;
pub use json::JsonFormatter;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "human" | "text" | "pretty" => Ok(OutputFormat::Human),
            "json" => Ok(OutputFormat::Json),
            _ => Err(format!("Unknown output format: {}", s)),
        }
    }
}

pub trait OutputFormatter {
    fn format_whois(&self, response: &crate::whois::WhoisResponse) -> String;
    fn format_rdap(&self, response: &crate::rdap::RdapResponse) -> String;
    fn format_dns(&self, records: &[crate::dns::DnsRecord]) -> String;
    fn format_propagation(&self, result: &crate::dns::PropagationResult) -> String;
    fn format_lookup(&self, result: &crate::lookup::LookupResult) -> String;
}

pub fn get_formatter(format: OutputFormat) -> Box<dyn OutputFormatter> {
    match format {
        OutputFormat::Human => Box::new(HumanFormatter::new()),
        OutputFormat::Json => Box::new(JsonFormatter::new()),
    }
}
