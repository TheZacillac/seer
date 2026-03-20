use super::OutputFormatter;
use crate::dns::{DnsRecord, FollowIteration, FollowResult, PropagationResult};
use crate::lookup::LookupResult;
use crate::rdap::RdapResponse;
use crate::status::StatusResponse;
use crate::whois::WhoisResponse;

pub struct JsonFormatter {
    pretty: bool,
}

impl Default for JsonFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl JsonFormatter {
    pub fn new() -> Self {
        Self { pretty: true }
    }

    pub fn compact(mut self) -> Self {
        self.pretty = false;
        self
    }

    fn to_json<T: serde::Serialize + ?Sized>(&self, value: &T) -> String {
        if self.pretty {
            serde_json::to_string_pretty(value)
                .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
        } else {
            serde_json::to_string(value).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
        }
    }
}

impl OutputFormatter for JsonFormatter {
    fn format_whois(&self, response: &WhoisResponse) -> String {
        self.to_json(response)
    }

    fn format_rdap(&self, response: &RdapResponse) -> String {
        self.to_json(response)
    }

    fn format_dns(&self, records: &[DnsRecord]) -> String {
        self.to_json(records)
    }

    fn format_propagation(&self, result: &PropagationResult) -> String {
        self.to_json(result)
    }

    fn format_lookup(&self, result: &LookupResult) -> String {
        self.to_json(result)
    }

    fn format_status(&self, response: &StatusResponse) -> String {
        self.to_json(response)
    }

    fn format_follow_iteration(&self, iteration: &FollowIteration) -> String {
        self.to_json(iteration)
    }

    fn format_follow(&self, result: &FollowResult) -> String {
        self.to_json(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::RecordType;
    use crate::status::StatusResponse;

    #[test]
    fn test_json_format_status() {
        let response = StatusResponse::new("example.com".to_string());
        let formatter = JsonFormatter::new();
        let output = formatter.format_status(&response);
        assert!(output.contains("example.com"));
        assert!(output.contains("domain"));
    }

    #[test]
    fn test_json_compact() {
        let response = StatusResponse::new("example.com".to_string());
        let formatter = JsonFormatter::new().compact();
        let output = formatter.format_status(&response);
        // Compact format should not have newlines within the JSON
        assert!(!output.contains("\n  "));
    }

    #[test]
    fn test_json_format_dns_records() {
        let records = vec![crate::dns::DnsRecord {
            name: "example.com".to_string(),
            record_type: RecordType::A,
            ttl: 300,
            data: crate::dns::RecordData::A {
                address: "93.184.216.34".to_string(),
            },
        }];
        let formatter = JsonFormatter::new();
        let output = formatter.format_dns(&records);
        assert!(output.contains("93.184.216.34"));
        assert!(output.contains("\"A\""));
    }
}
