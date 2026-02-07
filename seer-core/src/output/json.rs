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
