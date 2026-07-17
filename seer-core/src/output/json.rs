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

    fn format_availability(&self, result: &crate::availability::AvailabilityResult) -> String {
        self.to_json(result)
    }

    fn format_dnssec(&self, report: &crate::dns::DnssecReport) -> String {
        self.to_json(report)
    }

    fn format_delegation(&self, report: &crate::dns::DelegationReport) -> String {
        self.to_json(report)
    }

    fn format_tld(&self, info: &crate::tld::TldInfo) -> String {
        self.to_json(info)
    }

    fn format_dns_comparison(&self, comparison: &crate::dns::DnsComparison) -> String {
        self.to_json(comparison)
    }

    fn format_subdomains(&self, result: &crate::subdomains::SubdomainResult) -> String {
        self.to_json(result)
    }

    fn format_diff(&self, diff: &crate::diff::DomainDiff) -> String {
        self.to_json(diff)
    }

    fn format_ssl(&self, report: &crate::ssl::SslReport) -> String {
        self.to_json(report)
    }

    fn format_watch(&self, report: &crate::watchlist::WatchReport) -> String {
        self.to_json(report)
    }

    fn format_domain_info(&self, info: &crate::domain_info::DomainInfo) -> String {
        self.to_json(info)
    }
    fn format_drift(&self, report: &crate::drift::DriftReport) -> String {
        self.to_json(report)
    }
    fn format_posture(&self, posture: &crate::posture::EmailPosture) -> String {
        self.to_json(posture)
    }
    fn format_caa(&self, policy: &crate::caa::CaaPolicy) -> String {
        self.to_json(policy)
    }
    fn format_confusables(&self, report: &crate::confusables::ConfusableReport) -> String {
        self.to_json(report)
    }
    fn format_subdomain_classification(
        &self,
        result: &crate::subdomains::SubdomainClassification,
    ) -> String {
        self.to_json(result)
    }

    fn format_subdomain_baseline_diff(
        &self,
        report: &crate::subdomains::SubdomainBaselineDiff,
    ) -> String {
        self.to_json(report)
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
        let records = vec![DnsRecord {
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
