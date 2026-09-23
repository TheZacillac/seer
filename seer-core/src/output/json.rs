use super::OutputFormatter;

/// Pretty-printed JSON output formatter.
#[derive(Default)]
pub struct JsonFormatter;

impl JsonFormatter {
    pub fn new() -> Self {
        Self
    }

    fn to_json<T: serde::Serialize + ?Sized>(&self, value: &T) -> String {
        serde_json::to_string_pretty(value).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
    }
}

with_report_methods!(impl_serializing!(JsonFormatter, to_json;));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{DnsRecord, RecordType};
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
