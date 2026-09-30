use super::OutputFormatter;

/// Pretty-printed JSON output formatter.
#[derive(Default)]
pub struct JsonFormatter;

impl JsonFormatter {
    pub fn new() -> Self {
        Self
    }

    fn to_json<T: serde::Serialize + ?Sized>(&self, value: &T) -> String {
        // Built through `json!` so the error text is escaped: a message
        // carrying a quote must not yield invalid JSON.
        serde_json::to_string_pretty(value)
            .unwrap_or_else(|e| serde_json::json!({ "error": e.to_string() }).to_string())
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

    #[test]
    fn error_fallback_is_valid_json() {
        // A serializer error carrying a quote was interpolated raw into
        // `{"error": "…"}`, producing invalid JSON.
        struct Failing;
        impl serde::Serialize for Failing {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("bad \"value\"\n"))
            }
        }
        let out = JsonFormatter::new().to_json(&Failing);
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["error"], "bad \"value\"\n");
    }

    #[test]
    fn dig_and_trace_serialize_as_objects() {
        // `seer dig -q` / `--format json` emit the whole result object (status,
        // flags, answers, …), not the record list `format_dns` emits.
        use crate::dns::{DnsQueryResult, DnsStatus, DnsTrace};
        let result = DnsQueryResult {
            name: "gone.seer.test".to_string(),
            record_type: RecordType::A,
            server: None,
            answered_locally: false,
            status: DnsStatus::NxDomain,
            flags: Vec::new(),
            answers: Vec::new(),
            failed_types: Vec::new(),
            authority: Vec::new(),
            wildcard: None,
            query_time_ms: 7,
        };
        let json: serde_json::Value =
            serde_json::from_str(&JsonFormatter::new().format_dig(&result)).unwrap();
        assert_eq!(json["status"], "NXDOMAIN");
        assert_eq!(json["server"], serde_json::Value::Null);

        let trace = DnsTrace {
            name: "gone.seer.test".to_string(),
            record_type: RecordType::A,
            hops: Vec::new(),
            status: DnsStatus::NxDomain,
            answers: Vec::new(),
            error: Some("stopped".to_string()),
        };
        let json: serde_json::Value =
            serde_json::from_str(&JsonFormatter::new().format_dns_trace(&trace)).unwrap();
        assert_eq!(json["status"], "NXDOMAIN");
        assert_eq!(json["error"], "stopped");
    }
}
