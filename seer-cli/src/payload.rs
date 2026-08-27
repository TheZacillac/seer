//! Interface-agnostic result payload: one enum over every formatter-backed
//! seer-core result type, shared by the TUI (raw view / `y` copy) and the
//! REPL (`copy` command). Serialization reuses seer-core's formatters so
//! copied text matches `seer --format …` exactly.
use seer_core::output::{get_formatter, OutputFormat};

#[derive(Debug, Clone)]
pub enum Payload {
    Overview(Box<seer_core::LookupResult>),
    Whois(Box<seer_core::WhoisResponse>),
    Rdap(Box<seer_core::RdapResponse>),
    Dns(Vec<seer_core::DnsRecord>),
    Ssl(Box<seer_core::SslReport>),
    Status(Box<seer_core::StatusResponse>),
    Prop(Box<seer_core::PropagationResult>),
    Reverse(Vec<seer_core::DnsRecord>),
    Avail(Box<seer_core::AvailabilityResult>),
    Tld(Box<seer_core::TldInfo>),
    Dnssec(Box<seer_core::DnssecReport>),
    Compare(Box<seer_core::DnsComparison>),
    Diff(Box<seer_core::DomainDiff>),
    Watch(Box<seer_core::WatchReport>),
    History(Vec<seer_core::HistoryEntry>),
    Subdomains(Box<seer_core::SubdomainResult>),
    Info(Box<seer_core::DomainInfo>),
    Drift(Box<seer_core::DriftReport>),
    Posture(Box<seer_core::EmailPosture>),
    Headers(Box<seer_core::HeaderReport>),
    Takeover(Box<seer_core::TakeoverReport>),
    Caa(Box<seer_core::CaaPolicy>),
    Confusables(Box<seer_core::ConfusableReport>),
    /// Unlike the others this has no `OutputFormatter` method — doctor reports
    /// render through `crate::render_doctor_report`, the same helper the CLI
    /// and REPL print with. Carried here anyway so `copy` after `doctor`
    /// copies the doctor report instead of silently copying whatever ran
    /// before it.
    Doctor(Box<seer_core::doctor::DoctorReport>),
}

impl Payload {
    /// Short lowercase label for user-facing messages ("copied whois …").
    pub fn kind(&self) -> &'static str {
        match self {
            Payload::Overview(_) => "lookup",
            Payload::Whois(_) => "whois",
            Payload::Rdap(_) => "rdap",
            Payload::Dns(_) => "dns",
            Payload::Ssl(_) => "ssl",
            Payload::Status(_) => "status",
            Payload::Prop(_) => "propagation",
            Payload::Reverse(_) => "reverse",
            Payload::Avail(_) => "availability",
            Payload::Tld(_) => "tld",
            Payload::Dnssec(_) => "dnssec",
            Payload::Compare(_) => "compare",
            Payload::Diff(_) => "diff",
            Payload::Watch(_) => "watch",
            Payload::History(_) => "history",
            Payload::Subdomains(_) => "subdomains",
            Payload::Info(_) => "info",
            Payload::Drift(_) => "drift",
            Payload::Posture(_) => "posture",
            Payload::Headers(_) => "headers",
            Payload::Takeover(_) => "takeover",
            Payload::Caa(_) => "caa",
            Payload::Confusables(_) => "confusables",
            Payload::Doctor(_) => "doctor",
        }
    }
}

pub fn serialize(data: &Payload, format: OutputFormat) -> String {
    let fmt = get_formatter(format);
    match data {
        Payload::Overview(r) => fmt.format_lookup(r),
        Payload::Whois(w) => fmt.format_whois(w),
        Payload::Rdap(r) => fmt.format_rdap(r),
        Payload::Dns(records) => fmt.format_dns(records),
        Payload::Ssl(s) => fmt.format_ssl(s),
        Payload::Status(s) => fmt.format_status(s),
        Payload::Prop(p) => fmt.format_propagation(p),
        Payload::Reverse(records) => fmt.format_dns(records),
        Payload::Avail(a) => fmt.format_availability(a),
        Payload::Tld(t) => fmt.format_tld(t),
        Payload::Dnssec(r) => fmt.format_dnssec(r),
        Payload::Compare(c) => fmt.format_dns_comparison(c),
        Payload::Diff(d) => fmt.format_diff(d),
        Payload::Watch(w) => fmt.format_watch(w),
        Payload::History(_) => "history (raw view not applicable)".to_string(),
        Payload::Subdomains(s) => fmt.format_subdomains(s),
        Payload::Info(i) => fmt.format_domain_info(i),
        Payload::Drift(d) => fmt.format_drift(d),
        Payload::Posture(p) => fmt.format_posture(p),
        Payload::Headers(h) => fmt.format_headers(h),
        Payload::Takeover(t) => fmt.format_takeover(t),
        Payload::Caa(c) => fmt.format_caa(c),
        Payload::Confusables(c) => fmt.format_confusables(c),
        // No formatter method exists for doctor reports; reuse the shared
        // renderer so copied text matches what `seer doctor --format …` prints.
        Payload::Doctor(r) => crate::render_doctor_report(r, format),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seer_core::dns::{RecordData, RecordType};
    use seer_core::DnsRecord;

    #[test]
    fn serializes_dns_as_json() {
        let data = Payload::Dns(vec![DnsRecord {
            name: "example.com".into(),
            record_type: RecordType::A,
            ttl: 300,
            data: RecordData::A {
                address: "1.2.3.4".into(),
            },
        }]);
        let out = serialize(&data, OutputFormat::Json);
        assert!(out.contains("1.2.3.4"));
        assert!(out.trim_start().starts_with('['));
    }

    #[test]
    fn serializes_dns_as_markdown() {
        let data = Payload::Dns(vec![DnsRecord {
            name: "example.com".into(),
            record_type: RecordType::A,
            ttl: 300,
            data: RecordData::A {
                address: "1.2.3.4".into(),
            },
        }]);
        let out = serialize(&data, OutputFormat::Markdown);
        assert!(out.contains("1.2.3.4"));
        assert!(
            out.contains('#') || out.contains('|'),
            "expected markdown structure"
        );
    }

    #[test]
    fn serializes_new_caa_variant() {
        let policy = seer_core::CaaPolicy {
            records: vec![],
            effective_domain: None,
            has_policy: false,
            issuer_match: None,
            iodef: vec![],
            wildcard_note: None,
            note: "no CAA policy found".into(),
        };
        let data = Payload::Caa(Box::new(policy));
        let out = serialize(&data, OutputFormat::Markdown);
        assert!(!out.is_empty());
    }

    #[test]
    fn kind_labels_are_lowercase() {
        let data = Payload::Dns(vec![]);
        assert_eq!(data.kind(), "dns");
    }
}
