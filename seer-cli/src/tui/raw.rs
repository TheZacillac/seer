//! Raw-output serialization: reuse seer-core's formatters so `r` / `:set
//! output …` produce the exact same text as `seer --format …`.
use seer_core::output::{get_formatter, OutputFormat};

use crate::tui::action::LensData;

pub fn serialize(data: &LensData, format: OutputFormat) -> String {
    let fmt = get_formatter(format);
    match data {
        LensData::Overview(r) => fmt.format_lookup(r),
        LensData::Whois(w) => fmt.format_whois(w),
        LensData::Rdap(r) => fmt.format_rdap(r),
        LensData::Dns(records) => fmt.format_dns(records),
        LensData::Ssl(s) => fmt.format_ssl(s),
        LensData::Status(s) => fmt.format_status(s),
        LensData::Prop(p) => fmt.format_propagation(p),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seer_core::dns::{RecordData, RecordType};
    use seer_core::DnsRecord;

    #[test]
    fn serializes_dns_as_json() {
        let data = LensData::Dns(vec![DnsRecord {
            name: "example.com".into(),
            record_type: RecordType::A,
            ttl: 300,
            data: RecordData::A { address: "1.2.3.4".into() },
        }]);
        let out = serialize(&data, OutputFormat::Json);
        assert!(out.contains("1.2.3.4"));
        assert!(out.trim_start().starts_with('['));
    }
}
