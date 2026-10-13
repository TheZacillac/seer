//! Parser for .cn domains (CNNIC format).
//!
//! CNNIC's body is plain `Label: value` lines the generic parser reads,
//! except for the dates: `Registration Time` and `Expiration Time` carry no
//! zone and are China Standard Time (UTC+8), so they are read here and
//! converted rather than taken as UTC by the generic tables.
//!
//! Example CNNIC response:
//! ```text
//! Domain Name: example.cn
//! ROID: 20051104s10001s36905914-cn
//! Domain Status: clientTransferProhibited
//! Registrant: Example Registrant
//! Registrant Contact Email: hostmaster@example.cn
//! Sponsoring Registrar: Example Registrar Co., Ltd.
//! Name Server: dns.example.net
//! Registration Time: 2005-11-04 00:17:02
//! Expiration Time: 2026-11-04 00:17:02
//! DNSSEC: unsigned
//! ```

use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use regex::Regex;

use crate::whois::parser::{
    extract_field_with_patterns, line_field_patterns, normalize_label_padding,
    parse_fixed_offset_date, WhoisResponse,
};

static REGISTRATION_TIME: LazyLock<Vec<Regex>> =
    LazyLock::new(|| line_field_patterns(&["Registration Time"]));
static EXPIRATION_TIME: LazyLock<Vec<Regex>> =
    LazyLock::new(|| line_field_patterns(&["Expiration Time"]));

/// China Standard Time, UTC+8.
const CST_OFFSET_HOURS: i64 = 8;

/// TLDs this parser handles: .cn, .中国 and .中國.
pub(super) const TLDS: &[&str] = &["cn", "xn--fiqs8s", "xn--fiqz9s"];

/// Parses .cn domains: the generic parser plus CNNIC's CST dates.
pub(super) fn parse(domain: &str, server: &str, raw: &str) -> WhoisResponse {
    let mut response = WhoisResponse::parse_internal(domain, server, raw);
    let normalized = normalize_label_padding(raw);
    if let Some(date) = cnnic_date(&normalized, &REGISTRATION_TIME) {
        response.creation_date = Some(date);
    }
    if let Some(date) = cnnic_date(&normalized, &EXPIRATION_TIME) {
        response.expiration_date = Some(date);
    }
    response
}

fn cnnic_date(raw: &str, patterns: &[Regex]) -> Option<DateTime<Utc>> {
    let value = extract_field_with_patterns(raw, patterns)?;
    parse_fixed_offset_date(&value, "%Y-%m-%d", CST_OFFSET_HOURS)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Domain Name: homeview.cn\n\
        ROID: 20051104s10001s36905914-cn\n\
        Domain Status: clientTransferProhibited\n\
        Registrant: 刘记保\n\
        Registrant Contact Email: pem2008@126.com\n\
        Sponsoring Registrar: 厦门易名科技股份有限公司\n\
        Name Server: dns.goyes.net\n\
        Name Server: dns2.goyes.net\n\
        Registration Time: 2005-11-04 00:17:02\n\
        Expiration Time: 2026-11-04 00:17:02\n\
        DNSSEC: unsigned\n";

    fn ymd_hms(date: Option<DateTime<Utc>>) -> Option<String> {
        date.map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
    }

    #[test]
    fn registration_and_expiration_times_are_read_as_utc_plus_8() {
        let r = parse("homeview.cn", "whois.cnnic.cn", SAMPLE);
        // 00:17:02 CST == 16:17:02 UTC the previous day.
        assert_eq!(
            ymd_hms(r.creation_date).as_deref(),
            Some("2005-11-03 16:17:02")
        );
        assert_eq!(
            ymd_hms(r.expiration_date).as_deref(),
            Some("2026-11-03 16:17:02")
        );
    }

    #[test]
    fn generic_fields_still_parse() {
        let r = parse("homeview.cn", "whois.cnnic.cn", SAMPLE);
        assert_eq!(r.registrar.as_deref(), Some("厦门易名科技股份有限公司"));
        assert_eq!(r.registrant.as_deref(), Some("刘记保"));
        assert_eq!(r.registrant_email.as_deref(), Some("pem2008@126.com"));
        assert_eq!(r.nameservers, vec!["dns.goyes.net", "dns2.goyes.net"]);
        assert_eq!(r.status, vec!["clientTransferProhibited"]);
        assert_eq!(r.dnssec.as_deref(), Some("unsigned"));
    }

    #[test]
    fn crlf_body_parses_like_lf() {
        let crlf = SAMPLE.replace('\n', "\r\n");
        let r = parse("homeview.cn", "whois.cnnic.cn", &crlf);
        assert_eq!(
            ymd_hms(r.expiration_date).as_deref(),
            Some("2026-11-03 16:17:02")
        );
        assert_eq!(r.registrant_email.as_deref(), Some("pem2008@126.com"));
    }

    #[test]
    fn empty_first_label_does_not_hide_a_later_value() {
        let raw = "Expiration Time: \r\nExpiration Time: 2026-11-04 00:17:02\r\n";
        let r = parse("example.cn", "whois.cnnic.cn", raw);
        assert_eq!(
            ymd_hms(r.expiration_date).as_deref(),
            Some("2026-11-03 16:17:02")
        );
    }

    #[test]
    fn padded_label_is_read() {
        let raw = "Registration Time   : 2005-11-04 00:17:02\n";
        let r = parse("example.cn", "whois.cnnic.cn", raw);
        assert_eq!(
            ymd_hms(r.creation_date).as_deref(),
            Some("2005-11-03 16:17:02")
        );
    }

    #[test]
    fn date_only_value_is_kept_as_that_day() {
        let raw = "Expiration Time: 2026-11-04\n";
        let r = parse("example.cn", "whois.cnnic.cn", raw);
        assert_eq!(
            ymd_hms(r.expiration_date).as_deref(),
            Some("2026-11-04 00:00:00")
        );
    }

    #[test]
    fn placeholder_email_is_not_stored() {
        let raw = "Registrant Contact Email: Please query the RDDS service of the \
                   Registrar of Record for information on how to contact the Registrant.\n";
        let r = parse("example.cn", "whois.cnnic.cn", raw);
        assert_eq!(r.registrant_email, None);
    }
}
