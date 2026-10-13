//! Parser for .cn domains (CNNIC format).
//!
//! CNNIC's body is plain `Label: value` lines the generic parser reads,
//! except for three labels of its own: `Registration Time`, `Expiration
//! Time` and `Registrant Contact Email`. Its times carry no zone and are
//! China Standard Time (UTC+8), so they are converted here rather than read
//! as UTC.
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

use chrono::{DateTime, Duration, NaiveDateTime, Utc};

use crate::whois::parser::WhoisResponse;

static_regex! {
    REGISTRATION_TIME = r"(?im)^[ \t]*Registration Time:[ \t]*(.+)$";
    EXPIRATION_TIME = r"(?im)^[ \t]*Expiration Time:[ \t]*(.+)$";
    REGISTRANT_CONTACT_EMAIL = r"(?im)^[ \t]*Registrant Contact Email:[ \t]*(.+)$";
}

/// TLDs this parser handles: .cn, .中国 and .中國.
pub(super) const TLDS: &[&str] = &["cn", "xn--fiqs8s", "xn--fiqz9s"];

/// Parses .cn domains: the generic parser plus CNNIC's own labels.
pub(super) fn parse(domain: &str, server: &str, raw: &str) -> WhoisResponse {
    let mut response = WhoisResponse::parse_internal(domain, server, raw);
    if let Some(date) = capture(&REGISTRATION_TIME, raw).and_then(parse_cnnic_time) {
        response.creation_date = Some(date);
    }
    if let Some(date) = capture(&EXPIRATION_TIME, raw).and_then(parse_cnnic_time) {
        response.expiration_date = Some(date);
    }
    if response.registrant_email.is_none() {
        response.registrant_email = capture(&REGISTRANT_CONTACT_EMAIL, raw).map(str::to_string);
    }
    response
}

fn capture<'a>(pattern: &regex::Regex, raw: &'a str) -> Option<&'a str> {
    pattern
        .captures(raw)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().trim())
        .filter(|value| !value.is_empty())
}

/// Reads `YYYY-MM-DD HH:MM:SS` in China Standard Time as UTC.
fn parse_cnnic_time(value: &str) -> Option<DateTime<Utc>> {
    let local = NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S").ok()?;
    // Checked: the body is untrusted (port 43 is plaintext), and a year at
    // chrono's lower bound would make the plain `-` operator panic.
    local.and_utc().checked_sub_signed(Duration::hours(8))
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
    fn unparseable_or_extreme_times_are_none() {
        assert_eq!(parse_cnnic_time("not a date"), None);
        // Chrono's minimum: subtracting the offset must not underflow.
        let min = NaiveDateTime::MIN.format("%Y-%m-%d %H:%M:%S").to_string();
        assert_eq!(parse_cnnic_time(&min), None);
    }
}
