//! Parser for .pl domains (NASK format).
//!
//! NASK's body is `label: value` lines the generic parser mostly reads, with
//! two exceptions handled here:
//!
//! - The domain's expiry is `renewal date:`. The reply can also carry an
//!   `option expiration date:` — the expiry of a registration *option* on the
//!   name, not of the domain — which the generic `Expiration Date` label
//!   matched.
//! - `nameservers:` holds the first host and continues on indented lines,
//!   the last one possibly followed by glue in brackets.
//!
//! Example NASK response:
//! ```text
//! DOMAIN NAME:                    nic.pl
//! nameservers:                    ns-01.hyperone-dns.com.
//!                                 ns-01.hyperone-dns.pl. [62.181.3.100]
//! created:                        1998.03.11 12:00:00
//! last modified:                  2021.02.12 13:35:25
//! renewal date:                   2027.03.10 13:00:00
//!
//! option created:                 2017.01.31 19:01:09
//! option expiration date:         2029.01.31 19:01:09
//! ```

use std::sync::LazyLock;

use regex::Regex;

use super::{push_bounded, MAX_NAMESERVERS};
use crate::whois::parser::{
    extract_field_with_patterns, line_field_patterns, parse_date, WhoisResponse,
};

static RENEWAL_DATE: LazyLock<Vec<Regex>> =
    LazyLock::new(|| line_field_patterns(&["renewal date"]));

/// TLDs this parser handles.
pub(super) const TLDS: &[&str] = &["pl"];

/// Parses .pl domains: the generic parser plus NASK's expiry and
/// multi-line nameserver list.
pub(super) fn parse(domain: &str, server: &str, raw: &str) -> WhoisResponse {
    let mut response = WhoisResponse::parse_internal(domain, server, raw);
    // `renewal date` is the only domain expiry NASK prints; without it the
    // reply has none (an option's expiry must not stand in).
    response.expiration_date =
        extract_field_with_patterns(raw, &RENEWAL_DATE).and_then(|v| parse_date(&v));
    let nameservers = nameservers(raw);
    if !nameservers.is_empty() {
        response.nameservers = nameservers;
    }
    response
}

/// Hosts from the `nameservers:` line and the indented lines under it.
fn nameservers(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut lines = raw.lines();
    let Some(first) = lines.find_map(|l| {
        let (label, value) = l.split_once(':')?;
        label
            .trim()
            .eq_ignore_ascii_case("nameservers")
            .then_some(value)
    }) else {
        return out;
    };
    let continuation = lines.take_while(|l| l.starts_with([' ', '\t']) && !l.trim().is_empty());
    for value in std::iter::once(first).chain(continuation) {
        // Glue follows the host: `ns-01.hyperone-dns.pl. [62.181.3.100]`.
        if let Some(host) = value.split_whitespace().next() {
            let host = host.trim_end_matches('.').to_lowercase();
            push_bounded(&mut out, host, MAX_NAMESERVERS);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live whois.dns.pl reply for nic.pl (2026-10-13), trimmed; CRLF as served.
    // `concat!` rather than `\` continuations, which would strip the
    // indentation the nameserver continuation lines depend on.
    const NIC_PL: &str = concat!(
        "DOMAIN NAME:                    nic.pl\r\n",
        "registrant type:                organization\r\n",
        "nameservers:                    ns-01.hyperone-dns.com. \r\n",
        "                                ns-01.hyperone-dns.net. \r\n",
        "                                ns-01.hyperone-dns.pl. [62.181.3.100]\r\n",
        "created:                        1998.03.11 12:00:00\r\n",
        "last modified:                  2021.02.12 13:35:25\r\n",
        "renewal date:                   2027.03.10 13:00:00\r\n",
        "\r\n",
        "option created:                 2017.01.31 19:01:09\r\n",
        "option expiration date:         2029.01.31 19:01:09\r\n",
        "\r\n",
        "dnssec:                         Unsigned\r\n",
        "\r\n",
        "REGISTRAR:\r\n",
        "Warsaw Data Center sp. z o.o.\r\n",
    );

    fn ymd(d: Option<chrono::DateTime<chrono::Utc>>) -> Option<String> {
        d.map(|d| d.format("%Y-%m-%d").to_string())
    }

    #[test]
    fn expiry_is_the_renewal_date_not_the_option_expiry() {
        let r = parse("nic.pl", "whois.dns.pl", NIC_PL);
        assert_eq!(ymd(r.expiration_date).as_deref(), Some("2027-03-10"));
    }

    #[test]
    fn option_expiry_alone_is_not_a_domain_expiry() {
        let raw = "DOMAIN NAME: example.pl\noption expiration date: 2029.01.31 19:01:09\n";
        let r = parse("example.pl", "whois.dns.pl", raw);
        assert!(r.expiration_date.is_none());
    }

    #[test]
    fn multi_line_nameservers_are_all_read() {
        let r = parse("nic.pl", "whois.dns.pl", NIC_PL);
        assert_eq!(
            r.nameservers,
            vec![
                "ns-01.hyperone-dns.com",
                "ns-01.hyperone-dns.net",
                "ns-01.hyperone-dns.pl"
            ]
        );
    }

    #[test]
    fn generic_fields_still_parse() {
        let r = parse("nic.pl", "whois.dns.pl", NIC_PL);
        assert_eq!(ymd(r.creation_date).as_deref(), Some("1998-03-11"));
        assert_eq!(ymd(r.updated_date).as_deref(), Some("2021-02-12"));
        assert_eq!(
            r.registrar.as_deref(),
            Some("Warsaw Data Center sp. z o.o.")
        );
    }
}
