//! Parser for .rs domains (RNIDS format).
//!
//! RNIDS's body is `Label: value` lines the generic parser reads, except the
//! nameservers: one `DNS: <host> - <glue>` line each. The generic tables
//! can't take a bare `DNS:` label, since Punktum (.dk) prints the domain
//! itself under it, so it is read here.
//!
//! Example RNIDS response (trimmed):
//! ```text
//! Domain name: nic.rs
//! Registration date: 10.03.2008 12:00:00
//! Expiration date: 10.03.2108 12:00:00
//!
//! DNS: a.nic.rs - 91.199.17.59
//! DNS: h.nic.rs - 91.199.17.60
//! ```

use std::sync::LazyLock;

use regex::Regex;

use super::{push_bounded, MAX_NAMESERVERS};
use crate::whois::parser::{line_field_patterns, WhoisResponse};

static DNS_LINE: LazyLock<Vec<Regex>> = LazyLock::new(|| line_field_patterns(&["DNS"]));

/// TLDs this parser handles: .rs and .срб.
pub(super) const TLDS: &[&str] = &["rs", "xn--90a3ac"];

/// Parses .rs domains: the generic parser plus RNIDS's `DNS:` lines.
pub(super) fn parse(domain: &str, server: &str, raw: &str) -> WhoisResponse {
    let mut response = WhoisResponse::parse_internal(domain, server, raw);
    let mut nameservers = Vec::new();
    for re in DNS_LINE.iter() {
        for caps in re.captures_iter(raw) {
            // Glue follows the host after ` - `.
            if let Some(host) = caps
                .get(1)
                .and_then(|m| m.as_str().split_whitespace().next())
            {
                let host = host.trim_end_matches('.').to_lowercase();
                push_bounded(&mut nameservers, host, MAX_NAMESERVERS);
            }
        }
    }
    if !nameservers.is_empty() {
        response.nameservers = nameservers;
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live whois.rnids.rs reply for nic.rs (2026-10-13), trimmed.
    const NIC_RS: &str = "Domain name: nic.rs\n\
Domain status: Active https://www.rnids.rs/en/domain-name-status-codes#Active\n\
Registration date: 10.03.2008 12:00:00\n\
Modification date: 17.03.2025 14:55:15\n\
Expiration date: 10.03.2108 12:00:00\n\
Registrar: Fondacija Registar nacionalnog internet domena Srbije\n\
\n\
DNS: a.nic.rs - 91.199.17.59\n\
DNS: h.nic.rs - 91.199.17.60\n\
DNS: c.nic.rs - 45.142.220.81\n\
DNS: l.nic.rs - 194.146.106.114\n\
\n\
DNSSEC signed: yes\n";

    #[test]
    fn dns_lines_are_the_nameservers_without_glue() {
        let r = parse("nic.rs", "whois.rnids.rs", NIC_RS);
        assert_eq!(
            r.nameservers,
            vec!["a.nic.rs", "h.nic.rs", "c.nic.rs", "l.nic.rs"]
        );
    }

    #[test]
    fn generic_fields_still_parse() {
        let r = parse("nic.rs", "whois.rnids.rs", NIC_RS);
        assert_eq!(r.status, vec!["Active"]);
        assert!(r.creation_date.is_some() && r.expiration_date.is_some());
        assert!(r.has_core_data());
    }
}
