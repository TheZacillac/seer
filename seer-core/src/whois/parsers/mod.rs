//! Registry-specific WHOIS response parsers.
//!
//! Registries use different formats, field names and date formats, so TLDs
//! with a known registry format get a dedicated parser. Each parser module
//! exposes its `TLDS` and a `parse` fn; [`parse`] dispatches on the domain's
//! second-level zone or TLD and falls back to the generic regex parser
//! ([`WhoisResponse::parse_internal`]) for everything else.

mod denic;
mod educause;
mod eis;
mod eurid;
mod isoc_il;
mod jprs;
mod kisa;
mod nic_it;
mod nic_lv;
mod nominet;
mod sidn;

use super::parser::WhoisResponse;

/// Maximum number of nameservers extracted from a single WHOIS response,
/// by every parser including the generic one. Real domains have ≤ 13 NS records (DNS
/// protocol limit); cap defensively so a hostile/malformed registry body of
/// distinct `nserver:` lines can't drive the O(n) `Vec::contains` dedup into
/// O(n²) CPU.
pub(crate) const MAX_NAMESERVERS: usize = 32;

/// Maximum number of domain-level status codes extracted by every parser,
/// including the generic one. EPP defines ~16 status values; a real domain rarely has
/// more than 5-6. Cap to bound CPU/memory against a hostile body.
pub(crate) const MAX_STATUSES: usize = 32;

/// Pushes `value` into `vec` when it is non-empty, below `cap`, and not already
/// present. The linear `Vec::contains` dedup is fine because `cap` bounds `n`,
/// so this stays O(cap) per call against adversarial input.
pub(crate) fn push_bounded(vec: &mut Vec<String>, value: String, cap: usize) {
    if !value.is_empty() && vec.len() < cap && !vec.contains(&value) {
        vec.push(value);
    }
}

/// A registry parser: `(domain, whois_server, raw) -> WhoisResponse`.
type ParseFn = fn(&str, &str, &str) -> WhoisResponse;

/// Every registry parser with the TLDs (or second-level zones) it handles.
const PARSERS: &[(&[&str], ParseFn)] = &[
    (denic::TLDS, denic::parse),       // .de
    (educause::TLDS, educause::parse), // .edu
    (eis::TLDS, eis::parse),           // .ee
    (eurid::TLDS, eurid::parse),       // .eu, .ею, .ευ
    (isoc_il::TLDS, isoc_il::parse),   // .il (co.il, org.il, …), .ישראל
    (jprs::TLDS, jprs::parse),         // .jp
    (kisa::TLDS, kisa::parse),         // .kr, .한국, .삼성
    (nic_it::TLDS, nic_it::parse),     // .it
    (nic_lv::TLDS, nic_lv::parse),     // .lv
    (nominet::TLDS, nominet::parse),   // .uk, .co.uk
    (sidn::TLDS, sidn::parse),         // .nl
];

/// Parses a WHOIS response with the registry parser for the domain's
/// second-level zone (e.g. `co.uk`) or TLD, falling back to the generic
/// parser when no registry parser claims it.
pub(crate) fn parse(domain: &str, server: &str, raw: &str) -> WhoisResponse {
    let zones: Vec<String> = [
        extract_second_level_tld(domain),
        super::get_tld(domain).map(str::to_lowercase),
    ]
    .into_iter()
    .flatten()
    .collect();
    for (tlds, parse) in PARSERS {
        if zones.iter().any(|zone| tlds.contains(&zone.as_str())) {
            return parse(domain, server, raw);
        }
    }
    WhoisResponse::parse_internal(domain, server, raw)
}

/// Extracts the second-level TLD from a domain name (e.g., "co.uk" from "example.co.uk").
fn extract_second_level_tld(domain: &str) -> Option<String> {
    let parts: Vec<&str> = domain.rsplit('.').collect();
    if parts.len() >= 3 {
        Some(format!(
            "{}.{}",
            parts[1].to_lowercase(),
            parts[0].to_lowercase()
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_second_level_tld() {
        assert_eq!(
            extract_second_level_tld("example.co.uk"),
            Some("co.uk".to_string())
        );
        assert_eq!(extract_second_level_tld("example.com"), None);
    }

    // Every parser sets `domain`, so the selection tests assert a field only
    // the expected parser produces from the given body.

    #[test]
    fn test_parser_registry_selects_denic_for_de() {
        let result = parse(
            "example.de",
            "whois.denic.de",
            "Domain: example.de\nStatus: connect",
        );
        // DENIC maps its `connect` vocabulary to `active`; the generic
        // parser would keep `connect` verbatim.
        assert_eq!(result.status, vec!["active"]);
    }

    #[test]
    fn test_parser_registry_selects_nominet_for_uk() {
        let result = parse(
            "example.co.uk",
            "whois.nic.uk",
            "Domain name:\n    example.co.uk\n\nRegistrar:\n    Example Registrar Ltd [Tag = EXAMPLE]\n",
        );
        // Nominet strips the `[Tag = …]` suffix; the generic parser keeps it.
        assert_eq!(result.registrar.as_deref(), Some("Example Registrar Ltd"));
    }

    #[test]
    fn test_parser_registry_uses_generic_for_unknown() {
        let result = parse(
            "example.com",
            "whois.verisign-grs.com",
            "Domain Name: example.com\nRegistrar: Example Registrar, Inc.\nStatus: connect\n",
        );
        assert_eq!(result.registrar.as_deref(), Some("Example Registrar, Inc."));
        // Not routed through DENIC's status mapping.
        assert_eq!(result.status, vec!["connect"]);
    }

    /// whois.kr serves .한국 / .삼성 in the KISA format: those IDN TLDs (which
    /// reach the parser as A-labels) must use the KISA parser, whose
    /// `Authorized Agency` / `Host Name` fields the generic parser ignores.
    #[test]
    fn test_parser_registry_selects_kisa_for_korean_idn_tlds() {
        let raw = "# ENGLISH\n\
                   \n\
                   Domain Name                 : example.xn--3e0b707e\n\
                   Authorized Agency           : Whois Corp.(http://whois.co.kr)\n\
                   \n\
                   Primary Name Server\n\
                   \x20  Host Name                : ns1.example.kr\n";
        for domain in ["example.xn--3e0b707e", "example.xn--cg4bki"] {
            let result = parse(domain, "whois.kr", raw);
            assert_eq!(
                result.registrar.as_deref(),
                Some("Whois Corp."),
                "{domain} must use the KISA parser"
            );
            assert_eq!(result.nameservers, vec!["ns1.example.kr"], "{domain}");
        }
    }

    /// whois.eu serves .ею / .ευ in the EURid format.
    #[test]
    fn test_parser_registry_selects_eurid_for_eu_idn_tlds() {
        let raw = "Domain: example.xn--e1a4c\n\
                   \n\
                   Name servers:\n\
                   \x20       ns1.example.eu (192.0.2.1)\n\
                   \x20       ns2.example.eu\n\
                   \n\
                   Keys:\n\
                   \x20       flags:KSK protocol:3 algorithm:RSA_SHA256 pubKey:AwEAAtest\n";
        for domain in ["example.xn--e1a4c", "example.xn--qxa6a"] {
            let result = parse(domain, "whois.eu", raw);
            assert_eq!(
                result.nameservers,
                vec!["ns1.example.eu", "ns2.example.eu"],
                "{domain} must use the EURid parser"
            );
            assert_eq!(
                result.dnssec.as_deref(),
                Some("signedDelegation"),
                "{domain}"
            );
        }
    }
}
