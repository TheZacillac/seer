//! Parser for .de domains (DENIC format).
//!
//! DENIC (Deutsches Network Information Center) uses a unique format
//! with specific field names and date formats.
//!
//! Example DENIC response:
//! ```text
//! Domain: example.de
//! Nserver: ns1.example.de
//! Nserver: ns2.example.de
//! Status: connect
//! Changed: 2023-01-15T10:30:00+01:00
//! ```

use super::{push_bounded, MAX_NAMESERVERS, MAX_STATUSES};
use crate::whois::parse_date;
use crate::whois::parser::WhoisResponse;

// Regex patterns for DENIC-specific fields.
static_regex! {
    NSERVER_PATTERN = r"(?i)^Nserver:\s*(.+)$";
    STATUS_PATTERN = r"(?i)^Status:\s*(.+)$";
    CHANGED_PATTERN = r"(?i)^Changed:\s*(.+)$";
    HOLDER_PATTERN = r"(?i)^\[Holder\]";
    HOLDER_NAME_PATTERN = r"(?i)^Name:\s*(.+)$";
    HOLDER_COUNTRY_PATTERN = r"(?i)^CountryCode:\s*([A-Za-z]{2})$";
    DNSKEY_PATTERN = r"(?i)^Dnskey:\s*(.+)$";
}

/// TLDs this parser handles.
pub(super) const TLDS: &[&str] = &["de"];

/// Parses .de domains using the DENIC format.
pub(super) fn parse(domain: &str, server: &str, raw: &str) -> WhoisResponse {
    let mut nameservers = Vec::new();
    let mut status = Vec::new();
    let mut updated_date = None;
    let mut holder_name = None;
    let mut holder_country = None;
    let mut in_holder_section = false;
    let mut dnssec = None;

    for line in raw.lines() {
        let line = line.trim();

        // Check for holder section
        if HOLDER_PATTERN.is_match(line) {
            in_holder_section = true;
            continue;
        }

        // Parse holder name / country within the holder section, which
        // ends at an empty line or the next `[Section]` header.
        if in_holder_section {
            if line.is_empty() || line.starts_with('[') {
                in_holder_section = false;
            } else if let Some(caps) = HOLDER_NAME_PATTERN.captures(line) {
                if holder_name.is_none() {
                    holder_name = caps.get(1).map(|m| m.as_str().trim().to_string());
                }
            } else if let Some(caps) = HOLDER_COUNTRY_PATTERN.captures(line) {
                if holder_country.is_none() {
                    holder_country = caps.get(1).map(|m| m.as_str().to_ascii_uppercase());
                }
            }
        }

        // Parse nameservers
        if let Some(caps) = NSERVER_PATTERN.captures(line) {
            if let Some(m) = caps.get(1) {
                let ns = m.as_str().trim().to_lowercase();
                // DENIC may include IP addresses after the hostname
                let ns = ns.split_whitespace().next().unwrap_or(&ns).to_string();
                push_bounded(&mut nameservers, ns, MAX_NAMESERVERS);
            }
        }

        // Parse status
        if let Some(caps) = STATUS_PATTERN.captures(line) {
            if let Some(m) = caps.get(1) {
                let s = m.as_str().trim().to_string();
                push_bounded(&mut status, s, MAX_STATUSES);
            }
        }

        // Parse changed date (this is the updated date)
        if let Some(caps) = CHANGED_PATTERN.captures(line) {
            if let Some(m) = caps.get(1) {
                updated_date = parse_date(m.as_str());
            }
        }

        // Parse DNSSEC
        if let Some(caps) = DNSKEY_PATTERN.captures(line) {
            if let Some(m) = caps.get(1) {
                dnssec = Some(m.as_str().trim().to_string());
            }
        }
    }

    // Map DENIC's status vocabulary to more descriptive values. These are
    // DENIC-specific terms, NOT EPP statuses — in particular `failed` means
    // the registry's automated nameserver delegation check failed (the
    // domain is registered but its DNS is misconfigured), which is unrelated
    // to the EPP `redemptionPeriod` deletion-grace state.
    let mapped_status: Vec<String> = status
        .iter()
        .map(|s| match s.as_str() {
            "connect" => "active".to_string(),
            "free" => "available".to_string(),
            "invalid" => "invalid".to_string(),
            "failed" => "failed (nameserver check failed)".to_string(),
            other => other.to_string(),
        })
        .collect();

    WhoisResponse {
        domain: domain.to_string(),
        registrant: holder_name.clone(),
        organization: holder_name,
        // Only what the [Holder] block states: .de accepts holders outside
        // Germany, and a "free" body must not report a registrant country.
        registrant_country: holder_country,
        updated_date,
        nameservers,
        status: mapped_status,
        dnssec,
        whois_server: server.to_string(),
        raw_response: raw.to_string(),
        // DENIC's WHOIS exposes no registrar, creation or expiration date.
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    const SAMPLE_DENIC_RESPONSE: &str = r#"
Domain: example.de
Nserver: ns1.example.de 192.0.2.1
Nserver: ns2.example.de
Status: connect
Changed: 2023-01-15T10:30:00+01:00

[Holder]
Type: PERSON
Name: Max Mustermann
Address: Musterstraße 1
PostalCode: 12345
City: Musterstadt
CountryCode: DE

[Tech-C]
Type: PERSON
Name: Technical Contact
"#;

    #[test]
    fn test_denic_parser_basic() {
        let result = parse("example.de", "whois.denic.de", SAMPLE_DENIC_RESPONSE);

        assert_eq!(result.domain, "example.de");
        assert_eq!(result.nameservers.len(), 2);
        assert!(result.nameservers.contains(&"ns1.example.de".to_string()));
        assert!(result.nameservers.contains(&"ns2.example.de".to_string()));
    }

    #[test]
    fn test_denic_parser_status() {
        let result = parse("example.de", "whois.denic.de", SAMPLE_DENIC_RESPONSE);

        assert!(result.status.contains(&"active".to_string()));
    }

    #[test]
    fn test_denic_parser_holder() {
        let result = parse("example.de", "whois.denic.de", SAMPLE_DENIC_RESPONSE);

        assert_eq!(result.registrant, Some("Max Mustermann".to_string()));
        assert_eq!(result.organization, Some("Max Mustermann".to_string()));
    }

    #[test]
    fn test_denic_parser_updated_date() {
        let result = parse("example.de", "whois.denic.de", SAMPLE_DENIC_RESPONSE);

        assert!(result.updated_date.is_some());
        let dt = result.updated_date.unwrap();
        assert_eq!(dt.year(), 2023);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 15);
    }

    const SAMPLE_DENIC_FAILED: &str = r#"
Domain: broken.de
Nserver: ns1.broken.de
Status: failed
Changed: 2023-01-15T10:30:00+01:00
"#;

    /// DENIC `Status: failed` means the registry's nameserver delegation check
    /// failed (DNS misconfigured) — the registration itself is intact. It must
    /// NOT be relabeled `redemptionPeriod`, an EPP/RGP concept (domain pending
    /// deletion) that doesn't apply to .de and would mislead the user into
    /// thinking the domain is about to be released.
    #[test]
    fn test_denic_failed_status_is_not_redemption_period() {
        let result = parse("broken.de", "whois.denic.de", SAMPLE_DENIC_FAILED);

        assert!(
            !result.status.contains(&"redemptionPeriod".to_string()),
            "DENIC 'failed' must not be mapped to redemptionPeriod, got {:?}",
            result.status
        );
        assert!(
            result
                .status
                .contains(&"failed (nameserver check failed)".to_string()),
            "expected a delegation-failure label, got {:?}",
            result.status
        );
    }

    /// The registrant country comes from the `[Holder]` block's
    /// `CountryCode:` — never from the TLD: .de accepts holders outside
    /// Germany, and an unregistered domain must not report `DE`.
    #[test]
    fn test_denic_registrant_country_not_hardcoded() {
        let result = parse("example.de", "whois.denic.de", SAMPLE_DENIC_RESPONSE);
        assert_eq!(result.registrant_country.as_deref(), Some("DE"));
        assert_eq!(result.registrant.as_deref(), Some("Max Mustermann"));

        let austrian = SAMPLE_DENIC_RESPONSE.replace("CountryCode: DE", "CountryCode: AT");
        let result = parse("example.de", "whois.denic.de", &austrian);
        assert_eq!(result.registrant_country.as_deref(), Some("AT"));

        // Current DENIC output publishes no [Holder] block at all.
        let result = parse(
            "example.de",
            "whois.denic.de",
            "Domain: example.de\nNserver: ns1.example.de\nStatus: connect\n",
        );
        assert_eq!(result.registrant_country, None);

        let result = parse(
            "nosuch-xyz.de",
            "whois.denic.de",
            "Domain: nosuch-xyz.de\nStatus: free\n",
        );
        assert_eq!(result.registrant_country, None);
    }

    #[test]
    fn test_denic_date_parsing() {
        // Test various DENIC date formats
        assert!(parse_date("2023-01-15T10:30:00+01:00").is_some());
        assert!(parse_date("2023-01-15T10:30:00Z").is_some());
        // DENIC also emits naive ISO datetimes; they read as UTC.
        assert_eq!(
            parse_date("2023-01-15T10:30:00").map(|d| d.to_rfc3339()),
            Some("2023-01-15T10:30:00+00:00".to_string())
        );
        assert!(parse_date("2023-01-15").is_some());
    }
}
