//! Parser for .uk domains (Nominet format).
//!
//! Nominet uses a section-based format with indented values and
//! human-readable date formats.
//!
//! Example Nominet response:
//! ```text
//! Domain name:
//!     example.co.uk
//!
//! Registrant:
//!     Example Ltd
//!
//! Registration date:
//!     01-January-2020
//!
//! Expiry date:
//!     01-January-2025
//!
//! Name servers:
//!     ns1.example.co.uk
//!     ns2.example.co.uk
//! ```

use chrono::{DateTime, NaiveDate, Utc};
use once_cell::sync::Lazy;
use regex::Regex;

use super::RegistryParser;
use crate::whois::parser::WhoisResponse;

/// Regex patterns for Nominet-specific fields.
static DOMAIN_SECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Domain name:\s*$").expect("Invalid Nominet domain regex"));

static REGISTRANT_SECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Registrant:\s*$").expect("Invalid Nominet registrant regex"));

static REGISTRAR_SECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Registrar:\s*$").expect("Invalid Nominet registrar regex"));

static REGISTRATION_DATE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^Registration date:\s*$").expect("Invalid Nominet registration date regex")
});

static EXPIRY_DATE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Expiry date:\s*$").expect("Invalid Nominet expiry date regex"));

static LAST_UPDATED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^Last updated:\s*$").expect("Invalid Nominet last updated regex")
});

static NAME_SERVERS_SECTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^Name servers:\s*$").expect("Invalid Nominet name servers regex")
});

static STATUS_SECTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^Registration status:\s*$").expect("Invalid Nominet status regex")
});

static DNSSEC_SECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^DNSSEC:\s*$").expect("Invalid Nominet DNSSEC regex"));

/// Parser for .uk domains using the Nominet format.
#[derive(Debug, Clone, Default)]
pub struct NominetParser;

impl NominetParser {
    pub fn new() -> Self {
        Self
    }

    /// Parses Nominet's date format: DD-Month-YYYY or DD Month YYYY
    fn parse_nominet_date(date_str: &str) -> Option<DateTime<Utc>> {
        let cleaned = date_str.trim();

        // Nominet uses formats like "01-January-2020" or "01 January 2020"
        let formats = [
            "%d-%B-%Y", // 01-January-2020
            "%d %B %Y", // 01 January 2020
            "%d-%b-%Y", // 01-Jan-2020
            "%d %b %Y", // 01 Jan 2020
            "%Y-%m-%d", // 2020-01-01 (fallback)
        ];

        for fmt in &formats {
            if let Ok(date) = NaiveDate::parse_from_str(cleaned, fmt) {
                return Some(date.and_hms_opt(0, 0, 0)?.and_utc());
            }
        }

        None
    }
}

impl RegistryParser for NominetParser {
    fn supported_tlds(&self) -> &[&str] {
        &[
            "uk", "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
        ]
    }

    fn parse(&self, domain: &str, server: &str, raw: &str) -> WhoisResponse {
        let mut registrant = None;
        let mut registrar = None;
        let mut creation_date = None;
        let mut expiration_date = None;
        let mut updated_date = None;
        let mut nameservers = Vec::new();
        let mut status = Vec::new();
        let mut dnssec = None;

        #[derive(Clone, Copy)]
        enum Section {
            None,
            Registrant,
            Registrar,
            RegistrationDate,
            ExpiryDate,
            LastUpdated,
            NameServers,
            Status,
            Dnssec,
        }

        let mut current_section = Section::None;

        for line in raw.lines() {
            let trimmed = line.trim();

            // Check for section headers
            if REGISTRANT_SECTION.is_match(trimmed) {
                current_section = Section::Registrant;
                continue;
            } else if REGISTRAR_SECTION.is_match(trimmed) {
                current_section = Section::Registrar;
                continue;
            } else if REGISTRATION_DATE.is_match(trimmed) {
                current_section = Section::RegistrationDate;
                continue;
            } else if EXPIRY_DATE.is_match(trimmed) {
                current_section = Section::ExpiryDate;
                continue;
            } else if LAST_UPDATED.is_match(trimmed) {
                current_section = Section::LastUpdated;
                continue;
            } else if NAME_SERVERS_SECTION.is_match(trimmed) {
                current_section = Section::NameServers;
                continue;
            } else if STATUS_SECTION.is_match(trimmed) {
                current_section = Section::Status;
                continue;
            } else if DNSSEC_SECTION.is_match(trimmed) {
                current_section = Section::Dnssec;
                continue;
            } else if DOMAIN_SECTION.is_match(trimmed) {
                current_section = Section::None;
                continue;
            }

            // Empty line ends the current section (except for nameservers which may have multiple)
            if trimmed.is_empty() {
                if !matches!(current_section, Section::NameServers) {
                    current_section = Section::None;
                }
                continue;
            }

            // Parse section content (indented values)
            if line.starts_with("    ") || line.starts_with('\t') {
                let value = trimmed.to_string();

                match current_section {
                    Section::Registrant if registrant.is_none() => {
                        if !is_redacted(&value) {
                            registrant = Some(value);
                        }
                    }
                    Section::Registrar if registrar.is_none() => {
                        // Extract registrar name from format like "Example Ltd [Tag = EXAMPLE]"
                        let name = value.split('[').next().unwrap_or(&value).trim().to_string();
                        if !is_redacted(&name) {
                            registrar = Some(name);
                        }
                    }
                    Section::RegistrationDate if creation_date.is_none() => {
                        creation_date = Self::parse_nominet_date(&value);
                    }
                    Section::ExpiryDate if expiration_date.is_none() => {
                        expiration_date = Self::parse_nominet_date(&value);
                    }
                    Section::LastUpdated if updated_date.is_none() => {
                        updated_date = Self::parse_nominet_date(&value);
                    }
                    Section::NameServers => {
                        let ns = value.to_lowercase();
                        if !ns.is_empty() && !nameservers.contains(&ns) {
                            nameservers.push(ns);
                        }
                    }
                    Section::Status => {
                        if !value.is_empty() && !status.contains(&value) {
                            status.push(value);
                        }
                    }
                    Section::Dnssec if dnssec.is_none() => {
                        dnssec = Some(value);
                    }
                    _ => {}
                }
            } else {
                // Non-indented line might start a new section or be a different header
                // Check for inline headers like "Registrar: Example Ltd"
                if let Some(pos) = trimmed.find(':') {
                    let key = &trimmed[..pos].to_lowercase();
                    let value = trimmed[pos + 1..].trim();

                    if !value.is_empty() && !is_redacted(value) {
                        match key.as_str() {
                            "registrant" => registrant = Some(value.to_string()),
                            "registrar" => registrar = Some(value.to_string()),
                            _ => {}
                        }
                    }
                }

                // End current section if we hit a non-indented, non-empty line
                current_section = Section::None;
            }
        }

        WhoisResponse {
            domain: domain.to_string(),
            registrar,
            registrant: registrant.clone(),
            organization: registrant,
            registrant_email: None,
            registrant_phone: None,
            registrant_address: None,
            registrant_country: Some("GB".to_string()),
            admin_name: None,
            admin_organization: None,
            admin_email: None,
            admin_phone: None,
            tech_name: None,
            tech_organization: None,
            tech_email: None,
            tech_phone: None,
            creation_date,
            expiration_date,
            updated_date,
            nameservers,
            status,
            dnssec,
            whois_server: server.to_string(),
            raw_response: raw.to_string(),
        }
    }
}

/// Checks if a value is a privacy/redaction placeholder.
fn is_redacted(value: &str) -> bool {
    let lower = value.to_lowercase();
    lower.contains("redacted")
        || lower.contains("data protected")
        || lower.contains("privacy")
        || lower.contains("not disclosed")
        || lower.contains("withheld")
        || lower == "n/a"
        || lower == "none"
        || value.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[allow(dead_code)]
    const SAMPLE_NOMINET_RESPONSE: &str = r#"
    Domain name:
        example.co.uk

    Registrant:
        Example Ltd

    Registrar:
        Registrar Name [Tag = REGISTRAR]

    Relevant dates:
        Registered on: 01-January-2020
        Expiry date:  01-January-2025
        Last updated:  15-June-2023

    Registration status:
        Registered until expiry date.

    Name servers:
        ns1.example.co.uk
        ns2.example.co.uk

    WHOIS lookup made at 10:00:00 01-Jan-2024
"#;

    // Alternative format with section headers on separate lines
    const SAMPLE_NOMINET_RESPONSE_2: &str = r#"
Domain name:
    example.co.uk

Registrant:
    Test Company

Registrar:
    Another Registrar

Registration date:
    15-March-2019

Expiry date:
    15-March-2024

Last updated:
    10-October-2023

Name servers:
    ns1.test.co.uk
    ns2.test.co.uk
    ns3.test.co.uk

DNSSEC:
    Signed
"#;

    #[test]
    fn test_nominet_parser_basic() {
        let parser = NominetParser::new();
        let result = parser.parse("example.co.uk", "whois.nic.uk", SAMPLE_NOMINET_RESPONSE_2);

        assert_eq!(result.domain, "example.co.uk");
        assert_eq!(result.registrant, Some("Test Company".to_string()));
        assert_eq!(result.registrar, Some("Another Registrar".to_string()));
    }

    #[test]
    fn test_nominet_parser_dates() {
        let parser = NominetParser::new();
        let result = parser.parse("example.co.uk", "whois.nic.uk", SAMPLE_NOMINET_RESPONSE_2);

        assert!(result.creation_date.is_some());
        let creation = result.creation_date.unwrap();
        assert_eq!(creation.year(), 2019);
        assert_eq!(creation.month(), 3);
        assert_eq!(creation.day(), 15);

        assert!(result.expiration_date.is_some());
        let expiry = result.expiration_date.unwrap();
        assert_eq!(expiry.year(), 2024);
        assert_eq!(expiry.month(), 3);
        assert_eq!(expiry.day(), 15);
    }

    #[test]
    fn test_nominet_parser_nameservers() {
        let parser = NominetParser::new();
        let result = parser.parse("example.co.uk", "whois.nic.uk", SAMPLE_NOMINET_RESPONSE_2);

        assert_eq!(result.nameservers.len(), 3);
        assert!(result.nameservers.contains(&"ns1.test.co.uk".to_string()));
        assert!(result.nameservers.contains(&"ns2.test.co.uk".to_string()));
        assert!(result.nameservers.contains(&"ns3.test.co.uk".to_string()));
    }

    #[test]
    fn test_nominet_parser_dnssec() {
        let parser = NominetParser::new();
        let result = parser.parse("example.co.uk", "whois.nic.uk", SAMPLE_NOMINET_RESPONSE_2);

        assert_eq!(result.dnssec, Some("Signed".to_string()));
    }

    #[test]
    fn test_nominet_date_parsing() {
        assert!(NominetParser::parse_nominet_date("01-January-2020").is_some());
        assert!(NominetParser::parse_nominet_date("15 March 2019").is_some());
        assert!(NominetParser::parse_nominet_date("01-Jan-2020").is_some());
    }

    #[test]
    fn test_supported_tlds() {
        let parser = NominetParser::new();
        let tlds = parser.supported_tlds();
        assert!(tlds.contains(&"uk"));
        assert!(tlds.contains(&"co.uk"));
        assert!(tlds.contains(&"org.uk"));
    }

    #[test]
    fn test_redaction_detection() {
        assert!(is_redacted("REDACTED FOR PRIVACY"));
        assert!(is_redacted("Data protected"));
        assert!(is_redacted("Not disclosed"));
        assert!(!is_redacted("Example Ltd"));
    }

    #[test]
    fn test_country_code() {
        let parser = NominetParser::new();
        let result = parser.parse("example.co.uk", "whois.nic.uk", SAMPLE_NOMINET_RESPONSE_2);

        assert_eq!(result.registrant_country, Some("GB".to_string()));
    }
}
