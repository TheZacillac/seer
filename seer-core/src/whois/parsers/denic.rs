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

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;

use super::RegistryParser;
use crate::whois::parser::WhoisResponse;

/// Regex patterns for DENIC-specific fields.
static NSERVER_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Nserver:\s*(.+)$").expect("Invalid DENIC nserver regex"));

static STATUS_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Status:\s*(.+)$").expect("Invalid DENIC status regex"));

static CHANGED_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Changed:\s*(.+)$").expect("Invalid DENIC changed regex"));

static HOLDER_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^\[Holder\]").expect("Invalid DENIC holder regex"));

static HOLDER_NAME_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Name:\s*(.+)$").expect("Invalid DENIC holder name regex"));

static DNSKEY_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Dnskey:\s*(.+)$").expect("Invalid DENIC dnskey regex"));

/// Parser for .de domains using the DENIC format.
#[derive(Debug, Clone, Default)]
pub struct DenicParser;

impl DenicParser {
    pub fn new() -> Self {
        Self
    }

    fn parse_denic_date(date_str: &str) -> Option<DateTime<Utc>> {
        // DENIC uses ISO 8601 format with timezone
        // Example: 2023-01-15T10:30:00+01:00
        let cleaned = date_str.trim();

        // Try parsing as ISO 8601 with timezone
        if let Ok(dt) = DateTime::parse_from_rfc3339(cleaned) {
            return Some(dt.with_timezone(&Utc));
        }

        // Try without timezone
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(cleaned, "%Y-%m-%dT%H:%M:%S") {
            return Some(dt.and_utc());
        }

        // Try date only
        if let Ok(d) = chrono::NaiveDate::parse_from_str(cleaned, "%Y-%m-%d") {
            return Some(d.and_hms_opt(0, 0, 0)?.and_utc());
        }

        None
    }
}

impl RegistryParser for DenicParser {
    fn supported_tlds(&self) -> &[&str] {
        &["de"]
    }

    fn parse(&self, domain: &str, server: &str, raw: &str) -> WhoisResponse {
        let mut nameservers = Vec::new();
        let mut status = Vec::new();
        let mut updated_date = None;
        let mut holder_name = None;
        let mut in_holder_section = false;
        let mut dnssec = None;

        for line in raw.lines() {
            let line = line.trim();

            // Check for holder section
            if HOLDER_PATTERN.is_match(line) {
                in_holder_section = true;
                continue;
            }

            // Parse holder name within holder section
            if in_holder_section {
                if let Some(caps) = HOLDER_NAME_PATTERN.captures(line) {
                    if let Some(m) = caps.get(1) {
                        holder_name = Some(m.as_str().trim().to_string());
                        in_holder_section = false;
                    }
                }
                // Empty line ends the section
                if line.is_empty() {
                    in_holder_section = false;
                }
            }

            // Parse nameservers
            if let Some(caps) = NSERVER_PATTERN.captures(line) {
                if let Some(m) = caps.get(1) {
                    let ns = m.as_str().trim().to_lowercase();
                    // DENIC may include IP addresses after the hostname
                    let ns = ns.split_whitespace().next().unwrap_or(&ns).to_string();
                    if !ns.is_empty() && !nameservers.contains(&ns) {
                        nameservers.push(ns);
                    }
                }
            }

            // Parse status
            if let Some(caps) = STATUS_PATTERN.captures(line) {
                if let Some(m) = caps.get(1) {
                    let s = m.as_str().trim().to_string();
                    if !s.is_empty() && !status.contains(&s) {
                        status.push(s);
                    }
                }
            }

            // Parse changed date (this is the updated date)
            if let Some(caps) = CHANGED_PATTERN.captures(line) {
                if let Some(m) = caps.get(1) {
                    updated_date = Self::parse_denic_date(m.as_str());
                }
            }

            // Parse DNSSEC
            if let Some(caps) = DNSKEY_PATTERN.captures(line) {
                if let Some(m) = caps.get(1) {
                    dnssec = Some(m.as_str().trim().to_string());
                }
            }
        }

        // Map DENIC status to more descriptive values
        let mapped_status: Vec<String> = status
            .iter()
            .map(|s| match s.as_str() {
                "connect" => "active".to_string(),
                "free" => "available".to_string(),
                "invalid" => "invalid".to_string(),
                "failed" => "redemptionPeriod".to_string(),
                other => other.to_string(),
            })
            .collect();

        WhoisResponse {
            domain: domain.to_string(),
            registrar: None, // DENIC doesn't expose registrar in WHOIS
            registrant: holder_name.clone(),
            organization: holder_name,
            registrant_email: None,
            registrant_phone: None,
            registrant_address: None,
            registrant_country: Some("DE".to_string()),
            admin_name: None,
            admin_organization: None,
            admin_email: None,
            admin_phone: None,
            tech_name: None,
            tech_organization: None,
            tech_email: None,
            tech_phone: None,
            creation_date: None,   // DENIC doesn't expose creation date
            expiration_date: None, // DENIC doesn't expose expiration date
            updated_date,
            nameservers,
            status: mapped_status,
            dnssec,
            whois_server: server.to_string(),
            raw_response: raw.to_string(),
        }
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
        let parser = DenicParser::new();
        let result = parser.parse("example.de", "whois.denic.de", SAMPLE_DENIC_RESPONSE);

        assert_eq!(result.domain, "example.de");
        assert_eq!(result.nameservers.len(), 2);
        assert!(result.nameservers.contains(&"ns1.example.de".to_string()));
        assert!(result.nameservers.contains(&"ns2.example.de".to_string()));
    }

    #[test]
    fn test_denic_parser_status() {
        let parser = DenicParser::new();
        let result = parser.parse("example.de", "whois.denic.de", SAMPLE_DENIC_RESPONSE);

        assert!(result.status.contains(&"active".to_string()));
    }

    #[test]
    fn test_denic_parser_holder() {
        let parser = DenicParser::new();
        let result = parser.parse("example.de", "whois.denic.de", SAMPLE_DENIC_RESPONSE);

        assert_eq!(result.registrant, Some("Max Mustermann".to_string()));
        assert_eq!(result.organization, Some("Max Mustermann".to_string()));
    }

    #[test]
    fn test_denic_parser_updated_date() {
        let parser = DenicParser::new();
        let result = parser.parse("example.de", "whois.denic.de", SAMPLE_DENIC_RESPONSE);

        assert!(result.updated_date.is_some());
        let dt = result.updated_date.unwrap();
        assert_eq!(dt.year(), 2023);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 15);
    }

    #[test]
    fn test_denic_date_parsing() {
        // Test various DENIC date formats
        assert!(DenicParser::parse_denic_date("2023-01-15T10:30:00+01:00").is_some());
        assert!(DenicParser::parse_denic_date("2023-01-15T10:30:00Z").is_some());
        assert!(DenicParser::parse_denic_date("2023-01-15").is_some());
    }

    #[test]
    fn test_supported_tlds() {
        let parser = DenicParser::new();
        assert!(parser.supported_tlds().contains(&"de"));
    }
}
