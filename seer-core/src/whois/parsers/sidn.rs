//! Parser for .nl domains (SIDN format).
//!
//! SIDN uses a section-based format where nameservers appear under a
//! `Domain nameservers:` header with indented values on subsequent lines.
//!
//! Example SIDN response:
//! ```text
//! Domain name: example.nl
//! Status:      active
//!
//! Registrar:
//!    Stichting Internet Domeinregistratie Nederland
//!    ...
//!
//! DNSSEC:      yes
//!
//! Domain nameservers:
//!    ns1.example.nl
//!    ns2.example.nl
//!
//! Creation Date: 2005-02-11
//! Updated Date: 2025-02-07
//! ```

use chrono::{DateTime, NaiveDate, Utc};
use once_cell::sync::Lazy;
use regex::Regex;

use super::RegistryParser;
use crate::whois::parser::WhoisResponse;

static STATUS_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Status:\s*(.+)$").expect("Invalid SIDN status regex"));

static DNSSEC_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^DNSSEC:\s*(.+)$").expect("Invalid SIDN DNSSEC regex"));

static CREATION_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^Creation Date:\s*(.+)$").expect("Invalid SIDN creation date regex")
});

static UPDATED_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^Updated Date:\s*(.+)$").expect("Invalid SIDN updated date regex")
});

static REGISTRAR_SECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Registrar:\s*$").expect("Invalid SIDN registrar regex"));

static ABUSE_SECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Abuse Contact:\s*$").expect("Invalid SIDN abuse regex"));

static NAMESERVERS_SECTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^Domain nameservers:\s*$").expect("Invalid SIDN nameservers regex")
});

/// Parser for .nl domains using the SIDN format.
#[derive(Debug, Clone, Default)]
pub struct SidnParser;

impl SidnParser {
    pub fn new() -> Self {
        Self
    }

    fn parse_date(date_str: &str) -> Option<DateTime<Utc>> {
        let cleaned = date_str.trim();
        if let Ok(d) = NaiveDate::parse_from_str(cleaned, "%Y-%m-%d") {
            return Some(d.and_hms_opt(0, 0, 0)?.and_utc());
        }
        None
    }
}

impl RegistryParser for SidnParser {
    fn supported_tlds(&self) -> &[&str] {
        &["nl"]
    }

    fn parse(&self, domain: &str, server: &str, raw: &str) -> WhoisResponse {
        let mut registrar = None;
        let mut creation_date = None;
        let mut updated_date = None;
        let mut nameservers = Vec::new();
        let mut status = Vec::new();
        let mut dnssec = None;

        #[derive(Clone, Copy)]
        enum Section {
            None,
            Registrar,
            Abuse,
            Nameservers,
        }

        let mut current_section = Section::None;

        for line in raw.lines() {
            let trimmed = line.trim();

            // Non-indented inline fields
            if !line.starts_with(' ') && !line.starts_with('\t') {
                if let Some(caps) = STATUS_PATTERN.captures(trimmed) {
                    if let Some(m) = caps.get(1) {
                        let s = m.as_str().trim().to_string();
                        if !s.is_empty() && !status.contains(&s) {
                            status.push(s);
                        }
                    }
                    current_section = Section::None;
                    continue;
                }
                if let Some(caps) = DNSSEC_PATTERN.captures(trimmed) {
                    if let Some(m) = caps.get(1) {
                        let val = m.as_str().trim();
                        dnssec = Some(if val.eq_ignore_ascii_case("yes") {
                            "signedDelegation".to_string()
                        } else {
                            "unsigned".to_string()
                        });
                    }
                    current_section = Section::None;
                    continue;
                }
                if let Some(caps) = CREATION_PATTERN.captures(trimmed) {
                    if creation_date.is_none() {
                        if let Some(m) = caps.get(1) {
                            creation_date = Self::parse_date(m.as_str());
                        }
                    }
                    current_section = Section::None;
                    continue;
                }
                if let Some(caps) = UPDATED_PATTERN.captures(trimmed) {
                    if updated_date.is_none() {
                        if let Some(m) = caps.get(1) {
                            updated_date = Self::parse_date(m.as_str());
                        }
                    }
                    current_section = Section::None;
                    continue;
                }

                // Section headers
                if REGISTRAR_SECTION.is_match(trimmed) {
                    current_section = Section::Registrar;
                    continue;
                } else if ABUSE_SECTION.is_match(trimmed) {
                    current_section = Section::Abuse;
                    continue;
                } else if NAMESERVERS_SECTION.is_match(trimmed) {
                    current_section = Section::Nameservers;
                    continue;
                }

                // Non-indented, non-empty, non-header line
                if !trimmed.is_empty() {
                    current_section = Section::None;
                }
                continue;
            }

            // Indented content
            if trimmed.is_empty() {
                continue;
            }

            match current_section {
                Section::Nameservers => {
                    // Strip glue IPs if present
                    let ns = trimmed
                        .split_whitespace()
                        .next()
                        .unwrap_or(trimmed)
                        .to_lowercase();
                    if !ns.is_empty() && !nameservers.contains(&ns) {
                        nameservers.push(ns);
                    }
                }
                Section::Registrar if registrar.is_none() => {
                    registrar = Some(trimmed.to_string());
                }
                _ => {}
            }
        }

        WhoisResponse {
            domain: domain.to_string(),
            registrar,
            registrant: None, // SIDN doesn't include registrant in public WHOIS
            organization: None,
            registrant_email: None,
            registrant_phone: None,
            registrant_address: None,
            registrant_country: Some("NL".to_string()),
            admin_name: None,
            admin_organization: None,
            admin_email: None,
            admin_phone: None,
            tech_name: None,
            tech_organization: None,
            tech_email: None,
            tech_phone: None,
            creation_date,
            expiration_date: None, // SIDN doesn't include expiry
            updated_date,
            nameservers,
            status,
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

    const SAMPLE_SIDN_RESPONSE: &str = r#"Domain name: example.nl
Status:      active

Registrar:
   Stichting Internet Domeinregistratie Nederland
   Meander 501
   6825MD Arnhem
   Netherlands

Abuse Contact:
   +31.263525555
   abuse@sidn.nl

DNSSEC:      yes

Domain nameservers:
   anytest1.sidnlabs.nl
   ex1.sidnlabs.nl
   ex2.sidnlabs.nl

Creation Date: 2005-02-11

Updated Date: 2025-02-07

Record maintained by: SIDN BV"#;

    #[test]
    fn test_sidn_nameservers() {
        let parser = SidnParser::new();
        let result = parser.parse("example.nl", "whois.sidn.nl", SAMPLE_SIDN_RESPONSE);

        assert_eq!(result.nameservers.len(), 3);
        assert!(result
            .nameservers
            .contains(&"anytest1.sidnlabs.nl".to_string()));
        assert!(result.nameservers.contains(&"ex1.sidnlabs.nl".to_string()));
        assert!(result.nameservers.contains(&"ex2.sidnlabs.nl".to_string()));
    }

    #[test]
    fn test_sidn_registrar() {
        let parser = SidnParser::new();
        let result = parser.parse("example.nl", "whois.sidn.nl", SAMPLE_SIDN_RESPONSE);

        assert_eq!(
            result.registrar,
            Some("Stichting Internet Domeinregistratie Nederland".to_string())
        );
    }

    #[test]
    fn test_sidn_status() {
        let parser = SidnParser::new();
        let result = parser.parse("example.nl", "whois.sidn.nl", SAMPLE_SIDN_RESPONSE);

        assert!(result.status.contains(&"active".to_string()));
    }

    #[test]
    fn test_sidn_dnssec() {
        let parser = SidnParser::new();
        let result = parser.parse("example.nl", "whois.sidn.nl", SAMPLE_SIDN_RESPONSE);

        assert_eq!(result.dnssec, Some("signedDelegation".to_string()));
    }

    #[test]
    fn test_sidn_dates() {
        let parser = SidnParser::new();
        let result = parser.parse("example.nl", "whois.sidn.nl", SAMPLE_SIDN_RESPONSE);

        assert!(result.creation_date.is_some());
        let creation = result.creation_date.unwrap();
        assert_eq!(creation.year(), 2005);
        assert_eq!(creation.month(), 2);
        assert_eq!(creation.day(), 11);

        assert!(result.updated_date.is_some());
        let updated = result.updated_date.unwrap();
        assert_eq!(updated.year(), 2025);
        assert_eq!(updated.month(), 2);
        assert_eq!(updated.day(), 7);
    }

    #[test]
    fn test_sidn_country() {
        let parser = SidnParser::new();
        let result = parser.parse("example.nl", "whois.sidn.nl", SAMPLE_SIDN_RESPONSE);

        assert_eq!(result.registrant_country, Some("NL".to_string()));
    }

    #[test]
    fn test_supported_tlds() {
        let parser = SidnParser::new();
        assert_eq!(parser.supported_tlds(), &["nl"]);
    }
}
