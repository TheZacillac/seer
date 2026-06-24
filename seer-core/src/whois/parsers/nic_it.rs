//! Parser for .it domains (NIC.it format).
//!
//! NIC.it uses a section-based format. Nameservers appear under a
//! `Nameservers` header (no colon) with indented values on subsequent lines.
//!
//! Example NIC.it response:
//! ```text
//! Domain:             google.it
//! Status:             ok
//! Signed:             no
//! Created:            1999-12-10 00:00:00
//! Last Update:        2025-05-07 00:52:22
//! Expire Date:        2026-04-21
//!
//! Registrant
//!   Organization:     Example Corp
//!   ...
//!
//! Registrar
//!   Organization:     MarkMonitor International Limited
//!   Name:             MARKMONITOR-REG
//!   ...
//!
//! Nameservers
//!   ns1.google.com
//!   ns2.google.com
//! ```

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;

use super::{push_bounded, RegistryParser, MAX_NAMESERVERS, MAX_STATUSES};
use crate::whois::parser::WhoisResponse;

static DOMAIN_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Domain:\s*(.+)$").expect("Invalid NIC.it domain regex"));

static STATUS_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Status:\s*(.+)$").expect("Invalid NIC.it status regex"));

static CREATED_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Created:\s*(.+)$").expect("Invalid NIC.it created regex"));

static EXPIRE_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Expire Date:\s*(.+)$").expect("Invalid NIC.it expire regex"));

static LAST_UPDATE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^Last Update:\s*(.+)$").expect("Invalid NIC.it last update regex")
});

static SIGNED_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Signed:\s*(.+)$").expect("Invalid NIC.it signed regex"));

/// Section headers (no colon)
static REGISTRANT_SECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Registrant\s*$").expect("Invalid NIC.it registrant regex"));

static ADMIN_SECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Admin Contact\s*$").expect("Invalid NIC.it admin regex"));

static TECH_SECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Technical Contacts\s*$").expect("Invalid NIC.it tech regex"));

static REGISTRAR_SECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Registrar\s*$").expect("Invalid NIC.it registrar regex"));

static NAMESERVERS_SECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Nameservers\s*$").expect("Invalid NIC.it nameservers regex"));

/// Parser for .it domains using the NIC.it format.
#[derive(Debug, Clone, Default)]
pub struct NicItParser;

impl NicItParser {
    pub fn new() -> Self {
        Self
    }

    fn parse_date(date_str: &str) -> Option<DateTime<Utc>> {
        let cleaned = date_str.trim();

        // NIC.it uses "YYYY-MM-DD HH:MM:SS" or "YYYY-MM-DD"
        if let Ok(dt) = NaiveDateTime::parse_from_str(cleaned, "%Y-%m-%d %H:%M:%S") {
            return Some(dt.and_utc());
        }
        if let Ok(d) = NaiveDate::parse_from_str(cleaned, "%Y-%m-%d") {
            return Some(d.and_hms_opt(0, 0, 0)?.and_utc());
        }

        None
    }
}

impl RegistryParser for NicItParser {
    fn supported_tlds(&self) -> &[&str] {
        &["it"]
    }

    fn parse(&self, domain: &str, server: &str, raw: &str) -> WhoisResponse {
        let mut registrant_org = None;
        let mut registrar = None;
        let mut creation_date = None;
        let mut expiration_date = None;
        let mut updated_date = None;
        let mut nameservers = Vec::new();
        let mut status = Vec::new();
        let mut dnssec = None;
        let mut admin_name = None;
        let mut admin_org = None;
        let mut tech_name = None;
        let mut tech_org = None;

        #[derive(Clone, Copy)]
        enum Section {
            None,
            Registrant,
            Admin,
            Tech,
            Registrar,
            Nameservers,
        }

        let mut current_section = Section::None;

        for line in raw.lines() {
            let trimmed = line.trim();

            // Top-level inline fields (not indented)
            if !line.starts_with(' ') && !line.starts_with('\t') {
                if let Some(caps) = STATUS_PATTERN.captures(trimmed) {
                    if let Some(m) = caps.get(1) {
                        let s = m.as_str().trim().to_string();
                        push_bounded(&mut status, s, MAX_STATUSES);
                    }
                    current_section = Section::None;
                    continue;
                }
                if let Some(caps) = CREATED_PATTERN.captures(trimmed) {
                    if creation_date.is_none() {
                        if let Some(m) = caps.get(1) {
                            creation_date = Self::parse_date(m.as_str());
                        }
                    }
                    current_section = Section::None;
                    continue;
                }
                if let Some(caps) = EXPIRE_PATTERN.captures(trimmed) {
                    if expiration_date.is_none() {
                        if let Some(m) = caps.get(1) {
                            expiration_date = Self::parse_date(m.as_str());
                        }
                    }
                    current_section = Section::None;
                    continue;
                }
                if let Some(caps) = LAST_UPDATE_PATTERN.captures(trimmed) {
                    if updated_date.is_none() {
                        if let Some(m) = caps.get(1) {
                            updated_date = Self::parse_date(m.as_str());
                        }
                    }
                    current_section = Section::None;
                    continue;
                }
                if let Some(caps) = SIGNED_PATTERN.captures(trimmed) {
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
                if DOMAIN_PATTERN.is_match(trimmed) {
                    current_section = Section::None;
                    continue;
                }

                // Check section headers
                if REGISTRANT_SECTION.is_match(trimmed) {
                    current_section = Section::Registrant;
                    continue;
                } else if ADMIN_SECTION.is_match(trimmed) {
                    current_section = Section::Admin;
                    continue;
                } else if TECH_SECTION.is_match(trimmed) {
                    current_section = Section::Tech;
                    continue;
                } else if REGISTRAR_SECTION.is_match(trimmed) {
                    current_section = Section::Registrar;
                    continue;
                } else if NAMESERVERS_SECTION.is_match(trimmed) {
                    current_section = Section::Nameservers;
                    continue;
                }

                // Any other non-indented non-empty line ends the section
                if !trimmed.is_empty() {
                    current_section = Section::None;
                }
                continue;
            }

            // Indented content within sections
            if trimmed.is_empty() {
                continue;
            }

            match current_section {
                Section::Nameservers => {
                    let ns = trimmed.to_lowercase();
                    push_bounded(&mut nameservers, ns, MAX_NAMESERVERS);
                }
                Section::Registrant => {
                    if let Some(val) = extract_indented_field(trimmed, "Organization") {
                        if registrant_org.is_none() {
                            registrant_org = Some(val);
                        }
                    }
                }
                Section::Admin => {
                    if let Some(val) = extract_indented_field(trimmed, "Name") {
                        if admin_name.is_none() {
                            admin_name = Some(val);
                        }
                    } else if let Some(val) = extract_indented_field(trimmed, "Organization") {
                        if admin_org.is_none() {
                            admin_org = Some(val);
                        }
                    }
                }
                Section::Tech => {
                    if let Some(val) = extract_indented_field(trimmed, "Name") {
                        if tech_name.is_none() {
                            tech_name = Some(val);
                        }
                    } else if let Some(val) = extract_indented_field(trimmed, "Organization") {
                        if tech_org.is_none() {
                            tech_org = Some(val);
                        }
                    }
                }
                Section::Registrar => {
                    if let Some(val) = extract_indented_field(trimmed, "Organization") {
                        if registrar.is_none() {
                            registrar = Some(val);
                        }
                    }
                }
                _ => {}
            }
        }

        WhoisResponse {
            domain: domain.to_string(),
            registrar,
            registrant: registrant_org.clone(),
            organization: registrant_org,
            registrant_email: None,
            registrant_phone: None,
            registrant_address: None,
            registrant_country: Some("IT".to_string()),
            admin_name,
            admin_organization: admin_org,
            admin_email: None,
            admin_phone: None,
            tech_name,
            tech_organization: tech_org,
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

/// Extract a value from an indented "Key: Value" line.
///
/// Matches `key` case-insensitively, immediately followed by `:` (no leading
/// whitespace), then returns the trimmed remainder with original casing.
///
/// The value is sliced at the actual `:` separator (always a valid char
/// boundary) rather than by `key.len()`. `key.len()` is the byte length of the
/// ASCII key, but `to_lowercase()` is not length-preserving for all Unicode, so
/// indexing the untrusted original line by it could land off a char boundary
/// and panic.
fn extract_indented_field(line: &str, key: &str) -> Option<String> {
    let (prefix, value) = line.split_once(':')?;
    if prefix.eq_ignore_ascii_case(key) {
        let value = value.trim();
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    const SAMPLE_NIC_IT_RESPONSE: &str = r#"*********************************************************************
* Please note that the following result could be a subgroup of      *
* the data contained in the database.                               *
*                                                                   *
* Additional information can be visualized at:                      *
* http://web-whois.nic.it                                           *
*********************************************************************

Domain:             google.it
Status:             ok
Signed:             no
Created:            1999-12-10 00:00:00
Last Update:        2025-05-07 00:52:22
Expire Date:        2026-04-21

Registrant
  Organization:     Google Ireland Holdings Unlimited Company
  Address:          70 Sir John Rogerson's Quay
                    Dublin
                    2
                    Dublin
                    IE
  Created:          2018-03-02 19:04:02
  Last Update:      2018-03-02 19:04:02

Admin Contact
  Name:             Colm Buckley
  Organization:     Google LLC

Technical Contacts
  Name:             Domain Administrator
  Organization:     Google LLC

Registrar
  Organization:     MarkMonitor International Limited
  Name:             MARKMONITOR-REG
  Web:              https://www.markmonitor.com/
  DNSSEC:           no


Nameservers
  ns1.google.com
  ns2.google.com
  ns3.google.com
  ns4.google.com"#;

    #[test]
    fn test_nic_it_nameservers() {
        let parser = NicItParser::new();
        let result = parser.parse("google.it", "whois.nic.it", SAMPLE_NIC_IT_RESPONSE);

        assert_eq!(result.nameservers.len(), 4);
        assert!(result.nameservers.contains(&"ns1.google.com".to_string()));
        assert!(result.nameservers.contains(&"ns2.google.com".to_string()));
        assert!(result.nameservers.contains(&"ns3.google.com".to_string()));
        assert!(result.nameservers.contains(&"ns4.google.com".to_string()));
    }

    #[test]
    fn test_nic_it_registrant() {
        let parser = NicItParser::new();
        let result = parser.parse("google.it", "whois.nic.it", SAMPLE_NIC_IT_RESPONSE);

        assert_eq!(result.domain, "google.it");
        assert_eq!(
            result.registrant,
            Some("Google Ireland Holdings Unlimited Company".to_string())
        );
        assert_eq!(
            result.registrar,
            Some("MarkMonitor International Limited".to_string())
        );
    }

    #[test]
    fn test_nic_it_dates() {
        let parser = NicItParser::new();
        let result = parser.parse("google.it", "whois.nic.it", SAMPLE_NIC_IT_RESPONSE);

        assert!(result.creation_date.is_some());
        let creation = result.creation_date.unwrap();
        assert_eq!(creation.year(), 1999);
        assert_eq!(creation.month(), 12);
        assert_eq!(creation.day(), 10);

        assert!(result.expiration_date.is_some());
        let expiry = result.expiration_date.unwrap();
        assert_eq!(expiry.year(), 2026);
        assert_eq!(expiry.month(), 4);
        assert_eq!(expiry.day(), 21);
    }

    #[test]
    fn test_nic_it_status_and_dnssec() {
        let parser = NicItParser::new();
        let result = parser.parse("google.it", "whois.nic.it", SAMPLE_NIC_IT_RESPONSE);

        assert!(result.status.contains(&"ok".to_string()));
        assert_eq!(result.dnssec, Some("unsigned".to_string()));
    }

    #[test]
    fn test_nic_it_contacts() {
        let parser = NicItParser::new();
        let result = parser.parse("google.it", "whois.nic.it", SAMPLE_NIC_IT_RESPONSE);

        assert_eq!(result.admin_name, Some("Colm Buckley".to_string()));
        assert_eq!(result.admin_organization, Some("Google LLC".to_string()));
        assert_eq!(result.tech_name, Some("Domain Administrator".to_string()));
        assert_eq!(result.tech_organization, Some("Google LLC".to_string()));
    }

    #[test]
    fn test_supported_tlds() {
        let parser = NicItParser::new();
        assert_eq!(parser.supported_tlds(), &["it"]);
    }

    #[test]
    fn extract_indented_field_is_char_boundary_safe() {
        // The old impl sliced the ORIGINAL line by `key.len() + 1`, a length
        // derived from the ASCII key. WHOIS bodies are untrusted: a multibyte
        // character whose lowercase form changes byte length (e.g. Turkish İ →
        // i̇, 2→3 bytes) could make that index land off a char boundary and
        // panic. The helper must locate the value via the actual `:` separator
        // (always a valid boundary), preserving the original-case value.
        //
        // Multibyte content sitting at and after the byte offset the old code
        // would have indexed (`"Name".len() + 1` = 5) — must extract cleanly.
        assert_eq!(
            extract_indented_field("Name: Köln Über AG", "Name").as_deref(),
            Some("Köln Über AG")
        );
        // A leading multibyte char in the value, right where the old byte index
        // pointed, must not be split mid-codepoint.
        assert_eq!(
            extract_indented_field("Name:Über", "Name").as_deref(),
            Some("Über")
        );
    }

    #[test]
    fn extract_indented_field_preserves_strict_match_semantics() {
        // Regression guard: behaviour must match the old `starts_with("key:")`
        // gate exactly — no leading whitespace, key immediately before colon.
        assert_eq!(
            extract_indented_field("Organization: Google LLC", "Organization").as_deref(),
            Some("Google LLC")
        );
        assert_eq!(extract_indented_field("Name:", "Name"), None); // empty value
        assert_eq!(extract_indented_field("Other: x", "Name"), None); // wrong key
        assert_eq!(extract_indented_field("Name : x", "Name"), None); // space before colon
    }
}
