//! Parser for .lv domains (NIC.LV format).
//!
//! NIC.LV uses a section-based format where each section is introduced by a
//! bracketed header (e.g. `[Holder]`, `[Registrar]`, `[Nservers]`) and the
//! fields below it are written as `Key: value` until the next blank line or
//! next section header.
//!
//! Example NIC.LV response:
//! ```text
//! [Domain]
//! Domain: example.lv
//! Status: active
//!
//! [Holder]
//! Type: Legal person
//! Country: LV
//! Name: Example Holder SIA
//! Address: ...
//! RegNr: 12345678901
//! Visit: https://www.nic.lv/whois/contact/example.lv to contact.
//!
//! [Tech]
//! Type: Natural person
//! Visit: https://www.nic.lv/whois/contact/example.lv to contact.
//!
//! [Registrar]
//! Type: Legal person
//! Name: Example Registrar Ltd
//! ...
//!
//! [Nservers]
//! Nserver: ns1.example.com
//! Nserver: ns2.example.com
//!
//! [Whois]
//! Updated: 2026-05-26T11:12:34.874386+00:00
//! ```
//!
//! Unregistered domains return `Status: free` with no other sections; that
//! string is matched by the generic `AVAILABILITY_PATTERNS` in
//! `crate::whois::parser`, so this parser does not need to special-case it.

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;

use super::{push_bounded, RegistryParser, MAX_NAMESERVERS, MAX_STATUSES};
use crate::whois::parser::WhoisResponse;

static SECTION_HEADER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\[([A-Za-z]+)\]\s*$").expect("Invalid NIC.LV section regex"));

static KEY_VALUE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^([A-Za-z]+):\s*(.+?)\s*$").expect("Invalid NIC.LV key/value regex"));

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Domain,
    Holder,
    Tech,
    Registrar,
    Nservers,
    Whois,
    Other,
}

impl Section {
    fn from_header(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "domain" => Section::Domain,
            "holder" => Section::Holder,
            "tech" => Section::Tech,
            "registrar" => Section::Registrar,
            "nservers" => Section::Nservers,
            "whois" => Section::Whois,
            _ => Section::Other,
        }
    }
}

/// Parser for .lv domains using the NIC.LV section-based format.
#[derive(Debug, Clone, Default)]
pub struct NicLvParser;

impl NicLvParser {
    pub fn new() -> Self {
        Self
    }

    fn parse_iso8601(value: &str) -> Option<DateTime<Utc>> {
        // NIC.LV uses fractional-second ISO8601 like `2026-05-26T11:12:34.874386+00:00`.
        DateTime::parse_from_rfc3339(value.trim())
            .ok()
            .map(|dt| dt.with_timezone(&Utc))
    }
}

impl RegistryParser for NicLvParser {
    fn supported_tlds(&self) -> &[&str] {
        &["lv"]
    }

    fn parse(&self, domain: &str, server: &str, raw: &str) -> WhoisResponse {
        let mut current = Section::None;

        let mut status: Vec<String> = Vec::new();
        let mut nameservers: Vec<String> = Vec::new();
        let mut registrar: Option<String> = None;
        let mut registrant: Option<String> = None;
        let mut registrant_address: Option<String> = None;
        let mut registrant_country: Option<String> = None;
        let mut updated_date: Option<DateTime<Utc>> = None;

        for line in raw.lines() {
            let trimmed = line.trim();

            // Skip blanks and disclaimer comment lines.
            if trimmed.is_empty() || trimmed.starts_with('%') || trimmed.starts_with('#') {
                continue;
            }

            if let Some(caps) = SECTION_HEADER.captures(trimmed) {
                current = Section::from_header(&caps[1]);
                continue;
            }

            let Some(caps) = KEY_VALUE.captures(trimmed) else {
                continue;
            };
            let key = caps[1].to_ascii_lowercase();
            let value = caps[2].trim();
            if value.is_empty() {
                continue;
            }

            match (current, key.as_str()) {
                (Section::Domain, "status") => {
                    push_bounded(&mut status, value.to_string(), MAX_STATUSES);
                }
                (Section::Holder, "name") if registrant.is_none() => {
                    registrant = Some(value.to_string());
                }
                (Section::Holder, "address") if registrant_address.is_none() => {
                    registrant_address = Some(value.to_string());
                }
                (Section::Holder, "country") if registrant_country.is_none() => {
                    registrant_country = Some(value.to_string());
                }
                (Section::Registrar, "name") if registrar.is_none() => {
                    registrar = Some(value.to_string());
                }
                // NIC.LV emits `Nserver: -` for domains with no delegation;
                // the dash is a placeholder, not a nameserver.
                (Section::Nservers, "nserver") if value != "-" => {
                    push_bounded(
                        &mut nameservers,
                        value.to_ascii_lowercase(),
                        MAX_NAMESERVERS,
                    );
                }
                (Section::Whois, "updated") if updated_date.is_none() => {
                    updated_date = Self::parse_iso8601(value);
                }
                _ => {}
            }
        }

        WhoisResponse {
            domain: domain.to_string(),
            registrar,
            registrant,
            organization: None,
            registrant_email: None,
            registrant_phone: None,
            registrant_address,
            registrant_country,
            admin_name: None,
            admin_organization: None,
            admin_email: None,
            admin_phone: None,
            tech_name: None,
            tech_organization: None,
            tech_email: None,
            tech_phone: None,
            creation_date: None, // NIC.LV does not publish creation date in WHOIS
            expiration_date: None, // NIC.LV does not publish expiry in WHOIS
            updated_date,
            nameservers,
            status,
            dnssec: None, // not exposed via NIC.LV WHOIS
            whois_server: server.to_string(),
            raw_response: raw.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    const REGISTERED: &str = "[Domain]\n\
Domain: myroyalcanin.lv\n\
Status: active\n\
\n\
[Holder]\n\
Type: Legal person\n\
Country: LV\n\
Name: Mars Latvia SIA\n\
Address: Gertrudes Street 10/12, 4th Floor, Riga, , LV-1010, Latvia\n\
RegNr: 40003178606\n\
Visit: https://www.nic.lv/whois/contact/myroyalcanin.lv to contact.\n\
\n\
[Tech]\n\
Type: Natural person\n\
Visit: https://www.nic.lv/whois/contact/myroyalcanin.lv to contact.\n\
\n\
[Registrar]\n\
Type: Legal person\n\
Name: Com Laude\n\
Address: 28 Little Russell Street, London, , WC1A 2HN, United Kingdom\n\
RegNr: 5047655\n\
Visit: https://www.nic.lv/whois/contact/myroyalcanin.lv to contact.\n\
\n\
[Nservers]\n\
Nserver: ns-1060.awsdns-04.org\n\
Nserver: ns-2044.awsdns-63.co.uk\n\
Nserver: ns-444.awsdns-55.com\n\
Nserver: ns-585.awsdns-09.net\n\
\n\
[Whois]\n\
Updated: 2026-05-26T11:12:34.874386+00:00\n\
\n\
[Disclaimer]\n\
% boilerplate disclaimer text omitted\n";

    const FREE: &str = "[Domain]\n\
Domain: thisdomaindoesnotexist.lv\n\
Status: free\n\
\n\
[Whois]\n\
Updated: 2026-05-26T11:12:34.874386+00:00\n";

    fn parse(raw: &str) -> WhoisResponse {
        NicLvParser::new().parse("myroyalcanin.lv", "whois.nic.lv", raw)
    }

    #[test]
    fn registered_extracts_registrar() {
        let r = parse(REGISTERED);
        assert_eq!(r.registrar.as_deref(), Some("Com Laude"));
    }

    #[test]
    fn registered_extracts_holder_as_registrant() {
        let r = parse(REGISTERED);
        assert_eq!(r.registrant.as_deref(), Some("Mars Latvia SIA"));
        assert_eq!(r.registrant_country.as_deref(), Some("LV"));
        assert!(r
            .registrant_address
            .as_deref()
            .unwrap()
            .contains("Gertrudes Street"));
    }

    #[test]
    fn registered_extracts_status_active() {
        let r = parse(REGISTERED);
        assert_eq!(r.status, vec!["active".to_string()]);
    }

    #[test]
    fn registered_extracts_nameservers() {
        let r = parse(REGISTERED);
        assert_eq!(r.nameservers.len(), 4);
        assert!(r.nameservers.contains(&"ns-1060.awsdns-04.org".to_string()));
        assert!(r.nameservers.contains(&"ns-585.awsdns-09.net".to_string()));
    }

    #[test]
    fn registered_parses_updated_date() {
        let r = parse(REGISTERED);
        let updated = r.updated_date.expect("updated date should parse");
        assert_eq!(updated.year(), 2026);
        assert_eq!(updated.month(), 5);
        assert_eq!(updated.day(), 26);
    }

    #[test]
    fn registered_does_not_misclassify_as_available() {
        // Regression: the bug we shipped against — the generic parser left
        // these fields empty, the parallel race timed out, and the lookup fell
        // into availability_fallback which then mis-rendered the domain as
        // AVAILABLE. With this parser populating registrar/dates/etc., the
        // WHOIS leg has core data and the lookup stays in the WHOIS path.
        let r = parse(REGISTERED);
        assert!(
            !r.is_available(),
            "registered .lv must not match availability patterns"
        );
    }

    #[test]
    fn free_status_is_recognised_as_available() {
        let r = parse(FREE);
        assert!(r.status.contains(&"free".to_string()));
        assert!(
            r.is_available(),
            "Status: free should mark .lv as available"
        );
    }

    #[test]
    fn supported_tlds() {
        assert_eq!(NicLvParser::new().supported_tlds(), &["lv"]);
    }

    #[test]
    fn placeholder_dash_nserver_is_skipped() {
        // NIC.LV emits `Nserver: -` when a domain has no delegation (seen
        // live on nic.lv itself); "-" must not be recorded as a nameserver.
        let raw = "[Domain]\nDomain: nic.lv\nStatus: active\n\n[Nservers]\nNserver: -\n";
        let r = parse(raw);
        assert!(
            r.nameservers.is_empty(),
            "placeholder '-' must not be a nameserver, got {:?}",
            r.nameservers
        );
    }

    #[test]
    fn ignores_disclaimer_percent_lines() {
        // The disclaimer block uses `%` comment lines; the parser must skip
        // them rather than try to interpret them as Key:value pairs.
        let raw = "[Disclaimer]\n% foo: bar\n% baz: qux\n";
        let r = parse(raw);
        assert!(r.registrar.is_none());
        assert!(r.registrant.is_none());
    }
}
