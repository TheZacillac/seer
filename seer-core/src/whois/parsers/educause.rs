//! Parser for .edu domains (EDUCAUSE format).
//!
//! EDUCAUSE uses a section-based format with tab-indented values under
//! section headers. Nameservers appear as a "Name Servers:" header
//! followed by indented hostnames on subsequent lines.
//!
//! Example EDUCAUSE response:
//! ```text
//! Domain Name: UW.EDU
//!
//! Registrant:
//!     University of Washington
//!     ...
//!
//! Administrative Contact:
//!     Domain Admin
//!     ...
//!     +1.2062216000
//!     domain-admin@uw.edu
//!
//! Technical Contact:
//!     Domain Admin
//!     ...
//!     +1.2062216000
//!     domain-admin@uw.edu
//!
//! Name Servers:
//!     HOLLY.S.UW.EDU
//!     MARGE.CAC.WASHINGTON.EDU
//!
//! Domain record activated:    05-Mar-1999
//! Domain record last updated: 31-Jul-2025
//! Domain expires:             31-Jul-2027
//! ```

use chrono::{DateTime, NaiveDate, Utc};
use once_cell::sync::Lazy;
use regex::Regex;

use super::{push_bounded, RegistryParser, MAX_NAMESERVERS};
use crate::whois::parser::WhoisResponse;

/// Regex patterns for EDUCAUSE-specific fields.
static DOMAIN_NAME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Domain Name:\s*(.+)$").expect("Invalid EDUCAUSE domain regex"));

static REGISTRANT_SECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Registrant:\s*$").expect("Invalid EDUCAUSE registrant regex"));

static ADMIN_SECTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^Administrative Contact:\s*$").expect("Invalid EDUCAUSE admin contact regex")
});

static TECH_SECTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^Technical Contact:\s*$").expect("Invalid EDUCAUSE tech contact regex")
});

static NAME_SERVERS_SECTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^Name Servers:\s*$").expect("Invalid EDUCAUSE name servers regex")
});

static ACTIVATED_DATE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^Domain record activated:\s*(.+)$")
        .expect("Invalid EDUCAUSE activated date regex")
});

static UPDATED_DATE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^Domain record last updated:\s*(.+)$")
        .expect("Invalid EDUCAUSE updated date regex")
});

static EXPIRES_DATE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^Domain expires:\s*(.+)$").expect("Invalid EDUCAUSE expires date regex")
});

/// Regex to match an email address in a line.
static EMAIL_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[\w.+-]+@[\w.-]+\.\w+").expect("Invalid email regex"));

/// Regex to match a phone number in a line.
static PHONE_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\+[\d.]+$").expect("Invalid phone regex"));

/// Parser for .edu domains using the EDUCAUSE format.
#[derive(Debug, Clone, Default)]
pub struct EducauseParser;

impl EducauseParser {
    pub fn new() -> Self {
        Self
    }

    /// Parses EDUCAUSE date format: DD-Mon-YYYY (e.g., "31-Jul-2027")
    fn parse_educause_date(date_str: &str) -> Option<DateTime<Utc>> {
        let cleaned = date_str.trim();

        let formats = [
            "%d-%b-%Y", // 31-Jul-2027
            "%d-%B-%Y", // 31-July-2027
            "%Y-%m-%d", // 2027-07-31 (fallback)
        ];

        for fmt in &formats {
            if let Ok(date) = NaiveDate::parse_from_str(cleaned, fmt) {
                return Some(date.and_hms_opt(0, 0, 0)?.and_utc());
            }
        }

        None
    }
}

impl RegistryParser for EducauseParser {
    fn supported_tlds(&self) -> &[&str] {
        &["edu"]
    }

    fn parse(&self, domain: &str, server: &str, raw: &str) -> WhoisResponse {
        let mut registrant = None;
        let mut nameservers = Vec::new();
        let mut creation_date = None;
        let mut expiration_date = None;
        let mut updated_date = None;
        let mut admin_name = None;
        let mut admin_email = None;
        let mut admin_phone = None;
        let mut tech_name = None;
        let mut tech_email = None;
        let mut tech_phone = None;

        #[derive(Clone, Copy)]
        enum Section {
            None,
            Registrant,
            AdminContact,
            TechContact,
            NameServers,
        }

        let mut current_section = Section::None;
        // Tracks whether the body actually contained a registration record. A
        // not-found response ("No match for ...") has no `Domain Name:` line, so
        // we must not stamp it with a registrar — that would make
        // WhoisResponse::is_available() short-circuit to "registered".
        let mut domain_found = false;

        for line in raw.lines() {
            let trimmed = line.trim();

            // Check for inline date fields (not indented, appear at end of response)
            if let Some(caps) = ACTIVATED_DATE.captures(trimmed) {
                if creation_date.is_none() {
                    if let Some(m) = caps.get(1) {
                        creation_date = Self::parse_educause_date(m.as_str());
                    }
                }
                current_section = Section::None;
                continue;
            }
            if let Some(caps) = UPDATED_DATE.captures(trimmed) {
                if updated_date.is_none() {
                    if let Some(m) = caps.get(1) {
                        updated_date = Self::parse_educause_date(m.as_str());
                    }
                }
                current_section = Section::None;
                continue;
            }
            if let Some(caps) = EXPIRES_DATE.captures(trimmed) {
                if expiration_date.is_none() {
                    if let Some(m) = caps.get(1) {
                        expiration_date = Self::parse_educause_date(m.as_str());
                    }
                }
                current_section = Section::None;
                continue;
            }

            // Check for section headers
            if REGISTRANT_SECTION.is_match(trimmed) {
                current_section = Section::Registrant;
                continue;
            } else if ADMIN_SECTION.is_match(trimmed) {
                current_section = Section::AdminContact;
                continue;
            } else if TECH_SECTION.is_match(trimmed) {
                current_section = Section::TechContact;
                continue;
            } else if NAME_SERVERS_SECTION.is_match(trimmed) {
                current_section = Section::NameServers;
                continue;
            } else if DOMAIN_NAME.is_match(trimmed) {
                domain_found = true;
                current_section = Section::None;
                continue;
            }

            // Empty line ends registrant section but not nameservers (they may span blank lines)
            if trimmed.is_empty() {
                match current_section {
                    Section::NameServers => {
                        // Only end nameservers section if we already have some
                        if !nameservers.is_empty() {
                            current_section = Section::None;
                        }
                    }
                    _ => {
                        current_section = Section::None;
                    }
                }
                continue;
            }

            // Parse section content (indented values with tabs or spaces)
            if line.starts_with('\t') || line.starts_with("    ") {
                let value = trimmed.to_string();

                match current_section {
                    Section::Registrant if registrant.is_none() => {
                        registrant = Some(value);
                    }
                    Section::AdminContact => {
                        // Check email/phone first so a contact block that leads
                        // with an email or phone (no name line) doesn't have it
                        // mis-stored as the name.
                        if EMAIL_PATTERN.is_match(trimmed) && admin_email.is_none() {
                            admin_email = Some(trimmed.to_string());
                        } else if PHONE_PATTERN.is_match(trimmed) && admin_phone.is_none() {
                            admin_phone = Some(trimmed.to_string());
                        } else if admin_name.is_none()
                            && !EMAIL_PATTERN.is_match(trimmed)
                            && !PHONE_PATTERN.is_match(trimmed)
                        {
                            admin_name = Some(value);
                        }
                    }
                    Section::TechContact => {
                        if EMAIL_PATTERN.is_match(trimmed) && tech_email.is_none() {
                            tech_email = Some(trimmed.to_string());
                        } else if PHONE_PATTERN.is_match(trimmed) && tech_phone.is_none() {
                            tech_phone = Some(trimmed.to_string());
                        } else if tech_name.is_none()
                            && !EMAIL_PATTERN.is_match(trimmed)
                            && !PHONE_PATTERN.is_match(trimmed)
                        {
                            tech_name = Some(value);
                        }
                    }
                    Section::NameServers => {
                        let ns = value.to_lowercase();
                        push_bounded(&mut nameservers, ns, MAX_NAMESERVERS);
                    }
                    _ => {}
                }
            } else {
                // Non-indented, non-empty line that isn't a section header ends the section
                current_section = Section::None;
            }
        }

        // Only attribute the record to EDUCAUSE when the response actually
        // carried registration DATA; a not-found body must stay registrar-less
        // so availability detection works. The current not-found format echoes
        // the query as a `Domain Name:` line, so `domain_found` alone is not
        // sufficient evidence of a registration record.
        let has_data = domain_found
            && (registrant.is_some()
                || !nameservers.is_empty()
                || creation_date.is_some()
                || expiration_date.is_some()
                || admin_name.is_some()
                || tech_name.is_some());

        WhoisResponse {
            domain: domain.to_string(),
            registrar: has_data.then(|| "EDUCAUSE".to_string()),
            registrant: registrant.clone(),
            organization: registrant,
            registrant_email: None,
            registrant_phone: None,
            registrant_address: None,
            registrant_country: has_data.then(|| "US".to_string()),
            admin_name,
            admin_organization: None,
            admin_email,
            admin_phone,
            tech_name,
            tech_organization: None,
            tech_email,
            tech_phone,
            creation_date,
            expiration_date,
            updated_date,
            nameservers,
            status: Vec::new(),
            dnssec: None,
            whois_server: server.to_string(),
            raw_response: raw.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    const SAMPLE_EDUCAUSE_RESPONSE: &str = r#"This Registry database contains ONLY .EDU domains.
The data in the EDUCAUSE Whois database is provided
by EDUCAUSE for information purposes in order to
assist in the process of obtaining information about
or related to .edu domain registration records.

The EDUCAUSE Whois database is authoritative for the
.EDU domain.

A Web interface for the .EDU EDUCAUSE Whois Server is
available at: http://whois.educause.edu

By submitting a Whois query, you agree that this information
will not be used to allow, enable, or otherwise support
the transmission of unsolicited commercial advertising or
solicitations via e-mail.  The use of electronic processes to
harvest information from this server is generally prohibited
except as reasonably necessary to register or modify .edu
domain names.

-------------------------------------------------------------

Domain Name: UW.EDU

Registrant:
	University of Washington
	4545 15th Ave NE
	Suite 400
	Seattle, WA 98105-4527
	USA

Administrative Contact:
	Domain Admin
	University of Washington
	4545 15th Avenue NE
	Box 354840 UW-IT NOC
	Seattle, WA 98105-4527
	USA
	+1.2062216000
	domain-admin@uw.edu

Technical Contact:
	Domain Admin
	University of Washington
	4545 15th Avenue NE
	Box 354840 UW-IT NOC
	Seattle, WA 98105-4527
	USA
	+1.2062216000
	domain-admin@uw.edu

Name Servers:
	HOLLY.S.UW.EDU
	MARGE.CAC.WASHINGTON.EDU
	HANNA.CAC.WASHINGTON.EDU

Domain record activated:    05-Mar-1999
Domain record last updated: 31-Jul-2025
Domain expires:             31-Jul-2027"#;

    #[test]
    fn test_educause_parser_registrant() {
        let parser = EducauseParser::new();
        let result = parser.parse("uw.edu", "whois.educause.edu", SAMPLE_EDUCAUSE_RESPONSE);

        assert_eq!(result.domain, "uw.edu");
        assert_eq!(
            result.registrant,
            Some("University of Washington".to_string())
        );
        assert_eq!(result.registrar, Some("EDUCAUSE".to_string()));
    }

    #[test]
    fn test_educause_parser_nameservers() {
        let parser = EducauseParser::new();
        let result = parser.parse("uw.edu", "whois.educause.edu", SAMPLE_EDUCAUSE_RESPONSE);

        assert_eq!(result.nameservers.len(), 3);
        assert!(result.nameservers.contains(&"holly.s.uw.edu".to_string()));
        assert!(result
            .nameservers
            .contains(&"marge.cac.washington.edu".to_string()));
        assert!(result
            .nameservers
            .contains(&"hanna.cac.washington.edu".to_string()));
    }

    #[test]
    fn test_educause_parser_dates() {
        let parser = EducauseParser::new();
        let result = parser.parse("uw.edu", "whois.educause.edu", SAMPLE_EDUCAUSE_RESPONSE);

        assert!(result.creation_date.is_some());
        let creation = result.creation_date.unwrap();
        assert_eq!(creation.year(), 1999);
        assert_eq!(creation.month(), 3);
        assert_eq!(creation.day(), 5);

        assert!(result.expiration_date.is_some());
        let expiry = result.expiration_date.unwrap();
        assert_eq!(expiry.year(), 2027);
        assert_eq!(expiry.month(), 7);
        assert_eq!(expiry.day(), 31);

        assert!(result.updated_date.is_some());
        let updated = result.updated_date.unwrap();
        assert_eq!(updated.year(), 2025);
        assert_eq!(updated.month(), 7);
        assert_eq!(updated.day(), 31);
    }

    #[test]
    fn test_educause_parser_contacts() {
        let parser = EducauseParser::new();
        let result = parser.parse("uw.edu", "whois.educause.edu", SAMPLE_EDUCAUSE_RESPONSE);

        assert_eq!(result.admin_name, Some("Domain Admin".to_string()));
        assert_eq!(result.admin_email, Some("domain-admin@uw.edu".to_string()));
        assert_eq!(result.admin_phone, Some("+1.2062216000".to_string()));

        assert_eq!(result.tech_name, Some("Domain Admin".to_string()));
        assert_eq!(result.tech_email, Some("domain-admin@uw.edu".to_string()));
        assert_eq!(result.tech_phone, Some("+1.2062216000".to_string()));
    }

    #[test]
    fn test_educause_parser_country() {
        let parser = EducauseParser::new();
        let result = parser.parse("uw.edu", "whois.educause.edu", SAMPLE_EDUCAUSE_RESPONSE);

        assert_eq!(result.registrant_country, Some("US".to_string()));
    }

    #[test]
    fn test_educause_date_parsing() {
        assert!(EducauseParser::parse_educause_date("05-Mar-1999").is_some());
        assert!(EducauseParser::parse_educause_date("31-Jul-2027").is_some());
        assert!(EducauseParser::parse_educause_date("31-July-2027").is_some());
    }

    #[test]
    fn test_supported_tlds() {
        let parser = EducauseParser::new();
        let tlds = parser.supported_tlds();
        assert!(tlds.contains(&"edu"));
        assert_eq!(tlds.len(), 1);
    }

    /// A contact block whose first indented line is an email (not a name).
    /// The old `else if` ordering took the first indented line as the name
    /// unconditionally, mis-storing the email as `admin_name` / `tech_name`.
    const SAMPLE_LEADING_EMAIL: &str = r#"Domain Name: EX.EDU

Administrative Contact:
	admin@ex.edu
	+1.5551234567

Technical Contact:
	noc@ex.edu
	+1.5559876543

Name Servers:
	NS1.EX.EDU

Domain record activated:    05-Mar-1999"#;

    /// EDUCAUSE's not-found body for an unregistered .edu domain. It carries the
    /// standard notice preamble followed by a "No match for ..." line and no
    /// `Domain Name:` record. The parser must NOT stamp a registrar onto it, or
    /// `is_available()` short-circuits to `false` and the domain is wrongly
    /// reported as registered.
    const SAMPLE_NO_MATCH: &str = r#"This Registry database contains ONLY .EDU domains.
The data in the EDUCAUSE Whois database is provided
by EDUCAUSE for information purposes in order to
assist in the process of obtaining information about
or related to .edu domain registration records.

-------------------------------------------------------------

No match for "NOTAREALDOMAIN123XYZ.EDU"."#;

    /// EDUCAUSE's CURRENT not-found body (captured live 2026-07) ECHOES the
    /// queried domain as a `Domain Name:` line before the not-found sentence,
    /// so `Domain Name:` presence alone must not count as a registration
    /// record — only extracted data (registrant, nameservers, dates,
    /// contacts) may stamp the registrar.
    const SAMPLE_NO_MATCH_CURRENT: &str = r#"Domain Name: SEER-SWEEP-ZK8QV3XW.EDU

The domain name you requested was not found in our database.

>>> Last update of WHOIS database: 2026-07-04T22:55:30+00:00 <<<"#;

    #[test]
    fn test_educause_current_not_found_reports_available() {
        let parser = EducauseParser::new();
        let result = parser.parse(
            "seer-sweep-zk8qv3xw.edu",
            "whois.educause.edu",
            SAMPLE_NO_MATCH_CURRENT,
        );
        assert_eq!(
            result.registrar, None,
            "domain-name echo alone must not stamp a registrar"
        );
        assert!(
            result.is_available(),
            "current-format not-found must be reported available"
        );
    }

    #[test]
    fn test_educause_no_match_reports_available() {
        let parser = EducauseParser::new();
        let result = parser.parse(
            "notarealdomain123xyz.edu",
            "whois.educause.edu",
            SAMPLE_NO_MATCH,
        );

        // A not-found response carries no registration record, so it must not
        // claim a registrar.
        assert_eq!(
            result.registrar, None,
            "not-found response must not carry a registrar"
        );
        // With no registrar/dates/nameservers, is_available() can see the
        // "No match" sentinel and correctly report the domain as available.
        assert!(
            result.is_available(),
            "unregistered .edu domain should be reported available"
        );
    }

    #[test]
    fn test_educause_contact_leading_email_not_stored_as_name() {
        let parser = EducauseParser::new();
        let result = parser.parse("ex.edu", "whois.educause.edu", SAMPLE_LEADING_EMAIL);

        // The leading email must NOT be captured as the contact name.
        assert_ne!(result.admin_name.as_deref(), Some("admin@ex.edu"));
        assert_ne!(result.tech_name.as_deref(), Some("noc@ex.edu"));
        assert!(
            result.admin_name.is_none(),
            "no real name in block; admin_name should stay None, got {:?}",
            result.admin_name
        );
        assert!(
            result.tech_name.is_none(),
            "no real name in block; tech_name should stay None, got {:?}",
            result.tech_name
        );

        // The email and phone must still be captured into the right fields.
        assert_eq!(result.admin_email.as_deref(), Some("admin@ex.edu"));
        assert_eq!(result.admin_phone.as_deref(), Some("+1.5551234567"));
        assert_eq!(result.tech_email.as_deref(), Some("noc@ex.edu"));
        assert_eq!(result.tech_phone.as_deref(), Some("+1.5559876543"));
    }
}
