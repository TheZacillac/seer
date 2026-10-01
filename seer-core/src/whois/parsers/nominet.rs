//! Parser for .uk domains (Nominet format), also used for .gg and .je.
//!
//! Nominet uses a section-based format with indented values and
//! human-readable date formats. Island Networks (the CIDR registry for .gg
//! and .je) prints the same layout with a few differences: a `Domain:` /
//! `Domain Status:` heading pair, prose dates without a colon
//! (`Registered on 24th April 1997 at 00:00:00.000`), a registrar followed by
//! its URL in parentheses, and no expiry date (fees are annual).
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

use super::{push_bounded, MAX_NAMESERVERS, MAX_STATUSES};
use crate::whois::parser::WhoisResponse;

// Regex patterns for Nominet-specific fields.
static_regex! {
    DOMAIN_SECTION = r"(?i)^Domain(?: name)?:\s*$";
    /// Island Networks' heading for the domain state (`Active`).
    DOMAIN_STATUS_SECTION = r"(?i)^Domain Status:\s*$";
    REGISTRANT_SECTION = r"(?i)^Registrant:\s*$";
    REGISTRAR_SECTION = r"(?i)^Registrar:\s*$";
    REGISTRATION_DATE = r"(?i)^Registration date:\s*$";
    EXPIRY_DATE = r"(?i)^Expiry date:\s*$";
    LAST_UPDATED = r"(?i)^Last updated:\s*$";

    /// `.uk` output groups dates under a single `Relevant dates:` header with
    /// indented inline `Registered on:` / `Expiry date:` / `Last updated:`
    /// sub-fields, rather than as standalone per-date section headers.
    RELEVANT_DATES_SECTION = r"(?i)^Relevant dates:\s*$";
    NAME_SERVERS_SECTION = r"(?i)^Name servers:\s*$";
    STATUS_SECTION = r"(?i)^Registration status:\s*$";
    DNSSEC_SECTION = r"(?i)^DNSSEC:\s*$";
}

/// The .uk TLD and the second-level zones Nominet serves, plus Island
/// Networks' .gg and .je (their second-level zones dispatch on the TLD).
pub(super) const TLDS: &[&str] = &[
    "uk", "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "gg", "je",
];

/// Parses .uk domains using the Nominet format.
pub(super) fn parse(domain: &str, server: &str, raw: &str) -> WhoisResponse {
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
        RelevantDates,
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
        } else if RELEVANT_DATES_SECTION.is_match(trimmed) {
            current_section = Section::RelevantDates;
            continue;
        } else if NAME_SERVERS_SECTION.is_match(trimmed) {
            current_section = Section::NameServers;
            continue;
        } else if STATUS_SECTION.is_match(trimmed) || DOMAIN_STATUS_SECTION.is_match(trimmed) {
            current_section = Section::Status;
            continue;
        } else if DNSSEC_SECTION.is_match(trimmed) {
            current_section = Section::Dnssec;
            continue;
        } else if DOMAIN_SECTION.is_match(trimmed) {
            current_section = Section::None;
            continue;
        }

        // An empty line ends the current section. The one exception is a
        // blank line directly after `Name servers:` (before any host):
        // real .uk output indents EVERY line by 4 spaces, so a section
        // left open past its blank terminator would swallow the trailing
        // `    WHOIS lookup made at …` line as a nameserver.
        if trimmed.is_empty() {
            if !matches!(current_section, Section::NameServers) || !nameservers.is_empty() {
                current_section = Section::None;
            }
            continue;
        }

        // Parse section content (indented values)
        if line.starts_with("    ") || line.starts_with('\t') {
            let value = trimmed.to_string();

            match current_section {
                Section::Registrant if registrant.is_none() && !is_redacted(&value) => {
                    registrant = Some(value);
                }
                Section::Registrar if registrar.is_none() => {
                    // Drop Nominet's `[Tag = EXAMPLE]` and Island Networks'
                    // `(http://…)` suffixes.
                    let name = value
                        .split('[')
                        .next()
                        .and_then(|v| v.split(" (http").next())
                        .unwrap_or(&value)
                        .trim()
                        .to_string();
                    if !is_redacted(&name) {
                        registrar = Some(name);
                    }
                }
                Section::RegistrationDate if creation_date.is_none() => {
                    creation_date = parse_nominet_date(&value);
                }
                Section::ExpiryDate if expiration_date.is_none() => {
                    expiration_date = parse_nominet_date(&value);
                }
                Section::LastUpdated if updated_date.is_none() => {
                    updated_date = parse_nominet_date(&value);
                }
                Section::RelevantDates => {
                    // Indented inline `Sub-field: value` lines. Match the
                    // sub-field name case-insensitively and slice the value
                    // at the actual `:` (char-boundary safe). Island Networks
                    // writes `Registered on <date>` with no colon, and its
                    // time-of-day would otherwise be the split point.
                    let split =
                        relevant_date_without_colon(&value).or_else(|| value.split_once(':'));
                    if let Some((field, raw_date)) = split {
                        let date = raw_date.trim();
                        let field = field.trim();
                        if field.eq_ignore_ascii_case("Registered on") && creation_date.is_none() {
                            creation_date = parse_nominet_date(date);
                        } else if (field.eq_ignore_ascii_case("Expiry date")
                            || field.eq_ignore_ascii_case("Renewal date"))
                            && expiration_date.is_none()
                        {
                            expiration_date = parse_nominet_date(date);
                        } else if field.eq_ignore_ascii_case("Last updated")
                            && updated_date.is_none()
                        {
                            updated_date = parse_nominet_date(date);
                        }
                    }
                }
                Section::NameServers => {
                    // Hosts in the zone carry glue after the name
                    // (`ns1.example.co.uk   192.0.2.1  2001:db8::1`);
                    // keep only the hostname.
                    if let Some(host) = value.split_whitespace().next() {
                        push_bounded(&mut nameservers, host.to_lowercase(), MAX_NAMESERVERS);
                    }
                }
                Section::Status => {
                    push_bounded(&mut status, value, MAX_STATUSES);
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
        creation_date,
        expiration_date,
        updated_date,
        nameservers,
        status,
        dnssec,
        whois_server: server.to_string(),
        raw_response: raw.to_string(),
        // registrant_country is not inferred from the TLD: .uk accepts holders
        // worldwide, and a "no match" body must not report one.
        ..Default::default()
    }
}

/// Splits Island Networks' colon-less `Registered on 24th April 1997 at …`
/// into `("Registered on", "24th April 1997 at …")`.
fn relevant_date_without_colon(value: &str) -> Option<(&str, &str)> {
    const FIELD: &str = "Registered on ";
    let head = value.get(..FIELD.len())?;
    let rest = &value[FIELD.len()..];
    (head.eq_ignore_ascii_case(FIELD) && !rest.trim_start().starts_with(':'))
        .then(|| (head.trim_end(), rest))
}

/// Parses Nominet's date format: DD-Month-YYYY or DD Month YYYY, plus Island
/// Networks' `24th April 1997 at 00:00:00.000` (time dropped, ordinal
/// suffix stripped).
fn parse_nominet_date(date_str: &str) -> Option<DateTime<Utc>> {
    static_regex! {
        ORDINAL_DAY = r"^(\d{1,2})(?:st|nd|rd|th)\b";
    }
    let date_part = date_str.split(" at ").next().unwrap_or(date_str).trim();
    let cleaned = ORDINAL_DAY.replace(date_part, "$1");
    let cleaned = cleaned.as_ref();

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
        let result = parse("example.co.uk", "whois.nic.uk", SAMPLE_NOMINET_RESPONSE_2);

        assert_eq!(result.domain, "example.co.uk");
        assert_eq!(result.registrant, Some("Test Company".to_string()));
        assert_eq!(result.registrar, Some("Another Registrar".to_string()));
    }

    #[test]
    fn test_nominet_parser_dates() {
        let result = parse("example.co.uk", "whois.nic.uk", SAMPLE_NOMINET_RESPONSE_2);

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
        let result = parse("example.co.uk", "whois.nic.uk", SAMPLE_NOMINET_RESPONSE_2);

        assert_eq!(result.nameservers.len(), 3);
        assert!(result.nameservers.contains(&"ns1.test.co.uk".to_string()));
        assert!(result.nameservers.contains(&"ns2.test.co.uk".to_string()));
        assert!(result.nameservers.contains(&"ns3.test.co.uk".to_string()));
    }

    #[test]
    fn test_nominet_parser_dnssec() {
        let result = parse("example.co.uk", "whois.nic.uk", SAMPLE_NOMINET_RESPONSE_2);

        assert_eq!(result.dnssec, Some("Signed".to_string()));
    }

    #[test]
    fn test_nominet_date_parsing() {
        assert!(parse_nominet_date("01-January-2020").is_some());
        assert!(parse_nominet_date("15 March 2019").is_some());
        assert!(parse_nominet_date("01-Jan-2020").is_some());
    }

    #[test]
    fn test_redaction_detection() {
        assert!(is_redacted("REDACTED FOR PRIVACY"));
        assert!(is_redacted("Data protected"));
        assert!(is_redacted("Not disclosed"));
        assert!(!is_redacted("Example Ltd"));
    }

    /// .uk accepts holders worldwide, so the country is not inferred from the
    /// TLD — and an unregistered domain must not print `Registrant Country: GB`.
    #[test]
    fn test_country_code() {
        let result = parse("example.co.uk", "whois.nic.uk", SAMPLE_NOMINET_RESPONSE_2);
        assert_eq!(result.registrant_country, None);

        let raw = "No match for \"nosuch-xyz.co.uk\".\n\n\
                   This domain name has not been registered.\n\n\
                   WHOIS lookup made at 10:04:07 22-Sep-2026\n";
        let result = parse("nosuch-xyz.co.uk", "whois.nic.uk", raw);
        assert_eq!(result.registrant_country, None);
        assert!(result.is_available());
    }

    #[test]
    fn test_nominet_relevant_dates_block() {
        // Real .uk output groups creation/expiry/updated under a single
        // `Relevant dates:` header with indented inline sub-fields, not as
        // standalone `Registration date:` / `Expiry date:` headers. All three
        // dates must be parsed from that block.
        let result = parse("example.co.uk", "whois.nic.uk", SAMPLE_NOMINET_RESPONSE);

        let creation = result
            .creation_date
            .expect("creation date from Registered on:");
        assert_eq!(creation.year(), 2020);
        assert_eq!(creation.month(), 1);
        assert_eq!(creation.day(), 1);

        let expiry = result
            .expiration_date
            .expect("expiry date from Expiry date:");
        assert_eq!(expiry.year(), 2025);
        assert_eq!(expiry.month(), 1);
        assert_eq!(expiry.day(), 1);

        let updated = result
            .updated_date
            .expect("updated date from Last updated:");
        assert_eq!(updated.year(), 2023);
        assert_eq!(updated.month(), 6);
        assert_eq!(updated.day(), 15);
    }

    /// Real .uk output indents every line (headers by 4 spaces, values by
    /// 8), so the blank line after the host list is the only thing ending the
    /// `Name servers:` section: the trailing `    WHOIS lookup made at …` line
    /// must not become a nameserver.
    #[test]
    fn test_nominet_nameservers_end_at_blank_line() {
        let result = parse("example.co.uk", "whois.nic.uk", SAMPLE_NOMINET_RESPONSE);
        assert_eq!(
            result.nameservers,
            vec!["ns1.example.co.uk", "ns2.example.co.uk"],
            "the WHOIS-lookup-made-at footer is not a nameserver"
        );
    }

    #[test]
    fn test_nominet_nameserver_glue_is_stripped() {
        let raw = "\
    Domain name:
        example.co.uk

    Name servers:
        ns1.example.co.uk         192.0.2.1  2001:db8::1
        ns2.example.co.uk         192.0.2.2
        ns1.example.net

    WHOIS lookup made at 10:04:07 22-Sep-2026
";
        let result = parse("example.co.uk", "whois.nic.uk", raw);
        assert_eq!(
            result.nameservers,
            vec!["ns1.example.co.uk", "ns2.example.co.uk", "ns1.example.net"]
        );
    }

    #[test]
    fn test_nominet_relevant_dates_renewal_alias() {
        // Some .uk responses use `Renewal date:` instead of `Expiry date:`
        // inside the Relevant dates block.
        let raw = "\
Domain name:
    example.co.uk

Relevant dates:
    Registered on: 03-March-2018
    Renewal date: 03-March-2026
    Last updated: 10-October-2023
";
        let result = parse("example.co.uk", "whois.nic.uk", raw);

        let expiry = result
            .expiration_date
            .expect("expiry date from Renewal date:");
        assert_eq!(expiry.year(), 2026);
        assert_eq!(expiry.month(), 3);
        assert_eq!(expiry.day(), 3);
    }

    /// Island Networks (.gg/.je) reply, trimmed from a live `nic.gg` query
    /// (2026-10-01, CRLF on some lines as served).
    const ISLAND_NETWORKS_RESPONSE: &str = "Domain:\r\n     nic.gg\r\n\
Domain Status:\r\n     Active\r\n\
Registrant:\n     Redacted for privacy\n\
Registrar:\n     Alderney Domains (http://www.channelisles.net)\n\
Relevant dates:\n     Registered on 24th April 1997 at 00:00:00.000\n\
\x20    Registry fee due on 01st January each year\n\
Registration status:\n     Registered until cancelled\n\
Name servers:\n     ns1.livedns.co.uk\n     ns2.livedns.co.uk\n\
\n\
WHOIS lookup made on Thu, 1 Oct 2026 at 19:14:26 BST\n";

    #[test]
    fn island_networks_format_parses() {
        let r = parse("nic.gg", "whois.gg", ISLAND_NETWORKS_RESPONSE);
        assert_eq!(r.registrar.as_deref(), Some("Alderney Domains"));
        assert!(r.registrant.is_none(), "redacted registrant is dropped");
        let created = r.creation_date.expect("Registered on <ordinal date>");
        assert_eq!(
            (created.year(), created.month(), created.day()),
            (1997, 4, 24)
        );
        assert!(
            r.expiration_date.is_none(),
            "annual fee line is not an expiry"
        );
        assert_eq!(
            r.nameservers,
            vec!["ns1.livedns.co.uk", "ns2.livedns.co.uk"]
        );
        assert_eq!(r.status, vec!["Active", "Registered until cancelled"]);
    }

    #[test]
    fn colon_less_relevant_date_split_only_matches_registered_on() {
        assert_eq!(
            relevant_date_without_colon("Registered on 24th April 1997 at 00:00:00.000"),
            Some(("Registered on", "24th April 1997 at 00:00:00.000"))
        );
        // Nominet's own colon form is left to the `:` split.
        assert_eq!(
            relevant_date_without_colon("Registered on: 01-January-2020"),
            None
        );
        assert_eq!(
            relevant_date_without_colon("Expiry date: 01-Jan-2025"),
            None
        );
    }
}
