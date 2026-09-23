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

use super::{push_bounded, MAX_NAMESERVERS, MAX_STATUSES};
use crate::whois::parser::WhoisResponse;

static_regex! {
    STATUS_PATTERN = r"(?i)^Status:\s*(.+)$";
    DNSSEC_PATTERN = r"(?i)^DNSSEC:\s*(.+)$";
    CREATION_PATTERN = r"(?i)^Creation Date:\s*(.+)$";
    UPDATED_PATTERN = r"(?i)^Updated Date:\s*(.+)$";
    REGISTRAR_SECTION = r"(?i)^Registrar:\s*$";
    ABUSE_SECTION = r"(?i)^Abuse Contact:\s*$";
    NAMESERVERS_SECTION = r"(?i)^Domain nameservers:\s*$";
}

/// TLDs this parser handles.
pub(super) const TLDS: &[&str] = &["nl"];

/// Parses .nl domains using the SIDN format.
pub(super) fn parse(domain: &str, server: &str, raw: &str) -> WhoisResponse {
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
                    push_bounded(&mut status, s, MAX_STATUSES);
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
                        creation_date = parse_date(m.as_str());
                    }
                }
                current_section = Section::None;
                continue;
            }
            if let Some(caps) = UPDATED_PATTERN.captures(trimmed) {
                if updated_date.is_none() {
                    if let Some(m) = caps.get(1) {
                        updated_date = parse_date(m.as_str());
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
                push_bounded(&mut nameservers, ns, MAX_NAMESERVERS);
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
        creation_date,
        updated_date,
        nameservers,
        status,
        dnssec,
        whois_server: server.to_string(),
        raw_response: raw.to_string(),
        // SIDN's public WHOIS omits the registrant and expiry. registrant_country
        // is not inferred from the TLD: .nl accepts holders worldwide, and a
        // "no match" body must not report one.
        ..Default::default()
    }
}

fn parse_date(date_str: &str) -> Option<DateTime<Utc>> {
    let cleaned = date_str.trim();
    if let Ok(d) = NaiveDate::parse_from_str(cleaned, "%Y-%m-%d") {
        return Some(d.and_hms_opt(0, 0, 0)?.and_utc());
    }
    None
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
        let result = parse("example.nl", "whois.sidn.nl", SAMPLE_SIDN_RESPONSE);

        assert_eq!(result.nameservers.len(), 3);
        assert!(result
            .nameservers
            .contains(&"anytest1.sidnlabs.nl".to_string()));
        assert!(result.nameservers.contains(&"ex1.sidnlabs.nl".to_string()));
        assert!(result.nameservers.contains(&"ex2.sidnlabs.nl".to_string()));
    }

    #[test]
    fn test_sidn_registrar() {
        let result = parse("example.nl", "whois.sidn.nl", SAMPLE_SIDN_RESPONSE);

        assert_eq!(
            result.registrar,
            Some("Stichting Internet Domeinregistratie Nederland".to_string())
        );
    }

    #[test]
    fn test_sidn_status() {
        let result = parse("example.nl", "whois.sidn.nl", SAMPLE_SIDN_RESPONSE);

        assert!(result.status.contains(&"active".to_string()));
    }

    #[test]
    fn test_sidn_dnssec() {
        let result = parse("example.nl", "whois.sidn.nl", SAMPLE_SIDN_RESPONSE);

        assert_eq!(result.dnssec, Some("signedDelegation".to_string()));
    }

    #[test]
    fn test_sidn_dates() {
        let result = parse("example.nl", "whois.sidn.nl", SAMPLE_SIDN_RESPONSE);

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

    /// .nl accepts holders worldwide and SIDN does not publish the
    /// registrant, so no country is reported (not even for a free name).
    #[test]
    fn test_sidn_country() {
        let result = parse("example.nl", "whois.sidn.nl", SAMPLE_SIDN_RESPONSE);
        assert_eq!(result.registrant_country, None);

        let result = parse("nosuch-xyz.nl", "whois.sidn.nl", "nosuch-xyz.nl is free\n");
        assert_eq!(result.registrant_country, None);
        assert!(result.is_available());
    }
}
