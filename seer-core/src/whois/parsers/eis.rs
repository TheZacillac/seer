//! Parser for .ee domains (EIS / Estonian Internet Foundation format).
//!
//! EIS uses an indented-section format: each section begins with a header
//! ending in `:` at column 0, followed by indented `key:    value` lines.
//! The same key name (`name:`, `email:`, `changed:`) appears under multiple
//! sections (Domain / Registrant / Registrar / contacts), so the generic
//! regex parser cannot disambiguate without sectioning.
//!
//! Example EIS response:
//! ```text
//! Domain:
//! name:       example.ee
//! status:     ok (paid and in zone)
//! registered: 2012-01-27 10:00:15 +02:00
//! changed:    2025-12-05 08:05:19 +02:00
//! expire:     2027-01-28
//!
//! Registrant:
//! name:       Example Holder AS
//! org id:     10421629
//! country:    EE
//! email:      ...
//!
//! Registrar:
//! name:       Zone Media OÜ
//! url:        http://www.zone.ee
//!
//! Name servers:
//! nserver:    ns1.example.com
//! nserver:    ns2.example.com
//!
//! DNSSEC:
//! dnskey:     257 3 13 ...
//! ```
//!
//! "Domain not found" responses use the bare phrase and are matched by the
//! generic `AVAILABILITY_PATTERNS`, so this parser does not special-case them.

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;

use super::RegistryParser;
use crate::whois::parser::WhoisResponse;

static KEY_VALUE: Lazy<Regex> = Lazy::new(|| {
    // `key:   value` lines. EIS fields are flush-left, with multiple spaces
    // padding before the value. Keys may contain spaces (e.g. `org id`).
    Regex::new(r"^([a-z][a-z0-9 ]*):\s*(.+?)\s*$").expect("Invalid EIS key/value regex")
});

/// Known section headers. We can't generically match `Foo:` as a section
/// because empty-value fields like `outzone:` would be ambiguous. Whitelist
/// the section names EIS actually uses; anything else keeps the current
/// section so we don't lose data on unexpected lines.
fn parse_section_header(line: &str) -> Option<Section> {
    let trimmed = line.trim_end();
    // Must end with `:` and have no leading whitespace.
    let stripped = trimmed.strip_suffix(':')?;
    if stripped.is_empty() || stripped.starts_with(char::is_whitespace) {
        return None;
    }
    Section::from_header(stripped)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Domain,
    Registrant,
    Admin,
    Tech,
    Registrar,
    Nameservers,
    Dnssec,
}

impl Section {
    /// Returns Some(section) only for the known EIS section names. Unknown
    /// headers leave the section unchanged so a stray colon-ending line
    /// doesn't drop following fields on the floor.
    fn from_header(name: &str) -> Option<Self> {
        let n = name.trim().to_ascii_lowercase();
        Some(match n.as_str() {
            "domain" => Section::Domain,
            "registrant" => Section::Registrant,
            "administrative contact" => Section::Admin,
            "technical contact" => Section::Tech,
            "registrar" => Section::Registrar,
            "name servers" => Section::Nameservers,
            "dnssec" => Section::Dnssec,
            _ => return None,
        })
    }
}

/// Parser for .ee domains using the EIS section-based format.
#[derive(Debug, Clone, Default)]
pub struct EisParser;

impl EisParser {
    pub fn new() -> Self {
        Self
    }

    /// EIS dates appear in two shapes: `YYYY-MM-DD HH:MM:SS ±HH:MM` (full
    /// timestamps for `registered:` and `changed:`) and bare `YYYY-MM-DD`
    /// (for `expire:`). Try both.
    fn parse_date(raw: &str) -> Option<DateTime<Utc>> {
        let s = raw.trim();
        if let Ok(dt) = DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S %:z") {
            return Some(dt.with_timezone(&Utc));
        }
        if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
            return Some(d.and_hms_opt(0, 0, 0)?.and_utc());
        }
        None
    }

    /// `email:` lines in EIS may carry a redaction placeholder; preserve only
    /// real-looking email values.
    fn is_real_value(value: &str) -> bool {
        let lower = value.to_ascii_lowercase();
        !lower.contains("not disclosed") && !lower.contains("redacted")
    }
}

impl RegistryParser for EisParser {
    fn supported_tlds(&self) -> &[&str] {
        &["ee"]
    }

    fn parse(&self, domain: &str, server: &str, raw: &str) -> WhoisResponse {
        let mut current = Section::None;

        let mut status: Vec<String> = Vec::new();
        let mut nameservers: Vec<String> = Vec::new();
        let mut registrar: Option<String> = None;
        let mut registrant: Option<String> = None;
        let mut organization: Option<String> = None;
        let mut registrant_country: Option<String> = None;
        let mut registrant_email: Option<String> = None;
        let mut registrant_phone: Option<String> = None;
        let mut admin_name: Option<String> = None;
        let mut admin_email: Option<String> = None;
        let mut tech_name: Option<String> = None;
        let mut tech_email: Option<String> = None;
        let mut creation_date: Option<DateTime<Utc>> = None;
        let mut expiration_date: Option<DateTime<Utc>> = None;
        let mut updated_date: Option<DateTime<Utc>> = None;
        let mut dnssec: Option<String> = None;

        for line in raw.lines() {
            // Skip preamble/footer chatter lines that don't match either shape.
            if let Some(section) = parse_section_header(line) {
                current = section;
                continue;
            }

            let Some(caps) = KEY_VALUE.captures(line) else {
                continue;
            };
            let key = caps[1].to_ascii_lowercase();
            let value = caps[2].trim().to_string();
            if value.is_empty() || !Self::is_real_value(&value) {
                continue;
            }

            match (current, key.as_str()) {
                (Section::Domain, "status") => {
                    // EIS statuses look like `ok (paid and in zone)`; keep the
                    // short form for downstream comparisons but preserve raw
                    // in the list too if it adds info.
                    let short = value
                        .split_whitespace()
                        .next()
                        .unwrap_or(&value)
                        .to_string();
                    if !status.contains(&short) {
                        status.push(short);
                    }
                }
                (Section::Domain, "registered") if creation_date.is_none() => {
                    creation_date = Self::parse_date(&value);
                }
                (Section::Domain, "changed") if updated_date.is_none() => {
                    updated_date = Self::parse_date(&value);
                }
                (Section::Domain, "expire") if expiration_date.is_none() => {
                    expiration_date = Self::parse_date(&value);
                }
                (Section::Registrant, "name") if registrant.is_none() => {
                    registrant = Some(value);
                }
                (Section::Registrant, "org id") if organization.is_none() => {
                    organization = Some(value);
                }
                (Section::Registrant, "country") if registrant_country.is_none() => {
                    registrant_country = Some(value);
                }
                (Section::Registrant, "email") if registrant_email.is_none() => {
                    registrant_email = Some(value);
                }
                (Section::Registrant, "phone") if registrant_phone.is_none() => {
                    registrant_phone = Some(value);
                }
                (Section::Admin, "name") if admin_name.is_none() => {
                    admin_name = Some(value);
                }
                (Section::Admin, "email") if admin_email.is_none() => {
                    admin_email = Some(value);
                }
                (Section::Tech, "name") if tech_name.is_none() => {
                    tech_name = Some(value);
                }
                (Section::Tech, "email") if tech_email.is_none() => {
                    tech_email = Some(value);
                }
                (Section::Registrar, "name") if registrar.is_none() => {
                    registrar = Some(value);
                }
                (Section::Nameservers, "nserver") => {
                    // EIS sometimes appends a glue IP after the host.
                    let ns = value
                        .split_whitespace()
                        .next()
                        .unwrap_or(&value)
                        .to_ascii_lowercase();
                    if !ns.is_empty() && !nameservers.contains(&ns) {
                        nameservers.push(ns);
                    }
                }
                (Section::Dnssec, "dnskey") if dnssec.is_none() => {
                    dnssec = Some("signedDelegation".to_string());
                }
                _ => {}
            }
        }

        WhoisResponse {
            domain: domain.to_string(),
            registrar,
            registrant,
            organization,
            registrant_email,
            registrant_phone,
            registrant_address: None,
            registrant_country,
            admin_name,
            admin_organization: None,
            admin_email,
            admin_phone: None,
            tech_name,
            tech_organization: None,
            tech_email,
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    const SAMPLE: &str = "Estonia .ee Top Level Domain WHOIS server\n\
\n\
Domain:\n\
name:       eestienergia.ee\n\
status:     ok (paid and in zone)\n\
registered: 2012-01-27 10:00:15 +02:00\n\
changed:    2025-12-05 08:05:19 +02:00\n\
expire:     2027-01-28\n\
\n\
Registrant:\n\
name:       Eesti Energia AS\n\
org id:     10421629\n\
country:    EE\n\
email:      Not Disclosed - Visit www.internet.ee for webbased WHOIS\n\
phone:      Not Disclosed - Visit www.internet.ee for webbased WHOIS\n\
changed:    2025-12-05 08:05:19 +02:00\n\
\n\
Administrative contact:\n\
name:       Not Disclosed - Visit www.internet.ee for webbased WHOIS\n\
email:      Not Disclosed - Visit www.internet.ee for webbased WHOIS\n\
\n\
Technical contact:\n\
name:       Not Disclosed - Visit www.internet.ee for webbased WHOIS\n\
email:      Not Disclosed - Visit www.internet.ee for webbased WHOIS\n\
\n\
Registrar:\n\
name:       Zone Media OÜ\n\
url:        http://www.zone.ee\n\
phone:      +372 6886886\n\
changed:    2020-07-01 13:55:58 +03:00\n\
\n\
Name servers:\n\
nserver:   leonidas.ns.cloudflare.com\n\
nserver:   sara.ns.cloudflare.com\n\
changed:   2023-04-20 16:05:04 +03:00\n\
\n\
DNSSEC:\n\
dnskey:    257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl\n\
changed:   2023-05-08 09:20:15 +03:00\n";

    fn parse(raw: &str) -> WhoisResponse {
        EisParser::new().parse("eestienergia.ee", "whois.tld.ee", raw)
    }

    #[test]
    fn extracts_registrar_from_registrar_section_not_domain_section() {
        // Regression: the generic parser previously returned
        // `name:       Zone Media OÜ` (the whole line) because it had no
        // section context. We must return the actual value.
        let r = parse(SAMPLE);
        assert_eq!(r.registrar.as_deref(), Some("Zone Media OÜ"));
    }

    #[test]
    fn extracts_registrant_separately_from_registrar() {
        let r = parse(SAMPLE);
        assert_eq!(r.registrant.as_deref(), Some("Eesti Energia AS"));
        assert_eq!(r.organization.as_deref(), Some("10421629"));
        assert_eq!(r.registrant_country.as_deref(), Some("EE"));
    }

    #[test]
    fn redacted_emails_are_dropped() {
        let r = parse(SAMPLE);
        assert!(
            r.registrant_email.is_none(),
            "redacted email should be skipped, got {:?}",
            r.registrant_email
        );
    }

    #[test]
    fn extracts_dates() {
        let r = parse(SAMPLE);
        let created = r.creation_date.expect("creation date");
        assert_eq!(created.year(), 2012);
        assert_eq!(created.month(), 1);
        let expires = r.expiration_date.expect("expiration date");
        assert_eq!(expires.year(), 2027);
        let updated = r.updated_date.expect("updated date");
        assert_eq!(updated.year(), 2025);
    }

    #[test]
    fn extracts_nameservers_without_glue() {
        let r = parse(SAMPLE);
        assert_eq!(r.nameservers.len(), 2);
        assert!(r
            .nameservers
            .contains(&"leonidas.ns.cloudflare.com".to_string()));
        assert!(r
            .nameservers
            .contains(&"sara.ns.cloudflare.com".to_string()));
    }

    #[test]
    fn dnssec_signed_when_dnskey_present() {
        let r = parse(SAMPLE);
        assert_eq!(r.dnssec.as_deref(), Some("signedDelegation"));
    }

    #[test]
    fn status_short_form() {
        let r = parse(SAMPLE);
        // Generic parser used to capture only `ok` — keep that short form so
        // downstream callers that compare on `"ok"` keep working.
        assert!(r.status.contains(&"ok".to_string()));
    }

    #[test]
    fn has_core_data_for_registered() {
        let r = parse(SAMPLE);
        assert!(r.has_core_data(), "registrar+dates+ns means core present");
    }

    #[test]
    fn supported_tlds() {
        assert_eq!(EisParser::new().supported_tlds(), &["ee"]);
    }
}
