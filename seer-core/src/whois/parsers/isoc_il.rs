//! Parser for .il domains (ISOC-IL / `whois.isoc.org.il` format).
//!
//! `.il` has no RDAP service (it is absent from the IANA bootstrap), so this
//! WHOIS response is the only registration source for `.co.il`, `.org.il`,
//! `.net.il`, `.ac.il`, `.muni.il`, … and the IDN `.ישראל` (`xn--4dbrk0ce`).
//!
//! ISOC-IL uses a RIPE-style `key:   value` layout. The domain object runs
//! from the `domain:` line until the first `person:` contact object; contact
//! objects (`person:` … `nic-hdl:`) follow, then a trailing `registrar name:`
//! / `registrar info:` pair.
//!
//! Example response (abridged; values illustrative):
//! ```text
//! % The data in the WHOIS database of the .il registry is provided
//! % by ISOC-IL for information purposes, ...
//!
//! query:        example.co.il
//!
//! reg-name:     example
//! domain:       example.co.il
//!
//! descr:        Example Ltd
//! descr:        1 Example St.
//! descr:        Tel Aviv
//! descr:        Israel
//! phone:        +972 3 1234567
//! e-mail:       hostmaster AT example.co.il
//! admin-c:      II-EX1234-IL
//! tech-c:       II-EX1234-IL
//! zone-c:       II-EX1234-IL
//! nserver:      ns1.example.com
//! nserver:      ns2.example.com
//! validity:     14-06-2027
//! DNSSEC:       unsigned
//! status:       Transfer Locked
//! changed:      domain-registrar AT isoc.org.il 20100614 (Assigned)
//! changed:      domain-registrar AT isoc.org.il 20240502 (Changed)
//!
//! person:       Domain Admin
//! address:      Example Ltd
//! phone:        +972 3 1234567
//! e-mail:       admin AT example.co.il
//! nic-hdl:      II-EX1234-IL
//! changed:      domain-registrar AT isoc.org.il 20240502
//!
//! registrar name: Example Registrar Ltd
//! registrar info: https://www.example-registrar.co.il
//! ```
//!
//! Why the generic parser fails here: the expiry is labelled `validity:` and
//! written `DD-MM-YYYY` (`N/A` for legacy names with no paid term), and the
//! creation date is embedded in a `changed: … YYYYMMDD (Assigned)` audit line.
//! Neither matches any generic pattern, so `.il` lookups came back with no
//! dates. The generic parser also truncated `status: Transfer Locked` to its
//! first word.
//!
//! Unregistered names return `% No data was found to match the request
//! criteria.`, which is matched by the generic `AVAILABILITY_PATTERNS` in
//! `crate::whois::parser`.

use chrono::{DateTime, NaiveDate, Utc};
use once_cell::sync::Lazy;
use regex::Regex;

use super::{push_bounded, RegistryParser, MAX_NAMESERVERS, MAX_STATUSES};
use crate::whois::parser::{parse_date, WhoisResponse};

/// `key:   value` lines. Keys may contain hyphens and spaces
/// (`reg-name`, `e-mail`, `nic-hdl`, `registrar name`).
static KEY_VALUE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^([A-Za-z][A-Za-z0-9 -]*?):\s*(.*?)\s*$").expect("Invalid ISOC-IL key/value regex")
});

/// Domain-level audit line: `changed: <who> YYYYMMDD (Assigned|Changed)`.
/// Contact objects also carry `changed:` lines, but without the parenthesised
/// marker — and they are excluded by section anyway.
static CHANGED_LINE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(\d{8})\s*\((assigned|changed)\)\s*$")
        .expect("Invalid ISOC-IL changed-line regex")
});

/// Maximum number of contact (`person:`) objects retained. A real response
/// carries at most a handful (admin/tech/zone, usually shared); cap so a
/// hostile body cannot drive unbounded allocation.
const MAX_CONTACTS: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    /// Disclaimer / `query:` preamble, before the domain object.
    Preamble,
    /// From `domain:` until the first `person:`.
    Domain,
    /// A `person:` contact object.
    Person,
    /// A `person:` object beyond [`MAX_CONTACTS`]; its lines are dropped so
    /// they cannot bleed into the last retained contact.
    Ignored,
}

#[derive(Default)]
struct Contact {
    name: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    handle: Option<String>,
}

/// Parser for .il domains using the ISOC-IL format.
#[derive(Debug, Clone, Default)]
pub struct IsocIlParser;

impl IsocIlParser {
    pub fn new() -> Self {
        Self
    }

    /// `validity:` is `DD-MM-YYYY` (e.g. `14-06-2027`). Legacy names with no
    /// paid term show `N/A`, which yields `None`. Falls back to the shared
    /// tolerant parser in case the registry ever switches to ISO dates.
    fn parse_validity(value: &str) -> Option<DateTime<Utc>> {
        let v = value.trim();
        if v.is_empty() || v.eq_ignore_ascii_case("n/a") {
            return None;
        }
        NaiveDate::parse_from_str(v, "%d-%m-%Y")
            .ok()
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .map(|dt| dt.and_utc())
            .or_else(|| parse_date(v))
    }

    /// `changed:` audit lines carry a compact `YYYYMMDD` date.
    fn parse_compact_date(value: &str) -> Option<DateTime<Utc>> {
        NaiveDate::parse_from_str(value, "%Y%m%d")
            .ok()
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .map(|dt| dt.and_utc())
    }

    /// ISOC-IL obfuscates addresses as `user AT example.co.il`.
    fn normalize_email(value: &str) -> String {
        value.replace(" AT ", "@")
    }
}

impl RegistryParser for IsocIlParser {
    fn supported_tlds(&self) -> &[&str] {
        // The client sends IDN domains to the wire as A-labels, so the IDN
        // ccTLD `.ישראל` reaches the registry as `xn--4dbrk0ce`.
        &["il", "xn--4dbrk0ce"]
    }

    fn parse(&self, domain: &str, server: &str, raw: &str) -> WhoisResponse {
        let mut section = Section::Preamble;

        let mut registrar: Option<String> = None;
        let mut descr: Vec<String> = Vec::new();
        let mut registrant_email: Option<String> = None;
        let mut registrant_phone: Option<String> = None;
        let mut admin_handle: Option<String> = None;
        let mut tech_handle: Option<String> = None;
        let mut nameservers: Vec<String> = Vec::new();
        let mut status: Vec<String> = Vec::new();
        let mut dnssec: Option<String> = None;
        let mut creation_date: Option<DateTime<Utc>> = None;
        let mut expiration_date: Option<DateTime<Utc>> = None;
        let mut updated_date: Option<DateTime<Utc>> = None;
        let mut contacts: Vec<Contact> = Vec::new();

        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('%') || trimmed.starts_with('#') {
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

            // Section transitions. `domain:` opens the domain object; each
            // `person:` opens a new contact object.
            match key.as_str() {
                "domain" => {
                    section = Section::Domain;
                    continue;
                }
                "person" => {
                    if contacts.len() < MAX_CONTACTS {
                        section = Section::Person;
                        contacts.push(Contact {
                            name: Some(value.to_string()),
                            ..Contact::default()
                        });
                    } else {
                        section = Section::Ignored;
                    }
                    continue;
                }
                // The registrar pair trails the contact objects but is
                // domain-level data; accept it from any section.
                "registrar name" if registrar.is_none() => {
                    registrar = Some(value.to_string());
                    continue;
                }
                _ => {}
            }

            match section {
                Section::Preamble | Section::Ignored => {}
                Section::Domain => match key.as_str() {
                    // First `descr:` is the holder name; the rest is the
                    // postal address, one line each.
                    "descr" if descr.len() < 16 => descr.push(value.to_string()),
                    "e-mail" if registrant_email.is_none() => {
                        registrant_email = Some(Self::normalize_email(value));
                    }
                    "phone" if registrant_phone.is_none() => {
                        registrant_phone = Some(value.to_string());
                    }
                    "admin-c" if admin_handle.is_none() => admin_handle = Some(value.to_string()),
                    "tech-c" if tech_handle.is_none() => tech_handle = Some(value.to_string()),
                    // Some entries append glue IPs after the hostname.
                    "nserver" => {
                        if let Some(host) = value.split_whitespace().next() {
                            push_bounded(
                                &mut nameservers,
                                host.to_ascii_lowercase(),
                                MAX_NAMESERVERS,
                            );
                        }
                    }
                    "validity" if expiration_date.is_none() => {
                        expiration_date = Self::parse_validity(value);
                    }
                    "dnssec" if dnssec.is_none() => dnssec = Some(value.to_string()),
                    "status" => push_bounded(&mut status, value.to_string(), MAX_STATUSES),
                    "changed" => {
                        if let Some(c) = CHANGED_LINE.captures(value) {
                            let date = Self::parse_compact_date(&c[1]);
                            if c[2].eq_ignore_ascii_case("assigned") {
                                if creation_date.is_none() {
                                    creation_date = date;
                                }
                            } else if let Some(d) = date {
                                // `(Changed)` lines are chronological; keep
                                // the latest regardless of ordering.
                                updated_date = Some(updated_date.map_or(d, |cur| cur.max(d)));
                            }
                        }
                    }
                    _ => {}
                },
                Section::Person => {
                    let Some(contact) = contacts.last_mut() else {
                        continue;
                    };
                    match key.as_str() {
                        "e-mail" if contact.email.is_none() => {
                            contact.email = Some(Self::normalize_email(value));
                        }
                        "phone" if contact.phone.is_none() => {
                            contact.phone = Some(value.to_string());
                        }
                        "nic-hdl" if contact.handle.is_none() => {
                            contact.handle = Some(value.to_string());
                        }
                        _ => {}
                    }
                }
            }
        }

        let find_contact = |handle: &Option<String>| -> Option<&Contact> {
            let h = handle.as_deref()?;
            contacts.iter().find(|c| {
                c.handle
                    .as_deref()
                    .is_some_and(|ch| ch.eq_ignore_ascii_case(h))
            })
        };
        let admin = find_contact(&admin_handle);
        let tech = find_contact(&tech_handle);

        let mut descr_iter = descr.into_iter();
        let registrant = descr_iter.next();
        let address: Vec<String> = descr_iter.collect();
        let registrant_address = if address.is_empty() {
            None
        } else {
            Some(address.join(", "))
        };

        WhoisResponse {
            domain: domain.to_string(),
            registrar,
            registrant,
            organization: None,
            registrant_email,
            registrant_phone,
            registrant_address,
            registrant_country: None,
            admin_name: admin.and_then(|c| c.name.clone()),
            admin_organization: None,
            admin_email: admin.and_then(|c| c.email.clone()),
            admin_phone: admin.and_then(|c| c.phone.clone()),
            tech_name: tech.and_then(|c| c.name.clone()),
            tech_organization: None,
            tech_email: tech.and_then(|c| c.email.clone()),
            tech_phone: tech.and_then(|c| c.phone.clone()),
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
    use crate::whois::parsers::ParserRegistry;
    use chrono::Datelike;

    const DISCLAIMER: &str = "\
% The data in the WHOIS database of the .il registry is provided
% by ISOC-IL for information purposes, and to assist persons in
% obtaining information about or related to a domain name
% registration record. ISOC-IL does not guarantee its accuracy.
% By submitting this query, you agree to abide by this policy.

";

    /// A current-era registration with a paid term (`validity:` set). Layout
    /// mirrors live `whois.isoc.org.il` output; values are illustrative.
    fn registered() -> String {
        format!(
            "{DISCLAIMER}\
query:        example.co.il

reg-name:     example
domain:       example.co.il

descr:        Example Ltd
descr:        1 Example St.
descr:        Tel Aviv
descr:        6100000
descr:        Israel
phone:        +972 3 1234567
fax-no:       +972 3 1234568
e-mail:       hostmaster AT example.co.il
admin-c:      II-EA1234-IL
tech-c:       II-ET5678-IL
zone-c:       II-ET5678-IL
nserver:      ns1.example.com
nserver:      ns2.example.com 192.0.2.53
validity:     14-06-2027
DNSSEC:       unsigned
status:       Transfer Locked
changed:      domain-registrar AT isoc.org.il 20100614 (Assigned)
changed:      domain-registrar AT isoc.org.il 20220101 (Changed)
changed:      domain-registrar AT isoc.org.il 20240502 (Changed)

person:       Admin Person
address:      Example Ltd
address:      1 Example St.
phone:        +972 3 1111111
e-mail:       admin AT example.co.il
nic-hdl:      II-EA1234-IL
changed:      domain-registrar AT isoc.org.il 20250909

person:       Tech Person
address:      Example Ltd
phone:        +972 3 2222222
e-mail:       tech AT example.co.il
nic-hdl:      II-ET5678-IL
changed:      domain-registrar AT isoc.org.il 20250909

registrar name: Example Registrar Ltd
registrar info: https://www.example-registrar.co.il

% Rights to the data above are restricted by copyright.
"
        )
    }

    /// A legacy (1990s) registration with no paid term: `validity: N/A` and
    /// no `DNSSEC:` line. Layout follows the public isoc.org.il fixture.
    fn legacy() -> String {
        format!(
            "{DISCLAIMER}\
query:        isoc.org.il

reg-name:     isoc
domain:       isoc.org.il

descr:        Israel Internet Association (ISOC-IL)
descr:        6 Bareket st., POB 7210
descr:        Petach Tikva
descr:        49517
descr:        Israel
phone:        +972 3 9700900
e-mail:       info-domains AT isoc.org.il
admin-c:      II-DB11403-IL
tech-c:       II-DB11403-IL
zone-c:       II-DB11403-IL
nserver:      ns.isoc.org.il
nserver:      grappa.isoc.org.il
validity:     N/A
status:       Transfer Locked
changed:      registrar AT ns.il 19960111 (Assigned)
changed:      registrar AT ns.il 19960623 (Changed)
changed:      domain-registrar AT isoc.org.il 20140116 (Changed)

person:       Dina Beer
address:      Israel Internet Association (ISOC-IL)
phone:        +972 3 9700900
e-mail:       dina.b AT isoc.org.il
nic-hdl:      II-DB11403-IL
changed:      domain-registrar AT isoc.org.il 20140116

registrar name: Israel Internet Association ISOC-IL
"
        )
    }

    const AVAILABLE: &str = "\
% The data in the WHOIS database of the .il registry is provided
% by ISOC-IL for information purposes, and to assist persons in
% obtaining information about or related to a domain name
% registration record. ISOC-IL does not guarantee its accuracy.

% No data was found to match the request criteria.


% Rights to the data above are restricted by copyright.
";

    fn parse(domain: &str, raw: &str) -> WhoisResponse {
        IsocIlParser::new().parse(domain, "whois.isoc.org.il", raw)
    }

    fn ymd(dt: DateTime<Utc>) -> (i32, u32, u32) {
        (dt.year(), dt.month(), dt.day())
    }

    #[test]
    fn registered_extracts_expiration_from_validity() {
        let r = parse("example.co.il", &registered());
        let exp = r.expiration_date.expect("validity: should parse");
        // `14-06-2027` is day-first; must not be read as month 14.
        assert_eq!(ymd(exp), (2027, 6, 14));
    }

    #[test]
    fn registered_extracts_creation_from_assigned_line() {
        let r = parse("example.co.il", &registered());
        let created = r.creation_date.expect("(Assigned) line should parse");
        assert_eq!(ymd(created), (2010, 6, 14));
    }

    #[test]
    fn registered_updated_is_latest_domain_changed_line() {
        let r = parse("example.co.il", &registered());
        let updated = r.updated_date.expect("(Changed) line should parse");
        // Latest domain-level (Changed) line wins; the contact objects'
        // later, unmarked `changed:` lines (20250909) must be ignored.
        assert_eq!(ymd(updated), (2024, 5, 2));
    }

    #[test]
    fn registered_extracts_registrar_status_dnssec() {
        let r = parse("example.co.il", &registered());
        assert_eq!(r.registrar.as_deref(), Some("Example Registrar Ltd"));
        // Full status phrase, not the generic parser's first-word truncation.
        assert_eq!(r.status, vec!["Transfer Locked".to_string()]);
        assert_eq!(r.dnssec.as_deref(), Some("unsigned"));
    }

    #[test]
    fn registered_extracts_nameservers_without_glue() {
        let r = parse("example.co.il", &registered());
        assert_eq!(
            r.nameservers,
            vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()]
        );
    }

    #[test]
    fn registered_extracts_holder_and_contacts() {
        let r = parse("example.co.il", &registered());
        assert_eq!(r.registrant.as_deref(), Some("Example Ltd"));
        assert_eq!(
            r.registrant_address.as_deref(),
            Some("1 Example St., Tel Aviv, 6100000, Israel")
        );
        assert_eq!(
            r.registrant_email.as_deref(),
            Some("hostmaster@example.co.il")
        );
        assert_eq!(r.registrant_phone.as_deref(), Some("+972 3 1234567"));
        // admin-c / tech-c handles resolve to their `person:` objects.
        assert_eq!(r.admin_name.as_deref(), Some("Admin Person"));
        assert_eq!(r.admin_email.as_deref(), Some("admin@example.co.il"));
        assert_eq!(r.admin_phone.as_deref(), Some("+972 3 1111111"));
        assert_eq!(r.tech_name.as_deref(), Some("Tech Person"));
        assert_eq!(r.tech_email.as_deref(), Some("tech@example.co.il"));
        assert_eq!(r.tech_phone.as_deref(), Some("+972 3 2222222"));
    }

    #[test]
    fn registered_has_core_data_and_is_not_available() {
        let r = parse("example.co.il", &registered());
        assert!(r.has_core_data(), "registrar + dates + NS present");
        assert!(!r.is_available());
        assert!(!r.registry_unavailable());
    }

    #[test]
    fn legacy_validity_na_yields_no_expiration_but_keeps_creation() {
        let r = parse("isoc.org.il", &legacy());
        assert!(
            r.expiration_date.is_none(),
            "validity: N/A must not produce a date"
        );
        assert_eq!(ymd(r.creation_date.expect("Assigned")), (1996, 1, 11));
        assert_eq!(ymd(r.updated_date.expect("Changed")), (2014, 1, 16));
        assert_eq!(
            r.registrar.as_deref(),
            Some("Israel Internet Association ISOC-IL")
        );
        assert!(r.dnssec.is_none());
        // Trailing whitespace after the hostname is trimmed.
        assert_eq!(r.nameservers, vec!["ns.isoc.org.il", "grappa.isoc.org.il"]);
        assert!(r.has_core_data());
        assert!(!r.is_available());
    }

    #[test]
    fn available_response_is_recognised() {
        let r = parse("nosuchname.co.il", AVAILABLE);
        assert!(r.creation_date.is_none());
        assert!(r.expiration_date.is_none());
        assert!(r.registrar.is_none());
        assert!(r.nameservers.is_empty());
        assert!(
            r.is_available(),
            "'% No data was found to match the request criteria.' must read as available"
        );
    }

    #[test]
    fn registry_routes_il_second_level_domains_here() {
        let registry = ParserRegistry::new();
        for domain in ["example.co.il", "example.org.il", "example.ac.il"] {
            let r = registry.parse(domain, "whois.isoc.org.il", &registered());
            assert!(
                r.expiration_date.is_some(),
                "{domain} should be parsed by the ISOC-IL parser"
            );
        }
        // The IDN ccTLD reaches the parser as its A-label.
        let r = registry.parse(
            "xn--4dbqfv.xn--4dbrk0ce",
            "whois.isoc.org.il",
            &registered(),
        );
        assert!(r.expiration_date.is_some());
    }

    #[test]
    fn contacts_beyond_cap_do_not_bleed_into_retained_ones() {
        // Build MAX_CONTACTS + 1 person objects; the last retained one has no
        // e-mail, and the overflow one must not supply it.
        let mut raw = String::from("domain: example.co.il\nadmin-c: II-LAST-IL\n\n");
        for i in 0..MAX_CONTACTS {
            let handle = if i + 1 == MAX_CONTACTS {
                "II-LAST-IL".to_string()
            } else {
                format!("II-P{i}-IL")
            };
            raw.push_str(&format!("person: Person {i}\nnic-hdl: {handle}\n\n"));
        }
        raw.push_str("person: Overflow\ne-mail: overflow AT example.co.il\nnic-hdl: II-OVER-IL\n");
        let r = parse("example.co.il", &raw);
        assert_eq!(
            r.admin_name.as_deref(),
            Some(&*format!("Person {}", MAX_CONTACTS - 1))
        );
        assert!(r.admin_email.is_none(), "overflow contact must be dropped");
    }

    #[test]
    fn supported_tlds() {
        assert_eq!(
            IsocIlParser::new().supported_tlds(),
            &["il", "xn--4dbrk0ce"]
        );
    }

    #[test]
    fn parse_validity_formats() {
        assert!(IsocIlParser::parse_validity("N/A").is_none());
        assert!(IsocIlParser::parse_validity("n/a").is_none());
        assert!(IsocIlParser::parse_validity("").is_none());
        assert_eq!(
            IsocIlParser::parse_validity("01-12-2030").map(ymd),
            Some((2030, 12, 1))
        );
        // Tolerates an ISO date should the registry ever change format.
        assert_eq!(
            IsocIlParser::parse_validity("2030-12-01").map(ymd),
            Some((2030, 12, 1))
        );
    }
}
