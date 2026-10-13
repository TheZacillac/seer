//! Parser for FRED-style object replies: CZ.NIC's FRED registry software
//! (.cz and the registries running it: .cr .ls .mk .mw .tz .ve) and NIC.ar,
//! which prints the same layout.
//!
//! The reply is a series of blank-line-separated objects, each opened by its
//! class key (`domain:`, `contact:`, `nsset:`, `keyset:`). Contact and nsset
//! objects carry their own `created:` / `changed:` / `status:` lines, so a
//! flat label scan took a contact's creation date as the domain's and mixed
//! contact statuses in. Domain-level fields are read only from the `domain:`
//! object here; nameservers, registrar and DNSSEC come from the generic
//! parser.
//!
//! Example FRED response (trimmed):
//! ```text
//! domain:       nic.cz
//! registrant:   CZ-NIC
//! nsset:        CZ.NIC
//! registrar:    REG-CZNIC
//! status:       Sponsoring registrar change forbidden
//! registered:   30.10.1997 01:00:00
//! changed:      17.11.2020 14:25:52
//! expire:       15.03.2027
//!
//! contact:      CZ-NIC
//! org:          CZ.NIC, z.s.p.o.
//! name:         CZ.NIC, z.s.p.o.
//! created:      17.10.2008 12:08:21
//!
//! nsset:        CZ.NIC
//! nserver:      a.ns.nic.cz (194.0.12.1, 2001:678:f::1)
//! ```
//!
//! FRED statuses are prose ("Sponsoring registrar change forbidden"), kept
//! whole. Times are the registry's local time without a zone and are read
//! as UTC, like the generic parser does.

use super::{push_bounded, MAX_STATUSES};
use crate::whois::parser::{parse_date, WhoisResponse};

static_regex! {
    KEY_VALUE = r"^([A-Za-z][A-Za-z-]*):[ \t]*(.*?)[ \t]*$";
}

/// TLDs this parser handles.
pub(super) const TLDS: &[&str] = &["ar", "cr", "cz", "ls", "mk", "mw", "tz", "ve"];

/// One object: its `key: value` lines in order, keys lowercased.
type Object<'a> = Vec<(String, &'a str)>;

/// Parses a FRED-style reply: the generic parser, with domain-level fields
/// taken from the `domain:` object only.
pub(super) fn parse(domain: &str, server: &str, raw: &str) -> WhoisResponse {
    let mut response = WhoisResponse::parse_internal(domain, server, raw);
    let objects = objects(raw);
    // A not-found or refusal reply has no domain object; keep the generic read.
    let Some(dom) = objects.iter().find(|o| class(o) == Some("domain")) else {
        return response;
    };

    response.creation_date = first(dom, "registered").and_then(parse_date);
    response.updated_date = first(dom, "changed").and_then(parse_date);
    response.expiration_date = first(dom, "expire").and_then(parse_date);

    let mut status = Vec::new();
    for (_, value) in dom.iter().filter(|(k, _)| k == "status") {
        push_bounded(&mut status, (*value).to_string(), MAX_STATUSES);
    }
    response.status = status;

    // `registrant:` is a contact handle; its object carries the name/org.
    if let Some(handle) = first(dom, "registrant") {
        let contact = objects
            .iter()
            .find(|o| class(o) == Some("contact") && o[0].1.eq_ignore_ascii_case(handle));
        // A contact without name or org (.ls, .tz) leaves the handle.
        if let Some(contact) = contact {
            let org = first(contact, "org").map(str::to_string);
            if let Some(name) = first(contact, "name").map(str::to_string).or(org.clone()) {
                response.registrant = Some(name);
            }
            response.organization = org;
        }
    }
    response
}

/// Splits the reply into objects at blank lines, skipping `%` comments.
fn objects(raw: &str) -> Vec<Object<'_>> {
    let mut out = Vec::new();
    let mut current: Object<'_> = Vec::new();
    for line in raw.lines() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            continue;
        }
        if line.starts_with('%') {
            continue;
        }
        if let Some(caps) = KEY_VALUE.captures(line) {
            if let (Some(k), Some(v)) = (caps.get(1), caps.get(2)) {
                current.push((k.as_str().to_ascii_lowercase(), v.as_str()));
            }
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// The object's class: the key of its first line.
fn class<'a>(object: &'a Object<'_>) -> Option<&'a str> {
    object.first().map(|(k, _)| k.as_str())
}

/// The first non-empty value for `key` in `object`.
fn first<'a>(object: &Object<'a>, key: &str) -> Option<&'a str> {
    object
        .iter()
        .find(|(k, v)| k == key && !v.is_empty())
        .map(|(_, v)| *v)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live whois.nic.cz reply for nic.cz (2026-10-13), trimmed.
    const CZ: &str = "%  (c) 2006-2021 CZ.NIC, z.s.p.o.\n\
%\n\
% Whoisd Server Version: 3.15.0\n\
\n\
domain:       nic.cz\n\
registrant:   CZ-NIC\n\
admin-c:      FEELA\n\
nsset:        CZ.NIC\n\
keyset:       AUTO-ZHHWRIDCGH9F46ZDG2K2VC284\n\
registrar:    REG-CZNIC\n\
status:       Sponsoring registrar change forbidden\n\
registered:   30.10.1997 01:00:00\n\
changed:      17.11.2020 14:25:52\n\
expire:       15.03.2027\n\
\n\
contact:      CZ-NIC\n\
org:          CZ.NIC, z.s.p.o.\n\
name:         CZ.NIC, z.s.p.o.\n\
address:      Milesovska 1136/5\n\
registrar:    REG-CZNIC\n\
created:      17.10.2008 12:08:21\n\
changed:      15.05.2018 21:32:00\n\
\n\
contact:      FEELA\n\
name:         Ondřej Filip\n\
registrar:    REG-MOJEID\n\
created:      04.01.2005 13:35:00\n\
\n\
nsset:        CZ.NIC\n\
nserver:      d.ns.nic.cz (193.29.206.1, 2001:678:1::1)\n\
nserver:      a.ns.nic.cz (194.0.12.1, 2001:678:f::1)\n\
tech-c:       JTALIR\n\
registrar:    REG-CZNIC\n\
created:      05.10.2007 13:36:00\n";

    /// Live whois.nic.ar reply for nic.ar (2026-10-13), trimmed.
    const AR: &str = "% La información a la que estás accediendo se provee exclusivamente para\n\
% fines relacionados con operaciones sobre nombres de dominios y DNS.\n\
\n\
domain:\t\tnic.ar\n\
registrant:\t30710551665\n\
registrar:\tnicar\n\
registered:\t1998-05-29 00:00:00\n\
changed:\t2023-07-17 17:23:05.989470\n\
expire:\t\t2100-12-31 00:00:00\n\
\n\
contact:\t30710551665\n\
name:\t\tSECRETARIA LEGAL Y TECNICA\n\
registrar:\tnicar\n\
created:\t2013-08-19 00:00:00\n\
changed:\t2024-04-18 15:16:11.362047\n\
\n\
nserver:\tns5.rdns.ar ()\n\
nserver:\tns6.rdns.ar ()\n\
registrar:\tnicar\n\
created:\t2019-07-12 17:36:57.685138\n";

    fn ymd(d: Option<chrono::DateTime<chrono::Utc>>) -> Option<String> {
        d.map(|d| d.format("%Y-%m-%d").to_string())
    }

    #[test]
    fn dates_come_from_the_domain_object_not_a_contact() {
        let r = parse("nic.cz", "whois.nic.cz", CZ);
        // The CZ-NIC contact's `created: 17.10.2008` was taken before.
        assert_eq!(ymd(r.creation_date).as_deref(), Some("1997-10-30"));
        assert_eq!(ymd(r.expiration_date).as_deref(), Some("2027-03-15"));
        assert_eq!(ymd(r.updated_date).as_deref(), Some("2020-11-17"));
    }

    #[test]
    fn prose_status_is_kept_whole() {
        let r = parse("nic.cz", "whois.nic.cz", CZ);
        assert_eq!(r.status, vec!["Sponsoring registrar change forbidden"]);
    }

    #[test]
    fn registrant_handle_resolves_to_its_contact_object() {
        let r = parse("nic.cz", "whois.nic.cz", CZ);
        assert_eq!(r.registrant.as_deref(), Some("CZ.NIC, z.s.p.o."));
        assert_eq!(r.organization.as_deref(), Some("CZ.NIC, z.s.p.o."));
    }

    #[test]
    fn generic_fields_still_parse() {
        let r = parse("nic.cz", "whois.nic.cz", CZ);
        assert_eq!(r.registrar.as_deref(), Some("REG-CZNIC"));
        assert_eq!(r.nameservers, vec!["d.ns.nic.cz", "a.ns.nic.cz"]);
        assert!(r.has_core_data());
    }

    #[test]
    fn nic_ar_layout_parses_the_same_way() {
        let r = parse("nic.ar", "whois.nic.ar", AR);
        assert_eq!(ymd(r.creation_date).as_deref(), Some("1998-05-29"));
        assert_eq!(ymd(r.expiration_date).as_deref(), Some("2100-12-31"));
        assert_eq!(ymd(r.updated_date).as_deref(), Some("2023-07-17"));
        assert_eq!(r.registrant.as_deref(), Some("SECRETARIA LEGAL Y TECNICA"));
        assert!(r.status.is_empty());
    }

    #[test]
    fn crlf_body_parses_like_lf() {
        let r = parse("nic.cz", "whois.nic.cz", &CZ.replace('\n', "\r\n"));
        assert_eq!(ymd(r.creation_date).as_deref(), Some("1997-10-30"));
        assert_eq!(r.status, vec!["Sponsoring registrar change forbidden"]);
    }

    #[test]
    fn reply_without_a_domain_object_keeps_the_generic_read() {
        let raw = "%  (c) CZ.NIC\n%\n%ERROR:101: no entries found\n";
        let r = parse("free-name.cz", "whois.nic.cz", raw);
        assert!(r.creation_date.is_none());
        assert!(r.indicates_not_found() || r.is_available());
    }
}
