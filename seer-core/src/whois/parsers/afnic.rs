//! Parser for AFNIC replies: .fr and the overseas ccTLDs AFNIC runs (.pm
//! .re .tf .wf .yt).
//!
//! The reply is a series of blank-line-separated objects: the `domain:`
//! object, then the nameserver, DS-key, registrar and contact (`nic-hdl:`)
//! objects. Contacts carry their own `eppstatus:` / `registered:` /
//! `changed:` lines, so domain-level fields are read from the `domain:`
//! object only; `holder-c:` / `admin-c:` / `tech-c:` are handles resolved to
//! their `nic-hdl:` objects. Registrar, nameservers, creation and expiry come
//! from the generic parser.
//!
//! Example AFNIC response (trimmed):
//! ```text
//! domain:                        nic.fr
//! status:                        ACTIVE
//! eppstatus:                     serverTransferProhibited
//! holder-c:                      NF100-FRNIC
//! registrar:                     Registry Operations
//! Expiry Date:                   2029-12-31T23:00:00Z
//! created:                       1995-01-01T00:00:00Z
//! last-update:                   2026-06-05T07:20:46.286415Z
//!
//! key1-tag:                      30098
//!
//! nic-hdl:                       NF100-FRNIC
//! type:                          ORGANIZATION
//! contact:                       AFNIC
//! e-mail:                        juridique@afnic.fr
//! anonymous:                     NO
//! eppstatus:                     active
//! ```
//!
//! A private individual's contact is published with `anonymous: YES`; its
//! values are not read.

use super::objects::{class, find_by_handle, first, objects, values, Object};
use super::{push_bounded, MAX_STATUSES};
use crate::whois::parser::{parse_date, WhoisResponse};

/// TLDs this parser handles.
pub(super) const TLDS: &[&str] = &["fr", "pm", "re", "tf", "wf", "yt"];

/// Parses an AFNIC reply: the generic parser, with domain-level fields from
/// the `domain:` object and contacts resolved from their handles.
pub(super) fn parse(domain: &str, server: &str, raw: &str) -> WhoisResponse {
    let mut response = WhoisResponse::parse_internal(domain, server, raw);
    let objects = objects(raw);
    // A not-found reply has no domain object; keep the generic read.
    let Some(dom) = objects.iter().find(|o| class(o) == Some("domain")) else {
        return response;
    };

    if let Some(date) = first(dom, "created").and_then(parse_date) {
        response.creation_date = Some(date);
    }
    response.updated_date = first(dom, "last-update").and_then(parse_date);

    // AFNIC's own state (`ACTIVE`) and the EPP statuses, domain object only.
    let mut status = Vec::new();
    for value in values(dom, "status").chain(values(dom, "eppstatus")) {
        push_bounded(&mut status, value.to_string(), MAX_STATUSES);
    }
    response.status = status;

    // A DS-key object (`key1-tag:`) is published only for a signed delegation.
    if objects.iter().any(|o| class(o) == Some("key1-tag")) {
        response.dnssec = Some("signedDelegation".to_string());
    }

    let contact = |role: &str| {
        let handle = first(dom, role)?;
        find_by_handle(&objects, "nic-hdl", handle).filter(|c| !is_anonymous(c))
    };
    if let Some(holder) = contact("holder-c") {
        response.registrant = first(holder, "contact").map(str::to_string);
        response.organization = is_organization(holder)
            .then(|| response.registrant.clone())
            .flatten();
        response.registrant_email = first(holder, "e-mail").map(str::to_string);
        response.registrant_phone = first(holder, "phone").map(str::to_string);
        response.registrant_country = first(holder, "country").map(str::to_string);
    }
    if let Some(admin) = contact("admin-c") {
        response.admin_name = first(admin, "contact").map(str::to_string);
        response.admin_email = first(admin, "e-mail").map(str::to_string);
        response.admin_phone = first(admin, "phone").map(str::to_string);
    }
    if let Some(tech) = contact("tech-c") {
        response.tech_name = first(tech, "contact").map(str::to_string);
        response.tech_email = first(tech, "e-mail").map(str::to_string);
        response.tech_phone = first(tech, "phone").map(str::to_string);
    }
    response
}

/// `anonymous: YES` marks a private individual's redacted contact.
fn is_anonymous(contact: &Object<'_>) -> bool {
    first(contact, "anonymous").is_some_and(|v| v.eq_ignore_ascii_case("yes"))
}

fn is_organization(contact: &Object<'_>) -> bool {
    first(contact, "type").is_some_and(|v| v.eq_ignore_ascii_case("organization"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live whois.nic.fr reply for nic.fr (2026-10-13), trimmed.
    const NIC_FR: &str = concat!(
        "%%\n%% This is the AFNIC Whois server.\n%%\n\n",
        "domain:                        nic.fr\n",
        "status:                        ACTIVE\n",
        "eppstatus:                     serverTransferProhibited\n",
        "eppstatus:                     serverDeleteProhibited\n",
        "hold:                          NO\n",
        "holder-c:                      NF100-FRNIC\n",
        "admin-c:                       AFNI30-FRNIC\n",
        "tech-c:                        CTC7206429-FRNIC\n",
        "registrar:                     Registry Operations\n",
        "Expiry Date:                   2029-12-31T23:00:00Z\n",
        "created:                       1995-01-01T00:00:00Z\n",
        "last-update:                   2026-06-05T07:20:46.286415Z\n",
        "source:                        FRNIC\n\n",
        "nserver:                       ns1.ext.nic.fr\n",
        "nserver:                       ns4.nic.fr\n",
        "source:                        FRNIC\n\n",
        "key1-tag:                      30098\n",
        "key1-algo:                     13 [ECDSAP256SHA256]\n",
        "source:                        FRNIC\n\n",
        "registrar:                     Registry Operations\n",
        "country:                       FR\n",
        "registered:                    2014-07-29T15:35:33Z\n",
        "source:                        FRNIC\n\n",
        "nic-hdl:                       NF100-FRNIC\n",
        "type:                          ORGANIZATION\n",
        "contact:                       AFNIC\n",
        "country:                       FR\n",
        "phone:                         +33.139308300\n",
        "e-mail:                        juridique@afnic.fr\n",
        "anonymous:                     NO\n",
        "eppstatus:                     associated\n",
        "eppstatus:                     active\n",
        "source:                        FRNIC\n\n",
        "nic-hdl:                       AFNI30-FRNIC\n",
        "type:                          ORGANIZATION\n",
        "contact:                       ASS FRANC NOMMAGE INTERNET EN COOP\n",
        "e-mail:                        contact@nic.fr\n",
        "changed:                       2024-04-11T13:45:52.051456Z\n",
        "anonymous:                     NO\n\n",
        "nic-hdl:                       CTC7206429-FRNIC\n",
        "type:                          ORGANIZATION\n",
        "contact:                       AFNIC\n",
        "e-mail:                        dnsops@afnic.fr\n",
        "anonymous:                     NO\n\n",
        ">>> Last update of WHOIS database: 2026-10-13T16:30:42.159104Z <<<\n",
    );

    fn ymd(d: Option<chrono::DateTime<chrono::Utc>>) -> Option<String> {
        d.map(|d| d.format("%Y-%m-%d").to_string())
    }

    #[test]
    fn dates_come_from_the_domain_object() {
        let r = parse("nic.fr", "whois.nic.fr", NIC_FR);
        assert_eq!(ymd(r.creation_date).as_deref(), Some("1995-01-01"));
        assert_eq!(ymd(r.expiration_date).as_deref(), Some("2029-12-31"));
        // `last-update:` was not read; a contact's `changed:` must not stand in.
        assert_eq!(ymd(r.updated_date).as_deref(), Some("2026-06-05"));
    }

    #[test]
    fn status_includes_epp_statuses_but_not_contacts() {
        let r = parse("nic.fr", "whois.nic.fr", NIC_FR);
        assert_eq!(
            r.status,
            vec![
                "ACTIVE",
                "serverTransferProhibited",
                "serverDeleteProhibited"
            ]
        );
    }

    #[test]
    fn contact_handles_resolve_to_their_objects() {
        let r = parse("nic.fr", "whois.nic.fr", NIC_FR);
        assert_eq!(r.registrant.as_deref(), Some("AFNIC"));
        assert_eq!(r.organization.as_deref(), Some("AFNIC"));
        assert_eq!(r.registrant_email.as_deref(), Some("juridique@afnic.fr"));
        assert_eq!(r.registrant_country.as_deref(), Some("FR"));
        assert_eq!(
            r.admin_name.as_deref(),
            Some("ASS FRANC NOMMAGE INTERNET EN COOP")
        );
        assert_eq!(r.tech_email.as_deref(), Some("dnsops@afnic.fr"));
    }

    #[test]
    fn ds_key_object_means_signed() {
        let r = parse("nic.fr", "whois.nic.fr", NIC_FR);
        assert_eq!(r.dnssec.as_deref(), Some("signedDelegation"));
        let unsigned = NIC_FR.replace("key1-tag:", "xkey1-tag:");
        assert!(parse("nic.fr", "whois.nic.fr", &unsigned).dnssec.is_none());
    }

    #[test]
    fn generic_fields_still_parse() {
        let r = parse("nic.fr", "whois.nic.fr", NIC_FR);
        assert_eq!(r.registrar.as_deref(), Some("Registry Operations"));
        assert_eq!(r.nameservers, vec!["ns1.ext.nic.fr", "ns4.nic.fr"]);
        assert!(r.has_core_data());
    }

    #[test]
    fn anonymous_holder_is_not_read() {
        let raw = concat!(
            "domain: example.fr\nholder-c: ANO00-FRNIC\nstatus: ACTIVE\n\n",
            "nic-hdl: ANO00-FRNIC\ntype: PERSON\ncontact: Ano Nymous\n",
            "e-mail: ano@example.fr\nanonymous: YES\n",
        );
        let r = parse("example.fr", "whois.nic.fr", raw);
        assert!(r.registrant.is_none());
        assert!(r.registrant_email.is_none());
    }

    #[test]
    fn crlf_body_parses_like_lf() {
        let r = parse("nic.fr", "whois.nic.fr", &NIC_FR.replace('\n', "\r\n"));
        assert_eq!(ymd(r.updated_date).as_deref(), Some("2026-06-05"));
        assert_eq!(r.registrant.as_deref(), Some("AFNIC"));
    }
}
