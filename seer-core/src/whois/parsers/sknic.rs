//! Parser for .sk domains (SK-NIC format).
//!
//! The reply is blank-line-separated blocks: the domain, then the registrant
//! (`Domain registrant: <handle>`) and registrar (`Registrar: <handle>`),
//! each opened by a handle with the entity's `Name:` / `Organization:` below
//! it. The generic parser takes the handles as names (and reads the
//! registrar from the registrant block's `Authorised Registrar:`), so names
//! are read from their blocks here; dates, status and nameservers come from
//! the generic parser.
//!
//! Example SK-NIC response (trimmed):
//! ```text
//! Domain:                       nic.sk
//! Created:                      2003-09-30
//! Valid Until:                  2027-09-30
//!
//! Domain registrant:            WY-237559
//! Name:                         Igor Strečko
//! Organization:                 Webglobe, a.s.
//! Authorised Registrar:         WEBG-0001
//!
//! Registrar:                    WEBG-0001
//! Name:                         Webglobe, a.s.
//! ```

use super::objects::{class, first, objects};
use crate::whois::parser::WhoisResponse;

/// TLDs this parser handles.
pub(super) const TLDS: &[&str] = &["sk"];

/// Parses .sk domains: the generic parser plus names from their blocks.
pub(super) fn parse(domain: &str, server: &str, raw: &str) -> WhoisResponse {
    let mut response = WhoisResponse::parse_internal(domain, server, raw);
    let objects = objects(raw);
    let block = |class_key: &str| objects.iter().find(|o| class(o) == Some(class_key));
    if let Some(registrar) = block("registrar") {
        if let Some(name) = first(registrar, "name").or_else(|| first(registrar, "organization")) {
            response.registrar = Some(name.to_string());
        }
    }
    if let Some(holder) = block("domain registrant") {
        let org = first(holder, "organization").map(str::to_string);
        if let Some(name) = first(holder, "name").map(str::to_string).or(org.clone()) {
            response.registrant = Some(name);
        }
        response.organization = org;
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live whois.sk-nic.sk reply for nic.sk (2026-10-13), trimmed.
    const NIC_SK: &str = "Domain:                       nic.sk\n\
Created:                      2003-09-30\n\
Valid Until:                  2027-09-30\n\
Updated:                      2026-09-08\n\
Domain Status:                clientTransferProhibited, clientUpdateProhibited\n\
Nameserver:                   ns1.nic.sk\n\
Nameserver:                   ns2.nic.sk\n\
\n\
Domain registrant:            WY-237559\n\
Name:                         Igor Strečko\n\
Organization:                 Webglobe, a.s.\n\
Country Code:                 SK\n\
Authorised Registrar:         WEBG-0001\n\
Created:                      2022-01-04\n\
\n\
Registrar:                    WEBG-0001\n\
Name:                         Webglobe, a.s.\n\
Organization:                 Webglobe, a.s.\n\
Created:                      2017-09-01\n";

    #[test]
    fn registrar_and_registrant_names_replace_handles() {
        let r = parse("nic.sk", "whois.sk-nic.sk", NIC_SK);
        assert_eq!(r.registrar.as_deref(), Some("Webglobe, a.s."));
        assert_eq!(r.registrant.as_deref(), Some("Igor Strečko"));
        assert_eq!(r.organization.as_deref(), Some("Webglobe, a.s."));
    }

    #[test]
    fn domain_dates_are_not_taken_from_contact_blocks() {
        let r = parse("nic.sk", "whois.sk-nic.sk", NIC_SK);
        let ymd =
            |d: Option<chrono::DateTime<chrono::Utc>>| d.map(|d| d.format("%Y-%m-%d").to_string());
        assert_eq!(ymd(r.creation_date).as_deref(), Some("2003-09-30"));
        assert_eq!(ymd(r.expiration_date).as_deref(), Some("2027-09-30"));
        assert_eq!(ymd(r.updated_date).as_deref(), Some("2026-09-08"));
        assert_eq!(r.nameservers, vec!["ns1.nic.sk", "ns2.nic.sk"]);
    }
}
