//! Generic WHOIS parser for standard formats.
//!
//! This parser uses the original regex-based parsing logic and serves
//! as a fallback when no specialized parser is available for a TLD.

use super::RegistryParser;
use crate::whois::parser::WhoisResponse;

/// Generic WHOIS parser that handles standard formats.
///
/// This parser uses regex patterns that work for most WHOIS responses,
/// including common gTLD and ccTLD formats.
#[derive(Debug, Clone, Default)]
pub struct GenericParser;

impl GenericParser {
    pub fn new() -> Self {
        Self
    }
}

impl RegistryParser for GenericParser {
    fn supported_tlds(&self) -> &[&str] {
        // Empty - this is the fallback parser
        &[]
    }

    fn parse(&self, domain: &str, server: &str, raw: &str) -> WhoisResponse {
        // Delegate to the original parsing logic
        WhoisResponse::parse_internal(domain, server, raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generic_parser_basic() {
        let parser = GenericParser::new();
        let raw = r#"
Domain Name: example.com
Registrar: Example Registrar, Inc.
Creation Date: 2020-01-15T00:00:00Z
Expiration Date: 2025-01-15T00:00:00Z
Name Server: ns1.example.com
Name Server: ns2.example.com
"#;
        let result = parser.parse("example.com", "whois.example.com", raw);

        assert_eq!(result.domain, "example.com");
        assert_eq!(
            result.registrar,
            Some("Example Registrar, Inc.".to_string())
        );
        assert_eq!(result.nameservers.len(), 2);
    }

    // ------------------------------------------------------------------
    // Real-world fixture tests (M13).
    //
    // The trivial LF-only fixture above hid regressions for the three most
    // common shapes of gTLD WHOIS responses:
    //   1. Current Verisign thick .com format (CRLF, registrar/registry split)
    //   2. Post-2018 GDPR-redacted .com responses (PII replaced with
    //      "REDACTED FOR PRIVACY")
    //   3. CRLF line endings throughout (TCP WHOIS protocol default)
    //
    // These fixtures assert only on parser-visible fields (domain name,
    // registrar, dates, nameservers, status) — never PII, since real
    // responses vary in what they redact.
    // ------------------------------------------------------------------

    /// Current Verisign thick-WHOIS format for `.com` (post-GDPR).
    /// Abbreviated from a real response, preserving structure and CRLF.
    const VERISIGN_COM_FIXTURE: &str = concat!(
        "   Domain Name: EXAMPLE.COM\r\n",
        "   Registry Domain ID: 2336799_DOMAIN_COM-VRSN\r\n",
        "   Registrar WHOIS Server: whois.iana.org\r\n",
        "   Registrar URL: http://res-dom.iana.org\r\n",
        "   Updated Date: 2024-08-14T07:01:34Z\r\n",
        "   Creation Date: 1995-08-14T04:00:00Z\r\n",
        "   Registry Expiry Date: 2025-08-13T04:00:00Z\r\n",
        "   Registrar: RESERVED-Internet Assigned Numbers Authority\r\n",
        "   Registrar IANA ID: 376\r\n",
        "   Registrar Abuse Contact Email:\r\n",
        "   Registrar Abuse Contact Phone:\r\n",
        "   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\r\n",
        "   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\r\n",
        "   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\r\n",
        "   Name Server: A.IANA-SERVERS.NET\r\n",
        "   Name Server: B.IANA-SERVERS.NET\r\n",
        "   DNSSEC: signedDelegation\r\n",
        "   DNSSEC DS Data: 370 13 2 BE74359954660069D5C63DA59519AB22E46C7A3AEFAD516946B72A91BC93D46F\r\n",
        "   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\r\n",
        ">>> Last update of whois database: 2026-04-20T12:34:56Z <<<\r\n",
    );

    #[test]
    fn test_verisign_thick_com_fixture() {
        let parser = GenericParser::new();
        let result = parser.parse("example.com", "whois.verisign-grs.com", VERISIGN_COM_FIXTURE);

        assert_eq!(result.domain, "example.com");
        assert_eq!(
            result.registrar.as_deref(),
            Some("RESERVED-Internet Assigned Numbers Authority"),
            "must extract registrar from current Verisign thick-WHOIS"
        );
        // Both A and B IANA servers should be captured.
        assert!(
            result
                .nameservers
                .iter()
                .any(|n| n.to_lowercase().contains("a.iana-servers.net")),
            "nameservers missing A: {:?}",
            result.nameservers
        );
        assert!(
            result
                .nameservers
                .iter()
                .any(|n| n.to_lowercase().contains("b.iana-servers.net")),
            "nameservers missing B: {:?}",
            result.nameservers
        );
        assert_eq!(result.nameservers.len(), 2);
        assert!(result.creation_date.is_some(), "creation date must parse");
        assert!(
            result.expiration_date.is_some(),
            "expiration date must parse"
        );
        assert_eq!(result.dnssec.as_deref(), Some("signedDelegation"));
        // At least three statuses captured.
        assert!(
            result.status.len() >= 3,
            "expected >= 3 statuses, got {:?}",
            result.status
        );
        // not-available: the response contains registration data.
        assert!(!result.is_available());
    }

    /// Post-2018 GDPR-redacted thick response for a `.com` domain.
    /// All PII is replaced by the string "REDACTED FOR PRIVACY"; core
    /// registry fields remain present. CRLF throughout.
    const GDPR_REDACTED_COM_FIXTURE: &str = concat!(
        "   Domain Name: REDACTED-EXAMPLE.COM\r\n",
        "   Registry Domain ID: 9999999_DOMAIN_COM-VRSN\r\n",
        "   Registrar WHOIS Server: whois.markmonitor.com\r\n",
        "   Registrar URL: http://www.markmonitor.com\r\n",
        "   Updated Date: 2025-11-08T10:00:00Z\r\n",
        "   Creation Date: 2010-03-12T17:22:00Z\r\n",
        "   Registry Expiry Date: 2027-03-12T17:22:00Z\r\n",
        "   Registrar: MarkMonitor Inc.\r\n",
        "   Registrar IANA ID: 292\r\n",
        "   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\r\n",
        "   Registry Registrant ID: REDACTED FOR PRIVACY\r\n",
        "   Registrant Name: REDACTED FOR PRIVACY\r\n",
        "   Registrant Organization: REDACTED FOR PRIVACY\r\n",
        "   Registrant Street: REDACTED FOR PRIVACY\r\n",
        "   Registrant City: REDACTED FOR PRIVACY\r\n",
        "   Registrant State/Province: REDACTED FOR PRIVACY\r\n",
        "   Registrant Postal Code: REDACTED FOR PRIVACY\r\n",
        "   Registrant Country: REDACTED FOR PRIVACY\r\n",
        "   Registrant Phone: REDACTED FOR PRIVACY\r\n",
        "   Registrant Email: Please query the RDDS service of the Registrar of Record identified in this output for information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.\r\n",
        "   Admin Name: REDACTED FOR PRIVACY\r\n",
        "   Admin Email: REDACTED FOR PRIVACY\r\n",
        "   Tech Name: REDACTED FOR PRIVACY\r\n",
        "   Tech Email: REDACTED FOR PRIVACY\r\n",
        "   Name Server: NS1.MARKMONITOR.COM\r\n",
        "   Name Server: NS2.MARKMONITOR.COM\r\n",
        "   DNSSEC: unsigned\r\n",
        ">>> Last update of WHOIS database: 2026-04-20T12:00:00Z <<<\r\n",
    );

    #[test]
    fn test_gdpr_redacted_com_fixture() {
        let parser = GenericParser::new();
        let result = parser.parse(
            "redacted-example.com",
            "whois.verisign-grs.com",
            GDPR_REDACTED_COM_FIXTURE,
        );

        // Registry-level fields MUST still be extracted — these are never
        // redacted for gTLDs.
        assert_eq!(result.registrar.as_deref(), Some("MarkMonitor Inc."));
        assert!(result.creation_date.is_some());
        assert!(result.expiration_date.is_some());
        assert!(result.updated_date.is_some());
        assert_eq!(result.nameservers.len(), 2);
        assert_eq!(result.dnssec.as_deref(), Some("unsigned"));

        // PII fields are redacted — the parser actively filters out any
        // value containing "redacted" / "privacy" / "withheld" and returns
        // None for those, so downstream JSON/human output hides them
        // cleanly. This is a critical contract: GDPR-redacted responses
        // must not leak the literal "REDACTED FOR PRIVACY" string as if
        // it were a real contact name.
        assert!(
            result.registrant.is_none(),
            "registrant must be None when WHOIS says 'REDACTED FOR PRIVACY' \
             (got: {:?})",
            result.registrant
        );
        assert!(
            result.admin_name.is_none(),
            "admin_name must be None for redacted response"
        );
        assert!(
            result.tech_name.is_none(),
            "tech_name must be None for redacted response"
        );
        assert!(
            result.registrant_email.is_none()
                || !result.registrant_email.as_deref().unwrap().is_empty(),
            "registrant_email should be None or non-empty; never the \
             redaction sentinel"
        );

        // has_core_data should still be true — we have registrar, dates,
        // and nameservers.
        assert!(
            result.has_core_data(),
            "GDPR-redacted response still has core registration data"
        );

        assert!(!result.is_available());
    }

    /// Pure-CRLF thin response (registry-only) without any registrant data.
    /// This is what typical gTLD registries return before the registrar
    /// referral.
    const CRLF_THIN_REGISTRY_FIXTURE: &str = concat!(
        "Domain Name: thin-example.com\r\n",
        "Registry Domain ID: 1234567_DOMAIN_COM-VRSN\r\n",
        "Registrar WHOIS Server: whois.godaddy.com\r\n",
        "Registrar URL: http://www.godaddy.com\r\n",
        "Updated Date: 2025-09-01T00:00:00Z\r\n",
        "Creation Date: 2015-05-20T00:00:00Z\r\n",
        "Registry Expiry Date: 2026-05-20T00:00:00Z\r\n",
        "Registrar: GoDaddy.com, LLC\r\n",
        "Registrar IANA ID: 146\r\n",
        "Domain Status: ok https://icann.org/epp#ok\r\n",
        "Name Server: ns1.thin-example.com\r\n",
        "Name Server: ns2.thin-example.com\r\n",
        "DNSSEC: unsigned\r\n",
    );

    #[test]
    fn test_crlf_thin_registry_fixture() {
        let parser = GenericParser::new();
        let result = parser.parse(
            "thin-example.com",
            "whois.verisign-grs.com",
            CRLF_THIN_REGISTRY_FIXTURE,
        );

        // CRLF line endings must not break regex-based extraction.
        assert_eq!(result.registrar.as_deref(), Some("GoDaddy.com, LLC"));
        assert!(
            result.creation_date.is_some(),
            "creation date must parse under CRLF"
        );
        assert!(
            result.expiration_date.is_some(),
            "expiration date must parse under CRLF"
        );
        assert_eq!(result.nameservers.len(), 2);
        assert_eq!(result.dnssec.as_deref(), Some("unsigned"));
        assert_eq!(result.status.len(), 1);
        assert!(result.has_core_data());
        assert!(!result.is_available());
    }

    /// Minimal "not found" response — typical for available gTLDs.
    const AVAILABLE_COM_FIXTURE: &str = concat!(
        "No match for domain \"THIS-IS-UNREGISTERED-FOR-SURE-12345.COM\".\r\n",
        ">>> Last update of WHOIS database: 2026-04-20T12:00:00Z <<<\r\n",
    );

    #[test]
    fn test_available_com_fixture_is_detected() {
        let parser = GenericParser::new();
        let result = parser.parse(
            "this-is-unregistered-for-sure-12345.com",
            "whois.verisign-grs.com",
            AVAILABLE_COM_FIXTURE,
        );
        assert!(
            result.is_available(),
            "'No match for domain' response must be detected as available"
        );
        assert!(result.registrar.is_none());
        assert!(result.nameservers.is_empty());
    }
}
