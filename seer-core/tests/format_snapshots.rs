//! Snapshot tests for the human and markdown formatters.
//!
//! These pin the rendered output of the main response types so formatting
//! regressions show up as snapshot diffs instead of going unnoticed (the
//! formatters previously had no test coverage at all).
//!
//! Determinism notes:
//! - `colored::control::set_override(true)` forces ANSI on regardless of tty,
//!   so the human snapshots capture the real styled output everywhere
//!   (matching the precedent in `output/human/diff.rs` tests).
//! - The whois/rdap formatters render "days until expiry" relative to
//!   `Utc::now()`; fixtures use far-future expiries (stable color bucket for
//!   decades) and an insta filter redacts the changing day count.

use seer_core::dns::{DnsRecord, RecordData, RecordType};
use seer_core::output::{get_formatter, OutputFormat, OutputFormatter};
use seer_core::rdap::RdapResponse;
use seer_core::status::{DomainExpiration, StatusResponse};
use seer_core::whois::WhoisResponse;

fn human() -> Box<dyn OutputFormatter> {
    colored::control::set_override(true);
    get_formatter(OutputFormat::Human)
}

fn markdown() -> Box<dyn OutputFormatter> {
    colored::control::set_override(true);
    get_formatter(OutputFormat::Markdown)
}

/// Redact now()-relative day counts so snapshots don't expire.
macro_rules! snap {
    ($value:expr) => {
        insta::with_settings!({filters => vec![(r"\b\d+ days?\b", "[N] days")]}, {
            insta::assert_snapshot!($value);
        });
    };
}

fn fixture_whois() -> WhoisResponse {
    WhoisResponse::parse(
        "example.com",
        "whois.verisign-grs.com",
        "Domain Name: EXAMPLE.COM\n\
         Registrar: Mock Registrar Inc.\n\
         Registrar WHOIS Server: whois.mock-registrar.example\n\
         Creation Date: 2010-03-15T04:00:00Z\n\
         Updated Date: 2024-02-01T09:30:00Z\n\
         Registry Expiry Date: 2099-03-15T04:00:00Z\n\
         Registrant Organization: Example Holdings LLC\n\
         Registrant Country: US\n\
         Name Server: NS1.EXAMPLE.COM\n\
         Name Server: NS2.EXAMPLE.COM\n\
         Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n\
         DNSSEC: signedDelegation\n",
    )
}

fn fixture_rdap() -> RdapResponse {
    serde_json::from_str(
        r#"{
            "objectClassName": "domain",
            "handle": "2336799_DOMAIN_COM-VRSN",
            "ldhName": "EXAMPLE.COM",
            "status": ["client transfer prohibited", "server delete prohibited"],
            "events": [
                {"eventAction": "registration", "eventDate": "2010-03-15T04:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2024-02-01T09:30:00Z"},
                {"eventAction": "expiration", "eventDate": "2099-03-15T04:00:00Z"}
            ],
            "nameservers": [
                {"objectClassName": "nameserver", "ldhName": "NS1.EXAMPLE.COM"},
                {"objectClassName": "nameserver", "ldhName": "NS2.EXAMPLE.COM"}
            ],
            "entities": [
                {
                    "objectClassName": "entity",
                    "handle": "MOCK-REGISTRAR",
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Mock Registrar Inc."]]]
                }
            ]
        }"#,
    )
    .expect("fixture RDAP JSON must deserialize")
}

fn fixture_dns_records() -> Vec<DnsRecord> {
    vec![
        DnsRecord {
            name: "example.com".into(),
            record_type: RecordType::A,
            ttl: 3600,
            data: RecordData::A {
                address: "93.184.216.34".into(),
            },
        },
        DnsRecord {
            name: "example.com".into(),
            record_type: RecordType::MX,
            ttl: 1800,
            data: RecordData::MX {
                preference: 10,
                exchange: "mail.example.com".into(),
            },
        },
        DnsRecord {
            name: "www.example.com".into(),
            record_type: RecordType::CNAME,
            ttl: 300,
            data: RecordData::CNAME {
                target: "example.com".into(),
            },
        },
    ]
}

fn fixture_status() -> StatusResponse {
    StatusResponse {
        domain: "example.com".into(),
        http_status: Some(200),
        http_status_text: Some("OK".into()),
        title: Some("Example Domain".into()),
        certificate: None,
        domain_expiration: Some(DomainExpiration {
            expiration_date: "2099-03-15T04:00:00Z".parse().unwrap(),
            days_until_expiry: 26_660,
            registrar: Some("Mock Registrar Inc.".into()),
        }),
        dns_resolution: None,
        caa: None,
        errors: Vec::new(),
    }
}

/// An already-expired domain (negative days remaining). Exercises the
/// expired-rendering path that previously printed "(-N days!)".
fn fixture_status_expired() -> StatusResponse {
    StatusResponse {
        domain: "expired.example".into(),
        http_status: Some(200),
        http_status_text: Some("OK".into()),
        title: None,
        certificate: None,
        domain_expiration: Some(DomainExpiration {
            expiration_date: "2020-01-01T00:00:00Z".parse().unwrap(),
            days_until_expiry: -45,
            registrar: Some("Mock Registrar Inc.".into()),
        }),
        dns_resolution: None,
        caa: None,
        errors: Vec::new(),
    }
}

#[test]
fn human_status_expired_domain_says_expired() {
    let out = human().format_status(&fixture_status_expired());
    assert!(
        out.contains("expired"),
        "human output should say 'expired': {out}"
    );
    assert!(
        !out.contains("(-"),
        "must not render a negative day count like (-45 days!): {out}"
    );
}

#[test]
fn markdown_status_expired_domain_says_expired() {
    let out = markdown().format_status(&fixture_status_expired());
    assert!(
        out.contains("expired"),
        "markdown output should say 'expired': {out}"
    );
    assert!(
        !out.contains("(-"),
        "must not render a negative day count: {out}"
    );
}

#[test]
fn human_whois_snapshot() {
    snap!(human().format_whois(&fixture_whois()));
}

#[test]
fn markdown_whois_snapshot() {
    snap!(markdown().format_whois(&fixture_whois()));
}

#[test]
fn human_rdap_snapshot() {
    snap!(human().format_rdap(&fixture_rdap()));
}

#[test]
fn markdown_rdap_snapshot() {
    snap!(markdown().format_rdap(&fixture_rdap()));
}

#[test]
fn human_dns_snapshot() {
    snap!(human().format_dns(&fixture_dns_records()));
}

#[test]
fn markdown_dns_snapshot() {
    snap!(markdown().format_dns(&fixture_dns_records()));
}

/// A single A record. Used to assert the uniform-type header path.
fn fixture_uniform_a_records() -> Vec<DnsRecord> {
    vec![DnsRecord {
        name: "example.com".into(),
        record_type: RecordType::A,
        ttl: 60,
        data: RecordData::A {
            address: "1.2.3.4".into(),
        },
    }]
}

#[test]
fn human_dns_header_labels_mixed_record_types_as_any() {
    // Regression: the header was derived from records[0].record_type, so an
    // ANY query (which returns A + AAAA + MX + ...) was mislabeled "DNS A
    // Records". A mixed result set must not be labeled by whichever type
    // happened to come back first.
    let out = human().format_dns(&fixture_dns_records()); // A + MX + CNAME
    assert!(
        out.contains("DNS ANY Records"),
        "mixed-type header should say ANY, got:\n{out}"
    );
    assert!(
        !out.contains("DNS A Records"),
        "mixed-type header must not be labeled by the first record type:\n{out}"
    );
}

#[test]
fn human_dns_header_uses_single_type_for_uniform_records() {
    let out = human().format_dns(&fixture_uniform_a_records());
    assert!(out.contains("DNS A Records"), "got:\n{out}");
}

#[test]
fn markdown_dns_header_labels_mixed_record_types_as_any() {
    let out = markdown().format_dns(&fixture_dns_records());
    assert!(out.contains("DNS ANY Records"), "got:\n{out}");
    assert!(!out.contains("DNS A Records"), "got:\n{out}");
}

#[test]
fn human_status_snapshot() {
    snap!(human().format_status(&fixture_status()));
}

#[test]
fn markdown_status_snapshot() {
    snap!(markdown().format_status(&fixture_status()));
}
