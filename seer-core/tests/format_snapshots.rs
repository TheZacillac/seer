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

use seer_core::caa::{CaaPolicy, CaaRecord, ISSUANCE_TIME_NOTE};
use seer_core::confusables::{ConfusableReport, RegisteredLookalike};
use seer_core::dns::{DnsRecord, RecordData, RecordType};
use seer_core::output::{get_formatter, OutputFormat, OutputFormatter};
use seer_core::posture::{
    BimiPolicy, DanePolicy, DmarcPolicy, EmailPosture, MtaStsPolicy, PostureVerdict, SpfPolicy,
    TlsaRecord,
};
use seer_core::rdap::RdapResponse;
use seer_core::ssl::{CertDetail, CertWarning, CertWarningSeverity, SslReport};
use seer_core::status::{DomainExpiration, StatusResponse};
use seer_core::subdomains::{ClassifiedSubdomain, SubdomainClassification, SubdomainStatus};
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

/// A subdomain baseline diff with additions, removals, and unchanged names.
/// The fixed `baseline_recorded_at` keeps the snapshot deterministic.
fn fixture_subdomain_baseline_diff() -> seer_core::subdomains::SubdomainBaselineDiff {
    seer_core::subdomains::SubdomainBaselineDiff {
        domain: "example.com".into(),
        baseline_recorded_at: Some("2026-06-01T12:00:00Z".parse().unwrap()),
        added: vec!["api.example.com".into(), "staging.example.com".into()],
        removed: vec!["old.example.com".into()],
        unchanged_count: 12,
        baseline_missing: false,
    }
}

/// First run: no stored baseline to compare against.
fn fixture_subdomain_baseline_diff_missing() -> seer_core::subdomains::SubdomainBaselineDiff {
    seer_core::subdomains::SubdomainBaselineDiff {
        domain: "example.com".into(),
        baseline_recorded_at: None,
        added: Vec::new(),
        removed: Vec::new(),
        unchanged_count: 0,
        baseline_missing: true,
    }
}

/// Email posture with a spread of verdicts (strict SPF, moderate DMARC,
/// absent MTA-STS, present BIMI/DANE) plus advisory notes, exercising the
/// detail-suffix paths (`-all`, `p=quarantine`, TLSA count).
fn fixture_posture() -> EmailPosture {
    EmailPosture {
        domain: "example.com".into(),
        spf: SpfPolicy {
            present: true,
            record: Some("v=spf1 include:_spf.example.com -all".into()),
            all_qualifier: Some("-".into()),
            verdict: PostureVerdict::Strict,
        },
        dmarc: DmarcPolicy {
            present: true,
            record: Some("v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@example.com".into()),
            policy: Some("quarantine".into()),
            subdomain_policy: None,
            aggregate_reports: vec!["mailto:dmarc@example.com".into()],
            percent: Some(50),
            verdict: PostureVerdict::Moderate,
        },
        mta_sts: MtaStsPolicy {
            present: false,
            record: None,
            id: None,
            verdict: PostureVerdict::Absent,
        },
        bimi: BimiPolicy {
            present: true,
            record: Some("v=BIMI1; l=https://example.com/logo.svg".into()),
            logo_url: Some("https://example.com/logo.svg".into()),
            authority_url: None,
            verdict: PostureVerdict::Present,
        },
        dane: DanePolicy {
            present: true,
            records: vec![TlsaRecord {
                scope: "_25._tcp".into(),
                cert_usage: 3,
                selector: 1,
                matching: 1,
                cert_data: "ABCDEF0123".into(),
            }],
            verdict: PostureVerdict::Present,
        },
        notes: vec![
            "DMARC pct=50 applies the policy to only half of spoofed mail".into(),
            "MTA-STS is not configured".into(),
        ],
    }
}

#[test]
fn human_posture_snapshot() {
    snap!(human().format_posture(&fixture_posture()));
}

#[test]
fn markdown_posture_snapshot() {
    snap!(markdown().format_posture(&fixture_posture()));
}

/// Registered look-alikes with both fully-populated and sparse (no
/// registrar/creation date) entries.
fn fixture_confusables() -> ConfusableReport {
    ConfusableReport {
        domain: "example.com".into(),
        candidates_generated: 42,
        candidates_checked: 42,
        registered: vec![
            RegisteredLookalike {
                domain: "examp1e.com".into(),
                technique: "homoglyph".into(),
                registrar: Some("Mock Registrar Inc.".into()),
                creation_date: Some("2025-11-02T00:00:00Z".parse().unwrap()),
                nameservers: vec!["ns1.parking.example".into()],
            },
            RegisteredLookalike {
                domain: "exampel.com".into(),
                technique: "transposition".into(),
                registrar: None,
                creation_date: None,
                nameservers: Vec::new(),
            },
        ],
    }
}

#[test]
fn human_confusables_snapshot() {
    snap!(human().format_confusables(&fixture_confusables()));
}

#[test]
fn markdown_confusables_snapshot() {
    snap!(markdown().format_confusables(&fixture_confusables()));
}

/// Classified subdomains covering all three statuses, a dangling-CNAME
/// takeover risk, a wildcard-detected banner, and a skipped-names notice.
fn fixture_subdomain_classification() -> SubdomainClassification {
    SubdomainClassification {
        domain: "example.com".into(),
        wildcard_detected: true,
        subdomains: vec![
            ClassifiedSubdomain {
                name: "www.example.com".into(),
                status: SubdomainStatus::Live,
                addresses: vec!["93.184.216.34".into()],
                cname: None,
                takeover_risk: None,
            },
            ClassifiedSubdomain {
                name: "docs.example.com".into(),
                status: SubdomainStatus::Dead,
                addresses: Vec::new(),
                cname: Some("example.github.io.".into()),
                takeover_risk: Some("GitHub Pages".into()),
            },
            ClassifiedSubdomain {
                name: "random.example.com".into(),
                status: SubdomainStatus::Wildcard,
                addresses: vec!["203.0.113.9".into()],
                cname: None,
                takeover_risk: None,
            },
        ],
        names_skipped: 3,
    }
}

#[test]
fn human_subdomain_classification_snapshot() {
    snap!(human().format_subdomain_classification(&fixture_subdomain_classification()));
}

#[test]
fn markdown_subdomain_classification_snapshot() {
    snap!(markdown().format_subdomain_classification(&fixture_subdomain_classification()));
}

/// A CAA policy exercising the PR #101 extensions: iodef incident-reporting
/// contacts and a wildcard-broader-than-named issuance note (mirrors what
/// `CaaPolicy::from_records` derives for these records).
fn fixture_caa_policy() -> CaaPolicy {
    CaaPolicy {
        records: vec![
            CaaRecord {
                flags: 0,
                tag: "issue".into(),
                value: "letsencrypt.org".into(),
            },
            CaaRecord {
                flags: 0,
                tag: "issuewild".into(),
                value: "pki.goog".into(),
            },
            CaaRecord {
                flags: 128,
                tag: "iodef".into(),
                value: "mailto:security@example.com".into(),
            },
        ],
        effective_domain: Some("example.com".into()),
        has_policy: true,
        issuer_match: None,
        iodef: vec!["mailto:security@example.com".into()],
        wildcard_note: Some(
            "issuewild permits CA(s) not allowed by issue (pki.goog) — wildcard issuance is \
             broader than named issuance"
                .into(),
        ),
        note: ISSUANCE_TIME_NOTE.to_string(),
    }
}

#[test]
fn human_caa_snapshot() {
    snap!(human().format_caa(&fixture_caa_policy()));
}

#[test]
fn markdown_caa_snapshot() {
    snap!(markdown().format_caa(&fixture_caa_policy()));
}

/// A date-valid but troubled leaf certificate whose warnings mirror what
/// `derive_cert_warnings` produces for these fields: weak RSA key, deprecated
/// SHA-1 signature, self-signed (subject == issuer), hostname mismatch.
/// `days_until_expiry` is a fixed struct field, so the output is stable.
fn fixture_ssl_report_with_warnings() -> SslReport {
    SslReport {
        domain: "example.com".into(),
        chain: vec![CertDetail {
            subject: "CN=example.com".into(),
            issuer: "CN=example.com".into(),
            valid_from: "2025-01-01T00:00:00Z".parse().unwrap(),
            valid_until: "2027-01-01T00:00:00Z".parse().unwrap(),
            serial_number: "04:AB:CD:EF".into(),
            signature_algorithm: Some("SHA1-RSA".into()),
            is_ca: false,
            key_type: Some("RSA".into()),
            key_bits: Some(1024),
        }],
        protocol_version: Some("TLSv1.3".into()),
        san_names: vec!["example.com".into(), "www.example.com".into()],
        is_valid: true,
        hostname_verified: false,
        days_until_expiry: 180,
        caa: None,
        warnings: vec![
            CertWarning {
                severity: CertWarningSeverity::Critical,
                message: "RSA key size 1024 is below the 2048-bit minimum".into(),
            },
            CertWarning {
                severity: CertWarningSeverity::Critical,
                message: "Certificate uses deprecated signature algorithm: SHA1-RSA".into(),
            },
            CertWarning {
                severity: CertWarningSeverity::Warning,
                message: "Certificate is self-signed (issuer equals subject)".into(),
            },
            CertWarning {
                severity: CertWarningSeverity::Critical,
                message: "Certificate does not match the requested hostname".into(),
            },
        ],
    }
}

#[test]
fn human_ssl_warnings_snapshot() {
    snap!(human().format_ssl(&fixture_ssl_report_with_warnings()));
}

#[test]
fn markdown_ssl_snapshot() {
    snap!(markdown().format_ssl(&fixture_ssl_report_with_warnings()));
}

#[test]
fn human_subdomain_baseline_diff_snapshot() {
    snap!(human().format_subdomain_baseline_diff(&fixture_subdomain_baseline_diff()));
}

#[test]
fn markdown_subdomain_baseline_diff_snapshot() {
    snap!(markdown().format_subdomain_baseline_diff(&fixture_subdomain_baseline_diff()));
}

#[test]
fn human_subdomain_baseline_diff_missing_snapshot() {
    snap!(human().format_subdomain_baseline_diff(&fixture_subdomain_baseline_diff_missing()));
}

#[test]
fn markdown_subdomain_baseline_diff_missing_snapshot() {
    snap!(markdown().format_subdomain_baseline_diff(&fixture_subdomain_baseline_diff_missing()));
}
