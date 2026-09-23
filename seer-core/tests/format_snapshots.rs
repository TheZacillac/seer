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

// Integration-test target: helper fns here run outside `#[test]` bodies, so
// clippy's `allow-unwrap-in-tests` doesn't reach them; unwrap is as idiomatic
// here as in unit tests.
#![allow(clippy::unwrap_used)]

use seer_core::availability::AvailabilityResult;
use seer_core::caa::{CaaPolicy, CaaRecord, ISSUANCE_TIME_NOTE};
use seer_core::confusables::{ConfusableReport, RegisteredLookalike};
use seer_core::diff::{DnsDiff, DomainDiff, RegistrationDiff, SslDiff};
use seer_core::dns::{
    DelegationReport, DnsComparison, DnsRecord, DnssecReport, FollowIteration, FollowResult,
    LameNs, PropagationResult, RecordData, RecordType, ServerResult,
};
use seer_core::domain_info::DomainInfo;
use seer_core::drift::{DriftReport, FieldChange};
use seer_core::headers::{CookieFinding, Disclosure, HeaderFinding, HeaderReport, HeaderVerdict};
use seer_core::lookup::LookupResult;
use seer_core::output::{get_formatter, OutputFormat, OutputFormatter};
use seer_core::posture::{
    BimiPolicy, DanePolicy, DmarcPolicy, EmailPosture, MtaStsPolicy, PostureVerdict, SpfPolicy,
    TlsaRecord,
};
use seer_core::rdap::RdapResponse;
use seer_core::ssl::{CertDetail, CertWarning, CertWarningSeverity, SslReport};
use seer_core::status::{CertificateInfo, DnsResolution, DomainExpiration, StatusResponse};
use seer_core::subdomains::{
    ClassifiedSubdomain, SubdomainClassification, SubdomainResult, SubdomainStatus,
};
use seer_core::takeover::{TakeoverFinding, TakeoverReport, TakeoverVerdict};
use seer_core::tld::TldInfo;
use seer_core::watchlist::{WatchReport, WatchResult};
use seer_core::whois::WhoisResponse;

fn human() -> Box<dyn OutputFormatter> {
    colored::control::set_override(true);
    get_formatter(OutputFormat::Human)
}

fn markdown() -> Box<dyn OutputFormatter> {
    colored::control::set_override(true);
    get_formatter(OutputFormat::Markdown)
}

fn json() -> Box<dyn OutputFormatter> {
    get_formatter(OutputFormat::Json)
}

fn yaml() -> Box<dyn OutputFormatter> {
    get_formatter(OutputFormat::Yaml)
}

/// Redact now()-relative day counts so snapshots don't expire.
macro_rules! snap {
    ($value:expr) => {
        insta::with_settings!({filters => vec![(r"\b\d+ days?\b", "[N] days")]}, {
            insta::assert_snapshot!($value);
        });
    };
}

/// Declares one snapshot test per `name => formatter.method(fixture);` row.
/// insta names each baseline after the test fn
/// (`snapshots/format_snapshots__<name>.snap`), so a row must never be
/// renamed without renaming its `.snap` file too.
macro_rules! snapshot_tests {
    ($($name:ident => $fmt:ident.$method:ident($fixture:expr);)+) => {
        $(
            #[test]
            fn $name() {
                snap!($fmt().$method(&$fixture));
            }
        )+
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

/// A date-valid certificate that does not match the queried hostname
/// (`is_valid` is date-range only, so it still reads "Valid").
fn fixture_status_hostname_mismatch() -> StatusResponse {
    StatusResponse {
        certificate: Some(CertificateInfo {
            issuer: "CN=Mock CA".into(),
            subject: "CN=other.example".into(),
            valid_from: "2025-01-01T00:00:00Z".parse().unwrap(),
            valid_until: "2099-01-01T00:00:00Z".parse().unwrap(),
            days_until_expiry: 26_000,
            is_valid: true,
            hostname_verified: false,
        }),
        ..fixture_status()
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

snapshot_tests! {
    human_whois_snapshot => human.format_whois(fixture_whois());
    markdown_whois_snapshot => markdown.format_whois(fixture_whois());
    human_rdap_snapshot => human.format_rdap(fixture_rdap());
    markdown_rdap_snapshot => markdown.format_rdap(fixture_rdap());
    human_dns_snapshot => human.format_dns(fixture_dns_records());
    markdown_dns_snapshot => markdown.format_dns(fixture_dns_records());
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

snapshot_tests! {
    human_status_snapshot => human.format_status(fixture_status());
    markdown_status_snapshot => markdown.format_status(fixture_status());
    // Markdown used to show only "- **Status**: Valid" for a mismatched cert,
    // while the human formatter warned; the hostname check must be visible.
    markdown_status_hostname_mismatch_snapshot =>
        markdown.format_status(fixture_status_hostname_mismatch());
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

snapshot_tests! {
    human_posture_snapshot => human.format_posture(fixture_posture());
    markdown_posture_snapshot => markdown.format_posture(fixture_posture());
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

snapshot_tests! {
    human_confusables_snapshot => human.format_confusables(fixture_confusables());
    markdown_confusables_snapshot => markdown.format_confusables(fixture_confusables());
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

snapshot_tests! {
    human_subdomain_classification_snapshot =>
        human.format_subdomain_classification(fixture_subdomain_classification());
    markdown_subdomain_classification_snapshot =>
        markdown.format_subdomain_classification(fixture_subdomain_classification());
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

snapshot_tests! {
    human_caa_snapshot => human.format_caa(fixture_caa_policy());
    markdown_caa_snapshot => markdown.format_caa(fixture_caa_policy());
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

snapshot_tests! {
    human_ssl_warnings_snapshot => human.format_ssl(fixture_ssl_report_with_warnings());
    markdown_ssl_snapshot => markdown.format_ssl(fixture_ssl_report_with_warnings());
}

/// A healthy delegation: parent and zone agree on the NS set, nothing lame.
fn fixture_delegation_healthy() -> DelegationReport {
    DelegationReport {
        domain: "example.com".into(),
        parent_zone: "com".into(),
        parent_server_queried: vec!["a.gtld-servers.net".into(), "b.gtld-servers.net".into()],
        delegated_ns: vec!["ns1.example.com".into(), "ns2.example.com".into()],
        zone_ns: vec!["ns1.example.com".into(), "ns2.example.com".into()],
        in_sync: true,
        missing_from_zone: Vec::new(),
        missing_from_parent: Vec::new(),
        lame: Vec::new(),
        warnings: Vec::new(),
    }
}

/// A broken delegation exercising every problem section: a set mismatch in
/// both directions, a lame (refusing) server, and a warning.
fn fixture_delegation_broken() -> DelegationReport {
    DelegationReport {
        domain: "example.com".into(),
        parent_zone: "com".into(),
        parent_server_queried: vec!["a.gtld-servers.net".into()],
        delegated_ns: vec!["ns-old.example.net".into(), "ns1.example.com".into()],
        zone_ns: vec!["ns1.example.com".into(), "ns2.example.com".into()],
        in_sync: false,
        missing_from_zone: vec!["ns-old.example.net".into()],
        missing_from_parent: vec!["ns2.example.com".into()],
        lame: vec![LameNs {
            host: "ns-old.example.net".into(),
            reason: "refused the query (REFUSED)".into(),
        }],
        warnings: vec!["skipped parent server b.gtld-servers.net: could not resolve".into()],
    }
}

snapshot_tests! {
    human_delegation_healthy_snapshot => human.format_delegation(fixture_delegation_healthy());
    markdown_delegation_healthy_snapshot =>
        markdown.format_delegation(fixture_delegation_healthy());
    human_delegation_broken_snapshot => human.format_delegation(fixture_delegation_broken());
    markdown_delegation_broken_snapshot => markdown.format_delegation(fixture_delegation_broken());
    human_subdomain_baseline_diff_snapshot =>
        human.format_subdomain_baseline_diff(fixture_subdomain_baseline_diff());
    markdown_subdomain_baseline_diff_snapshot =>
        markdown.format_subdomain_baseline_diff(fixture_subdomain_baseline_diff());
    human_subdomain_baseline_diff_missing_snapshot =>
        human.format_subdomain_baseline_diff(fixture_subdomain_baseline_diff_missing());
    markdown_subdomain_baseline_diff_missing_snapshot =>
        markdown.format_subdomain_baseline_diff(fixture_subdomain_baseline_diff_missing());
}

// --- Registration contacts, lookup, and merged domain info -----------------

/// WHOIS with every contact block populated (registrant details, admin,
/// tech) on top of [`fixture_whois`].
fn fixture_whois_with_contacts() -> WhoisResponse {
    let mut w = fixture_whois();
    w.registrant = Some("Jane Registrant".into());
    w.organization = Some("Example Holdings LLC".into());
    w.registrant_email = Some("owner@example.com".into());
    w.registrant_phone = Some("+1.5555550100".into());
    w.registrant_address = Some("1 Main St, Springfield".into());
    w.admin_name = Some("Alex Admin".into());
    w.admin_organization = Some("Example Holdings LLC".into());
    w.admin_email = Some("admin@example.com".into());
    w.admin_phone = Some("+1.5555550101".into());
    w.tech_name = Some("Terry Tech".into());
    w.tech_email = Some("tech@example.com".into());
    w
}

/// RDAP with registrant/admin/tech/billing entities and a registrar carrying
/// the IANA ID, URL, and abuse contact. Admin and tech carry no postal
/// address, so every formatter renders the same field set for them.
fn fixture_rdap_with_contacts() -> RdapResponse {
    serde_json::from_value(serde_json::json!({
        "objectClassName": "domain",
        "handle": "2336799_DOMAIN_COM-VRSN",
        "ldhName": "EXAMPLE.COM",
        "status": ["client transfer prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "2010-03-15T04:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2024-02-01T09:30:00Z"},
            {"eventAction": "expiration", "eventDate": "2099-03-15T04:00:00Z"}
        ],
        "nameservers": [{"objectClassName": "nameserver", "ldhName": "NS1.EXAMPLE.COM"}],
        "secureDNS": {"delegationSigned": true},
        "links": [{"rel": "self", "href": "https://rdap.example/domain/EXAMPLE.COM"}],
        "entities": [
            {
                "objectClassName": "entity",
                "roles": ["registrar"],
                "publicIds": [{"type": "IANA Registrar ID", "identifier": "9999"}],
                "links": [{"rel": "about", "href": "https://registrar.example"}],
                "vcardArray": ["vcard", [["fn", {}, "text", "Mock Registrar Inc."]]],
                "entities": [{
                    "objectClassName": "entity",
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [
                        ["email", {}, "text", "abuse@registrar.example"],
                        ["tel", {}, "uri", "tel:+1.5555550199"]
                    ]]
                }]
            },
            {
                "objectClassName": "entity",
                "roles": ["registrant"],
                "vcardArray": ["vcard", [
                    ["fn", {}, "text", "Jane Registrant"],
                    ["org", {}, "text", "Example Holdings LLC"],
                    ["email", {}, "text", "owner@example.com"],
                    ["adr", {}, "text", ["", "", "1 Main St", "Springfield", "", "", "US"]]
                ]]
            },
            {
                "objectClassName": "entity",
                "roles": ["administrative"],
                "vcardArray": ["vcard", [
                    ["fn", {}, "text", "Alex Admin"],
                    ["org", {}, "text", "Example Holdings LLC"],
                    ["email", {}, "text", "admin@example.com"],
                    ["tel", {}, "text", "+1.5555550101"]
                ]]
            },
            {
                "objectClassName": "entity",
                "roles": ["technical"],
                "vcardArray": ["vcard", [
                    ["fn", {}, "text", "Terry Tech"],
                    ["email", {}, "text", "tech@example.com"]
                ]]
            },
            {
                "objectClassName": "entity",
                "roles": ["billing"],
                "vcardArray": ["vcard", [
                    ["fn", {}, "text", "Bill Billing"],
                    ["adr", {}, "text", ["", "", "2 Side St", "Shelbyville", "", "", "US"]]
                ]]
            }
        ]
    }))
    .expect("fixture RDAP JSON must deserialize")
}

/// An IP-network RDAP object (start/end address, country).
fn fixture_rdap_ip_network() -> RdapResponse {
    serde_json::from_value(serde_json::json!({
        "objectClassName": "ip network",
        "handle": "NET-192-0-2-0-1",
        "name": "TEST-NET-1",
        "startAddress": "192.0.2.0",
        "endAddress": "192.0.2.255",
        "country": "US"
    }))
    .expect("fixture RDAP JSON must deserialize")
}

/// An autnum RDAP object.
fn fixture_rdap_autnum() -> RdapResponse {
    serde_json::from_value(serde_json::json!({
        "objectClassName": "autnum",
        "handle": "AS64496",
        "name": "EXAMPLE-AS",
        "startAutnum": 64496,
        "endAutnum": 64511
    }))
    .expect("fixture RDAP JSON must deserialize")
}

/// RDAP answered but carried only the registrar, so every contact comes
/// from the WHOIS fallback.
fn fixture_lookup_rdap_with_whois_fallback() -> LookupResult {
    LookupResult::Rdap {
        data: Box::new(fixture_rdap()),
        whois_fallback: Some(fixture_whois_with_contacts()),
    }
}

fn fixture_lookup_rdap_with_contacts() -> LookupResult {
    LookupResult::Rdap {
        data: Box::new(fixture_rdap_with_contacts()),
        whois_fallback: None,
    }
}

fn fixture_lookup_whois() -> LookupResult {
    LookupResult::Whois {
        data: fixture_whois_with_contacts(),
        rdap_error: Some("RDAP bootstrap has no entry for this TLD".into()),
        rdap_fallback: None,
    }
}

fn fixture_availability() -> AvailabilityResult {
    AvailabilityResult {
        domain: "example.com".into(),
        available: false,
        confidence: "medium".into(),
        method: "whois".into(),
        details: Some("WHOIS returned registration data".into()),
    }
}

fn fixture_lookup_available() -> LookupResult {
    LookupResult::Available {
        data: Box::new(fixture_availability()),
        rdap_error: "RDAP server returned 503".into(),
        whois_error: String::new(),
        whois_data: Some(fixture_whois()),
    }
}

/// Merged RDAP + WHOIS view. The now()-relative lifecycle counts are pinned
/// (markdown renders them without a "days" suffix the filter could redact).
fn fixture_domain_info() -> DomainInfo {
    let mut info = DomainInfo::from_sources(
        "example.com",
        Some(&fixture_rdap_with_contacts()),
        Some(&fixture_whois_with_contacts()),
    );
    info.days_until_expiration = Some(26_660);
    info.domain_age_days = Some(5_800);
    info
}

snapshot_tests! {
    human_whois_contacts_snapshot => human.format_whois(fixture_whois_with_contacts());
    markdown_whois_contacts_snapshot => markdown.format_whois(fixture_whois_with_contacts());
    human_rdap_contacts_snapshot => human.format_rdap(fixture_rdap_with_contacts());
    markdown_rdap_contacts_snapshot => markdown.format_rdap(fixture_rdap_with_contacts());
    human_rdap_ip_network_snapshot => human.format_rdap(fixture_rdap_ip_network());
    markdown_rdap_ip_network_snapshot => markdown.format_rdap(fixture_rdap_ip_network());
    human_rdap_autnum_snapshot => human.format_rdap(fixture_rdap_autnum());
    markdown_rdap_autnum_snapshot => markdown.format_rdap(fixture_rdap_autnum());
    human_lookup_rdap_fallback_snapshot =>
        human.format_lookup(fixture_lookup_rdap_with_whois_fallback());
    markdown_lookup_rdap_fallback_snapshot =>
        markdown.format_lookup(fixture_lookup_rdap_with_whois_fallback());
    human_lookup_rdap_contacts_snapshot => human.format_lookup(fixture_lookup_rdap_with_contacts());
    markdown_lookup_rdap_contacts_snapshot =>
        markdown.format_lookup(fixture_lookup_rdap_with_contacts());
    human_lookup_whois_snapshot => human.format_lookup(fixture_lookup_whois());
    markdown_lookup_whois_snapshot => markdown.format_lookup(fixture_lookup_whois());
    human_lookup_available_snapshot => human.format_lookup(fixture_lookup_available());
    markdown_lookup_available_snapshot => markdown.format_lookup(fixture_lookup_available());
    human_availability_snapshot => human.format_availability(fixture_availability());
    markdown_availability_snapshot => markdown.format_availability(fixture_availability());
    human_domain_info_snapshot => human.format_domain_info(fixture_domain_info());
    markdown_domain_info_snapshot => markdown.format_domain_info(fixture_domain_info());
    json_lookup_rdap_fallback_snapshot =>
        json.format_lookup(fixture_lookup_rdap_with_whois_fallback());
    yaml_lookup_rdap_fallback_snapshot =>
        yaml.format_lookup(fixture_lookup_rdap_with_whois_fallback());
}

// --- DNS, TLD, and watch reports ----------------------------------------

fn a_record(name: &str, address: &str) -> DnsRecord {
    DnsRecord {
        name: name.into(),
        record_type: RecordType::A,
        ttl: 300,
        data: RecordData::A {
            address: address.into(),
        },
    }
}

fn fixture_tld() -> TldInfo {
    TldInfo {
        tld: "com".into(),
        whois_server: Some("whois.verisign-grs.com".into()),
        rdap_url: Some("https://rdap.verisign.com/com/v1/".into()),
        registry_url: Some("https://www.verisign.com".into()),
        tld_type: "generic".into(),
    }
}

/// A TLD with no known servers (the "not available" branches).
fn fixture_tld_sparse() -> TldInfo {
    TldInfo {
        tld: "example".into(),
        whois_server: None,
        rdap_url: None,
        registry_url: None,
        tld_type: "reserved".into(),
    }
}

fn fixture_subdomains() -> SubdomainResult {
    SubdomainResult {
        domain: "example.com".into(),
        subdomains: vec!["api.example.com".into(), "www.example.com".into()],
        source: "crt.sh".into(),
        count: 2,
    }
}

fn fixture_watch() -> WatchReport {
    WatchReport {
        checked_at: "2026-06-01T12:00:00Z".parse().unwrap(),
        results: vec![
            WatchResult {
                domain: "example.com".into(),
                ssl_days_remaining: Some(80),
                domain_days_remaining: Some(400),
                registrar: Some("Mock Registrar Inc.".into()),
                http_status: Some(200),
                issues: Vec::new(),
            },
            WatchResult {
                domain: "expiring.example".into(),
                ssl_days_remaining: Some(5),
                domain_days_remaining: None,
                registrar: None,
                http_status: None,
                issues: vec!["SSL certificate expires in 5 days".into()],
            },
        ],
        total: 2,
        warnings: 1,
        critical: 0,
    }
}

fn fixture_dnssec() -> DnssecReport {
    serde_json::from_value(serde_json::json!({
        "domain": "example.com",
        "enabled": true,
        "has_ds_records": true,
        "has_dnskey_records": true,
        "ds_records": [
            {"key_tag": 370, "algorithm": 13, "digest_type": 2, "digest": "ABCD",
             "algorithm_name": "ECDSAP256SHA256", "digest_type_name": "SHA-256",
             "matched_key": true, "digest_verified": true},
            {"key_tag": 999, "algorithm": 8, "digest_type": 2, "digest": "EF01",
             "algorithm_name": "RSASHA256", "digest_type_name": "SHA-256",
             "matched_key": false, "digest_verified": false}
        ],
        "dnskey_records": [
            {"flags": 257, "protocol": 3, "algorithm": 13, "key_tag": 370,
             "is_ksk": true, "is_zsk": false, "algorithm_name": "ECDSAP256SHA256"},
            {"flags": 256, "protocol": 3, "algorithm": 13, "key_tag": 12345,
             "is_ksk": false, "is_zsk": true, "algorithm_name": "ECDSAP256SHA256"}
        ],
        "issues": ["DS key tag 999 matches no published DNSKEY"],
        "status": "misconfigured",
        "chain_valid": false,
        "authentication_tier": "digest-only"
    }))
    .expect("fixture DNSSEC JSON must deserialize")
}

fn fixture_dns_comparison() -> DnsComparison {
    DnsComparison {
        domain: "example.com".into(),
        record_type: RecordType::A,
        server_a: ServerResult {
            nameserver: "8.8.8.8".into(),
            records: vec![a_record("example.com", "192.0.2.1")],
            error: None,
        },
        server_b: ServerResult {
            nameserver: "1.1.1.1".into(),
            records: Vec::new(),
            error: Some("query timed out".into()),
        },
        matches: false,
        only_in_a: vec!["192.0.2.1".into()],
        only_in_b: Vec::new(),
        common: Vec::new(),
    }
}

fn fixture_follow_iteration() -> FollowIteration {
    FollowIteration {
        iteration: 2,
        total_iterations: 3,
        timestamp: "2026-06-01T12:00:30Z".parse().unwrap(),
        records: vec![a_record("example.com", "192.0.2.2")],
        changed: true,
        added: vec!["192.0.2.2".into()],
        removed: vec!["192.0.2.1".into()],
        error: None,
    }
}

fn fixture_follow() -> FollowResult {
    let first = FollowIteration {
        iteration: 1,
        timestamp: "2026-06-01T12:00:00Z".parse().unwrap(),
        records: vec![a_record("example.com", "192.0.2.1")],
        changed: false,
        added: Vec::new(),
        removed: Vec::new(),
        ..fixture_follow_iteration()
    };
    FollowResult {
        domain: "example.com".into(),
        record_type: RecordType::A,
        nameserver: None,
        iterations_requested: 3,
        interval_secs: 30,
        iterations: vec![first, fixture_follow_iteration()],
        interrupted: true,
        total_changes: 1,
        started_at: "2026-06-01T12:00:00Z".parse().unwrap(),
        ended_at: "2026-06-01T12:01:05Z".parse().unwrap(),
    }
}

/// Two regions, one unreachable server, and one divergent answer.
fn fixture_propagation() -> PropagationResult {
    let record = |ip: &str| serde_json::to_value(a_record("example.com", ip)).unwrap();
    serde_json::from_value(serde_json::json!({
        "domain": "example.com",
        "record_type": "A",
        "servers_checked": 3,
        "servers_responding": 2,
        "propagation_percentage": 50.0,
        "results": [
            {"server": {"name": "Google", "ip": "8.8.8.8", "location": "North America",
                        "provider": "Google"},
             "records": [record("192.0.2.1")], "response_time_ms": 12, "success": true,
             "error": null},
            {"server": {"name": "Quad9", "ip": "9.9.9.9", "location": "Europe",
                        "provider": "Quad9"},
             "records": [record("192.0.2.9")], "response_time_ms": 30, "success": true,
             "error": null},
            {"server": {"name": "Yandex", "ip": "77.88.8.8", "location": "Europe",
                        "provider": "Yandex"},
             "records": [], "response_time_ms": 5000, "success": false,
             "error": "timeout"}
        ],
        "consensus_values": [{"type": "A", "value": "192.0.2.1"}],
        "inconsistencies": [{"type": "A", "server_name": "Quad9", "server_ip": "9.9.9.9",
                             "values": ["192.0.2.9"], "consensus": ["192.0.2.1"]}],
        "unreachable_servers": [{"name": "Yandex", "ip": "77.88.8.8", "error": "timeout"}],
        "dnssec_validated": false
    }))
    .expect("fixture propagation JSON must deserialize")
}

snapshot_tests! {
    human_tld_snapshot => human.format_tld(fixture_tld());
    markdown_tld_snapshot => markdown.format_tld(fixture_tld());
    human_tld_sparse_snapshot => human.format_tld(fixture_tld_sparse());
    markdown_tld_sparse_snapshot => markdown.format_tld(fixture_tld_sparse());
    human_subdomains_snapshot => human.format_subdomains(fixture_subdomains());
    markdown_subdomains_snapshot => markdown.format_subdomains(fixture_subdomains());
    human_watch_snapshot => human.format_watch(fixture_watch());
    markdown_watch_snapshot => markdown.format_watch(fixture_watch());
    human_dnssec_snapshot => human.format_dnssec(fixture_dnssec());
    markdown_dnssec_snapshot => markdown.format_dnssec(fixture_dnssec());
    human_dns_comparison_snapshot => human.format_dns_comparison(fixture_dns_comparison());
    markdown_dns_comparison_snapshot => markdown.format_dns_comparison(fixture_dns_comparison());
    human_follow_iteration_snapshot => human.format_follow_iteration(fixture_follow_iteration());
    markdown_follow_iteration_snapshot =>
        markdown.format_follow_iteration(fixture_follow_iteration());
    human_follow_snapshot => human.format_follow(fixture_follow());
    markdown_follow_snapshot => markdown.format_follow(fixture_follow());
    human_propagation_snapshot => human.format_propagation(fixture_propagation());
    markdown_propagation_snapshot => markdown.format_propagation(fixture_propagation());
}

// --- Status, security, and comparison reports ---------------------------

/// Every status section populated: certificate, CAA, registration, DNS.
fn fixture_status_full() -> StatusResponse {
    StatusResponse {
        certificate: Some(CertificateInfo {
            issuer: "CN=Mock CA".into(),
            subject: "CN=example.com".into(),
            valid_from: "2025-01-01T00:00:00Z".parse().unwrap(),
            valid_until: "2099-01-01T00:00:00Z".parse().unwrap(),
            days_until_expiry: 26_000,
            is_valid: true,
            hostname_verified: true,
        }),
        dns_resolution: Some(DnsResolution {
            a_records: vec!["192.0.2.1".into()],
            aaaa_records: vec!["2001:db8::1".into()],
            cname_target: Some("edge.example.net".into()),
            nameservers: vec!["ns1.example.com".into()],
            resolves: true,
        }),
        caa: Some(fixture_caa_policy()),
        ..fixture_status()
    }
}

fn fixture_headers() -> HeaderReport {
    HeaderReport {
        domain: "example.com".into(),
        url: "https://www.example.com/".into(),
        status: 200,
        redirects: 1,
        grade: "C".into(),
        score: 55,
        headers: vec![
            HeaderFinding {
                header: "strict-transport-security".into(),
                present: true,
                value: Some("max-age=31536000".into()),
                verdict: HeaderVerdict::Moderate,
                note: None,
            },
            HeaderFinding {
                header: "content-security-policy".into(),
                present: false,
                value: None,
                verdict: HeaderVerdict::Absent,
                note: Some("add a CSP".into()),
            },
        ],
        cookies: vec![CookieFinding {
            name: "session".into(),
            secure: true,
            http_only: false,
            same_site: None,
            verdict: HeaderVerdict::Weak,
            issues: vec!["missing HttpOnly".into(), "missing SameSite".into()],
        }],
        disclosures: vec![Disclosure {
            header: "server".into(),
            value: "nginx/1.25.3".into(),
            versioned: true,
        }],
        notes: vec!["Content-Security-Policy is missing".into()],
    }
}

fn fixture_takeover() -> TakeoverReport {
    TakeoverReport {
        domain: "example.com".into(),
        hosts_checked: 12,
        hosts_skipped: 3,
        vulnerable: 1,
        potential: 1,
        findings: vec![
            TakeoverFinding {
                host: "docs.example.com".into(),
                verdict: TakeoverVerdict::Vulnerable,
                provider: Some("GitHub Pages".into()),
                cname: Some("example.github.io".into()),
                addresses: Vec::new(),
                evidence: Some("There isn't a GitHub Pages site here.".into()),
                http_status: Some(404),
                probe_note: None,
            },
            TakeoverFinding {
                host: "shop.example.com".into(),
                verdict: TakeoverVerdict::Potential,
                provider: Some("Shopify".into()),
                cname: Some("shops.myshopify.com".into()),
                addresses: Vec::new(),
                evidence: None,
                http_status: None,
                probe_note: Some("HTTP probe failed: connection refused".into()),
            },
        ],
        notes: vec!["3 hosts exceeded the scan cap".into()],
    }
}

fn fixture_drift() -> DriftReport {
    DriftReport {
        domain: "example.com".into(),
        changes: vec![
            FieldChange {
                field: "registrar".into(),
                old: Some("Old Registrar".into()),
                new: Some("New Registrar".into()),
            },
            FieldChange {
                field: "nameservers".into(),
                old: None,
                new: Some("ns1.example.com".into()),
            },
        ],
        inconclusive: None,
    }
}

fn fixture_domain_diff() -> DomainDiff {
    DomainDiff {
        domain_a: "example.com".into(),
        domain_b: "example.net".into(),
        registration: RegistrationDiff {
            registrar: (
                Some("Mock Registrar Inc.".into()),
                Some("Other Registrar".into()),
            ),
            organization: (None, Some("Example Org".into())),
            created: (Some("2010-03-15".into()), Some("2010-03-15".into())),
            expires: (Some("2099-03-15".into()), None),
        },
        dns: DnsDiff {
            a_records: (vec!["192.0.2.1".into()], vec!["192.0.2.2".into()]),
            nameservers: (
                vec!["ns1.example.com".into(), "ns2.example.com".into()],
                vec!["ns2.example.com".into(), "ns1.example.com".into()],
            ),
            resolves: (true, true),
        },
        ssl: SslDiff {
            issuer: (Some("Mock CA".into()), Some("Mock CA".into())),
            valid_until: (Some("2099-01-01".into()), Some("2098-01-01".into())),
            days_remaining: (Some(26_000), None),
            is_valid: (Some(true), None),
        },
    }
}

snapshot_tests! {
    human_status_full_snapshot => human.format_status(fixture_status_full());
    markdown_status_full_snapshot => markdown.format_status(fixture_status_full());
    human_headers_snapshot => human.format_headers(fixture_headers());
    markdown_headers_snapshot => markdown.format_headers(fixture_headers());
    human_takeover_snapshot => human.format_takeover(fixture_takeover());
    markdown_takeover_snapshot => markdown.format_takeover(fixture_takeover());
    human_drift_snapshot => human.format_drift(fixture_drift());
    markdown_drift_snapshot => markdown.format_drift(fixture_drift());
    human_domain_diff_snapshot => human.format_diff(fixture_domain_diff());
    markdown_domain_diff_snapshot => markdown.format_diff(fixture_domain_diff());
}
