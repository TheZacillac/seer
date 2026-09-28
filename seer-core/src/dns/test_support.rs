//! Test-only mock DNS fixture shared by the crate's hermetic DNS tests
//! (`resolver.rs`, `follow.rs`, `compare.rs`, `dnssec.rs`, `posture.rs`, …):
//! a real UDP socket on 127.0.0.1 serving
//! hickory-proto-encoded canned responses, so the full `resolve()` path
//! (normalization → custom-resolver construction → hickory transport →
//! RData conversion) runs without touching the network.
//!
//! Compiled only under `cfg(test)` — production builds never include this
//! module. The SSRF guards deliberately refuse loopback, so tests reach the
//! fixture through the `#[cfg(test)]`-only `allowing_private_hosts` /
//! `with_port` seams on [`DnsResolver`]; the production validation path is
//! never weakened.

use std::net::Ipv4Addr;
use std::time::Duration;

use hickory_resolver::proto::dnssec::rdata::{DNSSECRData, CDNSKEY, CDS, DNSKEY};
use hickory_resolver::proto::dnssec::{Algorithm, DigestType, PublicKeyBuf};
use hickory_resolver::proto::op::{Message, OpCode, ResponseCode};
use hickory_resolver::proto::rr::rdata::svcb::{
    Alpn, EchConfigList, IpHint, Mandatory, SvcParamKey, SvcParamValue, Unknown, SVCB,
};
use hickory_resolver::proto::rr::rdata::{self as wire, sshfp, tlsa, CAA, HTTPS};
use hickory_resolver::proto::rr::{
    Name, RData as HickoryRData, Record, RecordType as HickoryRecordType,
};
use tokio::net::UdpSocket;

use super::resolver::DnsResolver;

/// How the mock server answers every query it receives.
#[derive(Clone, Copy)]
pub(crate) enum MockMode {
    /// Answer from the canned zone (see [`zone_answers`]).
    Zone,
    /// NXDOMAIN for every query.
    Nxdomain,
    /// NOERROR with an empty answer section (NODATA).
    NoData,
    /// Never respond, forcing the client's timeout path.
    Ignore,
}

fn name(s: &str) -> Name {
    Name::from_ascii(s).expect("valid test name")
}

/// Canned zone for [`MockMode::Zone`]. Query names are matched with the
/// trailing root dot stripped, since hickory sends fully-qualified names.
fn zone_answers(qname: &str, qtype: HickoryRecordType) -> Vec<HickoryRData> {
    match (qname.trim_end_matches('.'), qtype) {
        ("seer.test", HickoryRecordType::A) => vec![
            HickoryRData::A(wire::A(Ipv4Addr::new(192, 0, 2, 1))),
            HickoryRData::A(wire::A(Ipv4Addr::new(192, 0, 2, 2))),
        ],
        ("seer.test", HickoryRecordType::AAAA) => vec![HickoryRData::AAAA(wire::AAAA(
            "2001:db8::1".parse().expect("valid IPv6 literal"),
        ))],
        // Deliberately out of preference order to prove resolve() sorts.
        ("seer.test", HickoryRecordType::MX) => vec![
            HickoryRData::MX(wire::MX::new(30, name("c.mail.seer.test."))),
            HickoryRData::MX(wire::MX::new(10, name("a.mail.seer.test."))),
            HickoryRData::MX(wire::MX::new(20, name("b.mail.seer.test."))),
        ],
        ("seer.test", HickoryRecordType::NS) => {
            vec![HickoryRData::NS(wire::NS(name("ns1.seer.test.")))]
        }
        // Two character-strings, to prove segments are joined.
        ("seer.test", HickoryRecordType::TXT) => vec![HickoryRData::TXT(wire::TXT::new(vec![
            "v=spf1 ".to_string(),
            "-all".to_string(),
        ]))],
        ("seer.test", HickoryRecordType::SOA) => vec![HickoryRData::SOA(wire::SOA::new(
            name("ns1.seer.test."),
            name("hostmaster.seer.test."),
            2026070101,
            7200,
            3600,
            1209600,
            300,
        ))],
        // `CAA` has no struct-literal constructor (#[non_exhaustive]).
        ("seer.test", HickoryRecordType::CAA) => vec![
            HickoryRData::CAA(CAA::new_issue(false, Some(name("letsencrypt.org")), vec![])),
            HickoryRData::CAA(CAA::new_iodef(
                true,
                url::Url::parse("mailto:security@seer.test").expect("valid iodef URL"),
            )),
        ],
        ("_443._tcp.seer.test", HickoryRecordType::TLSA) => {
            vec![HickoryRData::TLSA(wire::TLSA::new(
                tlsa::CertUsage::from(3),
                tlsa::Selector::from(1),
                tlsa::Matching::from(1),
                vec![0xAB, 0xCD, 0x01],
            ))]
        }
        ("seer.test", HickoryRecordType::SSHFP) => vec![HickoryRData::SSHFP(wire::SSHFP::new(
            sshfp::Algorithm::from(4),
            sshfp::FingerprintType::from(2),
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        ))],
        ("seer.test", HickoryRecordType::NAPTR) => vec![HickoryRData::NAPTR(wire::NAPTR::new(
            100,
            50,
            b"U".to_vec().into_boxed_slice(),
            b"E2U+sip".to_vec().into_boxed_slice(),
            b"!^.*$!sip:info@seer.test!".to_vec().into_boxed_slice(),
            Name::root(),
        ))],
        ("_sip._tcp.seer.test", HickoryRecordType::SRV) => vec![HickoryRData::SRV(wire::SRV::new(
            10,
            5,
            5060,
            name("sipserver.seer.test."),
        ))],
        ("1.2.0.192.in-addr.arpa", HickoryRecordType::PTR) => {
            vec![HickoryRData::PTR(wire::PTR(name("ptr.seer.test.")))]
        }
        // `www` carries its own record (the apex has no CNAME), so a query
        // that silently strips `www.` comes back empty.
        ("www.seer.test", HickoryRecordType::CNAME) => {
            vec![HickoryRData::CNAME(wire::CNAME(name("edge.cdn.test.")))]
        }
        // Reverse name of 2606:4700:4700::1111.
        (
            "1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6.2.ip6.arpa",
            HickoryRecordType::PTR,
        ) => vec![HickoryRData::PTR(wire::PTR(name("one.one.one.one.")))],
        // ServiceMode with every registered SvcParam kind plus a private-use
        // key, in the strictly increasing key order the wire requires.
        ("seer.test", HickoryRecordType::HTTPS) => {
            vec![HickoryRData::HTTPS(HTTPS(SVCB::new(
                1,
                Name::root(),
                vec![
                    (
                        SvcParamKey::Alpn,
                        SvcParamValue::Alpn(Alpn(vec!["h3".to_string(), "h2".to_string()])),
                    ),
                    (SvcParamKey::Port, SvcParamValue::Port(8443)),
                    (
                        SvcParamKey::Ipv4Hint,
                        SvcParamValue::Ipv4Hint(IpHint(vec![
                            wire::A::new(192, 0, 2, 1),
                            wire::A::new(192, 0, 2, 2),
                        ])),
                    ),
                    (
                        SvcParamKey::EchConfigList,
                        SvcParamValue::EchConfigList(EchConfigList(vec![0x00, 0x01, 0xFE])),
                    ),
                    (
                        SvcParamKey::Ipv6Hint,
                        SvcParamValue::Ipv6Hint(IpHint(vec![wire::AAAA::new(
                            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
                        )])),
                    ),
                    (
                        SvcParamKey::Key(65333),
                        SvcParamValue::Unknown(Unknown(b"ex 1".to_vec())),
                    ),
                ],
            )))]
        }
        // AliasMode: priority 0, the alias target, no params.
        ("alias.seer.test", HickoryRecordType::HTTPS) => vec![HickoryRData::HTTPS(HTTPS(
            SVCB::new(0, name("pool.seer.test."), vec![]),
        ))],
        ("_8443._foo.seer.test", HickoryRecordType::SVCB) => {
            vec![HickoryRData::SVCB(SVCB::new(
                2,
                name("svc.seer.test."),
                vec![
                    (
                        SvcParamKey::Mandatory,
                        SvcParamValue::Mandatory(Mandatory(vec![
                            SvcParamKey::Alpn,
                            SvcParamKey::Port,
                        ])),
                    ),
                    (
                        SvcParamKey::Alpn,
                        SvcParamValue::Alpn(Alpn(vec!["foo".to_string()])),
                    ),
                    (SvcParamKey::NoDefaultAlpn, SvcParamValue::NoDefaultAlpn),
                    (SvcParamKey::Port, SvcParamValue::Port(8443)),
                ],
            ))]
        }
        ("seer.test", HickoryRecordType::DNSKEY) => {
            vec![HickoryRData::DNSSEC(DNSSECRData::DNSKEY(DNSKEY::new(
                true,
                true,
                false,
                PublicKeyBuf::new(vec![7u8; 32], Algorithm::ED25519),
            )))]
        }
        // An update request plus the RFC 8078 delete request (`0 0 0 00`).
        ("seer.test", HickoryRecordType::CDS) => vec![
            HickoryRData::DNSSEC(DNSSECRData::CDS(CDS::new(
                2371,
                Some(Algorithm::ED25519),
                DigestType::SHA256,
                vec![0xAB, 0xCD, 0xEF],
            ))),
            HickoryRData::DNSSEC(DNSSECRData::CDS(CDS::new(
                0,
                None,
                DigestType::from(0),
                vec![0x00],
            ))),
        ],
        // An update request plus the RFC 8078 delete request (`0 3 0 AA==`).
        ("seer.test", HickoryRecordType::CDNSKEY) => vec![
            HickoryRData::DNSSEC(DNSSECRData::CDNSKEY(CDNSKEY::with_flags(
                257,
                Some(Algorithm::ED25519),
                vec![7u8; 32],
            ))),
            HickoryRData::DNSSEC(DNSSECRData::CDNSKEY(CDNSKEY::with_flags(
                0,
                None,
                vec![0x00],
            ))),
        ],
        _ => vec![],
    }
}

/// Builds the response skeleton for `request`: echoes the ID and the question
/// section (hickory discards responses whose queries don't match the request
/// — anti-spoofing) and marks recursion available.
fn response_skeleton(request: &Message) -> Message {
    let mut response = Message::response(request.metadata.id, OpCode::Query);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    for query in &request.queries {
        response.add_query(query.clone());
    }
    response
}

/// Binds a UDP socket on an ephemeral loopback port and answers DNS
/// queries per `mode` until the test runtime shuts down. Returns the
/// bound port.
pub(crate) async fn spawn_mock_dns(mode: MockMode) -> u16 {
    spawn_mock_dns_fn(move |qname, qtype| match mode {
        MockMode::Zone => MockReply::Answer(zone_answers(qname, qtype)),
        MockMode::Nxdomain => MockReply::NxDomain,
        MockMode::NoData => MockReply::NoData,
        MockMode::Ignore => MockReply::NoReply,
    })
    .await
}

/// Binds a UDP socket on an ephemeral loopback port and answers the n-th
/// query received with the n-th answer set, clamping to the last set once
/// the sequence is exhausted (an empty sequence answers NODATA). Every
/// answer echoes the query name, so any domain works. Lets follow-loop
/// tests observe record sets that change between iterations. Returns the
/// bound port.
pub(crate) async fn spawn_mock_dns_sequence(answer_sets: Vec<Vec<HickoryRData>>) -> u16 {
    let mut served = 0usize;
    spawn_mock_dns_fn(move |_, _| {
        let idx = served.min(answer_sets.len().saturating_sub(1));
        served += 1;
        MockReply::Answer(answer_sets.get(idx).cloned().unwrap_or_default())
    })
    .await
}

/// A plausible SOA RRdata for `zone` (for scripted apex answers).
pub(crate) fn soa_rdata(zone: &str) -> HickoryRData {
    HickoryRData::SOA(wire::SOA::new(
        name(&format!("ns1.{zone}.")),
        name(&format!("hostmaster.{zone}.")),
        2026070101,
        7200,
        3600,
        1209600,
        300,
    ))
}

/// A record owned by `owner` (a fully-qualified name, trailing dot
/// included), for [`MockReply::Records`] answers that must not be owned by
/// the query name — a CNAME chain's hops, the records at its target.
pub(crate) fn record(owner: &str, ttl: u32, rdata: HickoryRData) -> Record {
    Record::from_rdata(name(owner), ttl, rdata)
}

/// The SOA record of `zone`, owned by the zone apex (negative answers'
/// AUTHORITY section).
fn zone_soa(zone: &str) -> Record {
    Record::from_rdata(name(&format!("{zone}.")), 300, soa_rdata(zone))
}

/// A scripted reply for [`spawn_mock_dns_fn`].
pub(crate) enum MockReply {
    /// NOERROR with these answers, each owned by the query name.
    Answer(Vec<HickoryRData>),
    /// NOERROR with these complete records in ANSWER, in this order, under
    /// their own owner names (see [`record`]) — e.g. a CNAME chain followed
    /// by the records at its target, as a recursive resolver relays it.
    Records(Vec<Record>),
    /// Like [`MockReply::Answer`], with the AA (authoritative) bit set.
    AuthoritativeAnswer(Vec<HickoryRData>),
    /// NOERROR, empty ANSWER, these (NS) records for the query name in
    /// AUTHORITY — a classic parent-side referral.
    Referral(Vec<HickoryRData>),
    /// NOERROR with an empty answer section (NODATA).
    NoData,
    /// NODATA whose AUTHORITY section carries the SOA of the named zone — the
    /// shape a recursive resolver relays for a name inside that zone.
    NoDataWithSoa(&'static str),
    /// NXDOMAIN.
    NxDomain,
    /// NXDOMAIN whose AUTHORITY section carries the SOA of the named zone —
    /// the negative answer a recursive resolver relays (RFC 2308).
    NxDomainWithSoa(&'static str),
    /// An empty response with this response code (NOTIMP, FORMERR, …).
    Rcode(ResponseCode),
    /// SERVFAIL — e.g. a validating upstream rejecting a broken DNSSEC chain.
    ServFail,
    /// REFUSED.
    Refused,
    /// Send nothing, forcing the client's timeout path.
    NoReply,
}

/// Binds a UDP socket on an ephemeral loopback port and answers every query
/// with `handler(qname, qtype)`, where `qname` is the lowercased ASCII query
/// name without the trailing root dot. Lets a test script a whole multi-name
/// scenario (tree walks, redirects, per-name failures) that the fixed
/// [`MockMode::Zone`] table cannot express. The one server loop behind every
/// spawner here. Returns the bound port.
pub(crate) async fn spawn_mock_dns_fn<F>(mut handler: F) -> u16
where
    F: FnMut(&str, HickoryRecordType) -> MockReply + Send + 'static,
{
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock DNS");
    let port = socket.local_addr().expect("mock DNS local addr").port();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((len, src)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let Ok(request) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let mut response = response_skeleton(&request);
            if let Some(query) = request.queries.first() {
                let qname = query.name.to_ascii().to_ascii_lowercase();
                let owned = |rdata| Record::from_rdata(query.name.clone(), 300, rdata);
                match handler(qname.trim_end_matches('.'), query.query_type) {
                    MockReply::Answer(answers) => {
                        response.add_answers(answers.into_iter().map(owned));
                    }
                    MockReply::Records(records) => {
                        response.add_answers(records);
                    }
                    MockReply::AuthoritativeAnswer(answers) => {
                        response.metadata.authoritative = true;
                        response.add_answers(answers.into_iter().map(owned));
                    }
                    MockReply::Referral(records) => {
                        response.add_authorities(records.into_iter().map(owned));
                    }
                    MockReply::NoData => {}
                    MockReply::NoDataWithSoa(zone) => {
                        response.add_authority(zone_soa(zone));
                    }
                    MockReply::NxDomain => {
                        response.metadata.response_code = ResponseCode::NXDomain;
                    }
                    MockReply::NxDomainWithSoa(zone) => {
                        response.metadata.response_code = ResponseCode::NXDomain;
                        response.add_authority(zone_soa(zone));
                    }
                    MockReply::Rcode(code) => {
                        response.metadata.response_code = code;
                    }
                    MockReply::ServFail => {
                        response.metadata.response_code = ResponseCode::ServFail;
                    }
                    MockReply::Refused => {
                        response.metadata.response_code = ResponseCode::Refused;
                    }
                    MockReply::NoReply => continue,
                }
            }
            let Ok(bytes) = response.to_vec() else {
                continue;
            };
            let _ = socket.send_to(&bytes, src).await;
        }
    });
    port
}

/// A resolver wired to the loopback fixture through the `#[cfg(test)]`-only
/// seams, with a short timeout to keep failing tests fast.
pub(crate) fn mock_dns_resolver(port: u16) -> DnsResolver {
    DnsResolver::new()
        .with_timeout(Duration::from_millis(500))
        .allowing_private_hosts()
        .with_port(port)
}

/// Like [`mock_dns_resolver`], but ALSO routes queries that name no
/// nameserver (`resolve(.., None)`) to the fixture, so code that always uses
/// the default upstream (posture, CAA) can be exercised end to end.
pub(crate) fn mock_dns_resolver_default(port: u16) -> DnsResolver {
    mock_dns_resolver(port).with_default_nameserver("127.0.0.1")
}
