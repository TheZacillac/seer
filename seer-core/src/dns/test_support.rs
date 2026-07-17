//! Test-only mock DNS fixture shared by the dns module's hermetic tests
//! (`resolver.rs`, `follow.rs`): a real UDP socket on 127.0.0.1 serving
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

use hickory_resolver::proto::op::{Message, OpCode, ResponseCode};
use hickory_resolver::proto::rr::rdata::{self as wire, sshfp, tlsa, CAA};
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
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock DNS");
    let port = socket.local_addr().expect("mock DNS local addr").port();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((len, src)) = socket.recv_from(&mut buf).await else {
                return;
            };
            if matches!(mode, MockMode::Ignore) {
                continue;
            }
            let Ok(request) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let mut response = response_skeleton(&request);
            match mode {
                MockMode::Zone => {
                    if let Some(query) = request.queries.first() {
                        for rdata in zone_answers(&query.name.to_string(), query.query_type) {
                            response.add_answer(Record::from_rdata(query.name.clone(), 300, rdata));
                        }
                    }
                }
                MockMode::Nxdomain => {
                    response.metadata.response_code = ResponseCode::NXDomain;
                }
                MockMode::NoData | MockMode::Ignore => {}
            }
            let Ok(bytes) = response.to_vec() else {
                continue;
            };
            let _ = socket.send_to(&bytes, src).await;
        }
    });
    port
}

/// Binds a UDP socket on an ephemeral loopback port and answers the n-th
/// query received with the n-th answer set, clamping to the last set once
/// the sequence is exhausted (an empty sequence answers NODATA). Every
/// answer echoes the query name, so any domain works. Lets follow-loop
/// tests observe record sets that change between iterations. Returns the
/// bound port.
pub(crate) async fn spawn_mock_dns_sequence(answer_sets: Vec<Vec<HickoryRData>>) -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock DNS");
    let port = socket.local_addr().expect("mock DNS local addr").port();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let mut served = 0usize;
        loop {
            let Ok((len, src)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let Ok(request) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let mut response = response_skeleton(&request);
            let idx = served.min(answer_sets.len().saturating_sub(1));
            if let (Some(query), Some(answers)) = (request.queries.first(), answer_sets.get(idx)) {
                for rdata in answers {
                    response.add_answer(Record::from_rdata(query.name.clone(), 300, rdata.clone()));
                }
            }
            served += 1;
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
