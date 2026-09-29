//! Full DNS query results, as `dig` reports them.
//!
//! [`DnsResolver::query`](crate::dns::DnsResolver::query) returns a
//! [`DnsQueryResult`]: the response code, the header flags, the ANSWER
//! section with every record under its real owner name (so a CNAME chain
//! reads as it does in dig), the AUTHORITY section as the server sent it,
//! and a [`WildcardProbe`] telling whether the zone synthesizes answers for
//! names that do not exist.
//!
//! [`DnsStatus`] is the response code in dig's vocabulary (`NOERROR`,
//! `NXDOMAIN`, `SERVFAIL`, …), for a query result and for every hop of a
//! [`DnsTrace`](crate::dns::DnsTrace). It is what separates "the name does
//! not exist" (NXDOMAIN) from "the name exists but has no records of this
//! type" (NOERROR without records of the type, i.e. NODATA:
//! [`DnsQueryResult::is_nodata`]) — a distinction the record-list API
//! ([`crate::dns::DnsResolver::resolve`]) folds away. Behind a CNAME chain
//! in the ANSWER section, either one is about the chain's last target. A
//! referral (NOERROR with no answer, only the NS records of a zone below)
//! is neither: see [`DnsQueryResult::referral_zone`].
//!
//! The result is the response a server sent, section by section: the query
//! goes straight to the upstream servers (`dns::transport`), not through a
//! resolver lookup, so a CNAME chain that ends in NXDOMAIN or NODATA keeps
//! its chain and every response keeps its header. The special-use names of
//! RFC 6761 (`localhost`, `127.in-addr.arpa`, `invalid`, `onion`, …) are
//! the exception: hickory's resolver answers them itself, without sending a
//! query, and such a result says so ([`DnsQueryResult::answered_locally`])
//! rather than passing off the resolver's answer as a server's.
//!
//! The pure steps of assembling a result — mapping a response (or the
//! resolver's local answer) to an `Exchange`, ordering a CNAME chain first,
//! merging the ANY fan-out, choosing and judging the wildcard probe — live
//! here so they are unit-testable without a server; the resolver only runs
//! the queries.

use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::{Message, MessageType, Metadata, ResponseCode};
use hickory_resolver::proto::rr::domain::usage::{
    ResolverUsage, INVALID, IN_ADDR_ARPA_127, IP6_ARPA_1, LOCAL, LOCALHOST, ONION,
};
use hickory_resolver::proto::rr::Name;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::records::{DnsRecord, RecordData, RecordType};
use super::resolver::to_dns_record;
use super::transport::NoResponse;
use crate::error::{Result, SeerError};

/// A DNS response code, named as `dig` prints it.
///
/// Serializes as that name (`"NOERROR"`, `"NXDOMAIN"`, …). Codes without a
/// dedicated variant keep their numeric value in [`DnsStatus::Other`] and
/// render as their standard mnemonic (`FORMERR`, `NOTIMP`, `BADVERS`, …), or
/// `RCODE<n>` for an unassigned code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsStatus {
    /// `NOERROR`: the query succeeded. Without records of the queried type
    /// it is NODATA ([`DnsQueryResult::is_nodata`]) — behind a CNAME chain,
    /// about the chain's last target — unless it is a referral
    /// ([`DnsQueryResult::referral_zone`]).
    NoError,
    /// `NXDOMAIN`: the name does not exist — behind a CNAME chain, the
    /// chain's last target (a dangling CNAME).
    NxDomain,
    /// `SERVFAIL`: the server could not answer (often a DNSSEC or upstream
    /// failure).
    ServFail,
    /// `REFUSED`: the server declined to answer.
    Refused,
    /// Any other response code, by its numeric value.
    Other(u16),
}

impl DnsStatus {
    /// Whether the query succeeded (`NOERROR`), with or without answers.
    pub fn is_success(self) -> bool {
        self == DnsStatus::NoError
    }

    /// The numeric response code.
    pub fn code(self) -> u16 {
        match self {
            DnsStatus::NoError => 0,
            DnsStatus::ServFail => 2,
            DnsStatus::NxDomain => 3,
            DnsStatus::Refused => 5,
            DnsStatus::Other(code) => code,
        }
    }

    /// Builds the status for a numeric response code.
    pub fn from_code(code: u16) -> Self {
        match code {
            0 => DnsStatus::NoError,
            2 => DnsStatus::ServFail,
            3 => DnsStatus::NxDomain,
            5 => DnsStatus::Refused,
            other => DnsStatus::Other(other),
        }
    }
}

/// Standard mnemonics for the codes without a dedicated variant (RFC 6895
/// registry). Code 16 is both BADVERS and BADSIG; like dig, report BADVERS.
const OTHER_MNEMONICS: &[(u16, &str)] = &[
    (1, "FORMERR"),
    (4, "NOTIMP"),
    (6, "YXDOMAIN"),
    (7, "YXRRSET"),
    (8, "NXRRSET"),
    (9, "NOTAUTH"),
    (10, "NOTZONE"),
    (16, "BADVERS"),
    (17, "BADKEY"),
    (18, "BADTIME"),
    (19, "BADMODE"),
    (20, "BADNAME"),
    (21, "BADALG"),
    (22, "BADTRUNC"),
    (23, "BADCOOKIE"),
];

impl fmt::Display for DnsStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsStatus::NoError => f.write_str("NOERROR"),
            DnsStatus::NxDomain => f.write_str("NXDOMAIN"),
            DnsStatus::ServFail => f.write_str("SERVFAIL"),
            DnsStatus::Refused => f.write_str("REFUSED"),
            DnsStatus::Other(code) => match OTHER_MNEMONICS.iter().find(|(c, _)| c == code) {
                Some((_, name)) => f.write_str(name),
                None => write!(f, "RCODE{code}"),
            },
        }
    }
}

impl FromStr for DnsStatus {
    type Err = SeerError;

    /// Parses the names [`Display`](fmt::Display) produces, case-insensitively.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let upper = s.trim().to_ascii_uppercase();
        let status = match upper.as_str() {
            "NOERROR" => DnsStatus::NoError,
            "NXDOMAIN" => DnsStatus::NxDomain,
            "SERVFAIL" => DnsStatus::ServFail,
            "REFUSED" => DnsStatus::Refused,
            other => {
                if let Some((code, _)) = OTHER_MNEMONICS.iter().find(|(_, name)| *name == other) {
                    DnsStatus::Other(*code)
                } else if let Some(code) = other
                    .strip_prefix("RCODE")
                    .and_then(|n| n.parse::<u16>().ok())
                {
                    DnsStatus::from_code(code)
                } else {
                    return Err(SeerError::InvalidInput(format!("unknown DNS status: {s}")));
                }
            }
        };
        Ok(status)
    }
}

impl From<ResponseCode> for DnsStatus {
    fn from(code: ResponseCode) -> Self {
        DnsStatus::from_code(u16::from(code))
    }
}

impl Serialize for DnsStatus {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DnsStatus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A full DNS query result, the way `dig` reports it.
///
/// Built by [`DnsResolver::query`](crate::dns::DnsResolver::query). A negative
/// answer is a result, not an error: NXDOMAIN, NODATA (NOERROR with no
/// records of the type), SERVFAIL and REFUSED all come back as a
/// `DnsQueryResult` with that [`status`](Self::status). An `Err` means
/// there is no response to report: invalid input (a malformed name, a
/// bare-domain SRV query), a nameserver that was refused (a private or
/// reserved address) or did not resolve, or a transport failure (timeout,
/// no connection).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQueryResult {
    /// The normalized name that was queried (for an IP-literal PTR query,
    /// the reverse-DNS name).
    pub name: String,
    pub record_type: RecordType,
    /// The nameserver spec the caller passed (as given), or None for the
    /// default upstream (Google Public DNS) — and None when no server was
    /// asked at all ([`answered_locally`](Self::answered_locally)).
    pub server: Option<String>,
    /// True when no query was sent: the name is under a special-use zone
    /// (RFC 6761) that the resolver answers itself — `localhost`,
    /// `127.in-addr.arpa` and `1.0…0.ip6.arpa` with loopback answers (NODATA
    /// for other types), `invalid` and `onion` with NXDOMAIN. `server` is
    /// then None, `flags` empty and `wildcard` None.
    pub answered_locally: bool,
    pub status: DnsStatus,
    /// Header flags as dig prints them, lowercase, in dig's order: qr aa tc
    /// rd ra ad cd — the ones the response header set, whatever its status.
    ///
    /// Empty only for an answer no server gave
    /// ([`answered_locally`](Self::answered_locally)): seer never invents
    /// flags, nor passes on the header hickory makes up for its own answer.
    pub flags: Vec<String>,
    /// The ANSWER section in order: the CNAME chain first, then the records
    /// of the requested type — every record under its real owner name.
    /// MX records are ordered by preference, as
    /// [`resolve`](crate::dns::DnsResolver::resolve) orders them. For ANY:
    /// all sub-query answers merged in the ANY type order, identical records
    /// deduplicated.
    ///
    /// A negative answer lists its chain too: NXDOMAIN beside a CNAME chain
    /// means the chain's last target does not exist (RFC 6604 §2), and
    /// NODATA that the target has no records of the type — the queried name
    /// exists, since it owns the first CNAME.
    pub answers: Vec<DnsRecord>,
    /// The AUTHORITY section as the server sent it: for a negative answer
    /// the SOA of the zone that gave it, when the server sent one; for a
    /// referral the NS records of the zone it refers to
    /// ([`referral_zone`](Self::referral_zone)); beside an answer, whatever
    /// the server added (an authoritative server may list its zone's NS
    /// records). An ANY answer with records carries none (see
    /// [`answers`](Self::answers)).
    pub authority: Vec<DnsRecord>,
    /// For ANY: the types whose sub-query failed — no server responded, or
    /// it could not be sent — so the merged answer says nothing about them.
    /// Empty for any other type and when every sub-query was answered
    /// (omitted from the serialized form then).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_types: Vec<FailedType>,
    /// Wildcard probe outcome; None when the probe was not run or did not
    /// complete.
    pub wildcard: Option<WildcardProbe>,
    /// Wall-clock time of the main query in milliseconds.
    pub query_time_ms: u64,
}

impl DnsQueryResult {
    /// NOERROR with no answer of the requested type (for ANY: no answers at
    /// all) — the name exists, without records of the type. A referral is
    /// not NODATA ([`referral_zone`](Self::referral_zone)).
    pub fn is_nodata(&self) -> bool {
        self.status == DnsStatus::NoError && self.lacks_answer() && self.referral_zone().is_none()
    }

    /// The zone this response refers the query to, when it is a referral
    /// rather than an answer: NOERROR with no answer of the requested type,
    /// the AA (authoritative) flag clear, NS records in AUTHORITY and no SOA
    /// there (RFC 2308 §2.2) — the zone is the NS records' owner.
    ///
    /// A server that is neither authoritative for the name nor recursive (an
    /// `@server` serving only a parent zone) answers this way, pointing at
    /// the servers of the zone below it. Unlike NODATA, a referral says
    /// nothing about whether the name exists. An authoritative response is
    /// never a referral, even with its own zone's NS records in AUTHORITY
    /// beside an unfollowed CNAME.
    pub fn referral_zone(&self) -> Option<&str> {
        if self.status != DnsStatus::NoError
            || !self.lacks_answer()
            || self.flags.iter().any(|flag| flag == "aa")
            || self
                .authority
                .iter()
                .any(|r| r.record_type == RecordType::SOA)
        {
            return None;
        }
        self.authority
            .iter()
            .find(|r| r.record_type == RecordType::NS)
            .map(|r| r.name.as_str())
    }

    /// No answer of the requested type (for ANY: no answers at all).
    fn lacks_answer(&self) -> bool {
        match self.record_type {
            RecordType::ANY => self.answers.is_empty(),
            wanted => !self.records().any(|r| r.record_type == wanted),
        }
    }

    /// The CNAME records at the front of `answers`.
    pub fn cname_chain(&self) -> impl Iterator<Item = &DnsRecord> {
        self.answers[..chain_len(self.record_type, &self.answers)].iter()
    }

    /// The answers that are not part of the CNAME chain (for a CNAME query:
    /// the CNAME itself).
    pub fn records(&self) -> impl Iterator<Item = &DnsRecord> {
        self.answers[chain_len(self.record_type, &self.answers)..].iter()
    }
}

/// A record type an `ANY` fan-out asked for without getting an answer
/// ([`DnsQueryResult::failed_types`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailedType {
    pub record_type: RecordType,
    /// Why, safe to show: each asked server's transport failure
    /// (`8.8.8.8: timed out`), or a generic message.
    pub error: String,
}

/// The outcome of the wildcard probe: whether the zone answers a random,
/// certainly-unpublished sibling of the queried name.
///
/// A zone with a wildcard (`*.example.com`) answers every name under its
/// parent that has no records of its own, so an answer equal to the probe's
/// was likely synthesized from the wildcard rather than published for the
/// name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WildcardProbe {
    /// The random sibling name that was queried, e.g.
    /// `seer-probe-3f9a1c2e7b.example.com`.
    pub probe_name: String,
    /// The probe name returned records of the queried type → a wildcard
    /// answers under this parent.
    pub present: bool,
    /// The probe's final record set (the comparison-key set of its
    /// [`records`](DnsQueryResult::records)) equals this answer's → the
    /// answer is likely wildcard-synthesized (DNS alone cannot prove it
    /// without DNSSEC).
    pub matches_answer: bool,
}

/// How many leading `answers` form the CNAME chain. Zero for a CNAME query,
/// whose CNAME is the answer itself rather than a hop towards it.
fn chain_len(record_type: RecordType, answers: &[DnsRecord]) -> usize {
    if record_type == RecordType::CNAME {
        return 0;
    }
    answers
        .iter()
        .take_while(|r| r.record_type == RecordType::CNAME)
        .count()
}

/// One lookup's outcome in seer's terms: the response code, header flags and
/// the converted ANSWER/AUTHORITY sections. `DnsResolver::query` runs one per
/// wire query (one per type for ANY) and assembles a [`DnsQueryResult`] from
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Exchange {
    pub(crate) status: DnsStatus,
    pub(crate) flags: Vec<String>,
    pub(crate) answers: Vec<DnsRecord>,
    pub(crate) authority: Vec<DnsRecord>,
    /// An ANY merge's failed sub-queries ([`merge_any`]); empty otherwise.
    pub(crate) failed_types: Vec<FailedType>,
}

impl Exchange {
    /// Maps a response, exactly as the server sent it, to an exchange: the
    /// status from the header's response code — extended by EDNS, which
    /// hickory merges in as it decodes (BADVERS, BADCOOKIE, …) — the flags
    /// from the header, and the converted ANSWER and AUTHORITY sections.
    /// Whatever the response code, NXDOMAIN, SERVFAIL and REFUSED included,
    /// a response is an outcome to report.
    pub(crate) fn from_message(message: &Message) -> Self {
        Self {
            status: message.metadata.response_code.into(),
            flags: header_flags(&message.metadata),
            answers: message.answers.iter().filter_map(to_dns_record).collect(),
            authority: message
                .authorities
                .iter()
                .filter_map(to_dns_record)
                .collect(),
            failed_types: Vec::new(),
        }
    }

    /// Maps the answer hickory's resolver gives itself for a special-use
    /// name ([`answered_locally`]): its loopback records (A, AAAA, PTR), or
    /// a negative answer — NODATA for other types, NXDOMAIN for `invalid`
    /// and `onion` — that it reports as an error carrying the code. Its
    /// header is its own; [`into_result`](Self::into_result) drops it.
    pub(crate) fn from_local(
        result: std::result::Result<Lookup, NetError>,
        record_type: RecordType,
    ) -> Result<Self> {
        match result {
            Ok(lookup) => Ok(Self::from_message(lookup.message())),
            Err(NetError::Dns(DnsError::NoRecordsFound(no_records))) => Ok(Self {
                status: no_records.response_code.into(),
                flags: Vec::new(),
                answers: Vec::new(),
                authority: Vec::new(),
                failed_types: Vec::new(),
            }),
            Err(e) => Err(SeerError::DnsError(format!(
                "{record_type} lookup failed: {e}"
            ))),
        }
    }

    /// The exchange with its answers in report order (see
    /// [`order_answers`]).
    pub(crate) fn ordered(mut self, query_name: &str, record_type: RecordType) -> Self {
        self.answers = order_answers(query_name, record_type, self.answers);
        self
    }

    /// The answers past the CNAME chain.
    pub(crate) fn records(&self, record_type: RecordType) -> &[DnsRecord] {
        &self.answers[chain_len(record_type, &self.answers)..]
    }

    /// NOERROR with records past the CNAME chain — the only kind of answer a
    /// wildcard probe is judged against.
    pub(crate) fn has_records(&self, record_type: RecordType) -> bool {
        self.status == DnsStatus::NoError && !self.records(record_type).is_empty()
    }

    /// Assembles the public result. For a name the resolver answers itself
    /// ([`answered_locally`]) no server was asked and the header is
    /// hickory's own, so neither is reported.
    pub(crate) fn into_result(
        self,
        name: String,
        record_type: RecordType,
        server: Option<&str>,
        wildcard: Option<WildcardProbe>,
        query_time: Duration,
    ) -> DnsQueryResult {
        let local = answered_locally(&name);
        DnsQueryResult {
            name,
            record_type,
            server: server.filter(|_| !local).map(str::to_string),
            answered_locally: local,
            status: self.status,
            flags: if local { Vec::new() } else { self.flags },
            answers: self.answers,
            authority: self.authority,
            failed_types: self.failed_types,
            wildcard,
            query_time_ms: duration_ms(query_time),
        }
    }
}

/// Whole milliseconds in `elapsed`, saturating at `u64::MAX`: the
/// `query_time_ms` of a query result and of a trace hop.
pub(crate) fn duration_ms(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

/// Renders the header flags as dig prints them: lowercase, in dig's order
/// (qr aa tc rd ra ad cd), only the ones that are set.
pub(crate) fn header_flags(metadata: &Metadata) -> Vec<String> {
    [
        (metadata.message_type == MessageType::Response, "qr"),
        (metadata.authoritative, "aa"),
        (metadata.truncation, "tc"),
        (metadata.recursion_desired, "rd"),
        (metadata.recursion_available, "ra"),
        (metadata.authentic_data, "ad"),
        (metadata.checking_disabled, "cd"),
    ]
    .into_iter()
    .filter(|(set, _)| *set)
    .map(|(_, flag)| flag.to_string())
    .collect()
}

/// A reported DNS name in one comparable spelling: lowercase (RFC 4343),
/// without the trailing root dot. Every name in a result is already ASCII
/// (A-labels, see `to_dns_record`), but owner and query names are reported
/// without the dot and RDATA names such as a CNAME target with it.
fn name_key(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

/// Orders an ANSWER section for reporting: the CNAME chain that starts at
/// `query_name` first, hop by hop, then everything else in the server's
/// order (MX by preference, matching `resolve`). Names compare in one
/// spelling ([`name_key`]). A CNAME query's answer is left as is.
pub(crate) fn order_answers(
    query_name: &str,
    record_type: RecordType,
    answers: Vec<DnsRecord>,
) -> Vec<DnsRecord> {
    if record_type == RecordType::CNAME {
        return answers;
    }
    let mut rest = answers;
    let mut ordered = Vec::with_capacity(rest.len());
    let mut current = name_key(query_name);
    // Each hop removes a record, so even a looping chain terminates.
    while let Some(pos) = rest
        .iter()
        .position(|r| r.record_type == RecordType::CNAME && name_key(&r.name) == current)
    {
        let hop = rest.remove(pos);
        if let RecordData::CNAME { target } = &hop.data {
            current = name_key(target);
        }
        ordered.push(hop);
    }
    if record_type == RecordType::MX {
        rest.sort_by_key(|r| match &r.data {
            RecordData::MX { preference, .. } => *preference,
            _ => 0,
        });
    }
    ordered.extend(rest);
    ordered
}

/// Drops repeats of the same resource record, keeping the first. Two records
/// are the same RR when owner (case-insensitively), type and data
/// ([`RecordData::comparison_key`]) match — the TTL is ignored, because the
/// ANY fan-out's sub-queries can read one cached record a second apart.
pub(crate) fn dedupe_records(records: impl IntoIterator<Item = DnsRecord>) -> Vec<DnsRecord> {
    let mut seen = HashSet::new();
    records
        .into_iter()
        .filter(|r| {
            seen.insert((
                r.name.to_ascii_lowercase(),
                r.record_type,
                r.data.comparison_key(),
            ))
        })
        .collect()
}

/// Merges the ANY fan-out's sub-query outcomes (in ANY type order) into one
/// exchange:
///
/// - status: NOERROR if any sub-query got NOERROR, NXDOMAIN if all got
///   NXDOMAIN, else the first sub-query's status;
/// - flags: the first sub-query's that got a response;
/// - answers: concatenated in order, repeats removed ([`dedupe_records`]) —
///   a CNAME'd name returns its CNAME to every sub-query;
/// - authority: only for a negative merge (no answers), and only from the
///   sub-queries that returned the merged status, deduplicated the same way.
///   A positive answer carries none: the sub-queries that came back NODATA
///   each bring their zone's SOA — the DS one, answered by the parent, the
///   parent's — and none of those describes the answer.
///
/// - failed_types: the sub-queries that got no response (or could not be
///   sent), each with its reason — so a partial merge does not pass for a
///   complete one.
///
/// When every sub-query failed, the last error is returned ([`fold_any`]).
pub(crate) fn merge_any(results: Vec<(RecordType, SubQuery)>) -> Result<Exchange> {
    let (exchanges, failures) = fold_any(results.into_iter().map(|(record_type, result)| {
        let result = match result {
            Ok(Ok(exchange)) => Ok(exchange),
            // The per-server reasons are what a caller's own `Silent` reply
            // already shows; nothing internal.
            Ok(Err(why)) => Err((
                why.to_string(),
                SeerError::DnsError(format!("{record_type} lookup failed: {why}")),
            )),
            Err(e) => Err((e.sanitized_message(), e)),
        };
        (record_type, result)
    }))
    .map_err(|(_, e)| e)?;
    let failed_types = failures
        .into_iter()
        .map(|(record_type, (error, _))| FailedType { record_type, error })
        .collect();
    let Some(first) = exchanges.first() else {
        return Err(SeerError::DnsError("ANY lookup ran no queries".to_string()));
    };
    let status = if exchanges.iter().any(|e| e.status == DnsStatus::NoError) {
        DnsStatus::NoError
    } else if exchanges.iter().all(|e| e.status == DnsStatus::NxDomain) {
        DnsStatus::NxDomain
    } else {
        first.status
    };
    let flags = first.flags.clone();
    let answers = dedupe_records(exchanges.iter().flat_map(|e| e.answers.iter().cloned()));
    let authority = if answers.is_empty() {
        dedupe_records(
            exchanges
                .iter()
                .filter(|e| e.status == status)
                .flat_map(|e| e.authority.iter().cloned()),
        )
    } else {
        Vec::new()
    };
    Ok(Exchange {
        status,
        flags,
        answers,
        authority,
        failed_types,
    })
}

/// One ANY sub-query's outcome: an exchange, no response from any server
/// (the inner `Err`), or an error before one could be sent.
pub(crate) type SubQuery = Result<std::result::Result<Exchange, NoResponse>>;

/// [`fold_any`]'s split: the successes, and the failures by type.
pub(crate) type Folded<T, E> = (Vec<T>, Vec<(RecordType, E)>);

/// The ANY fan-out's fold, shared by `DnsResolver::resolve` and
/// [`merge_any`]: the sub-queries that succeeded, in order, and the failed
/// ones by type — or, when none succeeded, the last failure, rather than an
/// empty set that would read as "no records".
pub(crate) fn fold_any<T, E>(
    results: impl IntoIterator<Item = (RecordType, std::result::Result<T, E>)>,
) -> std::result::Result<Folded<T, E>, E> {
    let mut succeeded = Vec::new();
    let mut failed = Vec::new();
    for (record_type, result) in results {
        match result {
            Ok(value) => succeeded.push(value),
            Err(e) => failed.push((record_type, e)),
        }
    }
    if succeeded.is_empty() {
        if let Some((_, e)) = failed.pop() {
            return Err(e);
        }
    }
    Ok((succeeded, failed))
}

/// Whether hickory's resolver answers `name` itself, without sending a
/// query: its caching client handles the special-use zones of RFC 6761
/// locally — `localhost`, `127.in-addr.arpa` and `1.0…0.ip6.arpa` get
/// loopback answers (NODATA for other types), `invalid` and `onion`
/// NXDOMAIN. The zones and their treatment are hickory's own, consulted as
/// its `CachingClient` consults them (`local` among them, whose queries it
/// sends on).
pub(crate) fn answered_locally(name: &str) -> bool {
    let Ok(name) = Name::from_ascii(name) else {
        return false;
    };
    [
        &LOCALHOST,
        &IN_ADDR_ARPA_127,
        &IP6_ARPA_1,
        &INVALID,
        &LOCAL,
        &ONION,
    ]
    .into_iter()
    .find(|zone| zone.name().zone_of(&name))
    .is_some_and(|zone| {
        matches!(
            zone.resolver(),
            ResolverUsage::Loopback | ResolverUsage::NxDomain
        )
    })
}

/// Leftmost label of every wildcard probe name, before its random hex.
const PROBE_LABEL_PREFIX: &str = "seer-probe-";

/// A fresh random probe label, e.g. `seer-probe-3f9a1c2e7b`: 40 random bits
/// as 10 lowercase hex digits, so the name is certainly not published.
pub(crate) fn random_probe_label() -> String {
    use rand::RngExt;
    let bits = rand::rng().random::<u64>() & 0xFF_FFFF_FFFF;
    format!("{PROBE_LABEL_PREFIX}{bits:010x}")
}

/// The wildcard probe name for a query: `label` in place of the leftmost
/// label of `name` — a sibling under the same parent. For an
/// `_service._proto` style name too, only the leftmost label is replaced.
///
/// `None` when a probe is meaningless or out of bounds: for ANY (a fan-out,
/// not one answer), for a wildcard name itself (`*.example.com`), for a
/// name that is not strictly below its registrable domain — a sibling of
/// `example.com` or `example.co.uk` would sit directly under a public
/// suffix, and seer never probes at TLD level — and for a name the resolver
/// answers itself ([`answered_locally`]), whose sibling it answers alike.
pub(crate) fn wildcard_probe_name(
    name: &str,
    record_type: RecordType,
    label: &str,
) -> Option<String> {
    if record_type == RecordType::ANY
        || name == "*"
        || name.starts_with("*.")
        || answered_locally(name)
    {
        return None;
    }
    crate::psl::registrable_parent(name)?;
    let (_, parent) = name.split_once('.')?;
    Some(format!("{label}.{parent}"))
}

/// Whether two answers carry the same record set, ignoring owner names and
/// TTLs: their (type, [`RecordData::comparison_key`]) sets are equal.
pub(crate) fn same_record_set(a: &[DnsRecord], b: &[DnsRecord]) -> bool {
    let key_set = |records: &[DnsRecord]| {
        records
            .iter()
            .map(|r| (r.record_type, r.data.comparison_key()))
            .collect::<HashSet<_>>()
    };
    key_set(a) == key_set(b)
}

/// Judges the wildcard probe against the main answer.
///
/// `None` — nothing to report — unless the main answer is NOERROR with
/// records and the probe completed: a transport error or a SERVFAIL-style
/// status says nothing about a wildcard. A probe NXDOMAIN means no wildcard
/// answers there; a probe NOERROR with records of the queried type means one
/// does, and its record set is compared with the main answer's.
pub(crate) fn wildcard_outcome(
    probe_name: &str,
    record_type: RecordType,
    answer: &Exchange,
    probe: Result<Exchange>,
) -> Option<WildcardProbe> {
    if !answer.has_records(record_type) {
        return None;
    }
    let answered = answer.records(record_type);
    let probe = probe.ok()?;
    let probed = probe.records(record_type);
    let present = match probe.status {
        DnsStatus::NoError => probed.iter().any(|r| r.record_type == record_type),
        DnsStatus::NxDomain => false,
        _ => return None,
    };
    Some(WildcardProbe {
        probe_name: probe_name.to_string(),
        present,
        matches_answer: present && same_record_set(answered, probed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_names_match_dig() {
        assert_eq!(DnsStatus::NoError.to_string(), "NOERROR");
        assert_eq!(DnsStatus::NxDomain.to_string(), "NXDOMAIN");
        assert_eq!(DnsStatus::ServFail.to_string(), "SERVFAIL");
        assert_eq!(DnsStatus::Refused.to_string(), "REFUSED");
        assert_eq!(DnsStatus::Other(1).to_string(), "FORMERR");
        assert_eq!(DnsStatus::Other(4).to_string(), "NOTIMP");
        assert_eq!(DnsStatus::Other(16).to_string(), "BADVERS");
        assert_eq!(DnsStatus::Other(3000).to_string(), "RCODE3000");
    }

    #[test]
    fn status_maps_every_hickory_code_by_value() {
        assert_eq!(DnsStatus::from(ResponseCode::NoError), DnsStatus::NoError);
        assert_eq!(DnsStatus::from(ResponseCode::NXDomain), DnsStatus::NxDomain);
        assert_eq!(DnsStatus::from(ResponseCode::ServFail), DnsStatus::ServFail);
        assert_eq!(DnsStatus::from(ResponseCode::Refused), DnsStatus::Refused);
        assert_eq!(DnsStatus::from(ResponseCode::NotImp), DnsStatus::Other(4));
        assert_eq!(
            DnsStatus::from(ResponseCode::Unknown(3000)),
            DnsStatus::Other(3000)
        );
    }

    #[test]
    fn status_round_trips_through_its_name() {
        for code in [0u16, 1, 2, 3, 4, 5, 6, 9, 16, 23, 3000] {
            let status = DnsStatus::from_code(code);
            assert_eq!(status.to_string().parse::<DnsStatus>().unwrap(), status);
            assert_eq!(status.code(), code);
        }
        assert_eq!(
            "nxdomain".parse::<DnsStatus>().unwrap(),
            DnsStatus::NxDomain
        );
        assert!("NOPE".parse::<DnsStatus>().is_err());
    }

    #[test]
    fn status_serializes_as_its_name() {
        assert_eq!(
            serde_json::to_string(&DnsStatus::NxDomain).unwrap(),
            "\"NXDOMAIN\""
        );
        assert_eq!(
            serde_json::from_str::<DnsStatus>("\"SERVFAIL\"").unwrap(),
            DnsStatus::ServFail
        );
    }

    // --- Pure result-assembly pieces -----------------------------------

    use hickory_resolver::net::NoRecords;
    use hickory_resolver::proto::op::{OpCode, Query};
    use hickory_resolver::proto::rr::rdata::SOA;
    use hickory_resolver::proto::rr::{Name, RData, Record, RecordType as WireType};

    fn rec(name: &str, record_type: RecordType, ttl: u32, data: RecordData) -> DnsRecord {
        DnsRecord {
            name: name.to_string(),
            record_type,
            ttl,
            data,
        }
    }

    fn a(name: &str, address: &str) -> DnsRecord {
        rec(
            name,
            RecordType::A,
            300,
            RecordData::A {
                address: address.to_string(),
            },
        )
    }

    fn cname(name: &str, target: &str) -> DnsRecord {
        rec(
            name,
            RecordType::CNAME,
            300,
            RecordData::CNAME {
                target: target.to_string(),
            },
        )
    }

    fn mx(name: &str, preference: u16) -> DnsRecord {
        rec(
            name,
            RecordType::MX,
            300,
            RecordData::MX {
                preference,
                exchange: format!("mx{preference}.seer.test."),
            },
        )
    }

    fn exchange(status: DnsStatus, answers: Vec<DnsRecord>) -> Exchange {
        Exchange {
            status,
            flags: vec!["qr".to_string(), "rd".to_string(), "ra".to_string()],
            answers,
            authority: vec![],
            failed_types: vec![],
        }
    }

    /// An answerless response with `status` and `authority`.
    fn negative(status: DnsStatus, authority: Vec<DnsRecord>) -> Exchange {
        Exchange {
            authority,
            ..exchange(status, vec![])
        }
    }

    fn soa_record(zone: &str) -> Record<SOA> {
        Record::from_rdata(
            Name::from_ascii(format!("{zone}.")).unwrap(),
            900,
            SOA::new(
                Name::from_ascii(format!("ns1.{zone}.")).unwrap(),
                Name::from_ascii(format!("hostmaster.{zone}.")).unwrap(),
                7,
                7200,
                3600,
                1209600,
                300,
            ),
        )
    }

    fn query_for(name: &str) -> Query {
        Query::query(Name::from_ascii(name).unwrap(), WireType::A)
    }

    #[test]
    fn header_flags_follow_digs_order() {
        let mut metadata = Metadata::new(7, MessageType::Response, OpCode::Query);
        metadata.recursion_desired = true;
        metadata.recursion_available = true;
        assert_eq!(header_flags(&metadata), ["qr", "rd", "ra"]);

        metadata.authoritative = true;
        metadata.truncation = true;
        metadata.authentic_data = true;
        metadata.checking_disabled = true;
        assert_eq!(
            header_flags(&metadata),
            ["qr", "aa", "tc", "rd", "ra", "ad", "cd"]
        );

        // A query message has no `qr`; nothing is invented.
        let query = Metadata::new(7, MessageType::Query, OpCode::Query);
        assert!(header_flags(&query).is_empty());
    }

    /// A response to `name`/A as a server sends it, with `code` and the
    /// header flags qr rd ra.
    fn response(name: &str, code: ResponseCode) -> Message {
        let mut message = Message::response(7, OpCode::Query);
        message.metadata.response_code = code;
        message.metadata.recursion_desired = true;
        message.metadata.recursion_available = true;
        message.add_query(query_for(name));
        message
    }

    fn wire_record(owner: &str, data: RData) -> Record {
        Record::from_rdata(Name::from_ascii(owner).unwrap(), 300, data)
    }

    fn wire_cname(owner: &str, target: &str) -> Record {
        wire_record(
            owner,
            RData::CNAME(hickory_resolver::proto::rr::rdata::CNAME(
                Name::from_ascii(target).unwrap(),
            )),
        )
    }

    #[test]
    fn from_message_reads_status_flags_and_sections_as_sent() {
        let mut message = response("www.seer.test.", ResponseCode::NoError);
        message.add_answer(wire_record(
            "www.seer.test.",
            RData::A(hickory_resolver::proto::rr::rdata::A::new(192, 0, 2, 1)),
        ));
        let exchange = Exchange::from_message(&message);
        assert_eq!(exchange.status, DnsStatus::NoError);
        assert_eq!(exchange.flags, ["qr", "rd", "ra"]);
        assert_eq!(exchange.answers, [a("www.seer.test", "192.0.2.1")]);
        assert!(exchange.authority.is_empty());
    }

    #[test]
    fn from_message_keeps_the_chain_and_header_of_a_negative_answer() {
        // Regression: a CNAME whose target does not exist came back as a
        // bare NXDOMAIN — no chain, no flags — because hickory's resolver
        // chased the target itself and turned its negative answer into an
        // error. The response as sent keeps all three sections.
        let mut dangling = response("www.seer.test.", ResponseCode::NXDomain);
        dangling.add_answer(wire_cname("www.seer.test.", "gone.cdn.test."));
        dangling.add_authority(soa_record("cdn.test").into_record_of_rdata());
        let exchange = Exchange::from_message(&dangling);
        assert_eq!(exchange.status, DnsStatus::NxDomain);
        assert_eq!(exchange.flags, ["qr", "rd", "ra"]);
        assert_eq!(exchange.answers, [cname("www.seer.test", "gone.cdn.test.")]);
        assert_eq!(exchange.authority.len(), 1);
        assert_eq!(exchange.authority[0].name, "cdn.test");
        assert_eq!(exchange.authority[0].record_type, RecordType::SOA);

        // An error code is a response too, header and all.
        for (code, status) in [
            (ResponseCode::ServFail, DnsStatus::ServFail),
            (ResponseCode::Refused, DnsStatus::Refused),
            (ResponseCode::NotImp, DnsStatus::Other(4)),
            (ResponseCode::BADVERS, DnsStatus::Other(16)),
        ] {
            let exchange = Exchange::from_message(&response("www.seer.test.", code));
            assert_eq!(exchange, negative(status, vec![]), "{code}");
        }
    }

    #[test]
    fn from_local_maps_the_resolvers_own_answers() {
        // Loopback records for an address or PTR query.
        let answer = wire_record(
            "localhost.",
            RData::A(hickory_resolver::proto::rr::rdata::A::new(127, 0, 0, 1)),
        );
        let lookup = Lookup::new_with_max_ttl(query_for("localhost."), [answer]);
        let exchange = Exchange::from_local(Ok(lookup), RecordType::A).unwrap();
        assert_eq!(exchange.status, DnsStatus::NoError);
        assert_eq!(exchange.answers, [a("localhost", "127.0.0.1")]);

        // NODATA for other types, NXDOMAIN for `invalid` and `onion`: the
        // code alone, with no header and no records.
        for (code, status) in [
            (ResponseCode::NoError, DnsStatus::NoError),
            (ResponseCode::NXDomain, DnsStatus::NxDomain),
        ] {
            let no_records = NoRecords::new(query_for("x.onion."), code);
            let exchange =
                Exchange::from_local(Err(NetError::from(no_records)), RecordType::MX).unwrap();
            assert_eq!(exchange.status, status);
            assert!(exchange.flags.is_empty() && exchange.answers.is_empty());
            assert!(exchange.authority.is_empty());
        }

        for transport in [NetError::Timeout, NetError::NoConnections] {
            let err = Exchange::from_local(Err(transport), RecordType::MX).unwrap_err();
            assert!(matches!(&err, SeerError::DnsError(m) if m.starts_with("MX lookup failed")));
        }
    }

    #[test]
    fn order_answers_puts_the_chain_first_hop_by_hop() {
        // Server order: target records, then the chain backwards.
        let answers = vec![
            a("edge.origin.test", "192.0.2.7"),
            cname("edge.cdn.test", "edge.origin.test."),
            cname("WWW.Seer.Test", "edge.cdn.test."),
        ];
        let ordered = order_answers("www.seer.test", RecordType::A, answers);
        assert_eq!(
            ordered,
            vec![
                cname("WWW.Seer.Test", "edge.cdn.test."),
                cname("edge.cdn.test", "edge.origin.test."),
                a("edge.origin.test", "192.0.2.7"),
            ]
        );
    }

    #[test]
    fn order_answers_leaves_a_cname_answer_and_sorts_mx_after_the_chain() {
        let answers = vec![cname("www.seer.test", "edge.cdn.test.")];
        assert_eq!(
            order_answers("www.seer.test", RecordType::CNAME, answers.clone()),
            answers
        );

        let answers = vec![
            mx("mail.cdn.test", 30),
            cname("mail.seer.test", "mail.cdn.test."),
            mx("mail.cdn.test", 10),
        ];
        let ordered = order_answers("mail.seer.test", RecordType::MX, answers);
        assert_eq!(
            ordered,
            vec![
                cname("mail.seer.test", "mail.cdn.test."),
                mx("mail.cdn.test", 10),
                mx("mail.cdn.test", 30),
            ]
        );
    }

    #[test]
    fn order_answers_walks_a_chain_through_idn_names() {
        // Owners and CNAME targets are both A-labels (see `to_dns_record`);
        // only the case and the trailing dot differ.
        let answers = vec![
            a("edge.xn--caf-dma.test", "192.0.2.7"),
            cname("xn--bcher-kva.seer.test", "Edge.XN--CAF-DMA.test."),
        ];
        let ordered = order_answers("xn--bcher-kva.seer.test", RecordType::A, answers);
        assert_eq!(
            ordered,
            vec![
                cname("xn--bcher-kva.seer.test", "Edge.XN--CAF-DMA.test."),
                a("edge.xn--caf-dma.test", "192.0.2.7"),
            ]
        );
        assert_eq!(name_key("Edge.XN--CAF-DMA.test."), "edge.xn--caf-dma.test");
        assert_eq!(name_key("WWW.seer.test"), "www.seer.test");
    }

    #[test]
    fn order_answers_terminates_on_a_cname_loop() {
        let answers = vec![
            cname("a.seer.test", "b.seer.test."),
            cname("b.seer.test", "a.seer.test."),
        ];
        let ordered = order_answers("a.seer.test", RecordType::A, answers);
        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].name, "a.seer.test");
    }

    #[test]
    fn dedupe_keeps_the_first_copy_of_each_rr() {
        let mut later = cname("WWW.seer.test", "Edge.CDN.test.");
        later.ttl = 299;
        let records = vec![
            cname("www.seer.test", "edge.cdn.test."),
            a("edge.cdn.test", "192.0.2.7"),
            later,
            a("edge.cdn.test", "192.0.2.8"),
        ];
        assert_eq!(
            dedupe_records(records),
            vec![
                cname("www.seer.test", "edge.cdn.test."),
                a("edge.cdn.test", "192.0.2.7"),
                a("edge.cdn.test", "192.0.2.8"),
            ]
        );
    }

    fn soa(zone: &str) -> DnsRecord {
        to_dns_record(&soa_record(zone).into_record_of_rdata()).unwrap()
    }

    /// A sub-query that got `exchange`.
    fn answered(record_type: RecordType, exchange: Exchange) -> (RecordType, SubQuery) {
        (record_type, Ok(Ok(exchange)))
    }

    /// A sub-query no server responded to.
    fn silent(record_type: RecordType) -> (RecordType, SubQuery) {
        (
            record_type,
            Ok(Err(NoResponse::timed_out("192.0.2.53".parse().unwrap()))),
        )
    }

    #[test]
    fn merge_any_status_flags_and_answers() {
        let chain = cname("www.seer.test", "edge.cdn.test.");
        let nodata = negative(DnsStatus::NoError, vec![soa("seer.test")]);
        let mut authoritative = nodata.clone();
        authoritative.flags = vec!["qr".to_string(), "aa".to_string()];
        let merged = merge_any(vec![
            silent(RecordType::A),
            answered(RecordType::AAAA, authoritative),
            answered(
                RecordType::CNAME,
                exchange(
                    DnsStatus::NoError,
                    vec![chain.clone(), a("edge.cdn.test", "192.0.2.7")],
                ),
            ),
            silent(RecordType::MX),
            answered(
                RecordType::NS,
                exchange(DnsStatus::NoError, vec![chain.clone()]),
            ),
            // The DS sub-query, answered NODATA by the parent zone.
            answered(
                RecordType::DS,
                negative(DnsStatus::NoError, vec![soa("test")]),
            ),
        ])
        .unwrap();
        assert_eq!(merged.status, DnsStatus::NoError);
        // The flags of the first sub-query that got a response.
        assert_eq!(merged.flags, ["qr", "aa"]);
        assert_eq!(merged.answers, vec![chain, a("edge.cdn.test", "192.0.2.7")]);
        // Regression: the NODATA sub-queries' SOAs — the parent's among
        // them — were merged into a positive answer's AUTHORITY.
        assert!(merged.authority.is_empty(), "{:?}", merged.authority);

        // A negative merge keeps the SOA, once, from the sub-queries that
        // returned the merged status.
        let all_nodata = merge_any(vec![
            answered(RecordType::A, nodata.clone()),
            answered(
                RecordType::AAAA,
                negative(DnsStatus::ServFail, vec![soa("other")]),
            ),
            answered(RecordType::MX, nodata),
        ])
        .unwrap();
        assert_eq!(all_nodata.status, DnsStatus::NoError);
        assert_eq!(all_nodata.authority, [soa("seer.test")]);
        assert!(all_nodata.failed_types.is_empty());

        let all_nx = merge_any(vec![
            answered(
                RecordType::A,
                negative(DnsStatus::NxDomain, vec![soa("seer.test")]),
            ),
            answered(
                RecordType::MX,
                negative(DnsStatus::NxDomain, vec![soa("seer.test")]),
            ),
        ])
        .unwrap();
        assert_eq!(all_nx.status, DnsStatus::NxDomain);
        assert_eq!(
            all_nx.flags,
            ["qr", "rd", "ra"],
            "a negative answer has a header"
        );
        assert_eq!(all_nx.authority, [soa("seer.test")]);

        // Mixed failures: the first sub-query's status.
        let mixed = merge_any(vec![
            answered(RecordType::A, negative(DnsStatus::ServFail, vec![])),
            answered(RecordType::MX, negative(DnsStatus::NxDomain, vec![])),
        ])
        .unwrap();
        assert_eq!(mixed.status, DnsStatus::ServFail);
    }

    #[test]
    fn merge_any_reports_the_types_whose_sub_query_failed() {
        // Regression: a sub-query that timed out was dropped without a
        // trace, so an ANY answer missing its TXT records read as complete.
        let merged = merge_any(vec![
            answered(
                RecordType::A,
                exchange(DnsStatus::NoError, vec![a("seer.test", "192.0.2.1")]),
            ),
            silent(RecordType::TXT),
            (
                RecordType::DNSKEY,
                Err(SeerError::DnsError("internal detail".to_string())),
            ),
        ])
        .unwrap();
        assert_eq!(merged.answers, [a("seer.test", "192.0.2.1")]);
        assert_eq!(
            merged.failed_types,
            [
                FailedType {
                    record_type: RecordType::TXT,
                    error: "192.0.2.53: timed out".to_string(),
                },
                // An error that is not a transport failure is reported
                // sanitized.
                FailedType {
                    record_type: RecordType::DNSKEY,
                    error: "DNS resolution failed".to_string(),
                },
            ]
        );
        let result = merged.into_result(
            "seer.test".to_string(),
            RecordType::ANY,
            None,
            None,
            Duration::ZERO,
        );
        assert_eq!(result.failed_types.len(), 2);
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["failed_types"][0]["record_type"], "TXT");
    }

    #[test]
    fn merge_any_errors_only_when_every_sub_query_failed() {
        let err = merge_any(vec![silent(RecordType::A), silent(RecordType::AAAA)]).unwrap_err();
        assert!(err.to_string().contains("AAAA lookup failed"), "{err}");
        assert!(err.to_string().contains("192.0.2.53: timed out"), "{err}");
        assert!(merge_any(vec![]).is_err());
    }

    #[test]
    fn fold_any_keeps_successes_and_failures_apart() {
        let (ok, failed) = fold_any([
            (RecordType::A, Ok(1)),
            (RecordType::MX, Err("mx")),
            (RecordType::TXT, Ok(3)),
        ])
        .unwrap();
        assert_eq!(ok, [1, 3]);
        assert_eq!(failed, [(RecordType::MX, "mx")]);
        // Nothing succeeded: the last failure.
        let all_failed: std::result::Result<(Vec<u8>, _), _> =
            fold_any([(RecordType::A, Err("a")), (RecordType::MX, Err("mx"))]);
        assert_eq!(all_failed.unwrap_err(), "mx");
        let none: std::result::Result<Folded<u8, &str>, &str> = fold_any([]);
        assert_eq!(none.unwrap(), (vec![], vec![]));
    }

    #[test]
    fn probe_label_is_ten_random_lowercase_hex_digits() {
        let label = random_probe_label();
        let hex = label.strip_prefix(PROBE_LABEL_PREFIX).expect("prefixed");
        assert_eq!(hex.len(), 10, "{label}");
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        assert_ne!(random_probe_label(), label, "40 random bits per label");
    }

    #[test]
    fn probe_name_is_a_sibling_below_the_registrable_domain() {
        let probe =
            |name: &str, record_type| wildcard_probe_name(name, record_type, "seer-probe-x");
        assert_eq!(
            probe("www.example.com", RecordType::A).as_deref(),
            Some("seer-probe-x.example.com")
        );
        assert_eq!(
            probe("a.b.example.co.uk", RecordType::TXT).as_deref(),
            Some("seer-probe-x.b.example.co.uk")
        );
        // Underscore names: only the leftmost label is replaced.
        assert_eq!(
            probe("_sip._tcp.example.com", RecordType::SRV).as_deref(),
            Some("seer-probe-x._tcp.example.com")
        );
        assert_eq!(
            probe("_443._tcp.www.example.com", RecordType::TLSA).as_deref(),
            Some("seer-probe-x._tcp.www.example.com")
        );
    }

    #[test]
    fn probe_is_never_run_at_tld_level_for_wildcards_or_for_any() {
        let probe =
            |name: &str, record_type| wildcard_probe_name(name, record_type, "seer-probe-x");
        // A registrable domain's sibling sits directly under a public suffix.
        assert_eq!(probe("example.com", RecordType::A), None);
        assert_eq!(probe("example.co.uk", RecordType::A), None);
        assert_eq!(probe("com", RecordType::A), None);
        // The private-section rule does not count: github.io is registrable.
        assert_eq!(probe("github.io", RecordType::A), None);
        assert_eq!(probe("*.example.com", RecordType::A), None);
        assert_eq!(probe("*", RecordType::A), None);
        assert_eq!(probe("www.example.com", RecordType::ANY), None);
        // Regression: the resolver answers a special-use name's sibling
        // itself, the same way, so the probe "found" a wildcard.
        assert_eq!(probe("1.0.0.127.in-addr.arpa", RecordType::PTR), None);
        assert_eq!(probe("a.b.localhost", RecordType::A), None);
    }

    #[test]
    fn record_sets_compare_by_type_and_data_only() {
        let ours = vec![
            a("www.seer.test", "192.0.2.1"),
            a("www.seer.test", "192.0.2.2"),
        ];
        let mut theirs = vec![
            a("seer-probe-1.seer.test", "192.0.2.2"),
            a("seer-probe-1.seer.test", "192.0.2.1"),
        ];
        theirs[0].ttl = 5;
        assert!(same_record_set(&ours, &theirs));
        assert!(!same_record_set(&ours, &theirs[..1]));
        assert!(!same_record_set(
            &[cname("x.seer.test", "a.test.")],
            &[a("x.seer.test", "a.test.")]
        ));
    }

    #[test]
    fn wildcard_outcome_needs_a_positive_answer_and_a_completed_probe() {
        let answer = exchange(DnsStatus::NoError, vec![a("www.seer.test", "192.0.2.1")]);
        let probe_answer = |address: &str| {
            Ok(exchange(
                DnsStatus::NoError,
                vec![a("seer-probe-1.seer.test", address)],
            ))
        };
        let judge = |answer: &Exchange, probe| {
            wildcard_outcome("seer-probe-1.seer.test", RecordType::A, answer, probe)
        };

        let matched = judge(&answer, probe_answer("192.0.2.1")).unwrap();
        assert_eq!(
            matched,
            WildcardProbe {
                probe_name: "seer-probe-1.seer.test".to_string(),
                present: true,
                matches_answer: true,
            }
        );
        let different = judge(&answer, probe_answer("192.0.2.99")).unwrap();
        assert!(different.present && !different.matches_answer);

        let absent = judge(&answer, Ok(negative(DnsStatus::NxDomain, vec![]))).unwrap();
        assert!(!absent.present && !absent.matches_answer);
        let nodata = judge(&answer, Ok(negative(DnsStatus::NoError, vec![]))).unwrap();
        assert!(!nodata.present);

        // The probe did not complete: nothing to say.
        assert_eq!(
            judge(&answer, Ok(negative(DnsStatus::ServFail, vec![]))),
            None
        );
        assert_eq!(
            judge(&answer, Err(SeerError::DnsError("timeout".to_string()))),
            None
        );

        // Nothing to judge against: a negative main answer, or a bare chain.
        let nx = negative(DnsStatus::NxDomain, vec![]);
        assert_eq!(judge(&nx, probe_answer("192.0.2.1")), None);
        let chain_only = exchange(
            DnsStatus::NoError,
            vec![cname("www.seer.test", "edge.cdn.test.")],
        );
        assert_eq!(judge(&chain_only, probe_answer("192.0.2.1")), None);
    }

    fn result(
        record_type: RecordType,
        status: DnsStatus,
        answers: Vec<DnsRecord>,
    ) -> DnsQueryResult {
        exchange(status, answers).into_result(
            "www.seer.test".to_string(),
            record_type,
            None,
            None,
            Duration::from_millis(12),
        )
    }

    #[test]
    fn result_splits_the_chain_from_the_records() {
        let chained = result(
            RecordType::A,
            DnsStatus::NoError,
            vec![
                cname("www.seer.test", "edge.cdn.test."),
                a("edge.cdn.test", "192.0.2.7"),
            ],
        );
        assert_eq!(chained.cname_chain().count(), 1);
        assert_eq!(
            chained
                .records()
                .map(|r| r.name.as_str())
                .collect::<Vec<_>>(),
            ["edge.cdn.test"]
        );
        assert!(!chained.is_nodata());
        assert_eq!(chained.query_time_ms, 12);

        // A CNAME query's CNAME is the answer, not a hop.
        let cname_query = result(
            RecordType::CNAME,
            DnsStatus::NoError,
            vec![cname("www.seer.test", "edge.cdn.test.")],
        );
        assert_eq!(cname_query.cname_chain().count(), 0);
        assert_eq!(cname_query.records().count(), 1);
        assert!(!cname_query.is_nodata());
    }

    #[test]
    fn nodata_means_noerror_without_records_of_the_type() {
        assert!(result(RecordType::A, DnsStatus::NoError, vec![]).is_nodata());
        // A chain that ends without the type is still NODATA for it.
        assert!(result(
            RecordType::A,
            DnsStatus::NoError,
            vec![cname("www.seer.test", "edge.cdn.test.")]
        )
        .is_nodata());
        assert!(!result(RecordType::A, DnsStatus::NxDomain, vec![]).is_nodata());
        assert!(!result(RecordType::A, DnsStatus::ServFail, vec![]).is_nodata());
        // ANY: NODATA only with no answers at all.
        assert!(result(RecordType::ANY, DnsStatus::NoError, vec![]).is_nodata());
        assert!(!result(
            RecordType::ANY,
            DnsStatus::NoError,
            vec![mx("www.seer.test", 10)]
        )
        .is_nodata());
    }

    fn ns(zone: &str, host: &str) -> DnsRecord {
        rec(
            zone,
            RecordType::NS,
            300,
            RecordData::NS {
                nameserver: host.to_string(),
            },
        )
    }

    #[test]
    fn a_referral_is_not_nodata() {
        // Regression: a non-recursive server's referral (NOERROR, no answer,
        // the child zone's NS records in AUTHORITY, no SOA) was reported as
        // NODATA — "the name exists" — which a referral does not say.
        let mut referral = result(RecordType::A, DnsStatus::NoError, vec![]);
        referral.authority = vec![
            ns("child.seer.test", "ns1.child.seer.test."),
            ns("child.seer.test", "ns2.child.seer.test."),
        ];
        assert_eq!(referral.referral_zone(), Some("child.seer.test"));
        assert!(!referral.is_nodata());

        // NODATA may carry the zone's NS next to its SOA (RFC 2308 §2.2):
        // the SOA makes it an answer, not a referral.
        let mut nodata = referral.clone();
        nodata.authority.insert(0, soa("seer.test"));
        assert_eq!(nodata.referral_zone(), None);
        assert!(nodata.is_nodata());

        // NS records beside an answer, or under another status, are no
        // referral either.
        let mut answered = result(
            RecordType::A,
            DnsStatus::NoError,
            vec![a("www.seer.test", "192.0.2.1")],
        );
        answered.authority = referral.authority.clone();
        assert_eq!(answered.referral_zone(), None);
        let mut nx = result(RecordType::A, DnsStatus::NxDomain, vec![]);
        nx.authority = referral.authority.clone();
        assert_eq!(nx.referral_zone(), None);
        // An ANY fan-out whose sub-queries were all referred.
        let mut any = referral.clone();
        any.record_type = RecordType::ANY;
        assert_eq!(any.referral_zone(), Some("child.seer.test"));
        assert!(!any.is_nodata());

        // An authoritative server's answer is never a referral: here its own
        // zone's NS records sit beside a CNAME it did not follow out of the
        // zone, with no SOA. The AA flag tells the two apart.
        let mut unfollowed = result(
            RecordType::A,
            DnsStatus::NoError,
            vec![cname("www.seer.test", "edge.cdn.test.")],
        );
        unfollowed.flags = vec!["qr".to_string(), "aa".to_string(), "rd".to_string()];
        unfollowed.authority = vec![ns("seer.test", "ns1.seer.test.")];
        assert_eq!(unfollowed.referral_zone(), None);
        unfollowed.flags.retain(|flag| flag != "aa");
        assert_eq!(unfollowed.referral_zone(), Some("seer.test"));
    }

    #[test]
    fn special_use_names_are_answered_locally() {
        for name in [
            "localhost",
            "foo.localhost",
            "1.0.0.127.in-addr.arpa",
            "seer-probe-0123456789.0.0.127.in-addr.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
            "x.invalid",
            "facebookcorewwwi.onion",
            "Foo.LOCALHOST",
        ] {
            assert!(answered_locally(name), "{name}");
        }
        for name in [
            "www.seer.test",
            // `local` is consulted, but hickory sends its queries on.
            "printer.local",
            "1.0.0.10.in-addr.arpa",
            "localhost.example.com",
            "onion.seer.test",
        ] {
            assert!(!answered_locally(name), "{name}");
        }
    }

    #[test]
    fn a_local_answer_names_no_server_and_no_invented_header() {
        // Regression: hickory's own answer for a special-use name was
        // reported as the server's — `server: 1.1.1.1`, `flags: qr` — though
        // no query was sent.
        let local = exchange(
            DnsStatus::NoError,
            vec![rec(
                "1.0.0.127.in-addr.arpa",
                RecordType::PTR,
                86400,
                RecordData::PTR {
                    target: "localhost.".to_string(),
                },
            )],
        )
        .into_result(
            "1.0.0.127.in-addr.arpa".to_string(),
            RecordType::PTR,
            Some("1.1.1.1"),
            None,
            Duration::ZERO,
        );
        assert!(local.answered_locally);
        assert_eq!(local.server, None);
        assert!(local.flags.is_empty());
        assert_eq!(local.records().count(), 1);

        let sent = exchange(DnsStatus::NoError, vec![]).into_result(
            "www.seer.test".to_string(),
            RecordType::A,
            Some("1.1.1.1"),
            None,
            Duration::ZERO,
        );
        assert_eq!(sent.server.as_deref(), Some("1.1.1.1"));
        assert!(!sent.answered_locally);
        assert_eq!(sent.flags, ["qr", "rd", "ra"]);
    }

    #[test]
    fn result_serializes_to_the_documented_shape() {
        let mut query = result(
            RecordType::A,
            DnsStatus::NoError,
            vec![
                cname("www.seer.test", "edge.cdn.test."),
                a("edge.cdn.test", "192.0.2.7"),
            ],
        );
        query.server = Some("1.1.1.1".to_string());
        query.wildcard = Some(WildcardProbe {
            probe_name: "seer-probe-3f9a1c2e7b.seer.test".to_string(),
            present: false,
            matches_answer: false,
        });
        let json = serde_json::to_value(&query).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "name": "www.seer.test",
                "record_type": "A",
                "server": "1.1.1.1",
                "answered_locally": false,
                "status": "NOERROR",
                "flags": ["qr", "rd", "ra"],
                "answers": [
                    {
                        "name": "www.seer.test",
                        "record_type": "CNAME",
                        "ttl": 300,
                        "data": {"record_type": "CNAME", "value": {"target": "edge.cdn.test."}}
                    },
                    {
                        "name": "edge.cdn.test",
                        "record_type": "A",
                        "ttl": 300,
                        "data": {"record_type": "A", "value": {"address": "192.0.2.7"}}
                    }
                ],
                "authority": [],
                "wildcard": {
                    "probe_name": "seer-probe-3f9a1c2e7b.seer.test",
                    "present": false,
                    "matches_answer": false
                },
                "query_time_ms": 12
            })
        );
        let back: DnsQueryResult = serde_json::from_value(json).unwrap();
        assert_eq!(back, query);

        // The default upstream and an unrun probe serialize as null.
        let default = result(RecordType::A, DnsStatus::NxDomain, vec![]);
        let json = serde_json::to_value(&default).unwrap();
        assert_eq!(json["server"], serde_json::Value::Null);
        assert_eq!(json["wildcard"], serde_json::Value::Null);
        assert_eq!(json["status"], "NXDOMAIN");
    }
}
