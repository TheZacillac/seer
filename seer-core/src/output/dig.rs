//! dig-style rendering shared across formats: the `+short` lines
//! ([`dig_short`], [`dig_trace_short`]) and the wording of a query's
//! outcome — the negative-answer verdict, the referral, the local-answer
//! note, the wildcard note, a trace's verdict and its unfollowed CNAME — so
//! the human and Markdown formatters and the TUI's DNS lens say the same
//! thing and differ only in styling and escaping.
//!
//! The wording takes remote strings (a probe name, a CNAME target, a
//! referral's zone) already escaped for the caller's format — or the escape
//! to apply — and returns them embedded as given.

use std::fmt;

use super::human::sanitize_line;
use crate::dns::{
    DnsQueryResult, DnsRecord, DnsStatus, DnsTrace, RecordData, RecordType, WildcardProbe,
};

/// `dig +short` for a query result: the value of every ANSWER record, one
/// per line — the CNAME chain's targets first, then the records, as dig
/// prints them — with no owner, TTL or type. Empty when the response has no
/// answers (NXDOMAIN, NODATA, SERVFAIL, …), again like dig.
///
/// Each value is sanitized for a terminal and kept to one line, so remote
/// record data (a TXT string, say) can neither inject escape sequences nor
/// forge an extra answer line for a script reading the output.
pub fn dig_short(result: &DnsQueryResult) -> String {
    short_lines(result.cname_chain().chain(result.records()))
}

/// [`dig_short`] for a trace: the final ANSWER section's values, one per
/// line, in the order the authoritative server sent them. Empty when the
/// walk ended without an answer.
pub fn dig_trace_short(trace: &DnsTrace) -> String {
    short_lines(&trace.answers)
}

fn short_lines<'r>(records: impl IntoIterator<Item = &'r DnsRecord>) -> String {
    records
        .into_iter()
        .map(|r| sanitize_line(&r.data.to_string()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// How a response code reads, for styling: an answer (NOERROR), a negative
/// answer (NXDOMAIN — the name does not exist), or no answer at all.
///
/// The tone is the response code's alone, so NODATA (the name exists, but
/// not with the type) is NOERROR and reads [`Tone::Answered`]; tell it apart
/// with [`DnsQueryResult::is_nodata`], or word it with [`query_verdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// NOERROR, with or without records — NODATA included.
    Answered,
    /// NXDOMAIN only.
    Negative,
    /// SERVFAIL, REFUSED and every other error code.
    Failed,
}

/// The [`Tone`] of a response code.
pub fn tone(status: DnsStatus) -> Tone {
    match status {
        DnsStatus::NoError => Tone::Answered,
        DnsStatus::NxDomain => Tone::Negative,
        _ => Tone::Failed,
    }
}

/// The sentence printed under a response that carries no answer of the
/// queried type: it tells NXDOMAIN ("the name does not exist") from NODATA
/// ("the name exists, but not with this type"), and a server failure from
/// both. `None` for a positive answer.
///
/// `nodata` is whether a NOERROR response lacks records of `record_type`
/// ([`DnsQueryResult::is_nodata`] for a query).
pub fn verdict(status: DnsStatus, record_type: RecordType, nodata: bool) -> Option<String> {
    let text = match status {
        DnsStatus::NoError if !nodata => return None,
        DnsStatus::NoError if record_type == RecordType::ANY => {
            "No records (NODATA — the name exists)".to_string()
        }
        DnsStatus::NoError => format!("No {record_type} records (NODATA — the name exists)"),
        DnsStatus::NxDomain => "Name does not exist (NXDOMAIN)".to_string(),
        DnsStatus::ServFail => {
            "No answer: the server failed to resolve the name (SERVFAIL)".to_string()
        }
        DnsStatus::Refused => "No answer: the server refused the query (REFUSED)".to_string(),
        other => format!("No answer: the server returned {other}"),
    };
    Some(text)
}

/// The sentence printed under a query result without an answer. `None` for
/// a positive answer. `escape` renders the remote name it quotes — a
/// referral's zone, a CNAME target — for the caller's format.
///
/// - A referral ([`DnsQueryResult::referral_zone`]) names the zone it
///   refers to, and the missing `aa` flag when the header is known.
/// - A negative answer behind a CNAME chain is about the chain's last
///   target, not the queried name, which exists — it owns the first CNAME:
///   NXDOMAIN says the target does not exist (RFC 6604 §2), NODATA that it
///   has no records of the type. A chain that ends in a bare CNAME, with no
///   SOA and no `ra` flag, is one the server did not follow (it does not
///   recurse, and the target is outside its zones), which says nothing about
///   the target.
/// - Anything else reads as the [`verdict`] for its status.
pub fn query_verdict<D: fmt::Display>(
    result: &DnsQueryResult,
    escape: impl FnOnce(&str) -> D,
) -> Option<String> {
    if let Some(zone) = result.referral_zone() {
        let header = if result.flags.is_empty() {
            ""
        } else {
            " (no aa flag)"
        };
        return Some(format!(
            "No answer: referral to {}{} — the server is not authoritative for the \
             name{header} and does not recurse",
            escape(zone),
            zone_suffix(zone)
        ));
    }
    let record_type = result.record_type;
    match (result.status, last_cname_target(result.cname_chain())) {
        (DnsStatus::NxDomain, Some(target)) => Some(missing_target(escape(target))),
        (DnsStatus::NoError, Some(target)) if result.is_nodata() => {
            let followed = result.flags.iter().any(|flag| flag == "ra")
                || result
                    .authority
                    .iter()
                    .any(|r| r.record_type == RecordType::SOA);
            Some(if followed {
                format!(
                    "The CNAME target {} has no {record_type} records (NODATA)",
                    escape(target)
                )
            } else {
                format!(
                    "No {record_type} records here: the server returned the CNAME to {} \
                     without following it (it does not recurse)",
                    escape(target)
                )
            })
        }
        _ => verdict(result.status, record_type, result.is_nodata()),
    }
}

/// The verdict for NXDOMAIN beside a CNAME chain: the name that does not
/// exist is the chain's last target (`target`, escaped by the caller). One
/// sentence for a query result and a trace.
fn missing_target(target: impl fmt::Display) -> String {
    format!("The CNAME target {target} does not exist (NXDOMAIN)")
}

/// The note under a result the resolver answered itself
/// ([`DnsQueryResult::answered_locally`]).
pub const LOCAL_NOTE: &str = "Answered locally, not by a server: a special-use name (RFC 6761) \
                              that the resolver answers itself";

/// The status line's server when the result names none: `none` for an
/// answer the resolver made itself, else `default` (the default upstream).
/// A named server is the caller's spec, which the caller escapes.
pub fn unnamed_server(result: &DnsQueryResult) -> &'static str {
    if result.answered_locally {
        "none"
    } else {
        "default"
    }
}

/// The wildcard note for a probe that found a wildcard, `None` when the
/// probe name got no answer. `probe_name` is the probe's name as the caller
/// escaped it for its format.
pub fn wildcard_note(probe: &WildcardProbe, probe_name: impl fmt::Display) -> Option<String> {
    if !probe.present {
        return None;
    }
    Some(if probe.matches_answer {
        format!(
            "a random sibling ({probe_name}) resolves — this answer matches it and is likely \
             wildcard-synthesized"
        )
    } else {
        format!("a random sibling ({probe_name}) resolves too, but with different data")
    })
}

/// The suffix that marks the root zone (`.`) in a trace hop's heading.
pub fn zone_suffix(zone: &str) -> &'static str {
    if zone == "." {
        " (root)"
    } else {
        ""
    }
}

/// The sentence printed under a trace's final result without an answer of
/// the queried type: the [`verdict`] for its status — except for an NXDOMAIN
/// whose answer holds a CNAME. The server followed that chain itself, and
/// the response code is about the chain's last name (RFC 6604 §2), so the
/// sentence names that target as the name that does not exist rather than
/// the queried name, which the CNAME shows does. `None` for a positive
/// answer. `escape` renders the target — a remote string — for the caller's
/// format.
pub fn trace_verdict<D: fmt::Display>(
    trace: &DnsTrace,
    escape: impl FnOnce(&str) -> D,
) -> Option<String> {
    if trace.status == DnsStatus::NxDomain {
        if let Some(target) = last_cname_target(&trace.answers) {
            return Some(missing_target(escape(target)));
        }
    }
    verdict(trace.status, trace.record_type, trace.answers.is_empty())
}

/// The CNAME a trace ended at without following it: a NOERROR answer that
/// holds a CNAME but no record of the queried type (`dig +trace` stops
/// there too). Returns the CNAME's target — the last one, for a partial
/// chain. `None` under any other response code: a CNAME beside NXDOMAIN (or
/// an error) means the server followed the chain itself and the code is
/// about its target (see [`trace_verdict`]), so there is nothing left to
/// trace.
pub fn unfollowed_cname(trace: &DnsTrace) -> Option<&str> {
    let wanted = trace.record_type;
    if trace.status != DnsStatus::NoError
        || wanted == RecordType::CNAME
        || trace.answers.iter().any(|r| r.record_type == wanted)
    {
        return None;
    }
    last_cname_target(&trace.answers)
}

/// The target of the last CNAME in `answers` (in the order given): the end
/// of the chain the answer holds.
fn last_cname_target<'r>(answers: impl IntoIterator<Item = &'r DnsRecord>) -> Option<&'r str> {
    answers
        .into_iter()
        .filter_map(|r| match &r.data {
            RecordData::CNAME { target } => Some(target.as_str()),
            _ => None,
        })
        .last()
}

/// The note under a trace that stopped at a CNAME (see
/// [`unfollowed_cname`]); `target` is escaped by the caller.
pub fn cname_note(target: impl fmt::Display) -> String {
    format!(
        "The answer is a CNAME to {target}, which a trace does not follow: trace that name next"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::TraceHop;

    fn record(name: &str, data: RecordData) -> DnsRecord {
        let record_type = match &data {
            RecordData::A { .. } => RecordType::A,
            RecordData::CNAME { .. } => RecordType::CNAME,
            RecordData::TXT { .. } => RecordType::TXT,
            RecordData::MX { .. } => RecordType::MX,
            other => panic!("fixture does not model {other:?}"),
        };
        DnsRecord {
            name: name.to_string(),
            record_type,
            ttl: 300,
            data,
        }
    }

    fn a(name: &str, address: &str) -> DnsRecord {
        record(
            name,
            RecordData::A {
                address: address.to_string(),
            },
        )
    }

    fn cname(name: &str, target: &str) -> DnsRecord {
        record(
            name,
            RecordData::CNAME {
                target: target.to_string(),
            },
        )
    }

    fn txt(name: &str, text: &str) -> DnsRecord {
        record(name, RecordData::txt(vec![text.to_string()]))
    }

    fn result(
        record_type: RecordType,
        status: DnsStatus,
        answers: Vec<DnsRecord>,
    ) -> DnsQueryResult {
        DnsQueryResult {
            name: "www.seer.test".to_string(),
            record_type,
            server: None,
            answered_locally: false,
            status,
            flags: vec!["qr".into(), "rd".into(), "ra".into()],
            answers,
            failed_types: Vec::new(),
            authority: Vec::new(),
            wildcard: None,
            query_time_ms: 12,
        }
    }

    fn trace(record_type: RecordType, answers: Vec<DnsRecord>) -> DnsTrace {
        DnsTrace {
            name: "www.seer.test".to_string(),
            record_type,
            hops: vec![TraceHop {
                zone: "seer.test.".to_string(),
                server: "ns1.seer.test.".to_string(),
                address: "192.0.2.53".to_string(),
                query_time_ms: 20,
                status: DnsStatus::NoError,
                authoritative: true,
                referral_zone: None,
                referral: Vec::new(),
                answers: answers.clone(),
                failed_servers: Vec::new(),
            }],
            status: DnsStatus::NoError,
            answers,
            error: None,
        }
    }

    #[test]
    fn dig_short_prints_cname_targets_first_then_one_value_per_line() {
        let r = result(
            RecordType::A,
            DnsStatus::NoError,
            vec![
                cname("www.seer.test", "edge.cdn.test."),
                cname("edge.cdn.test", "pop1.cdn.test."),
                a("pop1.cdn.test", "192.0.2.7"),
                a("pop1.cdn.test", "192.0.2.8"),
            ],
        );
        assert_eq!(
            dig_short(&r),
            "edge.cdn.test.\npop1.cdn.test.\n192.0.2.7\n192.0.2.8"
        );
    }

    #[test]
    fn dig_short_prints_each_record_data_as_displayed() {
        // The value is the record's Display form — MX keeps its preference,
        // TXT its quotes — exactly as the formatters' data column shows it.
        let mut r = result(
            RecordType::MX,
            DnsStatus::NoError,
            vec![record(
                "seer.test",
                RecordData::MX {
                    preference: 10,
                    exchange: "mail.seer.test.".to_string(),
                },
            )],
        );
        assert_eq!(dig_short(&r), "10 mail.seer.test.");
        r.record_type = RecordType::TXT;
        r.answers = vec![txt("seer.test", "v=spf1 -all")];
        assert_eq!(dig_short(&r), "\"v=spf1 -all\"");
    }

    #[test]
    fn dig_short_is_empty_without_answers() {
        for status in [
            DnsStatus::NxDomain,
            DnsStatus::NoError,
            DnsStatus::ServFail,
            DnsStatus::Refused,
        ] {
            assert_eq!(dig_short(&result(RecordType::A, status, Vec::new())), "");
        }
    }

    #[test]
    fn dig_short_sanitizes_terminal_escapes_and_line_breaks() {
        // A TXT string carrying an OSC 52 clipboard write, a screen clear and
        // an embedded newline + fake address: none may reach the terminal,
        // and the newline must not forge a second answer line.
        let r = result(
            RecordType::TXT,
            DnsStatus::NoError,
            vec![txt(
                "seer.test",
                "v=spf1\x1b]52;c;AAAA\x07 -all\x1b[2J\n203.0.113.66\r\tend",
            )],
        );
        let short = dig_short(&r);
        assert_eq!(short, "\"v=spf1 -all 203.0.113.66 end\"");
        assert_eq!(short.lines().count(), 1, "one line per record: {short:?}");
    }

    #[test]
    fn dig_trace_short_prints_the_final_answers_in_server_order() {
        let t = trace(
            RecordType::A,
            vec![
                a("www.seer.test", "192.0.2.9"),
                a("www.seer.test", "192.0.2.1"),
            ],
        );
        assert_eq!(dig_trace_short(&t), "192.0.2.9\n192.0.2.1");

        let unanswered = DnsTrace {
            status: DnsStatus::NxDomain,
            ..trace(RecordType::A, Vec::new())
        };
        assert_eq!(dig_trace_short(&unanswered), "");

        let evil = trace(RecordType::TXT, vec![txt("www.seer.test", "a\x1b[31m\nb")]);
        assert_eq!(dig_trace_short(&evil), "\"a b\"");
    }

    #[test]
    fn verdict_tells_nxdomain_from_nodata_from_failure() {
        assert_eq!(verdict(DnsStatus::NoError, RecordType::A, false), None);
        assert_eq!(
            verdict(DnsStatus::NoError, RecordType::AAAA, true).as_deref(),
            Some("No AAAA records (NODATA — the name exists)")
        );
        assert_eq!(
            verdict(DnsStatus::NoError, RecordType::ANY, true).as_deref(),
            Some("No records (NODATA — the name exists)")
        );
        assert_eq!(
            verdict(DnsStatus::NxDomain, RecordType::A, false).as_deref(),
            Some("Name does not exist (NXDOMAIN)")
        );
        assert_eq!(
            verdict(DnsStatus::ServFail, RecordType::A, false).as_deref(),
            Some("No answer: the server failed to resolve the name (SERVFAIL)")
        );
        assert_eq!(
            verdict(DnsStatus::Refused, RecordType::A, false).as_deref(),
            Some("No answer: the server refused the query (REFUSED)")
        );
        assert_eq!(
            verdict(DnsStatus::from_code(4), RecordType::A, false).as_deref(),
            Some("No answer: the server returned NOTIMP")
        );
    }

    fn ns(zone: &str, host: &str) -> DnsRecord {
        DnsRecord {
            name: zone.to_string(),
            record_type: RecordType::NS,
            ttl: 300,
            data: RecordData::NS {
                nameserver: host.to_string(),
            },
        }
    }

    #[test]
    fn query_verdict_names_a_referral_instead_of_claiming_nodata() {
        let mut referral = result(RecordType::A, DnsStatus::NoError, Vec::new());
        referral.flags.clear();
        referral.authority = vec![ns("child.seer.test", "ns1.child.seer.test.")];
        assert_eq!(
            query_verdict(&referral, |zone| format!("`{zone}`")).as_deref(),
            Some(
                "No answer: referral to `child.seer.test` — the server is not authoritative \
                 for the name and does not recurse"
            )
        );
        // An upward referral, to the root.
        referral.authority = vec![ns(".", "a.root-servers.net.")];
        let upward = query_verdict(&referral, str::to_string).unwrap();
        assert!(
            upward.starts_with("No answer: referral to . (root) — "),
            "{upward}"
        );

        // With the header known, the verdict cites the missing `aa` flag.
        referral.flags = vec!["qr".into(), "rd".into()];
        referral.authority = vec![ns("child.seer.test", "ns1.child.seer.test.")];
        assert_eq!(
            query_verdict(&referral, str::to_string).as_deref(),
            Some(
                "No answer: referral to child.seer.test — the server is not authoritative \
                 for the name (no aa flag) and does not recurse"
            )
        );
        // An authoritative response is no referral.
        referral.flags.push("aa".into());
        assert_eq!(
            query_verdict(&referral, str::to_string).as_deref(),
            Some("No A records (NODATA — the name exists)")
        );

        // Anything else reads as its status's verdict.
        let nodata = result(RecordType::AAAA, DnsStatus::NoError, Vec::new());
        assert_eq!(
            query_verdict(&nodata, str::to_string).as_deref(),
            Some("No AAAA records (NODATA — the name exists)")
        );
        let answered = result(
            RecordType::A,
            DnsStatus::NoError,
            vec![a("www.seer.test", "192.0.2.1")],
        );
        assert_eq!(query_verdict(&answered, str::to_string), None);
    }

    fn soa(zone: &str) -> DnsRecord {
        DnsRecord {
            name: zone.to_string(),
            record_type: RecordType::SOA,
            ttl: 900,
            data: RecordData::SOA {
                mname: format!("ns1.{zone}."),
                rname: format!("hostmaster.{zone}."),
                serial: 1,
                refresh: 7200,
                retry: 3600,
                expire: 1209600,
                minimum: 900,
            },
        }
    }

    #[test]
    fn query_verdict_names_the_chains_last_target_for_a_negative_answer() {
        // Regression: a dangling CNAME read "Name does not exist (NXDOMAIN)",
        // though the queried name exists — it owns the CNAME. The code is
        // about the chain's last target (RFC 6604 §2).
        let chain = vec![
            cname("www.seer.test", "shop.seer.test."),
            cname("shop.seer.test", "gone.cdn.test."),
        ];
        let mut dangling = result(RecordType::A, DnsStatus::NxDomain, chain.clone());
        dangling.authority = vec![soa("cdn.test")];
        assert_eq!(
            query_verdict(&dangling, |target| format!("`{target}`")).as_deref(),
            Some("The CNAME target `gone.cdn.test.` does not exist (NXDOMAIN)")
        );
        // The sentence a trace prints for the same response.
        let mut traced = trace(RecordType::A, chain.clone());
        traced.status = DnsStatus::NxDomain;
        assert_eq!(
            trace_verdict(&traced, |target| format!("`{target}`")),
            query_verdict(&dangling, |target| format!("`{target}`"))
        );

        // NODATA behind a chain: the target lacks the type.
        let mut nodata = result(RecordType::AAAA, DnsStatus::NoError, chain.clone());
        nodata.authority = vec![soa("cdn.test")];
        assert!(nodata.is_nodata());
        assert_eq!(
            query_verdict(&nodata, str::to_string).as_deref(),
            Some("The CNAME target gone.cdn.test. has no AAAA records (NODATA)")
        );
        // A recursive server followed it even when it sent no SOA.
        nodata.authority.clear();
        assert_eq!(
            query_verdict(&nodata, str::to_string).as_deref(),
            Some("The CNAME target gone.cdn.test. has no AAAA records (NODATA)")
        );

        // A server that does not recurse returns an out-of-zone CNAME as is
        // (AA set, no SOA, no `ra`): nothing is known about the target, so
        // no NODATA is claimed for it.
        let mut unfollowed = result(
            RecordType::A,
            DnsStatus::NoError,
            vec![cname("www.seer.test", "edge.cdn.test.")],
        );
        unfollowed.flags = vec!["qr".into(), "aa".into(), "rd".into()];
        unfollowed.authority = vec![ns("seer.test", "ns1.seer.test.")];
        assert_eq!(
            query_verdict(&unfollowed, |target| format!("`{target}`")).as_deref(),
            Some(
                "No A records here: the server returned the CNAME to `edge.cdn.test.` \
                 without following it (it does not recurse)"
            )
        );

        // A chain that reached records has no verdict; without a chain the
        // queried name itself is meant.
        let answered = result(
            RecordType::A,
            DnsStatus::NoError,
            vec![
                cname("www.seer.test", "edge.cdn.test."),
                a("edge.cdn.test", "192.0.2.7"),
            ],
        );
        assert_eq!(query_verdict(&answered, str::to_string), None);
        assert_eq!(
            query_verdict(
                &result(RecordType::A, DnsStatus::NxDomain, vec![]),
                str::to_string
            )
            .as_deref(),
            Some("Name does not exist (NXDOMAIN)")
        );
        // A CNAME query's CNAME is its answer, not a chain.
        let asked = result(
            RecordType::CNAME,
            DnsStatus::NoError,
            vec![cname("www.seer.test", "edge.cdn.test.")],
        );
        assert_eq!(query_verdict(&asked, str::to_string), None);
    }

    #[test]
    fn unnamed_server_is_none_for_a_local_answer() {
        let mut r = result(RecordType::A, DnsStatus::NoError, Vec::new());
        assert_eq!(unnamed_server(&r), "default");
        r.answered_locally = true;
        assert_eq!(unnamed_server(&r), "none");
    }

    #[test]
    fn tone_classes_response_codes() {
        assert_eq!(tone(DnsStatus::NoError), Tone::Answered);
        // NODATA is NOERROR: Answered, not Negative. Only is_nodata (and the
        // verdict worded from it) tells it from an answer with records.
        let nodata = result(RecordType::A, DnsStatus::NoError, Vec::new());
        assert!(nodata.is_nodata());
        assert_eq!(tone(nodata.status), Tone::Answered);
        assert_eq!(
            query_verdict(&nodata, |z: &str| z.to_string()).as_deref(),
            Some("No A records (NODATA — the name exists)")
        );
        assert_eq!(tone(DnsStatus::NxDomain), Tone::Negative);
        assert_eq!(tone(DnsStatus::ServFail), Tone::Failed);
        assert_eq!(tone(DnsStatus::Refused), Tone::Failed);
        assert_eq!(tone(DnsStatus::from_code(1)), Tone::Failed);
    }

    #[test]
    fn wildcard_note_only_when_a_wildcard_answers() {
        let mut probe = WildcardProbe {
            probe_name: "seer-probe-3f9a1c2e7b.seer.test".to_string(),
            present: false,
            matches_answer: false,
        };
        assert_eq!(wildcard_note(&probe, &probe.probe_name), None);

        probe.present = true;
        let differs = wildcard_note(&probe, &probe.probe_name).unwrap();
        assert!(
            differs.contains("(seer-probe-3f9a1c2e7b.seer.test) resolves too, but with different"),
            "{differs}"
        );

        probe.matches_answer = true;
        let matches = wildcard_note(&probe, "`escaped`").unwrap();
        assert!(matches.contains("(`escaped`) resolves"), "{matches}");
        assert!(matches.contains("likely wildcard-synthesized"), "{matches}");
    }

    #[test]
    fn unfollowed_cname_only_when_no_record_of_the_type_came_back() {
        let stopped = trace(
            RecordType::A,
            vec![
                cname("www.seer.test", "mid.seer.test."),
                cname("mid.seer.test", "edge.cdn.test."),
            ],
        );
        assert_eq!(unfollowed_cname(&stopped), Some("edge.cdn.test."));

        // An in-zone chain the server completed: there is an A record.
        let completed = trace(
            RecordType::A,
            vec![
                cname("www.seer.test", "web.seer.test."),
                a("web.seer.test", "192.0.2.1"),
            ],
        );
        assert_eq!(unfollowed_cname(&completed), None);

        // A CNAME query's CNAME is the answer itself.
        let asked = trace(
            RecordType::CNAME,
            vec![cname("www.seer.test", "edge.cdn.test.")],
        );
        assert_eq!(unfollowed_cname(&asked), None);
        assert_eq!(unfollowed_cname(&trace(RecordType::A, Vec::new())), None);
    }

    /// A dangling in-zone CNAME: the authoritative server followed the chain
    /// itself and answered NXDOMAIN beside the CNAME (RFC 6604 §2).
    fn dangling(chain: Vec<DnsRecord>) -> DnsTrace {
        let mut t = trace(RecordType::A, chain);
        t.status = DnsStatus::NxDomain;
        t.hops[0].status = DnsStatus::NxDomain;
        t
    }

    #[test]
    fn a_cname_beside_nxdomain_was_followed_by_the_server() {
        let t = dangling(vec![cname("www.seer.test", "gone.seer.test.")]);
        assert_eq!(unfollowed_cname(&t), None, "nothing is left to trace");
        for status in [DnsStatus::ServFail, DnsStatus::Refused] {
            let failed = DnsTrace {
                status,
                ..t.clone()
            };
            assert_eq!(unfollowed_cname(&failed), None, "{status}");
        }
    }

    #[test]
    fn trace_verdict_names_the_missing_cname_target_not_the_queried_name() {
        // The queried name owns the CNAME, so it exists: the NXDOMAIN is
        // about the chain's last target.
        let t = dangling(vec![
            cname("www.seer.test", "mid.seer.test."),
            cname("mid.seer.test", "gone.seer.test."),
        ]);
        assert_eq!(
            trace_verdict(&t, |target| format!("`{target}`")).as_deref(),
            Some("The CNAME target `gone.seer.test.` does not exist (NXDOMAIN)")
        );

        // Without a CNAME the queried name itself does not exist.
        assert_eq!(
            trace_verdict(&dangling(Vec::new()), str::to_string).as_deref(),
            Some("Name does not exist (NXDOMAIN)")
        );

        // Every other outcome reads as its status's verdict.
        assert_eq!(
            trace_verdict(&trace(RecordType::AAAA, Vec::new()), str::to_string).as_deref(),
            Some("No AAAA records (NODATA — the name exists)")
        );
        let stopped = trace(
            RecordType::A,
            vec![cname("www.seer.test", "edge.cdn.test.")],
        );
        assert_eq!(trace_verdict(&stopped, str::to_string), None);
        let answered = trace(RecordType::A, vec![a("www.seer.test", "192.0.2.1")]);
        assert_eq!(trace_verdict(&answered, str::to_string), None);
        let failed = DnsTrace {
            status: DnsStatus::ServFail,
            ..trace(RecordType::A, Vec::new())
        };
        assert_eq!(
            trace_verdict(&failed, str::to_string).as_deref(),
            Some("No answer: the server failed to resolve the name (SERVFAIL)")
        );
    }
}
