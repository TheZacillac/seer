//! dig-style rendering shared across formats: the `+short` lines
//! ([`dig_short`], [`dig_trace_short`]) and the wording of a query's
//! outcome — the negative-answer verdict, the wildcard note, the unfollowed
//! CNAME of a trace — so the human and Markdown formatters say the same
//! thing and differ only in styling and escaping.

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

/// How a response code reads, for styling: an answer, a negative answer
/// (the name or the type does not exist), or no answer at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Tone {
    /// NOERROR, with or without records.
    Answered,
    /// NXDOMAIN.
    Negative,
    /// SERVFAIL, REFUSED and every other error code.
    Failed,
}

/// The [`Tone`] of a response code.
pub(super) fn tone(status: DnsStatus) -> Tone {
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
pub(super) fn verdict(status: DnsStatus, record_type: RecordType, nodata: bool) -> Option<String> {
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

/// The wildcard note for a probe that found a wildcard, `None` when the
/// probe name got no answer. `probe_name` is the probe's name as the caller
/// escaped it for its format.
pub(super) fn wildcard_note(
    probe: &WildcardProbe,
    probe_name: impl fmt::Display,
) -> Option<String> {
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
pub(super) fn zone_suffix(zone: &str) -> &'static str {
    if zone == "." {
        " (root)"
    } else {
        ""
    }
}

/// The CNAME a trace ended at without following it: the final answer holds
/// a CNAME but no record of the queried type (`dig +trace` stops there
/// too). Returns the CNAME's target — the last one, for a partial chain.
pub(super) fn unfollowed_cname(trace: &DnsTrace) -> Option<&str> {
    let wanted = trace.record_type;
    if wanted == RecordType::CNAME || trace.answers.iter().any(|r| r.record_type == wanted) {
        return None;
    }
    trace.answers.iter().rev().find_map(|r| match &r.data {
        RecordData::CNAME { target } => Some(target.as_str()),
        _ => None,
    })
}

/// The note under a trace that stopped at a CNAME (see
/// [`unfollowed_cname`]); `target` is escaped by the caller.
pub(super) fn cname_note(target: impl fmt::Display) -> String {
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
        record(
            name,
            RecordData::TXT {
                text: text.to_string(),
            },
        )
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
            status,
            flags: vec!["qr".into(), "rd".into(), "ra".into()],
            answers,
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

    #[test]
    fn tone_classes_response_codes() {
        assert_eq!(tone(DnsStatus::NoError), Tone::Answered);
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
}
