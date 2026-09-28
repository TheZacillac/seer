//! Markdown renderers for a dig-style query result and a `+trace` walk.
//! Summary facts are `Bullets`, records a `record_table`; every remote
//! string (names, data, server spec, failure notes) goes through `MdSafe`.

use super::{record_table, Bullets, MarkdownFormatter, MdSafe, DNSSEC_NOTE};
use crate::dns::{DnsQueryResult, DnsTrace, TraceHop};
use crate::output::dig as wording;

impl MarkdownFormatter {
    pub(super) fn format_dig(&self, result: &DnsQueryResult) -> String {
        let mut out = vec![
            format!(
                "## DNS {} Records: {}",
                result.record_type,
                MdSafe(&result.name)
            ),
            String::new(),
        ];

        let mut b = Bullets(&mut out);
        b.code("Status", &result.status.to_string());
        // Left out, not shown empty, when the response surfaced no header
        // (a negative or error answer — see `DnsQueryResult::flags`).
        if !result.flags.is_empty() {
            b.code("Flags", &result.flags.join(" "));
        }
        match &result.server {
            Some(server) => b.code("Server", server),
            None => b.raw("Server", "default"),
        }
        b.raw("Query time", format_args!("{} ms", result.query_time_ms));
        if let Some(probe) = &result.wildcard {
            let name = format!("`{}`", MdSafe(&probe.probe_name));
            if let Some(note) = wording::wildcard_note(probe, name) {
                b.raw("Wildcard", note);
            }
        }

        if let Some(verdict) =
            wording::verdict(result.status, result.record_type, result.is_nodata())
        {
            out.extend([String::new(), format!("*{verdict}*")]);
        }
        if !result.answers.is_empty() {
            out.extend([String::new(), "### Answer".to_string(), String::new()]);
            // The CNAME chain first, then the records it leads to, each
            // under its own owner name.
            record_table(&mut out, result.cname_chain().chain(result.records()));
        }
        if !result.authority.is_empty() {
            out.extend([String::new(), "### Authority".to_string(), String::new()]);
            record_table(&mut out, &result.authority);
        }

        out.push(String::new());
        out.push(format!("> {DNSSEC_NOTE}."));
        out.join("\n")
    }

    pub(super) fn format_dns_trace(&self, trace: &DnsTrace) -> String {
        let mut out = vec![format!(
            "## DNS Trace: {} {}",
            MdSafe(&trace.name),
            trace.record_type
        )];

        for (index, hop) in trace.hops.iter().enumerate() {
            trace_hop(&mut out, index + 1, hop);
        }

        out.extend([String::new(), "### Result".to_string(), String::new()]);
        let mut b = Bullets(&mut out);
        b.code("Status", &trace.status.to_string());
        if let Some(error) = &trace.error {
            b.text("Error", error);
        } else {
            let nodata = trace.answers.is_empty();
            if let Some(verdict) = wording::verdict(trace.status, trace.record_type, nodata) {
                out.extend([String::new(), format!("*{verdict}*")]);
            }
            if let Some(target) = wording::unfollowed_cname(trace) {
                let note = wording::cname_note(format!("`{}`", MdSafe(target)));
                out.extend([String::new(), format!("*{note}*")]);
            }
        }
        if !trace.answers.is_empty() {
            out.push(String::new());
            record_table(&mut out, &trace.answers);
        }

        out.push(String::new());
        out.push(format!("> {DNSSEC_NOTE}."));
        out.join("\n")
    }
}

/// One trace hop: a `### Hop N` heading naming the zone, then the server
/// asked, its response, and either the referral it gave or its answer.
fn trace_hop(out: &mut Vec<String>, number: usize, hop: &TraceHop) {
    out.extend([
        String::new(),
        format!(
            "### Hop {number}: `{}`{}",
            MdSafe(&hop.zone),
            wording::zone_suffix(&hop.zone)
        ),
        String::new(),
    ]);
    let mut b = Bullets(out);
    b.raw(
        "Server",
        format_args!("`{}` (`{}`)", MdSafe(&hop.server), MdSafe(&hop.address)),
    );
    b.code("Status", &hop.status.to_string());
    b.raw(
        "Authoritative",
        if hop.authoritative { "yes" } else { "no" },
    );
    b.raw("Query time", format_args!("{} ms", hop.query_time_ms));
    // The servers that failed before this one answered, then what it said.
    if !hop.failed_servers.is_empty() {
        b.push("- **Failed servers**:".to_string());
        for failure in &hop.failed_servers {
            b.push(format!("  - {}", MdSafe(failure)));
        }
    }
    if let Some(referral) = &hop.referral_zone {
        b.code("Referral", referral);
        b.code_list("Referral nameservers", &hop.referral);
    }
    if !hop.answers.is_empty() {
        out.push(String::new());
        record_table(out, &hop.answers);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{DnsRecord, DnsStatus, RecordData, RecordType};

    #[test]
    fn dig_escapes_remote_strings() {
        let result = DnsQueryResult {
            name: "www.seer.test".to_string(),
            record_type: RecordType::TXT,
            server: Some("[x](https://phish.example)".to_string()),
            status: DnsStatus::NoError,
            flags: vec!["qr".into()],
            answers: vec![DnsRecord {
                name: "www|seer`test".to_string(),
                record_type: RecordType::TXT,
                ttl: 60,
                data: RecordData::TXT {
                    text: "a|b`c\nd".to_string(),
                },
            }],
            authority: Vec::new(),
            wildcard: None,
            query_time_ms: 3,
        };
        let out = MarkdownFormatter::new().format_dig(&result);
        assert!(
            out.contains("- **Server**: `\\[x\\](https://phish.example)`"),
            "{out}"
        );
        assert!(
            out.contains("| `www\\|seer'test` | 60 | TXT | `\"a\\|b'c d\"` |"),
            "{out}"
        );
    }

    #[test]
    fn trace_ending_at_a_cname_says_it_was_not_followed() {
        let cname = DnsRecord {
            name: "www.seer.test".to_string(),
            record_type: RecordType::CNAME,
            ttl: 300,
            data: RecordData::CNAME {
                target: "edge`cdn.test.".to_string(),
            },
        };
        let trace = DnsTrace {
            name: "www.seer.test".to_string(),
            record_type: RecordType::A,
            hops: Vec::new(),
            status: DnsStatus::NoError,
            answers: vec![cname],
            error: None,
        };
        let out = MarkdownFormatter::new().format_dns_trace(&trace);
        assert!(
            out.contains(
                "*The answer is a CNAME to `edge'cdn.test.`, which a trace does not follow: \
                 trace that name next*"
            ),
            "{out}"
        );
    }

    #[test]
    fn trace_escapes_failures_and_error() {
        let trace = DnsTrace {
            name: "www.seer.test".to_string(),
            record_type: RecordType::A,
            hops: vec![TraceHop {
                zone: "seer.test.".to_string(),
                server: "ns1.seer.test.".to_string(),
                address: "192.0.2.53".to_string(),
                query_time_ms: 5,
                status: DnsStatus::Refused,
                authoritative: false,
                referral_zone: None,
                referral: Vec::new(),
                answers: Vec::new(),
                failed_servers: vec!["ns2.seer.test.: <img src=x>".to_string()],
            }],
            status: DnsStatus::Refused,
            answers: Vec::new(),
            error: Some("gave up | `badly`".to_string()),
        };
        let out = MarkdownFormatter::new().format_dns_trace(&trace);
        assert!(out.contains("  - ns2.seer.test.: \\<img src=x\\>"), "{out}");
        assert!(out.contains("- **Error**: gave up \\| 'badly'"), "{out}");
    }
}
