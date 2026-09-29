//! Human (colored) renderers for a dig-style query result and a `+trace`
//! walk. Label/value rows go through the `Rows` writer; the aligned record
//! rows and the one-line status header are bespoke, so every remote string
//! in them is passed through `sanitize_line` by hand.

use super::{sanitize_line, HumanFormatter, DNSSEC_NOTE};
use crate::dns::{DnsQueryResult, DnsRecord, DnsStatus, DnsTrace, TraceHop};
use crate::output::dig::{self as wording, Tone};

/// One aligned record row before styling: the cells as they will print.
struct RecordRow {
    owner: String,
    ttl: String,
    record_type: &'static str,
    data: String,
    /// Answer data proper (green), as opposed to a CNAME hop or an
    /// AUTHORITY record (plain).
    highlight: bool,
}

/// Spaces that pad `text` out to `width` characters.
fn pad(text: &str, width: usize) -> String {
    " ".repeat(width.saturating_sub(text.chars().count()))
}

impl HumanFormatter {
    pub(super) fn format_dig(&self, result: &DnsQueryResult) -> String {
        let mut out = vec![self.header(&format!(
            "DNS {} Records: {}",
            result.record_type,
            sanitize_line(&result.name)
        ))];

        // dig's header line. An answer no server gave has no header (see
        // `DnsQueryResult::flags`), so the flags field is left out rather
        // than shown empty.
        let mut fields = vec![self.field("status", self.dns_status(result.status))];
        if !result.flags.is_empty() {
            let flags = sanitize_line(&result.flags.join(" "));
            fields.push(self.field("flags", self.value(&flags)));
        }
        let server = result.server.as_deref().map_or_else(
            || wording::unnamed_server(result).to_string(),
            sanitize_line,
        );
        fields.push(self.field("server", self.value(&server)));
        let time = format!("{} ms", result.query_time_ms);
        fields.push(self.field("time", self.value(&time)));
        out.push(format!("  {}", fields.join("  ")));

        let mut rows = self.rows(&mut out, "  ");
        // The CNAME chain first, each hop under its own owner, then the
        // records it leads to — dig's ANSWER section.
        let chain = result.cname_chain().map(|r| (r, false));
        let answers = self.record_rows("    ", chain.chain(result.records().map(|r| (r, true))));
        if !answers.is_empty() {
            rows.section("Answer").extend(answers);
        }
        if let Some(verdict) = wording::query_verdict(result, sanitize_line) {
            rows.blank();
            let verdict = self.outcome(result.status, &verdict);
            rows.push(format!("  {verdict}"));
        }
        // AUTHORITY: the SOA of a negative answer, when the server sent one,
        // or the NS records of a referral.
        let authority = self.record_rows("    ", result.authority.iter().map(|r| (r, false)));
        if !authority.is_empty() {
            rows.section("Authority").extend(authority);
        }
        if result.answered_locally {
            rows.blank();
            rows.push(format!("  {}", self.warning(wording::LOCAL_NOTE)));
        }
        if let Some(probe) = &result.wildcard {
            if let Some(note) = wording::wildcard_note(probe, sanitize_line(&probe.probe_name)) {
                // A likely-synthesized answer is the one worth a warning.
                let note = if probe.matches_answer {
                    self.warning(&note)
                } else {
                    self.value(&note)
                };
                rows.blank();
                rows.kv("Wildcard", note);
            }
        }

        out.push(String::new());
        out.push(self.warning(DNSSEC_NOTE));
        out.join("\n")
    }

    pub(super) fn format_dns_trace(&self, trace: &DnsTrace) -> String {
        let mut out = vec![self.header(&format!(
            "DNS Trace: {} {}",
            sanitize_line(&trace.name),
            trace.record_type
        ))];

        for (index, hop) in trace.hops.iter().enumerate() {
            self.trace_hop(&mut out, index + 1, hop);
        }

        // The final result: the last hop's status and answer, or why the
        // walk stopped short of one.
        out.push(String::new());
        let mut rows = self.rows(&mut out, "  ");
        rows.kv("Result", self.dns_status(trace.status));
        rows.extend(self.record_rows("    ", trace.answers.iter().map(|r| (r, true))));
        if trace.error.is_none() {
            if let Some(verdict) = wording::trace_verdict(trace, sanitize_line) {
                let verdict = self.outcome(trace.status, &verdict);
                rows.push(format!("    {verdict}"));
            }
            if let Some(target) = wording::unfollowed_cname(trace) {
                let note = wording::cname_note(sanitize_line(target));
                rows.push(format!("    {}", self.dim(&note)));
            }
        }
        if let Some(error) = &trace.error {
            rows.kv("Error", self.error(&sanitize_line(error)));
        }

        out.push(String::new());
        out.push(self.warning(DNSSEC_NOTE));
        out.join("\n")
    }

    /// One trace hop: a `Hop N: <zone>` heading, then the server asked, its
    /// response, and either the referral it gave or its answer.
    fn trace_hop(&self, out: &mut Vec<String>, number: usize, hop: &TraceHop) {
        out.push(format!(
            "\n  {}: {}{}",
            self.label(&format!("Hop {number}")),
            self.value(&sanitize_line(&hop.zone)),
            wording::zone_suffix(&hop.zone)
        ));

        let mut rows = self.rows(out, "    ");
        let server = format!(
            "{} ({}) in {} ms",
            sanitize_line(&hop.server),
            sanitize_line(&hop.address),
            hop.query_time_ms
        );
        rows.kv("Server", self.value(&server));
        let mut status = self.dns_status(hop.status);
        if hop.authoritative {
            status.push_str(&self.value(" (authoritative)"));
        }
        rows.kv("Status", status);
        if !hop.failed_servers.is_empty() {
            rows.push(format!("    {}:", self.label("Failed servers")));
            for failure in &hop.failed_servers {
                rows.push(format!(
                    "      {} {}",
                    self.error("\u{2717}"),
                    self.value(&sanitize_line(failure))
                ));
            }
        }
        if let Some(referral) = &hop.referral_zone {
            rows.kv("Referral", self.value(&sanitize_line(referral)));
            for ns in &hop.referral {
                rows.push(format!("      - {}", self.value(&sanitize_line(ns))));
            }
        }
        let answers = self.record_rows("      ", hop.answers.iter().map(|r| (r, true)));
        if !answers.is_empty() {
            rows.push(format!("    {}:", self.label("Answer")));
            rows.extend(answers);
        }
    }

    /// `label: <styled>` — one field of a single-line header.
    fn field(&self, label: &str, styled: String) -> String {
        format!("{}: {styled}", self.label(label))
    }

    /// A response code, colored by what it means: green for NOERROR,
    /// yellow for NXDOMAIN, red for a server failure (SERVFAIL, REFUSED, …).
    fn dns_status(&self, status: DnsStatus) -> String {
        let text = status.to_string();
        match wording::tone(status) {
            Tone::Answered => self.success(&text),
            Tone::Negative => self.warning(&text),
            Tone::Failed => self.error(&text),
        }
    }

    /// A verdict line (see `wording::verdict`): yellow for a negative
    /// answer, red when the server failed to answer at all.
    fn outcome(&self, status: DnsStatus, verdict: &str) -> String {
        match wording::tone(status) {
            Tone::Failed => self.error(verdict),
            Tone::Answered | Tone::Negative => self.warning(verdict),
        }
    }

    /// Record rows `owner  TTL  TYPE  data` at `indent`, the first three
    /// columns padded to a common width so a CNAME chain and the records it
    /// leads to line up as in dig's sections. Each record comes with whether
    /// its data is highlighted (see [`RecordRow::highlight`]).
    fn record_rows<'r>(
        &self,
        indent: &str,
        records: impl IntoIterator<Item = (&'r DnsRecord, bool)>,
    ) -> Vec<String> {
        let rows: Vec<RecordRow> = records
            .into_iter()
            .map(|(record, highlight)| RecordRow {
                owner: sanitize_line(&record.name),
                ttl: record.ttl.to_string(),
                record_type: record.record_type.as_str(),
                data: sanitize_line(&record.data.to_string()),
                highlight,
            })
            .collect();
        let width = |cell: fn(&RecordRow) -> &str| {
            rows.iter()
                .map(|row| cell(row).chars().count())
                .max()
                .unwrap_or(0)
        };
        let (owner_w, ttl_w, type_w) = (
            width(|r| &r.owner),
            width(|r| &r.ttl),
            width(|r| r.record_type),
        );
        rows.iter()
            .map(|row| {
                let data = if row.highlight {
                    self.success(&row.data)
                } else {
                    self.value(&row.data)
                };
                format!(
                    "{indent}{}{}  {}{}  {}{}  {data}",
                    self.value(&row.owner),
                    pad(&row.owner, owner_w),
                    pad(&row.ttl, ttl_w),
                    self.label(&row.ttl),
                    self.label(row.record_type),
                    pad(row.record_type, type_w),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{RecordData, RecordType, WildcardProbe};

    fn formatter() -> HumanFormatter {
        HumanFormatter::new().without_colors()
    }

    fn record(name: &str, ttl: u32, data: RecordData) -> DnsRecord {
        let record_type = match &data {
            RecordData::A { .. } => RecordType::A,
            RecordData::CNAME { .. } => RecordType::CNAME,
            RecordData::TXT { .. } => RecordType::TXT,
            other => panic!("fixture does not model {other:?}"),
        };
        DnsRecord {
            name: name.to_string(),
            record_type,
            ttl,
            data,
        }
    }

    fn chained() -> DnsQueryResult {
        DnsQueryResult {
            name: "www.seer.test".to_string(),
            record_type: RecordType::A,
            server: Some("1.1.1.1".to_string()),
            answered_locally: false,
            status: DnsStatus::NoError,
            flags: vec!["qr".into(), "rd".into(), "ra".into()],
            answers: vec![
                record(
                    "www.seer.test",
                    3600,
                    RecordData::CNAME {
                        target: "edge.cdn.test.".to_string(),
                    },
                ),
                record(
                    "edge.cdn.test",
                    60,
                    RecordData::A {
                        address: "192.0.2.7".to_string(),
                    },
                ),
            ],
            authority: Vec::new(),
            wildcard: None,
            query_time_ms: 12,
        }
    }

    #[test]
    fn dig_rows_align_owner_ttl_and_type_columns() {
        let out = formatter().format_dig(&chained());
        assert!(
            out.contains("\n    www.seer.test  3600  CNAME  edge.cdn.test.\n"),
            "{out}"
        );
        assert!(
            out.contains("\n    edge.cdn.test    60  A      192.0.2.7\n"),
            "{out}"
        );
        assert!(
            out.contains("status: NOERROR  flags: qr rd ra  server: 1.1.1.1  time: 12 ms"),
            "{out}"
        );
    }

    #[test]
    fn dig_leaves_out_flags_of_an_answer_no_server_gave() {
        // Only the resolver's own answer for a special-use name has no
        // header to show; the field is left out rather than shown empty.
        let mut result = chained();
        result.name = "x.onion".to_string();
        result.status = DnsStatus::NxDomain;
        result.answered_locally = true;
        result.flags.clear();
        result.answers.clear();
        result.server = None;
        let out = formatter().format_dig(&result);
        assert!(
            out.contains("  status: NXDOMAIN  server: none  time: 12 ms\n"),
            "{out}"
        );
        assert!(!out.contains("flags"), "{out}");
        assert!(out.contains("Name does not exist (NXDOMAIN)"), "{out}");
        assert!(!out.contains("Answer:"), "{out}");
    }

    #[test]
    fn dig_sanitizes_every_remote_string() {
        // Owner, data, server spec, flags and probe name all reach the
        // terminal; none may carry an escape sequence or break a row.
        const EVIL: &str = "\x1b]52;c;AAAA\x07\x1b[2J\nforged  300  A  203.0.113.66";
        let mut result = chained();
        result.name = format!("www{EVIL}");
        result.server = Some(format!("1.1.1.1{EVIL}"));
        result.flags.push(format!("ad{EVIL}"));
        result.answers[1].name = format!("edge{EVIL}");
        result.answers.push(record(
            "edge.cdn.test",
            60,
            RecordData::TXT {
                text: format!("v=spf1{EVIL}"),
            },
        ));
        result.wildcard = Some(WildcardProbe {
            probe_name: format!("seer-probe-0000000000.seer.test{EVIL}"),
            present: true,
            matches_answer: true,
        });
        let out = formatter().format_dig(&result);
        assert!(
            !out.contains('\x1b'),
            "ESC must not reach terminal: {out:?}"
        );
        assert!(
            !out.contains('\x07'),
            "BEL must not reach terminal: {out:?}"
        );
        assert!(
            !out.lines().any(|l| l.starts_with("forged")),
            "a newline in remote data must not forge a row: {out}"
        );
    }

    fn answered_trace(answers: Vec<DnsRecord>) -> DnsTrace {
        DnsTrace {
            name: "www.seer.test".to_string(),
            record_type: RecordType::A,
            hops: vec![TraceHop {
                zone: "seer.test.".to_string(),
                server: "ns1.seer.test.".to_string(),
                address: "192.0.2.53".to_string(),
                query_time_ms: 5,
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
    fn trace_ending_at_a_cname_says_it_was_not_followed() {
        let cname = record(
            "www.seer.test",
            300,
            RecordData::CNAME {
                target: "edge.cdn.test.".to_string(),
            },
        );
        let out = formatter().format_dns_trace(&answered_trace(vec![cname]));
        assert!(
            out.contains(
                "The answer is a CNAME to edge.cdn.test., which a trace does not follow: \
                 trace that name next"
            ),
            "{out}"
        );
        assert!(
            !out.contains("NODATA"),
            "a CNAME answer is not NODATA: {out}"
        );
    }

    #[test]
    fn trace_nxdomain_beside_a_cname_names_the_missing_target() {
        // A dangling in-zone CNAME: the authoritative server followed it
        // and answered NXDOMAIN beside it (RFC 6604 §2). The queried name
        // owns the CNAME, so it exists; the target does not, and the server
        // has already looked it up.
        let cname = record(
            "www.seer.test",
            300,
            RecordData::CNAME {
                target: "gone.seer.test.".to_string(),
            },
        );
        let mut trace = answered_trace(vec![cname]);
        trace.status = DnsStatus::NxDomain;
        trace.hops[0].status = DnsStatus::NxDomain;
        let out = formatter().format_dns_trace(&trace);
        assert!(
            out.contains(
                "\n    www.seer.test  300  CNAME  gone.seer.test.\n    \
                 The CNAME target gone.seer.test. does not exist (NXDOMAIN)\n"
            ),
            "{out}"
        );
        assert!(!out.contains("Name does not exist"), "{out}");
        assert!(!out.contains("trace does not follow"), "{out}");
    }

    #[test]
    fn trace_result_tells_nodata_and_nxdomain_apart() {
        let nodata = formatter().format_dns_trace(&answered_trace(Vec::new()));
        assert!(
            nodata.contains("No A records (NODATA — the name exists)"),
            "{nodata}"
        );

        let mut gone = answered_trace(Vec::new());
        gone.status = DnsStatus::NxDomain;
        let gone = formatter().format_dns_trace(&gone);
        assert!(gone.contains("Name does not exist (NXDOMAIN)"), "{gone}");

        // A walk that stopped short proves neither: only the error shows.
        let mut stopped = answered_trace(Vec::new());
        stopped.error = Some("ns1.seer.test. (192.0.2.53) referred upward".to_string());
        let stopped = formatter().format_dns_trace(&stopped);
        assert!(!stopped.contains("NODATA"), "{stopped}");
        assert!(
            stopped.contains("Error: ns1.seer.test. (192.0.2.53) referred upward"),
            "{stopped}"
        );
    }

    #[test]
    fn trace_sanitizes_hop_fields_and_error() {
        const EVIL: &str = "\x1b[31m\nforged";
        let trace = DnsTrace {
            name: format!("www.seer.test{EVIL}"),
            record_type: RecordType::A,
            hops: vec![TraceHop {
                zone: format!("seer.test.{EVIL}"),
                server: format!("ns1.seer.test.{EVIL}"),
                address: "192.0.2.53".to_string(),
                query_time_ms: 5,
                status: DnsStatus::ServFail,
                authoritative: false,
                referral_zone: Some(format!("www.seer.test.{EVIL}")),
                referral: vec![format!("ns.www.seer.test.{EVIL}")],
                answers: Vec::new(),
                failed_servers: vec![format!("ns2.seer.test. (192.0.2.54): timed out{EVIL}")],
            }],
            status: DnsStatus::ServFail,
            answers: Vec::new(),
            error: Some(format!("no nameserver gave a usable response{EVIL}")),
        };
        let out = formatter().format_dns_trace(&trace);
        assert!(
            !out.contains('\x1b'),
            "ESC must not reach terminal: {out:?}"
        );
        assert!(
            !out.lines().any(|l| l.starts_with("forged")),
            "a newline in remote data must not forge a line: {out}"
        );
    }
}
