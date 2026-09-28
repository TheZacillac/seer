//! Interface-agnostic result payload: one enum over every formatter-backed
//! seer-core result type, shared by the CLI and REPL (every single-shot
//! command's result, and `copy`) and the TUI (raw view / `y` copy).
//! Serialization reuses seer-core's formatters so copied text matches
//! `seer --format …` exactly.
use seer_core::output::{get_formatter, OutputFormat, YamlFormatter};

/// Serializes as the wrapped result itself (untagged), so `--quiet` JSON is
/// exactly the core type's.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
pub enum Payload {
    Overview(Box<seer_core::LookupResult>),
    Whois(Box<seer_core::WhoisResponse>),
    Rdap(Box<seer_core::RdapResponse>),
    /// `dig` for one record type — and the TUI's DNS lens: the whole
    /// response (status, flags, CNAME chain, authority, wildcard probe).
    Dig(Box<seer_core::DnsQueryResult>),
    /// `dig` for several record types, one result per type in the order
    /// asked — a JSON array where [`Payload::Dig`] is an object.
    DigMany(Vec<seer_core::DnsQueryResult>),
    /// `dig +trace`: the delegation walk from the root servers.
    Trace(Box<seer_core::DnsTrace>),
    Ssl(Box<seer_core::SslReport>),
    Status(Box<seer_core::StatusResponse>),
    Prop(Box<seer_core::PropagationResult>),
    Reverse(Vec<seer_core::DnsRecord>),
    Avail(Box<seer_core::AvailabilityResult>),
    Tld(Box<seer_core::TldInfo>),
    Dnssec(Box<seer_core::DnssecReport>),
    Compare(Box<seer_core::DnsComparison>),
    Diff(Box<seer_core::DomainDiff>),
    Watch(Box<seer_core::WatchReport>),
    History(Vec<seer_core::HistoryEntry>),
    Subdomains(Box<seer_core::SubdomainResult>),
    /// `subdomains --diff`: the fresh enumeration against the stored baseline.
    SubdomainBaselineDiff(Box<seer_core::SubdomainBaselineDiff>),
    Info(Box<seer_core::DomainInfo>),
    Drift(Box<seer_core::DriftReport>),
    Posture(Box<seer_core::EmailPosture>),
    Headers(Box<seer_core::HeaderReport>),
    Takeover(Box<seer_core::TakeoverReport>),
    Caa(Box<seer_core::CaaPolicy>),
    Confusables(Box<seer_core::ConfusableReport>),
    Delegation(Box<seer_core::dns::DelegationReport>),
    /// `subdomains --resolve` output (live/dead + dangling-CNAME classes).
    SubdomainClassification(Box<seer_core::SubdomainClassification>),
    /// Unlike the others this has no `OutputFormatter` method — doctor reports
    /// render through `crate::render_doctor_report`, the same helper the CLI
    /// and REPL print with. Carried here anyway so `copy` after `doctor`
    /// copies the doctor report instead of silently copying whatever ran
    /// before it.
    Doctor(Box<seer_core::doctor::DoctorReport>),
}

impl Payload {
    /// Short lowercase label for user-facing messages ("copied whois …").
    pub fn kind(&self) -> &'static str {
        match self {
            Payload::Overview(_) => "lookup",
            Payload::Whois(_) => "whois",
            Payload::Rdap(_) => "rdap",
            Payload::Dig(_) | Payload::DigMany(_) => "dig",
            Payload::Trace(_) => "trace",
            Payload::Ssl(_) => "ssl",
            Payload::Status(_) => "status",
            Payload::Prop(_) => "propagation",
            Payload::Reverse(_) => "reverse",
            Payload::Avail(_) => "availability",
            Payload::Tld(_) => "tld",
            Payload::Dnssec(_) => "dnssec",
            Payload::Compare(_) => "compare",
            Payload::Diff(_) => "diff",
            Payload::Watch(_) => "watch",
            Payload::History(_) => "history",
            Payload::Subdomains(_) => "subdomains",
            Payload::SubdomainBaselineDiff(_) => "subdomain diff",
            Payload::Info(_) => "info",
            Payload::Drift(_) => "drift",
            Payload::Posture(_) => "posture",
            Payload::Headers(_) => "headers",
            Payload::Takeover(_) => "takeover",
            Payload::Caa(_) => "caa",
            Payload::Confusables(_) => "confusables",
            Payload::Delegation(_) => "delegation",
            Payload::SubdomainClassification(_) => "subdomain classification",
            Payload::Doctor(_) => "doctor",
        }
    }

    /// The `+short` form of a dig result — bare values, one per line (see
    /// [`seer_core::output::dig_short`]), empty when there are none — or
    /// `None` for a payload that has no short form. Several types print
    /// their values one after another, as dig does for several queries.
    pub fn short(&self) -> Option<String> {
        use seer_core::output::{dig_short, dig_trace_short};
        Some(match self {
            Payload::Dig(result) => dig_short(result),
            Payload::DigMany(results) => results
                .iter()
                .map(dig_short)
                .filter(|lines| !lines.is_empty())
                .collect::<Vec<_>>()
                .join("\n"),
            Payload::Trace(trace) => dig_trace_short(trace),
            _ => return None,
        })
    }
}

pub fn serialize(data: &Payload, format: OutputFormat) -> String {
    let fmt = get_formatter(format);
    match data {
        Payload::Overview(r) => fmt.format_lookup(r),
        Payload::Whois(w) => fmt.format_whois(w),
        Payload::Rdap(r) => fmt.format_rdap(r),
        Payload::Dig(result) => fmt.format_dig(result),
        Payload::DigMany(results) => match format {
            // One document: the array of results, as `-q` prints it.
            OutputFormat::Json => serde_json::to_string_pretty(results)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            OutputFormat::Yaml => YamlFormatter::new().to_yaml_value(results),
            // One block per type, each with its own header. A human block
            // opens with a blank line of its own; Markdown needs one between
            // a block's closing note and the next heading.
            OutputFormat::Human | OutputFormat::Markdown => results
                .iter()
                .map(|result| fmt.format_dig(result))
                .collect::<Vec<_>>()
                .join(if format == OutputFormat::Markdown {
                    "\n\n"
                } else {
                    "\n"
                }),
        },
        Payload::Trace(trace) => fmt.format_dns_trace(trace),
        Payload::Ssl(s) => fmt.format_ssl(s),
        Payload::Status(s) => fmt.format_status(s),
        Payload::Prop(p) => fmt.format_propagation(p),
        Payload::Reverse(records) => fmt.format_dns(records),
        Payload::Avail(a) => fmt.format_availability(a),
        Payload::Tld(t) => fmt.format_tld(t),
        Payload::Dnssec(r) => fmt.format_dnssec(r),
        Payload::Compare(c) => fmt.format_dns_comparison(c),
        Payload::Diff(d) => fmt.format_diff(d),
        Payload::Watch(w) => fmt.format_watch(w),
        Payload::History(_) => "history (raw view not applicable)".to_string(),
        Payload::Subdomains(s) => fmt.format_subdomains(s),
        Payload::SubdomainBaselineDiff(d) => fmt.format_subdomain_baseline_diff(d),
        Payload::Info(i) => fmt.format_domain_info(i),
        Payload::Drift(d) => fmt.format_drift(d),
        Payload::Posture(p) => fmt.format_posture(p),
        Payload::Headers(h) => fmt.format_headers(h),
        Payload::Takeover(t) => fmt.format_takeover(t),
        Payload::Caa(c) => fmt.format_caa(c),
        Payload::Confusables(c) => fmt.format_confusables(c),
        Payload::Delegation(d) => fmt.format_delegation(d),
        Payload::SubdomainClassification(c) => fmt.format_subdomain_classification(c),
        // No formatter method exists for doctor reports; reuse the shared
        // renderer so copied text matches what `seer doctor --format …` prints.
        Payload::Doctor(r) => crate::render_doctor_report(r, format),
    }
}

/// dig and trace results for the CLI's tests.
#[cfg(test)]
pub(crate) mod fixtures {
    use seer_core::dns::{RecordData, RecordType, TraceHop};
    use seer_core::{DnsQueryResult, DnsRecord, DnsStatus, DnsTrace};

    pub fn a(name: &str, address: &str) -> DnsRecord {
        DnsRecord {
            name: name.into(),
            record_type: RecordType::A,
            ttl: 300,
            data: RecordData::A {
                address: address.into(),
            },
        }
    }

    pub fn cname(name: &str, target: &str) -> DnsRecord {
        DnsRecord {
            name: name.into(),
            record_type: RecordType::CNAME,
            ttl: 300,
            data: RecordData::CNAME {
                target: target.into(),
            },
        }
    }

    pub fn mx(name: &str, exchange: &str) -> DnsRecord {
        DnsRecord {
            name: name.into(),
            record_type: RecordType::MX,
            ttl: 300,
            data: RecordData::MX {
                preference: 10,
                exchange: exchange.into(),
            },
        }
    }

    /// A NOERROR answer from the default upstream.
    pub fn dig(record_type: RecordType, answers: Vec<DnsRecord>) -> DnsQueryResult {
        DnsQueryResult {
            name: "www.seer.test".into(),
            record_type,
            server: None,
            answered_locally: false,
            status: DnsStatus::NoError,
            flags: vec!["qr".into(), "rd".into(), "ra".into()],
            answers,
            authority: vec![],
            wildcard: None,
            query_time_ms: 12,
        }
    }

    /// A negative or failed answer: `status` and no records.
    pub fn dig_status(record_type: RecordType, status: DnsStatus) -> DnsQueryResult {
        DnsQueryResult {
            status,
            flags: vec![],
            ..dig(record_type, vec![])
        }
    }

    /// A two-hop trace ending at the authoritative answer, or at `error`.
    pub fn trace(answers: Vec<DnsRecord>, error: Option<&str>) -> DnsTrace {
        let hop = |zone: &str, server: &str, answers: Vec<DnsRecord>| TraceHop {
            zone: zone.into(),
            server: server.into(),
            address: "192.0.2.53".into(),
            query_time_ms: 20,
            status: DnsStatus::NoError,
            authoritative: zone != ".",
            referral_zone: (zone == ".").then(|| "seer.test.".into()),
            referral: if zone == "." {
                vec!["ns1.seer.test.".into()]
            } else {
                vec![]
            },
            answers,
            failed_servers: vec![],
        };
        DnsTrace {
            name: "www.seer.test".into(),
            record_type: RecordType::A,
            hops: vec![
                hop(".", "a.root-servers.net.", vec![]),
                hop("seer.test.", "ns1.seer.test.", answers.clone()),
            ],
            status: DnsStatus::NoError,
            answers,
            error: error.map(Into::into),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures;
    use super::*;
    use seer_core::dns::{RecordData, RecordType};
    use seer_core::{DnsRecord, DnsStatus};

    fn chained() -> seer_core::DnsQueryResult {
        fixtures::dig(
            RecordType::A,
            vec![
                fixtures::cname("www.seer.test", "edge.cdn.test."),
                fixtures::a("edge.cdn.test", "192.0.2.7"),
            ],
        )
    }

    fn mx() -> seer_core::DnsQueryResult {
        fixtures::dig(
            RecordType::MX,
            vec![fixtures::mx("www.seer.test", "mail.seer.test.")],
        )
    }

    /// One type is the result object itself, several an array of them —
    /// the shape `-q` and `--format json` print.
    #[test]
    fn dig_payloads_serialize_as_an_object_or_an_array() {
        let one = Payload::Dig(Box::new(chained()));
        let value = serde_json::to_value(&one).unwrap();
        assert_eq!(value, serde_json::to_value(chained()).unwrap());
        assert_eq!(value["status"], "NOERROR");
        assert_eq!(value["answers"][1]["name"], "edge.cdn.test");

        let many = Payload::DigMany(vec![chained(), mx()]);
        let value = serde_json::to_value(&many).unwrap();
        assert_eq!(value, serde_json::to_value([chained(), mx()]).unwrap());

        let json = serialize(&many, OutputFormat::Json);
        let parsed: Vec<seer_core::DnsQueryResult> =
            serde_json::from_str(&json).expect("--format json is one array document");
        assert_eq!(parsed, vec![chained(), mx()]);
        let json = serialize(&one, OutputFormat::Json);
        let parsed: seer_core::DnsQueryResult =
            serde_json::from_str(&json).expect("one type is one object");
        assert_eq!(parsed, chained());

        let yaml = serialize(&many, OutputFormat::Yaml);
        assert!(
            yaml.trim_start().starts_with("- "),
            "a YAML sequence: {yaml}"
        );
        assert!(yaml.contains("mail.seer.test."), "{yaml}");

        let trace = fixtures::trace(vec![fixtures::a("www.seer.test", "192.0.2.7")], None);
        let value = serde_json::to_value(Payload::Trace(Box::new(trace.clone()))).unwrap();
        assert_eq!(value, serde_json::to_value(&trace).unwrap());
    }

    /// Human and Markdown render one block per type, in the order asked.
    #[test]
    fn dig_many_renders_a_block_per_type() {
        let many = Payload::DigMany(vec![chained(), mx()]);
        let human = serialize(&many, OutputFormat::Human);
        let (a, mx_block) = (
            human.find("DNS A Records: www.seer.test").expect("A block"),
            human
                .find("DNS MX Records: www.seer.test")
                .expect("MX block"),
        );
        assert!(a < mx_block, "{human}");
        assert!(human.contains("edge.cdn.test") && human.contains("mail.seer.test."));

        let markdown = serialize(&many, OutputFormat::Markdown);
        assert_eq!(markdown.matches("## DNS ").count(), 2, "{markdown}");
        assert!(
            markdown.starts_with("## DNS A Records: www.seer.test"),
            "{markdown}"
        );
        assert!(
            markdown.contains(".\n\n## DNS MX Records: www.seer.test"),
            "a blank line before each later block's heading: {markdown}"
        );

        let trace = fixtures::trace(vec![fixtures::a("www.seer.test", "192.0.2.7")], None);
        let human = serialize(&Payload::Trace(Box::new(trace)), OutputFormat::Human);
        assert!(human.contains("DNS Trace: www.seer.test A"), "{human}");
        assert!(human.contains("a.root-servers.net."), "{human}");
    }

    /// `+short`: CNAME targets then values, per type in order; types
    /// without answers add nothing; non-dig payloads have no short form.
    #[test]
    fn short_form_covers_the_dig_payloads_only() {
        assert_eq!(
            Payload::Dig(Box::new(chained())).short().as_deref(),
            Some("edge.cdn.test.\n192.0.2.7")
        );
        let nxdomain = fixtures::dig_status(RecordType::AAAA, DnsStatus::NxDomain);
        assert_eq!(
            Payload::Dig(Box::new(nxdomain.clone())).short().as_deref(),
            Some("")
        );
        assert_eq!(
            Payload::DigMany(vec![chained(), nxdomain, mx()])
                .short()
                .as_deref(),
            Some("edge.cdn.test.\n192.0.2.7\n10 mail.seer.test.")
        );
        let trace = fixtures::trace(vec![fixtures::a("www.seer.test", "192.0.2.7")], None);
        assert_eq!(
            Payload::Trace(Box::new(trace)).short().as_deref(),
            Some("192.0.2.7")
        );
        let stopped = fixtures::trace(vec![], Some("every server failed"));
        assert_eq!(
            Payload::Trace(Box::new(stopped)).short().as_deref(),
            Some("")
        );
        assert_eq!(Payload::Reverse(vec![]).short(), None);
    }

    fn ptr_records() -> Vec<DnsRecord> {
        vec![DnsRecord {
            name: "7.2.0.192.in-addr.arpa".into(),
            record_type: RecordType::PTR,
            ttl: 300,
            data: RecordData::PTR {
                target: "host.seer.test.".into(),
            },
        }]
    }

    /// `reverse` stays a record list: `resolve` output through `format_dns`.
    #[test]
    fn serializes_reverse_as_a_json_list() {
        let out = serialize(&Payload::Reverse(ptr_records()), OutputFormat::Json);
        assert!(out.contains("host.seer.test."));
        assert!(out.trim_start().starts_with('['));
    }

    #[test]
    fn serializes_reverse_as_markdown() {
        let out = serialize(&Payload::Reverse(ptr_records()), OutputFormat::Markdown);
        assert!(out.contains("host.seer.test."));
        assert!(
            out.contains('#') || out.contains('|'),
            "expected markdown structure"
        );
    }

    #[test]
    fn serializes_new_caa_variant() {
        let policy = seer_core::CaaPolicy {
            records: vec![],
            effective_domain: None,
            has_policy: false,
            issuer_match: None,
            iodef: vec![],
            wildcard_note: None,
            note: "no CAA policy found".into(),
        };
        let data = Payload::Caa(Box::new(policy));
        let out = serialize(&data, OutputFormat::Markdown);
        assert!(!out.is_empty());
    }

    /// `-q` prints the payload's JSON, which must be exactly the wrapped
    /// result's — no enum tag, no Box wrapper.
    #[test]
    fn serde_form_is_the_wrapped_result() {
        let records = ptr_records();
        let drift = seer_core::DriftReport::empty("example.com");
        assert_eq!(
            serde_json::to_string(&Payload::Reverse(records.clone())).unwrap(),
            serde_json::to_string(&records).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&Payload::Drift(Box::new(drift.clone()))).unwrap(),
            serde_json::to_string(&drift).unwrap()
        );
    }

    #[test]
    fn kind_labels_are_lowercase() {
        assert_eq!(Payload::Reverse(vec![]).kind(), "reverse");
        assert_eq!(Payload::Dig(Box::new(chained())).kind(), "dig");
        assert_eq!(Payload::DigMany(vec![]).kind(), "dig");
        let trace = fixtures::trace(vec![], None);
        assert_eq!(Payload::Trace(Box::new(trace)).kind(), "trace");
    }
}
