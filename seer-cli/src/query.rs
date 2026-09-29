//! Single-shot commands shared by the CLI subcommands and the REPL.
//!
//! Each surface parses its own syntax into a [`Query`]; [`run`] performs it
//! and hands back a [`Payload`] plus any advisory notes (and, for a `dig`
//! over several record types, the types that failed; for a `+short` trace,
//! why the walk stopped). Each surface then renders every command the same
//! way — the CLI through `--quiet`/`--format` and its check-style exit
//! codes, the REPL by printing and keeping the result for `copy`; a
//! `+short` dig prints its bare values in both — so the two cannot drift
//! apart command by command.

use std::sync::Arc;

use seer_core::colors::CatppuccinExt;
use seer_core::output::OutputFormat;
use seer_core::{DnsQueryResult, RecordType, SeerConfig};

use crate::display::Spinner;
use crate::payload::Payload;

/// A parsed single-shot command.
pub enum Query {
    Lookup(String),
    Info(String),
    Whois(String),
    /// A domain, IP address, or ASN.
    Rdap(String),
    /// One query per record type, run concurrently (see
    /// [`crate::dig_args`] for the syntax both surfaces parse into this).
    Dig {
        name: String,
        /// Never empty; one type yields [`Payload::Dig`], several
        /// [`Payload::DigMany`].
        types: Vec<RecordType>,
        /// Falls back to the config file's nameserver.
        server: Option<String>,
        /// Present the result as its `+short` lines.
        short: bool,
    },
    /// `dig +trace`: the delegation walk from the root servers. It asks
    /// each zone's servers directly, so no nameserver (not even the config
    /// file's) applies.
    Trace {
        name: String,
        record_type: RecordType,
        /// Present the result as its `+short` lines.
        short: bool,
    },
    Prop {
        domain: String,
        record_type: RecordType,
    },
    Status(String),
    Reverse(String),
    Avail(String),
    Dnssec(String),
    Ssl(String),
    Tld(String),
    Compare {
        domain: String,
        record_type: RecordType,
        server_a: String,
        server_b: String,
    },
    /// `resolve` classifies the names; `diff`/`record` compare against or
    /// store the baseline (the parsers reject `resolve` with either).
    Subdomains {
        domain: String,
        resolve: bool,
        diff: bool,
        record: bool,
    },
    Diff(String, String),
    Drift {
        domain: String,
        record: bool,
    },
    Caa(String),
    Posture(String),
    Headers(String),
    /// Non-empty `hosts` skips CT enumeration.
    Takeover {
        domain: String,
        hosts: Vec<String>,
    },
    Confusables(String),
    Doctor,
    Delegation(String),
}

/// What a [`Query`] produced: its result plus advisory notes for stderr.
pub struct Outcome {
    pub payload: Payload,
    /// Shown before the result (e.g. drift's "no previous snapshot").
    note: Option<String>,
    /// Shown after the result (`subdomains --record`'s confirmation).
    footnote: Option<String>,
    /// The parts of a partial result that failed (one record type of a
    /// multi-type `dig`, or a `+short` trace's stopped walk: see
    /// [`trace_outcome`]), shown on stderr after it. Any failure fails the
    /// command: see [`Outcome::failed`].
    errors: Vec<String>,
    /// `+short`: print the payload's bare values ([`Payload::short`])
    /// instead of formatting it.
    short: bool,
}

impl Outcome {
    fn new(payload: Payload) -> Self {
        Self {
            payload,
            note: None,
            footnote: None,
            errors: Vec::new(),
            short: false,
        }
    }

    /// Whether part of the query failed, although the rest produced a
    /// result. The CLI exits 1 for it.
    pub fn failed(&self) -> bool {
        !self.errors.is_empty()
    }

    /// The `+short` lines printed in place of the formatted result, when
    /// the query asked for them.
    fn short_text(&self) -> Option<String> {
        self.payload.short().filter(|_| self.short)
    }

    /// Prints the notes to stderr around `show`, which prints the result,
    /// then the failed parts to stderr in `format`'s error form (as a failed
    /// command's error). A `+short` result prints its bare values instead,
    /// whatever the format — and nothing at all when it has none, like dig.
    pub fn present(&self, format: OutputFormat, show: impl FnOnce(&Payload)) {
        let print = |note: &Option<String>| {
            if let Some(note) = note {
                eprintln!("{} {}", "note:".ctp_yellow(), note);
            }
        };
        print(&self.note);
        match self.short_text() {
            Some(lines) if lines.is_empty() => {}
            Some(lines) => println!("{lines}"),
            None => show(&self.payload),
        }
        print(&self.footnote);
        for error in &self.errors {
            match crate::utils::machine_error(format, error) {
                Some(structured) => eprintln!("{structured}"),
                None => eprintln!("{} {}", "Error:".ctp_red(), error),
            }
        }
    }
}

/// Clients built from the user config. The REPL keeps one set for the whole
/// session, so resolver caches stay warm between commands; the CLI builds
/// one per invocation. Cheap to build: no I/O happens until a query runs.
pub struct Clients {
    whois: seer_core::WhoisClient,
    rdap: seer_core::RdapClient,
    dns: seer_core::DnsResolver,
    // Propagation and DNSSEC keep their own tuned timeouts by design.
    propagation: seer_core::dns::PropagationChecker,
    dnssec: seer_core::DnssecChecker,
    status: seer_core::StatusClient,
    avail: seer_core::AvailabilityChecker,
    ssl: seer_core::SslChecker,
}

impl Clients {
    pub fn from_config(config: &SeerConfig) -> Self {
        Self {
            whois: seer_core::WhoisClient::from_config(config),
            rdap: seer_core::RdapClient::from_config(config),
            dns: seer_core::DnsResolver::from_config(config),
            propagation: seer_core::dns::PropagationChecker::from_config(config),
            dnssec: seer_core::DnssecChecker::from_config(config),
            status: seer_core::StatusClient::from_config(config),
            avail: seer_core::AvailabilityChecker::from_config(config),
            ssl: seer_core::SslChecker::from_config(config),
        }
    }
}

/// Runs `query`, showing a stderr progress spinner when `spin` is set. The
/// spinner is always cleared before this returns, so callers can print the
/// outcome straight away.
pub async fn run(
    query: Query,
    clients: &Clients,
    config: &SeerConfig,
    spin: bool,
) -> seer_core::Result<Outcome> {
    // One arm per command makes the pipeline's state machine tens of KB;
    // boxing it keeps every caller's future (REPL dispatch, TUI fetch task)
    // pointer-sized instead of nesting that inline on the stack.
    Box::pin(run_query(query, clients, config, spin)).await
}

async fn run_query(
    query: Query,
    clients: &Clients,
    config: &SeerConfig,
    spin: bool,
) -> seer_core::Result<Outcome> {
    let spinner = |message: String| Spinner::maybe(spin, &message);
    let payload = match query {
        Query::Lookup(domain) => {
            let spinner = Arc::new(spinner(format!(
                "Smart lookup for {} (trying RDAP first)",
                domain
            )));
            let progress_spinner = spinner.clone();
            let progress: seer_core::LookupProgressCallback =
                Arc::new(move |message| progress_spinner.set_message(message));
            let result = seer_core::SmartLookup::from_config(config)
                .lookup_with_progress(&domain, Some(progress))
                .await;
            // The progress callback holds a clone, so clear it explicitly.
            spinner.finish();
            let result = result?;
            let saved = crate::ops::record_lookup_history(&domain, result.clone()).await;
            return Ok(Outcome {
                footnote: history_warning(saved),
                ..Outcome::new(Payload::Overview(Box::new(result)))
            });
        }
        Query::Info(domain) => {
            let _spinner = spinner(format!("Getting comprehensive info for {}", domain));
            let result = seer_core::SmartLookup::from_config(config)
                .lookup(&domain)
                .await?;
            Payload::Info(Box::new(seer_core::DomainInfo::from_lookup_result(&result)))
        }
        Query::Whois(domain) => {
            let _spinner = spinner(format!("Looking up WHOIS for {}", domain));
            Payload::Whois(Box::new(clients.whois.lookup(&domain).await?))
        }
        Query::Rdap(query) => {
            let _spinner = spinner(format!("Looking up RDAP for {}", query));
            // auto_lookup only routes `AS<digits>` to ASN when the query has
            // no `.`, so `as1234.io` / `asana.com` stay domain lookups.
            let response = seer_core::rdap::auto_lookup(&clients.rdap, &query).await?;
            Payload::Rdap(Box::new(response))
        }
        Query::Dig {
            name,
            types,
            server,
            short,
        } => {
            let type_names: Vec<String> = types.iter().map(ToString::to_string).collect();
            let _spinner = spinner(format!(
                "Querying {} {} records",
                name,
                type_names.join(" ")
            ));
            let nameserver = server.as_deref().or(config.nameserver.as_deref());
            let results = futures::future::join_all(
                types
                    .iter()
                    .map(|&record_type| clients.dns.query(&name, record_type, nameserver)),
            )
            .await;
            let mut outcome = dig_outcome(types.into_iter().zip(results).collect())?;
            outcome.short = short;
            return Ok(outcome);
        }
        Query::Trace {
            name,
            record_type,
            short,
        } => {
            let _spinner = spinner(format!(
                "Tracing {} {} from the root servers",
                name, record_type
            ));
            let trace = seer_core::DnsTracer::from_config(config)
                .trace(&name, record_type)
                .await?;
            return Ok(trace_outcome(trace, short));
        }
        Query::Prop {
            domain,
            record_type,
        } => {
            let _spinner = spinner(format!(
                "Checking {} {} propagation across DNS servers",
                domain, record_type
            ));
            let result = clients.propagation.check(&domain, record_type).await?;
            Payload::Prop(Box::new(result))
        }
        Query::Status(domain) => {
            let _spinner = spinner(format!("Checking status for {}", domain));
            Payload::Status(Box::new(clients.status.check(&domain).await?))
        }
        Query::Reverse(ip) => {
            let _spinner = spinner(format!("Looking up PTR for {}", ip));
            // Honor the configured nameserver, like `dig`.
            let nameserver = config.nameserver.as_deref();
            Payload::Reverse(
                clients
                    .dns
                    .resolve(&ip, RecordType::PTR, nameserver)
                    .await?,
            )
        }
        Query::Avail(domain) => {
            let _spinner = spinner(format!("Checking availability of {}", domain));
            Payload::Avail(Box::new(clients.avail.check(&domain).await?))
        }
        Query::Dnssec(domain) => {
            let _spinner = spinner(format!("Checking DNSSEC for {}", domain));
            Payload::Dnssec(Box::new(clients.dnssec.check(&domain).await?))
        }
        Query::Ssl(domain) => {
            let _spinner = spinner(format!("Checking SSL for {}", domain));
            Payload::Ssl(Box::new(clients.ssl.check(&domain).await?))
        }
        Query::Tld(tld) => Payload::Tld(Box::new(
            seer_core::lookup_tld_with(&tld, &clients.rdap).await,
        )),
        Query::Compare {
            domain,
            record_type,
            server_a,
            server_b,
        } => {
            let _spinner = spinner(format!(
                "Comparing {} records from {} and {}",
                domain, server_a, server_b
            ));
            let comparison = seer_core::dns::DnsComparator::from_config(config)
                .compare(&domain, record_type, &server_a, &server_b)
                .await?;
            Payload::Compare(Box::new(comparison))
        }
        Query::Subdomains {
            domain,
            resolve,
            diff,
            record,
        } => {
            let spinner = spinner(format!("Enumerating subdomains for {}", domain));
            if diff || record {
                return subdomain_baseline(&domain, diff, record).await;
            }
            let result = seer_core::SubdomainEnumerator::new()
                .enumerate(&domain)
                .await?;
            if resolve {
                spinner.set_message("Resolving and classifying discovered names");
                let classification = seer_core::classify_subdomains(
                    &clients.dns,
                    &result.domain,
                    result.subdomains,
                    config.bulk.concurrency,
                )
                .await;
                Payload::SubdomainClassification(Box::new(classification))
            } else {
                Payload::Subdomains(Box::new(result))
            }
        }
        Query::Diff(domain_a, domain_b) => {
            let _spinner = spinner(format!("Comparing {} vs {}", domain_a, domain_b));
            let diff = seer_core::DomainDiffer::new()
                .diff(&domain_a, &domain_b)
                .await?;
            Payload::Diff(Box::new(diff))
        }
        Query::Drift { domain, record } => {
            let _spinner = spinner(format!("Looking up {}", domain));
            let lookup = seer_core::SmartLookup::from_config(config);
            let outcome = crate::ops::drift_check(&lookup, &domain, record).await?;
            let report = Payload::Drift(Box::new(outcome.report));
            return Ok(Outcome {
                note: (!outcome.had_previous)
                    .then(|| crate::ops::no_baseline_note(&domain, record)),
                ..Outcome::new(report)
            });
        }
        Query::Caa(domain) => {
            // Normalize first so `caa HTTPS://WWW.EXAMPLE.COM` works and an
            // invalid domain fails before any lookup.
            let domain = seer_core::normalize_domain(&domain)?;
            let _spinner = spinner(format!("Looking up CAA policy for {}", domain));
            Payload::Caa(Box::new(
                seer_core::caa::lookup_caa(&clients.dns, &domain).await,
            ))
        }
        Query::Posture(domain) => {
            let _spinner = spinner(format!("Inspecting email posture for {}", domain));
            let posture = seer_core::lookup_email_posture(&clients.dns, &domain).await?;
            Payload::Posture(Box::new(posture))
        }
        Query::Headers(domain) => {
            let _spinner = spinner(format!("Auditing HTTP security headers for {}", domain));
            let report = seer_core::audit_headers(&domain, config.http_timeout()).await?;
            Payload::Headers(Box::new(report))
        }
        Query::Takeover { domain, hosts } => {
            let spinner = spinner(format!("Scanning {} for takeover exposure", domain));
            // --host skips CT enumeration entirely, which keeps a targeted
            // re-check of known hosts fast and independent of CT logs.
            let hosts = if hosts.is_empty() {
                spinner.set_message("Enumerating subdomains via CT logs");
                seer_core::SubdomainEnumerator::new()
                    .enumerate(&domain)
                    .await?
                    .subdomains
            } else {
                hosts
            };
            spinner.set_message(&format!("Checking {} host(s) for takeover", hosts.len()));
            let report = seer_core::scan_takeover(
                &clients.dns,
                &domain,
                hosts,
                config.bulk.concurrency,
                config.http_timeout(),
            )
            .await?;
            Payload::Takeover(Box::new(report))
        }
        Query::Confusables(domain) => {
            let _spinner = spinner(format!("Scanning look-alikes for {}", domain));
            let lookup = seer_core::SmartLookup::from_config(config);
            let report =
                seer_core::find_confusables(&lookup, &domain, config.bulk.concurrency).await?;
            Payload::Confusables(Box::new(report))
        }
        Query::Doctor => {
            let _spinner = spinner("Running environment diagnostics".to_string());
            // Infallible by design: probe failures become Fail checks.
            let report = seer_core::doctor::Doctor::from_config(config).run().await;
            Payload::Doctor(Box::new(report))
        }
        Query::Delegation(domain) => {
            let _spinner = spinner(format!("Checking NS delegation for {}", domain));
            let report = seer_core::dns::DelegationChecker::from_config(config)
                .check(&domain)
                .await?;
            Payload::Delegation(Box::new(report))
        }
    };
    Ok(Outcome::new(payload))
}

/// A lookup's history is best-effort — a failed save must not fail the
/// lookup — but it is no longer silent: the failure becomes a footnote.
fn history_warning(saved: seer_core::Result<()>) -> Option<String> {
    saved
        .err()
        .map(|e| format!("lookup history not saved: {e}"))
}

/// Assembles a `dig` outcome from its per-type results, in the requested
/// order. One type is its result or its error. Several are a
/// [`Payload::DigMany`] of the types that answered, with each failed type
/// reported (and failing the command) — unless every type failed, which is
/// the first type's error, as for the core's `ANY` fan-out. An `ANY` answer
/// with sub-queries that got no reply reports and fails the same way.
pub fn dig_outcome(
    results: Vec<(RecordType, seer_core::Result<DnsQueryResult>)>,
) -> seer_core::Result<Outcome> {
    let requested = results.len();
    let mut answered = Vec::with_capacity(requested);
    let mut errors = Vec::new();
    let mut first_error = None;
    for (record_type, result) in results {
        match result {
            Ok(result) => {
                // An ANY answer missing a type is incomplete: say which, and
                // fail the command like a multi-type dig's failed type.
                errors.extend(result.failed_types.iter().map(|f| {
                    format!(
                        "{record_type}: no reply for {}: {}",
                        f.record_type,
                        seer_core::output::sanitize_line(&f.error)
                    )
                }));
                answered.push(result);
            }
            Err(e) => {
                errors.push(format!("{record_type}: {e}"));
                first_error.get_or_insert(e);
            }
        }
    }
    if answered.is_empty() {
        if let Some(e) = first_error {
            return Err(e);
        }
    }
    let payload = match answered.len() {
        1 if requested == 1 => Payload::Dig(Box::new(answered.remove(0))),
        _ => Payload::DigMany(answered),
    };
    let mut outcome = Outcome::new(payload);
    outcome.errors = errors;
    Ok(outcome)
}

/// A finished `+trace`. A walk that stopped early is still a result — the
/// formatted trace shows where it stopped, under its error — except with
/// `short`: the bare values leave the error out, so it is reported on
/// stderr instead and fails the command, the only way a `+short` script can
/// tell a failed walk from a name with no records.
pub fn trace_outcome(trace: seer_core::DnsTrace, short: bool) -> Outcome {
    let stopped = trace
        .error
        .as_deref()
        .filter(|_| short)
        .map(|error| format!("trace stopped: {}", seer_core::output::sanitize_line(error)));
    let mut outcome = Outcome::new(Payload::Trace(Box::new(trace)));
    outcome.errors.extend(stopped);
    outcome.short = short;
    outcome
}

/// `subdomains --diff/--record`: the fresh enumeration against the stored
/// baseline (see [`crate::ops::subdomain_baseline_check`]). With `diff` the
/// result is the diff; `--record` alone shows the listing and confirms the
/// write afterwards.
async fn subdomain_baseline(domain: &str, diff: bool, record: bool) -> seer_core::Result<Outcome> {
    let outcome = crate::ops::subdomain_baseline_check(domain, record).await?;
    let name = outcome.result.domain.clone();
    Ok(if diff {
        Outcome {
            note: outcome
                .report
                .baseline_missing
                .then(|| crate::ops::no_subdomain_baseline_note(&name, record)),
            ..Outcome::new(Payload::SubdomainBaselineDiff(Box::new(outcome.report)))
        }
    } else {
        Outcome {
            footnote: Some(format!(
                "recorded subdomain baseline for {} ({} names)",
                name, outcome.result.count
            )),
            ..Outcome::new(Payload::Subdomains(Box::new(outcome.result)))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::fixtures;
    use seer_core::{DnsStatus, SeerError};

    fn timeout(record_type: RecordType) -> seer_core::Result<DnsQueryResult> {
        Err(SeerError::DnsError(format!(
            "{record_type} lookup failed: timed out"
        )))
    }

    fn answered(record_type: RecordType) -> seer_core::Result<DnsQueryResult> {
        Ok(fixtures::dig_status(record_type, DnsStatus::NoError))
    }

    #[test]
    fn one_type_is_its_result_or_its_error() {
        let outcome = dig_outcome(vec![(RecordType::MX, answered(RecordType::MX))]).expect("ok");
        assert!(matches!(outcome.payload, Payload::Dig(ref r) if r.record_type == RecordType::MX));
        assert!(!outcome.failed());

        let err = dig_outcome(vec![(RecordType::MX, timeout(RecordType::MX))])
            .err()
            .expect("the query's error");
        assert!(err.to_string().contains("MX lookup failed"), "{err}");
    }

    #[test]
    fn several_types_keep_the_requested_order() {
        let types = [RecordType::TXT, RecordType::A, RecordType::MX];
        let outcome = dig_outcome(types.iter().map(|&t| (t, answered(t))).collect()).expect("ok");
        let Payload::DigMany(results) = &outcome.payload else {
            panic!("several types are a DigMany");
        };
        let got: Vec<RecordType> = results.iter().map(|r| r.record_type).collect();
        assert_eq!(got, types);
        assert!(!outcome.failed());
    }

    /// Regression: an ANY whose TXT sub-query got no reply looked complete
    /// and exited 0; the missing type is now reported and fails the command.
    #[test]
    fn an_incomplete_any_answer_is_reported() {
        let mut any = fixtures::dig_status(RecordType::ANY, DnsStatus::NoError);
        any.failed_types = vec![seer_core::FailedType {
            record_type: RecordType::TXT,
            error: "8.8.8.8: timed out".to_string(),
        }];
        let outcome = dig_outcome(vec![(RecordType::ANY, Ok(any))]).expect("ok");
        assert!(matches!(outcome.payload, Payload::Dig(_)));
        assert!(outcome.failed());
        assert_eq!(
            outcome.errors,
            ["ANY: no reply for TXT: 8.8.8.8: timed out"]
        );
    }

    /// The types that answered are still shown; each failed one is reported
    /// under its type and fails the command. The shape stays an array even
    /// when only one type is left, so a script sees what it asked for.
    #[test]
    fn a_failed_type_is_reported_beside_the_others() {
        let outcome = dig_outcome(vec![
            (RecordType::A, answered(RecordType::A)),
            (RecordType::AAAA, timeout(RecordType::AAAA)),
        ])
        .expect("A answered");
        let Payload::DigMany(results) = &outcome.payload else {
            panic!("several types are a DigMany");
        };
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].record_type, RecordType::A);
        assert!(outcome.failed());
        assert_eq!(outcome.errors.len(), 1);
        assert!(
            outcome.errors[0].starts_with("AAAA: ") && outcome.errors[0].contains("timed out"),
            "{:?}",
            outcome.errors
        );
    }

    /// Every type failing is the first failure, like the core's ANY rule.
    #[test]
    fn every_type_failing_is_the_first_error() {
        let err = dig_outcome(vec![
            (
                RecordType::SRV,
                Err(SeerError::InvalidInput(
                    "SRV needs _service._proto.name".into(),
                )),
            ),
            (RecordType::MX, timeout(RecordType::MX)),
        ])
        .err()
        .expect("nothing answered");
        assert!(matches!(err, SeerError::InvalidInput(_)), "{err:?}");
    }

    /// `+short` replaces the formatted result with its bare values — an
    /// empty string for a negative answer, which prints nothing.
    #[test]
    fn short_mode_prints_bare_values_in_place_of_the_result() {
        let chained = fixtures::dig(
            RecordType::A,
            vec![
                fixtures::cname("www.seer.test", "edge.cdn.test."),
                fixtures::a("edge.cdn.test", "192.0.2.7"),
            ],
        );
        let mut outcome = dig_outcome(vec![(RecordType::A, Ok(chained))]).expect("ok");
        assert_eq!(outcome.short_text(), None, "formatted unless asked");
        outcome.short = true;
        assert_eq!(
            outcome.short_text().as_deref(),
            Some("edge.cdn.test.\n192.0.2.7")
        );

        let mut outcome = dig_outcome(vec![(
            RecordType::A,
            Ok(fixtures::dig_status(RecordType::A, DnsStatus::NxDomain)),
        )])
        .expect("ok");
        outcome.short = true;
        assert_eq!(outcome.short_text().as_deref(), Some(""));

        // No other payload has a short form, so it formats as usual.
        let mut outcome = Outcome::new(Payload::Reverse(vec![]));
        outcome.short = true;
        assert_eq!(outcome.short_text(), None);
    }

    /// A stopped trace's bare values are empty, like a name with no
    /// records, so `+short` reports why the walk stopped on stderr and
    /// fails; the formatted trace carries the error itself.
    #[test]
    fn a_stopped_trace_reports_its_error_when_short() {
        let stopped = || fixtures::trace(vec![], Some("every server of com. timed out\x1b[2J"));
        let outcome = trace_outcome(stopped(), true);
        assert_eq!(outcome.short_text().as_deref(), Some(""));
        assert!(outcome.failed());
        assert_eq!(
            outcome.errors,
            vec!["trace stopped: every server of com. timed out".to_string()],
            "the error is sanitized for the terminal"
        );

        let outcome = trace_outcome(stopped(), false);
        assert_eq!(outcome.short_text(), None);
        assert!(!outcome.failed(), "the formatted trace shows the error");

        let answered = fixtures::trace(vec![fixtures::a("www.seer.test", "192.0.2.7")], None);
        let outcome = trace_outcome(answered, true);
        assert_eq!(outcome.short_text().as_deref(), Some("192.0.2.7"));
        assert!(!outcome.failed());
    }

    /// A failed history save after a lookup was swallowed without a word.
    #[test]
    fn a_failed_history_save_is_a_footnote_not_a_failure() {
        assert_eq!(history_warning(Ok(())), None);
        let warning =
            history_warning(Err(SeerError::ConfigError("disk full".into()))).expect("a warning");
        assert!(
            warning.starts_with("lookup history not saved") && warning.contains("disk full"),
            "{warning}"
        );
    }

    /// Only a trace is slow enough for one-shot mode's spinner; a dig,
    /// even for several types, runs its queries concurrently.
    #[test]
    fn trace_spins_in_one_shot_mode() {
        let trace = Query::Trace {
            name: "example.com".into(),
            record_type: RecordType::A,
            short: false,
        };
        assert!(crate::cli_spinner(&trace));
        let dig = Query::Dig {
            name: "example.com".into(),
            types: vec![RecordType::A, RecordType::MX],
            server: None,
            short: false,
        };
        assert!(!crate::cli_spinner(&dig));
    }
}
