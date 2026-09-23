//! Single-shot commands shared by the CLI subcommands and the REPL.
//!
//! Each surface parses its own syntax into a [`Query`]; [`run`] performs it
//! and hands back a [`Payload`] plus any advisory notes. Each surface then
//! renders every command the same way — the CLI through `--quiet`/`--format`
//! and its check-style exit codes, the REPL by printing and keeping the
//! result for `copy` — so the two cannot drift apart command by command.

use std::sync::Arc;

use seer_core::colors::CatppuccinExt;
use seer_core::{RecordType, SeerConfig};

use crate::display::Spinner;
use crate::payload::Payload;

/// A parsed single-shot command.
pub enum Query {
    Lookup(String),
    Info(String),
    Whois(String),
    /// A domain, IP address, or ASN.
    Rdap(String),
    Dig {
        domain: String,
        record_type: RecordType,
        /// Falls back to the config file's nameserver.
        server: Option<String>,
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
}

impl Outcome {
    fn new(payload: Payload) -> Self {
        Self {
            payload,
            note: None,
            footnote: None,
        }
    }

    /// Prints the notes to stderr around `show`, which prints the result.
    pub fn present(&self, show: impl FnOnce(&Payload)) {
        let print = |note: &Option<String>| {
            if let Some(note) = note {
                eprintln!("{} {}", "note:".ctp_yellow(), note);
            }
        };
        print(&self.note);
        show(&self.payload);
        print(&self.footnote);
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
            propagation: seer_core::dns::PropagationChecker::new(),
            dnssec: seer_core::DnssecChecker::new(),
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
            crate::ops::record_lookup_history(&domain, result.clone()).await;
            Payload::Overview(Box::new(result))
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
            domain,
            record_type,
            server,
        } => {
            let _spinner = spinner(format!("Querying {} {} records", domain, record_type));
            let nameserver = server.as_deref().or(config.nameserver.as_deref());
            Payload::Dns(
                clients
                    .dns
                    .resolve(&domain, record_type, nameserver)
                    .await?,
            )
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
        Query::Tld(tld) => Payload::Tld(Box::new(seer_core::lookup_tld(&tld).await)),
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
            let comparison = seer_core::dns::DnsComparator::new()
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
            return Ok(Outcome {
                note: (!outcome.had_previous)
                    .then(|| crate::ops::no_baseline_note(&domain, record)),
                footnote: None,
                payload: Payload::Drift(Box::new(outcome.report)),
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
            let report =
                seer_core::scan_takeover(&clients.dns, &domain, hosts, config.bulk.concurrency)
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
            footnote: None,
            payload: Payload::SubdomainBaselineDiff(Box::new(outcome.report)),
        }
    } else {
        Outcome {
            note: None,
            footnote: Some(format!(
                "recorded subdomain baseline for {} ({} names)",
                name, outcome.result.count
            )),
            payload: Payload::Subdomains(Box::new(outcome.result)),
        }
    })
}
