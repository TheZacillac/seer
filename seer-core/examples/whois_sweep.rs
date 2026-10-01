//! Live ccTLD WHOIS health sweep — a maintainer tool, not part of the library.
//!
//! For every two-letter ccTLD in the catalog it picks a probe domain known to
//! be registered (the first of `nic.<tld>`, `google.<tld>`, `google.com.<tld>`,
//! `google.co.<tld>` that has NS records), runs a single-attempt
//! [`WhoisClient::lookup`] and sorts the outcome into one bucket:
//!
//! | Bucket | Meaning | Usual fix |
//! |--------|---------|-----------|
//! | `ok` | registrar + dates/status + nameservers parsed | — |
//! | `partial` | some fields parsed, some missing | registry parser |
//! | `unparsed` | reply received, no fields parsed | registry parser |
//! | `false_not_found` | "no match" for a domain with live NS | query format or server |
//! | `refused` | rate-limit / access-denied banner | none, or guidance |
//! | `service_retired` | "TLD not supported" / retirement notice | move to no-WHOIS lists |
//! | `unreachable` | connect / DNS / timeout failure | server map |
//! | `error` | any other client error | case by case |
//! | `no_probe` | no candidate domain has NS records | pass `--probe` |
//! | `no_whois` | catalogued as having no port-43 service | — (not queried) |
//!
//! Classification reuses the parser's own predicates, so a bucket reflects
//! what `seer whois` would actually show. Raw replies land in
//! `<out>/raw/<tld>.txt` (fixture material for new parsers) and every row in
//! `<out>/report.json`.
//!
//! ```text
//! cargo run -p seer-core --example whois_sweep -- \
//!     [--out DIR] [--only uk,de,...] [--probe tld=domain ...] [--concurrency N]
//!     [--nameserver SPEC] [--dns-qps N]
//! ```
//!
//! Probe selection sends up to four NS queries per ccTLD, so they are
//! paced to stay polite to the upstream. If a run turns into `no_probe` rows
//! full of timeouts from some point on, check the network before the tool:
//! IPS rule sets (e.g. Suricata ET "query to abused TLD" rules) drop every
//! later query to a resolver once it has seen a name under `.su`, `.tk`, …
//! — one `nic.su` query was enough when this was first run. Sweep from an
//! unfiltered network, or `--only` the affected ccTLDs once the block ages
//! out, with a fresh `--nameserver`.
//!
//! NS queries are paced to `--dns-qps` (default 10); WHOIS queries are not,
//! since each goes to a different registry.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use seer_core::whois::{all_tlds, get_whois_server};
use seer_core::{DnsResolver, RecordType, SeerError, WhoisClient, WhoisResponse};
use serde_json::{json, Value};

const DEFAULT_CONCURRENCY: usize = 8;
const DEFAULT_DNS_QPS: u32 = 10;
const PROBE_PREFIXES: &[&str] = &["nic", "google", "google.com", "google.co"];
/// ccTLDs whose first candidate has NS records but is not an ordinary
/// registration (`--probe` overrides these too). `nic.cn` is a CNNIC
/// reserved name: its WHOIS says it "can not be registered online".
const PINNED_PROBES: &[(&str, &str)] = &[("cn", "google.cn")];

struct Args {
    out: PathBuf,
    only: Option<Vec<String>>,
    probes: HashMap<String, String>,
    concurrency: usize,
    nameserver: Option<String>,
    dns_qps: u32,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        out: PathBuf::from("target/whois-sweep"),
        only: None,
        probes: HashMap::new(),
        concurrency: DEFAULT_CONCURRENCY,
        nameserver: None,
        dns_qps: DEFAULT_DNS_QPS,
    };
    for (tld, domain) in PINNED_PROBES {
        args.probes
            .insert((*tld).to_string(), (*domain).to_string());
    }
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--out" => args.out = PathBuf::from(value()?),
            "--only" => {
                args.only = Some(
                    value()?
                        .split(',')
                        .map(|s| s.trim().to_lowercase())
                        .collect(),
                );
            }
            "--probe" => {
                let v = value()?;
                let (tld, domain) = v.split_once('=').ok_or("--probe takes tld=domain")?;
                args.probes
                    .insert(tld.to_lowercase(), domain.to_lowercase());
            }
            "--concurrency" => {
                args.concurrency = value()?
                    .parse::<usize>()
                    .map_err(|e| e.to_string())?
                    .clamp(1, 32);
            }
            "--nameserver" => args.nameserver = Some(value()?),
            "--dns-qps" => {
                args.dns_qps = value()?
                    .parse::<u32>()
                    .map_err(|e| e.to_string())?
                    .clamp(1, 100);
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }
    Ok(args)
}

/// Shared token bucket of one: every NS query waits for the next tick.
struct Pacer(tokio::sync::Mutex<tokio::time::Interval>);

impl Pacer {
    fn new(qps: u32) -> Self {
        let mut interval = tokio::time::interval(Duration::from_secs(1) / qps);
        // A stall must not be followed by a catch-up burst.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Self(tokio::sync::Mutex::new(interval))
    }

    async fn wait(&self) {
        self.0.lock().await.tick().await;
    }
}

/// Two-letter ASCII ccTLDs from the catalog (IDN ccTLDs are left for later).
fn cctlds(only: Option<&[String]>) -> Vec<&'static str> {
    all_tlds()
        .iter()
        .copied()
        .filter(|t| t.len() == 2 && t.bytes().all(|b| b.is_ascii_lowercase()))
        .filter(|t| only.is_none_or(|o| o.iter().any(|x| x == t)))
        .collect()
}

/// First candidate with NS records at its own name, i.e. a registered zone.
/// `Err` carries each candidate's DNS error so a resolver failure is never
/// mistaken for "nothing registered".
async fn find_probe(
    dns: &DnsResolver,
    pacer: &Pacer,
    tld: &str,
    pinned: Option<&String>,
    nameserver: Option<&str>,
) -> Result<String, String> {
    if let Some(domain) = pinned {
        return Ok(domain.clone());
    }
    let mut errors = Vec::new();
    for prefix in PROBE_PREFIXES {
        let candidate = format!("{prefix}.{tld}");
        pacer.wait().await;
        match dns.resolve(&candidate, RecordType::NS, nameserver).await {
            Ok(records) if !records.is_empty() => return Ok(candidate),
            Ok(_) => errors.push(format!("{candidate}: no NS")),
            Err(e) => errors.push(format!("{candidate}: {e}")),
        }
    }
    Err(errors.join("; "))
}

/// Names of the core fields the parser failed to extract.
fn missing_fields(r: &WhoisResponse) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if r.registrar.is_none() {
        missing.push("registrar");
    }
    if r.creation_date.is_none() {
        missing.push("created");
    }
    if r.expiration_date.is_none() {
        missing.push("expires");
    }
    if r.nameservers.is_empty() {
        missing.push("nameservers");
    }
    if r.status.is_empty() {
        missing.push("status");
    }
    missing
}

fn classify_response(r: &WhoisResponse) -> (&'static str, String) {
    let missing = missing_fields(r);
    // Mirrors `availability::classify_fallback`: a reply carrying any
    // registration signal (the parser's `is_thin` fields) is a record, and
    // only a thin reply is read for refusal / "no match" banners — full
    // records routinely contain "Reserved by", "access denied" ToS text etc.
    let thin = r.registrar.is_none()
        && r.creation_date.is_none()
        && r.expiration_date.is_none()
        && r.nameservers.is_empty();
    let bucket = if r.registry_unavailable() {
        "service_retired"
    } else if r.has_core_data() {
        "ok"
    } else if !thin || !r.status.is_empty() {
        "partial"
    } else if r.is_available() || r.indicates_not_found() {
        "false_not_found"
    } else if r.indicates_registry_refusal() {
        "refused"
    } else {
        "unparsed"
    };
    let detail = if missing.is_empty() {
        String::new()
    } else {
        format!("missing: {}", missing.join(","))
    };
    (bucket, detail)
}

fn classify_error(e: &SeerError) -> &'static str {
    match e {
        SeerError::WhoisConnectionFailed(_) | SeerError::Timeout(_) => "unreachable",
        SeerError::WhoisError(m) if m.contains("failed to resolve") => "unreachable",
        SeerError::WhoisServerNotFound(_) => "no_whois",
        _ => "error",
    }
}

async fn sweep_one(
    tld: &'static str,
    whois: Arc<WhoisClient>,
    dns: Arc<DnsResolver>,
    pacer: Arc<Pacer>,
    pinned: Option<String>,
    nameserver: Option<Arc<str>>,
    raw_dir: PathBuf,
) -> Value {
    let server = get_whois_server(tld).unwrap_or("");
    let row = |bucket: &str, probe: &str, detail: String| json!({ "tld": tld, "bucket": bucket, "server": server, "probe": probe, "detail": detail });
    if server.is_empty() {
        return row("no_whois", "", String::new());
    }
    let probe = match find_probe(&dns, &pacer, tld, pinned.as_ref(), nameserver.as_deref()).await {
        Ok(p) => p,
        Err(why) => return row("no_probe", "", why),
    };
    match whois.lookup(&probe).await {
        Ok(r) => {
            let (bucket, detail) = classify_response(&r);
            let path = raw_dir.join(format!("{tld}.txt"));
            if let Err(e) = tokio::fs::write(&path, &r.raw_response).await {
                eprintln!("could not write {}: {e}", path.display());
            }
            let mut v = row(bucket, &probe, detail);
            v["answered_by"] = json!(r.whois_server);
            v["bytes"] = json!(r.raw_response.len());
            v
        }
        Err(e) => row(classify_error(&e), &probe, e.to_string()),
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return std::process::ExitCode::from(2);
        }
    };
    let raw_dir = args.out.join("raw");
    if let Err(e) = std::fs::create_dir_all(&raw_dir) {
        eprintln!("cannot create {}: {e}", raw_dir.display());
        return std::process::ExitCode::FAILURE;
    }

    // Single attempt: a sweep should see flakiness, not have retries hide it.
    let whois = Arc::new(WhoisClient::new().without_retries());
    let dns = Arc::new(DnsResolver::new());
    let pacer = Arc::new(Pacer::new(args.dns_qps));
    let nameserver: Option<Arc<str>> = args.nameserver.as_deref().map(Arc::from);
    let tlds = cctlds(args.only.as_deref());
    eprintln!(
        "sweeping {} ccTLDs, {} at a time",
        tlds.len(),
        args.concurrency
    );

    let mut rows: Vec<Value> = stream::iter(tlds)
        .map(|tld| {
            let pinned = args.probes.get(tld).cloned();
            sweep_one(
                tld,
                whois.clone(),
                dns.clone(),
                pacer.clone(),
                pinned,
                nameserver.clone(),
                raw_dir.clone(),
            )
        })
        .buffer_unordered(args.concurrency)
        .inspect(|row| {
            eprintln!(
                "  {:<4} {}",
                row["tld"].as_str().unwrap_or(""),
                row["bucket"].as_str().unwrap_or("")
            );
        })
        .collect()
        .await;
    rows.sort_by(|a, b| a["tld"].as_str().cmp(&b["tld"].as_str()));

    let report = args.out.join("report.json");
    match serde_json::to_string_pretty(&rows) {
        Ok(s) => {
            if let Err(e) = std::fs::write(&report, s) {
                eprintln!("could not write {}: {e}", report.display());
            }
        }
        Err(e) => eprintln!("could not serialize report: {e}"),
    }

    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for row in &rows {
        *counts
            .entry(row["bucket"].as_str().unwrap_or("?"))
            .or_default() += 1;
    }
    println!("\n== summary ==");
    for (bucket, n) in &counts {
        println!("{bucket:<16} {n}");
    }
    println!("\n== needs attention ==");
    for row in rows
        .iter()
        .filter(|r| !matches!(r["bucket"].as_str(), Some("ok" | "no_whois")))
    {
        println!(
            "{:<4} {:<16} {:<28} {:<20} {}",
            row["tld"].as_str().unwrap_or(""),
            row["bucket"].as_str().unwrap_or(""),
            row["server"].as_str().unwrap_or(""),
            row["probe"].as_str().unwrap_or(""),
            row["detail"].as_str().unwrap_or(""),
        );
    }
    println!(
        "\nreport: {}  raw replies: {}",
        report.display(),
        raw_dir.display()
    );
    std::process::ExitCode::SUCCESS
}
