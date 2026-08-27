//! Async data layer: run a parameterized `FetchReq` against seer-core.
//! The only module coupled to seer-core's network clients.

use seer_core::RecordType;

use crate::tui::action::{FetchReq, LensData};

fn e(e: seer_core::SeerError) -> String {
    e.to_string()
}

/// Concurrent host checks for the takeover scan. The TUI builds its clients
/// with `::new()` defaults rather than loading `~/.seer/config.toml`, so this
/// mirrors `SeerConfig`'s own `bulk.concurrency` default instead of reading it.
const TAKEOVER_CONCURRENCY: usize = 10;

pub async fn fetch(req: FetchReq) -> Result<LensData, String> {
    match req {
        FetchReq::Overview(d) => {
            let r = seer_core::SmartLookup::new().lookup(&d).await.map_err(e)?;
            // Record to history — best-effort, off the async reactor. Mirrors the
            // CLI lookup handler (main.rs). Detached (not awaited): the Overview
            // result renders immediately; the save lands a beat later.
            let result = r.clone();
            tokio::task::spawn_blocking(move || {
                let mut h = seer_core::LookupHistory::load();
                h.record(&d, result);
                let _ = h.save();
            });
            Ok(LensData::Overview(Box::new(r)))
        }
        FetchReq::Whois(d) => seer_core::WhoisClient::new()
            .lookup(&d)
            .await
            .map(|r| LensData::Whois(Box::new(r)))
            .map_err(e),
        FetchReq::RdapDomain(d) => seer_core::RdapClient::new()
            .lookup_domain(&d)
            .await
            .map(|r| LensData::Rdap(Box::new(r)))
            .map_err(e),
        FetchReq::RdapIp(ip) => seer_core::RdapClient::new()
            .lookup_ip(&ip)
            .await
            .map(|r| LensData::Rdap(Box::new(r)))
            .map_err(e),
        FetchReq::RdapAsn(asn) => seer_core::RdapClient::new()
            .lookup_asn(asn)
            .await
            .map(|r| LensData::Rdap(Box::new(r)))
            .map_err(e),
        FetchReq::Dns {
            domain,
            record_type,
            nameserver,
        } => seer_core::DnsResolver::new()
            .resolve(&domain, record_type, nameserver.as_deref())
            .await
            .map(LensData::Dns)
            .map_err(e),
        FetchReq::Dnssec(d) => seer_core::DnssecChecker::new()
            .check(&d)
            .await
            .map(|r| LensData::Dnssec(Box::new(r)))
            .map_err(e),
        FetchReq::Compare {
            domain,
            record_type,
            a,
            b,
        } => seer_core::dns::DnsComparator::new()
            .compare(&domain, record_type, &a, &b)
            .await
            .map(|r| LensData::Compare(Box::new(r)))
            .map_err(e),
        FetchReq::Ssl(d) => seer_core::SslChecker::new()
            .check(&d)
            .await
            .map(|r| LensData::Ssl(Box::new(r)))
            .map_err(e),
        FetchReq::Status(d) => seer_core::StatusClient::new()
            .check(&d)
            .await
            .map(|r| LensData::Status(Box::new(r)))
            .map_err(e),
        FetchReq::Prop(d) => seer_core::dns::PropagationChecker::new()
            .check(&d, RecordType::A)
            .await
            .map(|r| LensData::Prop(Box::new(r)))
            .map_err(e),
        FetchReq::Reverse(ip) => seer_core::DnsResolver::new()
            .resolve(&ip, RecordType::PTR, None)
            .await
            .map(LensData::Reverse)
            .map_err(e),
        FetchReq::Avail(d) => seer_core::AvailabilityChecker::new()
            .check(&d)
            .await
            .map(|r| LensData::Avail(Box::new(r)))
            .map_err(e),
        // lookup_tld is async + infallible.
        FetchReq::Tld(t) => Ok(LensData::Tld(Box::new(seer_core::lookup_tld(&t).await))),
        FetchReq::Diff { a, b } => seer_core::DomainDiffer::new()
            .diff(&a, &b)
            .await
            .map(|r| LensData::Diff(Box::new(r)))
            .map_err(e),
        FetchReq::Watch => {
            // Watchlist load is blocking file I/O — offload it so the TUI's
            // async select! loop keeps servicing other in-flight lookups
            // (mirrors the History path below).
            let wl = tokio::task::spawn_blocking(seer_core::Watchlist::load)
                .await
                .map_err(|err| err.to_string())?;
            Ok(LensData::Watch(Box::new(
                seer_core::check_watchlist(&wl.domains).await,
            )))
        }
        FetchReq::History => {
            let h = tokio::task::spawn_blocking(seer_core::LookupHistory::load)
                .await
                .map_err(|err| err.to_string())?;
            let mut flat: Vec<seer_core::HistoryEntry> =
                h.entries.into_values().flatten().collect();
            flat.sort_by_key(|e| std::cmp::Reverse(e.timestamp));
            Ok(LensData::History(flat))
        }
        FetchReq::Subdomains(d) => seer_core::SubdomainEnumerator::new()
            .enumerate(&d)
            .await
            .map(|r| LensData::Subdomains(Box::new(r)))
            .map_err(e),
        FetchReq::Headers(d) => seer_core::audit_headers(&d, seer_core::DEFAULT_HEADER_TIMEOUT)
            .await
            .map(|r| LensData::Headers(Box::new(r)))
            .map_err(e),
        FetchReq::Takeover(d) => {
            // Two stages, like the CLI's takeover command: enumerate via CT
            // logs, then scan. Enumeration failure aborts — with no host list
            // there is nothing to scan, and reporting an empty clean result
            // would be a false all-clear.
            let enumerated = seer_core::SubdomainEnumerator::new()
                .enumerate(&d)
                .await
                .map_err(e)?;
            let resolver = seer_core::DnsResolver::new();
            seer_core::scan_takeover(
                &resolver,
                &enumerated.domain,
                enumerated.subdomains,
                TAKEOVER_CONCURRENCY,
            )
            .await
            .map(|r| LensData::Takeover(Box::new(r)))
            .map_err(e)
        }
    }
}
