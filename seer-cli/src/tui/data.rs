//! Async data layer: run a parameterized `FetchReq` against seer-core.
//!
//! Every request with a command equivalent becomes a [`Query`] and runs
//! through [`query::run`] — the single-shot pipeline the CLI and the REPL
//! share — over the one [`Clients`] set `run_loop` keeps for the session, so
//! a lens shows exactly what the command prints (and a lookup records its
//! history there, once). Watch and History are views of the local stores
//! with no single-shot command (the CLI's `watch`/`history` run outside the
//! pipeline too), so they read their stores here.

use seer_core::{RecordType, SeerConfig};

use crate::query::{self, Clients, Query};
use crate::tui::action::{FetchReq, LensData};

/// Runs `req`. `clients` and `config` come from `~/.seer/config.toml`, so the
/// TUI honors the same timeouts, nameserver and concurrency as the CLI.
pub async fn fetch(
    req: FetchReq,
    clients: &Clients,
    config: &SeerConfig,
) -> Result<LensData, String> {
    match to_query(req) {
        Ok(query) => {
            let outcome = query::run(query, clients, config, false)
                .await
                .map_err(|e| e.to_string())?;
            Ok(outcome.payload)
        }
        Err(Store::Watch) => watchlist(config).await,
        Err(Store::History) => history().await,
    }
}

/// A lens request with no single-shot command: a local-store view.
#[derive(Debug, PartialEq, Eq)]
enum Store {
    Watch,
    History,
}

/// The single-shot command a lens request runs, or the store it views.
fn to_query(req: FetchReq) -> Result<Query, Store> {
    Ok(match req {
        // `lookup` records the result to history, as the CLI does.
        FetchReq::Overview(d) => Query::Lookup(d),
        FetchReq::Whois(d) => Query::Whois(d),
        // One RDAP command: `auto_lookup` routes an IP, `AS<n>` or domain
        // exactly as `rdap_command` picked the lens tab.
        FetchReq::RdapDomain(q) | FetchReq::RdapIp(q) => Query::Rdap(q),
        FetchReq::RdapAsn(asn) => Query::Rdap(format!("AS{asn}")),
        // An explicit nameserver wins; otherwise the configured one, like `dig`.
        FetchReq::Dns {
            domain,
            record_type,
            nameserver,
        } => Query::Dig {
            name: domain,
            types: vec![record_type],
            server: nameserver,
            short: false,
        },
        FetchReq::Dnssec(d) => Query::Dnssec(d),
        FetchReq::Compare {
            domain,
            record_type,
            a,
            b,
        } => Query::Compare {
            domain,
            record_type,
            server_a: a,
            server_b: b,
        },
        FetchReq::Trace {
            domain,
            record_type,
        } => Query::Trace {
            name: domain,
            record_type,
            short: false,
        },
        FetchReq::Ssl(d) => Query::Ssl(d),
        FetchReq::Status(d) => Query::Status(d),
        // The lens has no record-type input.
        FetchReq::Prop(d) => Query::Prop {
            domain: d,
            record_type: RecordType::A,
        },
        FetchReq::Reverse(ip) => Query::Reverse(ip),
        FetchReq::Avail(d) => Query::Avail(d),
        FetchReq::Tld(t) => Query::Tld(t),
        FetchReq::Diff { a, b } => Query::Diff(a, b),
        FetchReq::Subdomains(d) => Query::Subdomains {
            domain: d,
            resolve: false,
            diff: false,
            record: false,
        },
        FetchReq::Headers(d) => Query::Headers(d),
        // No host list: enumerate via CT logs first, like `seer takeover`.
        FetchReq::Takeover(d) => Query::Takeover {
            domain: d,
            hosts: Vec::new(),
        },
        FetchReq::Watch => return Err(Store::Watch),
        FetchReq::History => return Err(Store::History),
    })
}

/// The watchlist with every domain checked. The load is blocking file I/O,
/// so it runs off the async loop.
async fn watchlist(config: &SeerConfig) -> Result<LensData, String> {
    let wl = crate::ops::load_watchlist().await?;
    Ok(LensData::Watch(Box::new(
        seer_core::check_watchlist_with_config(&wl.domains, config).await,
    )))
}

/// Every recorded lookup, newest first.
async fn history() -> Result<LensData, String> {
    let h = crate::ops::load_history().await?;
    let mut flat: Vec<seer_core::HistoryEntry> = h.entries.into_values().flatten().collect();
    flat.sort_by_key(|e| std::cmp::Reverse(e.timestamp));
    Ok(LensData::History(flat))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Takeover used to scan under the enumerator's echo of the domain
    /// rather than the domain asked for; it now runs the CLI's own command.
    #[test]
    fn requests_map_to_the_cli_commands() {
        assert!(matches!(
            to_query(FetchReq::Takeover("www.example.com".into())),
            Ok(Query::Takeover { ref domain, ref hosts }) if domain == "www.example.com" && hosts.is_empty()
        ));
        assert!(matches!(
            to_query(FetchReq::Overview("example.com".into())),
            Ok(Query::Lookup(ref d)) if d == "example.com"
        ));
        assert!(matches!(
            to_query(FetchReq::RdapAsn(15169)),
            Ok(Query::Rdap(ref q)) if q == "AS15169"
        ));
        assert!(matches!(
            to_query(FetchReq::Dns {
                domain: "example.com".into(),
                record_type: RecordType::MX,
                nameserver: Some("1.1.1.1".into()),
            }),
            Ok(Query::Dig { ref types, ref server, short: false, .. })
                if *types == [RecordType::MX] && server.as_deref() == Some("1.1.1.1")
        ));
        assert!(matches!(
            to_query(FetchReq::Subdomains("example.com".into())),
            Ok(Query::Subdomains {
                resolve: false,
                diff: false,
                record: false,
                ..
            })
        ));
        assert!(matches!(to_query(FetchReq::Watch), Err(Store::Watch)));
        assert!(matches!(to_query(FetchReq::History), Err(Store::History)));
    }
}
