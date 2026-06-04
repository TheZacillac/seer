//! Async data layer: map a lens index to the matching seer-core client call.
//! The only module coupled to seer-core's network clients.

use seer_core::RecordType;

use crate::tui::action::LensData;
use crate::tui::lenses;

fn err_to_string(e: seer_core::SeerError) -> String {
    e.to_string()
}

/// Run the lookup for `lens` (index into the registry) at `domain`.
pub async fn fetch(lens: usize, domain: &str) -> Result<LensData, String> {
    let key = lenses::lenses()[lens].key;
    match key {
        "overview" => seer_core::SmartLookup::new()
            .lookup(domain)
            .await
            .map(|r| LensData::Overview(Box::new(r)))
            .map_err(err_to_string),
        "whois" => seer_core::WhoisClient::new()
            .lookup(domain)
            .await
            .map(|r| LensData::Whois(Box::new(r)))
            .map_err(err_to_string),
        "rdap" => seer_core::RdapClient::new()
            .lookup_domain(domain)
            .await
            .map(|r| LensData::Rdap(Box::new(r)))
            .map_err(err_to_string),
        "dns" => seer_core::DnsResolver::new()
            .resolve(domain, RecordType::A, None)
            .await
            .map(LensData::Dns)
            .map_err(err_to_string),
        "ssl" => seer_core::SslChecker::new()
            .check(domain)
            .await
            .map(|r| LensData::Ssl(Box::new(r)))
            .map_err(err_to_string),
        "status" => seer_core::StatusClient::new()
            .check(domain)
            .await
            .map(|r| LensData::Status(Box::new(r)))
            .map_err(err_to_string),
        "propagation" => seer_core::dns::PropagationChecker::new()
            .check(domain, RecordType::A)
            .await
            .map(|r| LensData::Prop(Box::new(r)))
            .map_err(err_to_string),
        other => Err(format!("{other} is not yet wired in the TUI")),
    }
}
