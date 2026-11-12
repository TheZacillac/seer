//! Registration data: lookup, merged info, WHOIS, RDAP, availability and
//! TLD info.

use axum::response::Response;
use seer_core::validation::normalize_domain;
use seer_core::{DomainInfo, SeerError};

use crate::call::Call;
use crate::edge::{self, PathParams};
use crate::error::ApiError;

/// `GET /lookup/{domain}`: RDAP first, WHOIS fallback.
pub async fn lookup(
    call: Call,
    PathParams(domain): PathParams<String>,
) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    let name = normalize_domain(&domain)?;
    call.respond(&[&name], call.state.clients.lookup.lookup(&domain))
        .await
}

/// `GET /info/{domain}`: the lookup's RDAP and WHOIS data merged into flat
/// fields.
pub async fn info(
    call: Call,
    PathParams(domain): PathParams<String>,
) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    let name = normalize_domain(&domain)?;
    call.respond(&[&name], async {
        let result = call.state.clients.lookup.lookup(&domain).await?;
        Ok::<_, SeerError>(DomainInfo::from_lookup_result(&result))
    })
    .await
}

/// `GET /whois/{domain}`.
pub async fn whois(
    call: Call,
    PathParams(domain): PathParams<String>,
) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    let name = normalize_domain(&domain)?;
    call.respond(&[&name], call.state.clients.whois.lookup(&domain))
        .await
}

/// `GET /rdap/domain/{domain}`.
pub async fn rdap_domain(
    call: Call,
    PathParams(domain): PathParams<String>,
) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    let name = normalize_domain(&domain)?;
    call.respond(&[&name], call.state.clients.rdap.lookup_domain(&domain))
        .await
}

/// `GET /rdap/ip/{ip}`. A reserved address is refused as invalid input.
pub async fn rdap_ip(call: Call, PathParams(ip): PathParams<String>) -> Result<Response, ApiError> {
    edge::domain(&ip)?;
    edge::public_literal(&ip, 443).await?;
    let name = ip.trim().to_ascii_lowercase();
    call.respond(&[&name], call.state.clients.rdap.lookup_ip(&ip))
        .await
}

/// `GET /rdap/asn/{asn}`.
pub async fn rdap_asn(
    call: Call,
    PathParams(asn): PathParams<String>,
) -> Result<Response, ApiError> {
    let asn = edge::asn(&asn)?;
    call.respond(&[&asn.to_string()], call.state.clients.rdap.lookup_asn(asn))
        .await
}

/// `GET /availability/{domain}`.
pub async fn availability(
    call: Call,
    PathParams(domain): PathParams<String>,
) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    let name = normalize_domain(&domain)?;
    call.respond(&[&name], call.state.clients.availability.check(&domain))
        .await
}

/// `GET /tld/`: every TLD seer knows. Embedded data, no network.
pub async fn tld_list(call: Call) -> Result<Response, ApiError> {
    call.respond(&[], async { Ok::<_, SeerError>(seer_core::all_tlds()) })
        .await
}

/// `GET /tld/{tld}`: WHOIS server, RDAP endpoint, registry URL and type.
/// An unknown but plausible TLD is a payload of nulls, not an error.
pub async fn tld_info(
    call: Call,
    PathParams(tld): PathParams<String>,
) -> Result<Response, ApiError> {
    edge::tld(&tld)?;
    let name = tld.trim_start_matches('.').to_ascii_lowercase();
    call.respond(&[&name], async {
        Ok::<_, SeerError>(seer_core::lookup_tld_with(&tld, &call.state.clients.rdap).await)
    })
    .await
}
