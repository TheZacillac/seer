//! Registration data: lookup, WHOIS, RDAP, availability and TLD info.

use axum::extract::State;
use axum::Json;
use seer_core::{AvailabilityResult, LookupResult, RdapResponse, TldInfo, WhoisResponse};

use crate::edge::{self, PathParams};
use crate::error::ApiError;
use crate::state::AppState;

/// `GET /lookup/{domain}`: RDAP first, WHOIS fallback.
pub async fn lookup(
    State(state): State<AppState>,
    PathParams(domain): PathParams<String>,
) -> Result<Json<LookupResult>, ApiError> {
    edge::domain(&domain)?;
    Ok(Json(state.clients.lookup.lookup(&domain).await?))
}

/// `GET /whois/{domain}`.
pub async fn whois(
    State(state): State<AppState>,
    PathParams(domain): PathParams<String>,
) -> Result<Json<WhoisResponse>, ApiError> {
    edge::domain(&domain)?;
    Ok(Json(state.clients.whois.lookup(&domain).await?))
}

/// `GET /rdap/domain/{domain}`.
pub async fn rdap_domain(
    State(state): State<AppState>,
    PathParams(domain): PathParams<String>,
) -> Result<Json<RdapResponse>, ApiError> {
    edge::domain(&domain)?;
    Ok(Json(state.clients.rdap.lookup_domain(&domain).await?))
}

/// `GET /rdap/ip/{ip}`. A reserved address is refused as invalid input.
pub async fn rdap_ip(
    State(state): State<AppState>,
    PathParams(ip): PathParams<String>,
) -> Result<Json<RdapResponse>, ApiError> {
    edge::domain(&ip)?;
    edge::public_literal(&ip, 443).await?;
    Ok(Json(state.clients.rdap.lookup_ip(&ip).await?))
}

/// `GET /rdap/asn/{asn}`.
pub async fn rdap_asn(
    State(state): State<AppState>,
    PathParams(asn): PathParams<String>,
) -> Result<Json<RdapResponse>, ApiError> {
    let asn = edge::asn(&asn)?;
    Ok(Json(state.clients.rdap.lookup_asn(asn).await?))
}

/// `GET /availability/{domain}`.
pub async fn availability(
    State(state): State<AppState>,
    PathParams(domain): PathParams<String>,
) -> Result<Json<AvailabilityResult>, ApiError> {
    edge::domain(&domain)?;
    Ok(Json(state.clients.availability.check(&domain).await?))
}

/// `GET /tld/`: every TLD seer knows. Embedded data, no network.
pub async fn tld_list() -> Json<&'static [&'static str]> {
    Json(seer_core::all_tlds())
}

/// `GET /tld/{tld}`: WHOIS server, RDAP endpoint, registry URL and type.
/// An unknown but plausible TLD is a payload of nulls, not an error.
pub async fn tld_info(
    State(state): State<AppState>,
    PathParams(tld): PathParams<String>,
) -> Result<Json<TldInfo>, ApiError> {
    edge::tld(&tld)?;
    Ok(Json(
        seer_core::lookup_tld_with(&tld, &state.clients.rdap).await,
    ))
}
