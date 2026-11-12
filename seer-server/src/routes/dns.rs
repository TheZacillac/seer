//! DNS: one query reported the way `dig` reports it, and the checks built
//! on many queries: DNSSEC, delegation, propagation, a trace from the
//! root, and one query compared across two servers.

use axum::response::Response;
use seer_core::validation::{normalize_domain, normalize_host};
use serde::Deserialize;

use crate::call::Call;
use crate::edge::{self, PathParams, QueryParams};
use crate::error::ApiError;
use crate::tier::Caller;

/// Query parameters of `GET /dns/{domain}/{record_type}`.
#[derive(Debug, Deserialize)]
pub struct DigQuery {
    /// Nameserver to ask: an IP or hostname with an optional port (UDP),
    /// `tls://host[:port]` or `https://host[:port][/path]`. Keyed callers
    /// only.
    nameserver: Option<String>,
}

/// `GET /dns/{domain}/{record_type}`. NXDOMAIN, NODATA, SERVFAIL and
/// REFUSED are results with that `status`, not errors.
pub async fn dig(
    call: Call,
    PathParams((domain, record_type)): PathParams<(String, String)>,
    QueryParams(query): QueryParams<DigQuery>,
) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    let record_type = edge::record_type(&record_type)?;
    let resolver = &call.state.clients.dns;
    match query.nameserver.as_deref() {
        Some(spec) => {
            // Choosing where Seer sends packets is not an anonymous
            // capability.
            if call.caller == Caller::Anonymous {
                return Err(ApiError::unauthorized(
                    "Choosing a nameserver requires an API key",
                ));
            }
            edge::nameserver(spec).await?;
            // Asking one named server is asking what it says now.
            call.respond_fresh(resolver.query(&domain, record_type, Some(spec)))
                .await
        }
        None => {
            // DNS names are case-insensitive; other spellings of one name
            // only miss the cache.
            let name = domain.to_ascii_lowercase();
            call.respond(
                &[&name, record_type.as_str()],
                resolver.query(&domain, record_type, None),
            )
            .await
        }
    }
}

/// `GET /dnssec/{domain}`: the DS and DNSKEY chain. Keeps `www.`: the zone
/// walk decides where the records live.
pub async fn dnssec(
    call: Call,
    PathParams(domain): PathParams<String>,
) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    let host = normalize_host(&domain)?;
    call.respond(&[&host], call.state.clients.dnssec.check(&domain))
        .await
}

/// `GET /delegation/{domain}`: the parent's NS set against the zone's own,
/// and a lameness probe of each nameserver.
pub async fn delegation(
    call: Call,
    PathParams(domain): PathParams<String>,
) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    let name = normalize_domain(&domain)?;
    call.respond(&[&name], call.state.clients.delegation.check(&domain))
        .await
}

/// `GET /propagation/{domain}/{record_type}`: one query asked of public
/// resolvers around the world.
pub async fn propagation(
    call: Call,
    PathParams((domain, record_type)): PathParams<(String, String)>,
) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    let record_type = edge::record_type(&record_type)?;
    let name = domain.to_ascii_lowercase();
    call.respond(
        &[&name, record_type.as_str()],
        call.state.clients.propagation.check(&domain, record_type),
    )
    .await
}

/// Query parameters of `GET /dns/trace/{domain}`.
#[derive(Debug, Deserialize)]
pub struct TraceQuery {
    /// One record type; `A` when absent. Core refuses `ANY`.
    record_type: Option<String>,
}

/// `GET /dns/trace/{domain}`: the walk from the root servers down, like
/// `dig +trace`. The servers asked come from the root hints and referrals,
/// each vetted by core.
pub async fn trace(
    call: Call,
    PathParams(domain): PathParams<String>,
    QueryParams(query): QueryParams<TraceQuery>,
) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    let record_type = edge::record_type_or_a(query.record_type.as_deref())?;
    let name = domain.to_ascii_lowercase();
    call.respond(
        &[&name, record_type.as_str()],
        call.state.clients.tracer.trace(&domain, record_type),
    )
    .await
}

/// Query parameters of `GET /dns/compare/{domain}`.
#[derive(Debug, Deserialize)]
pub struct CompareQuery {
    /// First nameserver spec (see `DigQuery::nameserver`). Required.
    server_a: Option<String>,
    /// Second nameserver spec. Required.
    server_b: Option<String>,
    /// One record type; `A` when absent.
    record_type: Option<String>,
}

/// `GET /dns/compare/{domain}`: one query asked of two servers the caller
/// names. Never cached: it reports what those servers say now.
pub async fn compare(
    call: Call,
    PathParams(domain): PathParams<String>,
    QueryParams(query): QueryParams<CompareQuery>,
) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    let record_type = edge::record_type_or_a(query.record_type.as_deref())?;
    let (Some(server_a), Some(server_b)) = (query.server_a.as_deref(), query.server_b.as_deref())
    else {
        return Err(ApiError::invalid("server_a and server_b are required"));
    };
    // Both are connect targets.
    edge::nameserver(server_a).await?;
    edge::nameserver(server_b).await?;
    call.respond_fresh(call.state.clients.comparator.compare(
        &domain,
        record_type,
        server_a,
        server_b,
    ))
    .await
}
