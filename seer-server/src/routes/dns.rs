//! DNS: one query, reported the way `dig` reports it.

use axum::extract::State;
use axum::{Extension, Json};
use seer_core::DnsQueryResult;
use serde::Deserialize;

use crate::edge::{self, PathParams, QueryParams};
use crate::error::ApiError;
use crate::state::AppState;
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
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    PathParams((domain, record_type)): PathParams<(String, String)>,
    QueryParams(query): QueryParams<DigQuery>,
) -> Result<Json<DnsQueryResult>, ApiError> {
    edge::domain(&domain)?;
    let record_type = edge::record_type(&record_type)?;
    if let Some(spec) = query.nameserver.as_deref() {
        // Choosing where Seer sends packets is not an anonymous capability.
        if caller == Caller::Anonymous {
            return Err(ApiError::unauthorized(
                "Choosing a nameserver requires an API key",
            ));
        }
        edge::nameserver(spec).await?;
    }
    let result = state
        .clients
        .dns
        .query(&domain, record_type, query.nameserver.as_deref())
        .await?;
    Ok(Json(result))
}
