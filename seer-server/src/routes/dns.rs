//! DNS: one query, reported the way `dig` reports it.

use axum::response::Response;
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
