//! Per-host probes: the TLS certificate chain and the HTTP status report.
//! The path's host is the connect target (port 443) on both.

use axum::response::Response;
use seer_core::validation::normalize_host;

use crate::call::Call;
use crate::edge::{self, PathParams};
use crate::error::ApiError;

/// `GET /ssl/{domain}`: the certificate chain and its warnings.
pub async fn ssl(call: Call, PathParams(domain): PathParams<String>) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    edge::public_literal(&domain, 443).await?;
    let host = normalize_host(&domain)?;
    call.respond(&[&host], call.state.clients.ssl.check(&domain))
        .await
}

/// `GET /status/{domain}`: HTTP status, title, certificate and expiry.
pub async fn status(
    call: Call,
    PathParams(domain): PathParams<String>,
) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    edge::public_literal(&domain, 443).await?;
    let host = normalize_host(&domain)?;
    call.respond(&[&host], call.state.clients.status.check(&domain))
        .await
}
