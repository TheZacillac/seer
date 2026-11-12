//! Per-host probes: the TLS certificate chain and the HTTP status report.
//! The path's host is the connect target (port 443) on both.

use axum::extract::State;
use axum::Json;
use seer_core::{SslReport, StatusResponse};

use crate::edge::{self, PathParams};
use crate::error::ApiError;
use crate::state::AppState;

/// `GET /ssl/{domain}`: the certificate chain and its warnings.
pub async fn ssl(
    State(state): State<AppState>,
    PathParams(domain): PathParams<String>,
) -> Result<Json<SslReport>, ApiError> {
    edge::domain(&domain)?;
    edge::public_literal(&domain, 443).await?;
    Ok(Json(state.clients.ssl.check(&domain).await?))
}

/// `GET /status/{domain}`: HTTP status, title, certificate and expiry.
pub async fn status(
    State(state): State<AppState>,
    PathParams(domain): PathParams<String>,
) -> Result<Json<StatusResponse>, ApiError> {
    edge::domain(&domain)?;
    edge::public_literal(&domain, 443).await?;
    Ok(Json(state.clients.status.check(&domain).await?))
}
