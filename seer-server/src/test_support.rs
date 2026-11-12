//! In-process request helpers for the router tests: no socket is opened.

use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde_json::Value;

/// A response reduced to what tests assert on.
pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    /// The body parsed as JSON, or `Value::Null` when it is not JSON.
    pub json: Value,
}

/// Collects a response into a [`Reply`].
pub async fn reply(response: Response) -> Reply {
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    Reply {
        status: parts.status,
        headers: parts.headers,
        json: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}
