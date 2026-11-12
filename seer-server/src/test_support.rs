//! In-process request helpers for the router tests: no socket is opened.

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use serde_json::Value;
use tower::ServiceExt;

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

/// Sends one request through `app` with the given method and headers.
pub async fn send(app: &Router, method: Method, uri: &str, headers: &[(&str, &[u8])]) -> Reply {
    let mut request = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    reply(response).await
}

/// `GET uri` with no headers.
pub async fn get(app: &Router, uri: &str) -> Reply {
    send(app, Method::GET, uri, &[]).await
}

/// `GET uri` with `Authorization: Bearer <key>`.
pub async fn get_with_key(app: &Router, uri: &str, key: &str) -> Reply {
    let value = format!("Bearer {key}");
    send(
        app,
        Method::GET,
        uri,
        &[("authorization", value.as_bytes())],
    )
    .await
}
