//! In-process request helpers for the router tests: no socket is opened.

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
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

/// The peer address `send`, `get` and `get_with_key` come from.
pub const PEER: &str = "203.0.113.7";

/// Sends one request through `app` as if it arrived from `peer`.
pub async fn send_from(
    app: &Router,
    peer: &str,
    method: Method,
    uri: &str,
    headers: &[(&str, &[u8])],
) -> Reply {
    let mut request = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let mut request = request.body(Body::empty()).unwrap();
    // What `into_make_service_with_connect_info` adds for a real socket.
    let peer: std::net::IpAddr = peer.parse().unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(peer, 40_000)));
    let response = app.clone().oneshot(request).await.unwrap();
    reply(response).await
}

/// Sends one request through `app` with the given method and headers.
pub async fn send(app: &Router, method: Method, uri: &str, headers: &[(&str, &[u8])]) -> Reply {
    send_from(app, PEER, method, uri, headers).await
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
