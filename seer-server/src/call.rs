//! One request's path through the protection layers.
//!
//! A handler does its edge checks, then hands its lookup to
//! [`Call::respond`], which runs it only if needed and only if allowed:
//! the cache is consulted first, then the client's own share of lookups in
//! flight is checked, then a slot is taken, and the wait for the slot plus
//! the lookup itself share one deadline, the row's. Dropping the future at
//! the deadline (or when the client disconnects) cancels the lookup and
//! returns its slots.

use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{FromRequestParts, MatchedPath};
use axum::http::header;
use axum::http::request::Parts;
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tokio::time::{timeout_at, Instant};

use crate::cache;
use crate::client_ip::ClientAddr;
use crate::error::ApiError;
use crate::state::{AppState, Deadline, RouteMeta};
use crate::tier::Caller;

/// The context of one gated request: the shared state, who is calling, and
/// which route matched.
pub struct Call {
    /// The shared state, for the seer-core clients.
    pub state: AppState,
    /// Who is calling, as the gate decided.
    pub caller: Caller,
    /// The client an anonymous request is limited as; `None` when keyed.
    client: Option<IpAddr>,
    route: String,
    /// The matched route's row.
    meta: RouteMeta,
}

impl FromRequestParts<AppState> for Call {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Both are set for every gated route; their absence means a handler
        // was mounted outside the gate. Fail closed.
        let caller = parts
            .extensions
            .get::<Caller>()
            .copied()
            .ok_or_else(ApiError::internal)?;
        let route = parts
            .extensions
            .get::<MatchedPath>()
            .map(|path| path.as_str().to_string())
            .ok_or_else(ApiError::internal)?;
        // The gate found this row already; missing here means a handler
        // was mounted outside the table. Fail closed.
        let meta = state
            .rows
            .get(route.as_str())
            .copied()
            .ok_or_else(ApiError::internal)?;
        let client = parts.extensions.get::<ClientAddr>().map(|addr| addr.0);
        if caller == Caller::Anonymous && client.is_none() {
            return Err(ApiError::internal());
        }
        Ok(Self {
            state: state.clone(),
            caller,
            client,
            route,
            meta,
        })
    }
}

impl Call {
    /// Answers with the cached response for this route and `parts` (the
    /// normalized values that select the answer), or runs `work` and caches
    /// its success.
    pub async fn respond<T, F>(&self, parts: &[&str], work: F) -> Result<Response, ApiError>
    where
        T: Serialize,
        F: Future<Output = seer_core::Result<T>> + Send,
    {
        let key = cache::key(&self.route, parts);
        let cache = &self.state.cache;
        if let Some(body) = cache.get(&key) {
            return Ok(json(body, cache.cache_control()));
        }
        let body = self.run(work).await?;
        cache.put(key, body.clone());
        Ok(json(body, cache.cache_control()))
    }

    /// Runs `work` every time and marks the answer `no-store`. For answers
    /// that must be current, such as a query to a nameserver the caller
    /// chose.
    pub async fn respond_fresh<T, F>(&self, work: F) -> Result<Response, ApiError>
    where
        T: Serialize,
        F: Future<Output = seer_core::Result<T>> + Send,
    {
        let body = self.run(work).await?;
        Ok(json(body, HeaderValue::from_static("no-store")))
    }

    /// Takes a slot, runs `work` and serializes its result, all within the
    /// row's deadline.
    async fn run<T, F>(&self, work: F) -> Result<Bytes, ApiError>
    where
        T: Serialize,
        F: Future<Output = seer_core::Result<T>> + Send,
    {
        // One client may have only so many lookups running. This is checked
        // first and never waits, so a client over its share costs nothing.
        let _client_slot = match self.client {
            Some(client) => Some(
                self.state
                    .per_client
                    .enter(client)
                    .ok_or_else(|| ApiError::rate_limited(Duration::from_secs(1)))?,
            ),
            None => None,
        };
        let budget = match self.meta.deadline {
            Deadline::Default => self.state.settings.request_timeout,
            Deadline::Audit => self.state.clients.audit_deadline,
        };
        let deadline = Instant::now() + budget;
        // No slot in time: nothing was started, so the caller may retry.
        let _held = timeout_at(deadline, self.state.permits.acquire(self.caller))
            .await
            .map_err(|_| ApiError::busy())?
            .map_err(|_| ApiError::internal())?;
        let value = timeout_at(deadline, work)
            .await
            .map_err(|_| ApiError::timeout())??;
        serde_json::to_vec(&value)
            .map(Bytes::from)
            .map_err(|_| ApiError::internal())
    }
}

/// A JSON success with the given `Cache-Control`.
fn json(body: Bytes, cache_control: HeaderValue) -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (header::CACHE_CONTROL, cache_control),
        ],
        body,
    )
        .into_response()
}
