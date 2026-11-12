//! Builds the router: the route table, the tier gate and the layers every
//! response passes through.
//!
//! Layers, innermost first: the gate (who may call this route, and how
//! often), panic
//! capture (a panicking handler is a 500, not a dropped connection),
//! `nosniff`, CORS, and the request log, which also stamps `X-Request-Id`.
//! `/health` sits outside the gate.

use std::any::Any;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::{header, HeaderValue, Method};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{self, MethodRouter};
use axum::{Json, Router};
use seer_core::contract::CostClass;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::Instrument;

use crate::client_ip::{client_ip, forwarded_for, ClientAddr};
use crate::error::ApiError;
use crate::limit::{self, Subject};
use crate::settings::{CorsOrigins, Settings};
use crate::state::{AppState, Clients};
use crate::tier::{self, Caller, Tier};

/// The response header carrying the id that also tags the request's log
/// lines.
const X_REQUEST_ID: &str = "x-request-id";

/// One row of the route table: a path, who may call it, what it costs,
/// and its handler.
pub struct Route {
    /// The path pattern, as Axum spells it (`/lookup/{domain}`).
    pub path: &'static str,
    /// Who may call it.
    pub tier: Tier,
    /// How expensive it is to serve, which sets its rate limit.
    pub cost: CostClass,
    /// The handler, already wrapped in its HTTP method.
    pub handler: MethodRouter<AppState>,
}

impl Route {
    /// A route anonymous callers may use when the server is public.
    pub fn public(path: &'static str, cost: CostClass, handler: MethodRouter<AppState>) -> Self {
        Self {
            path,
            tier: Tier::Public,
            cost,
            handler,
        }
    }

    /// A route only keyed callers may use.
    pub fn keyed(path: &'static str, cost: CostClass, handler: MethodRouter<AppState>) -> Self {
        Self {
            path,
            tier: Tier::Keyed,
            cost,
            handler,
        }
    }
}

/// Builds the application: every route in `routes` behind the gate, plus
/// `/health`, the JSON 404 and the response layers.
pub fn router(settings: Settings, clients: Clients, routes: Vec<Route>) -> Router {
    assemble(AppState::new(settings, clients, &routes), routes)
}

/// [`router`] over state that already exists (it must have been built from
/// the same `routes`).
pub fn assemble(state: AppState, routes: Vec<Route>) -> Router {
    let mut app = Router::new();
    for route in routes {
        app = app.route(route.path, route.handler);
    }
    app
        // Only the routes added above pass through the gate.
        .route_layer(middleware::from_fn_with_state(state.clone(), gate))
        .route("/health", routing::get(health))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        // Outermost last: the request log wraps everything, so even a
        // captured panic or a CORS preflight gets an id and a log line.
        .layer(CatchPanicLayer::custom(panic_response))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(cors_layer(&state.settings.cors))
        .layer(middleware::from_fn(request_log))
        .with_state(state)
}

/// Refuses a request its caller's tier may not make or that is over the
/// route's rate limit; otherwise records the caller for the handler.
async fn gate(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // A matched route missing from the table is a bug here: fail closed.
    let (route, meta) = request
        .extensions()
        .get::<MatchedPath>()
        .and_then(|path| state.rows.get_key_value(path.as_str()))
        .map(|(route, meta)| (*route, *meta))
        .ok_or_else(ApiError::internal)?;
    // A header that is not valid UTF-8 is present but wrong, never absent.
    // So is a repeated one: a proxy in front could honour a different copy
    // than this server would, so no order of two is accepted.
    let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
    let authorization = match (values.next(), values.next()) {
        (None, _) => None,
        (Some(value), None) => Some(value.to_str().unwrap_or("")),
        (Some(_), Some(_)) => Some(""),
    };
    let caller = tier::identify(authorization, state.settings.api_key.as_deref())?;
    tier::authorize(caller, meta.tier, state.settings.public)?;

    // Rate limit after the tier check: a refused caller gets the 401, and
    // only requests that would otherwise be served are counted.
    let subject = match caller {
        Caller::Keyed => Subject::Keyed,
        Caller::Anonymous => {
            // Without the socket peer there is no identity to limit by.
            let peer = request
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0.ip())
                .ok_or_else(ApiError::internal)?;
            Subject::Anonymous(client_ip(
                peer,
                &forwarded_for(request.headers()),
                &state.settings.trusted_proxies,
            ))
        }
    };
    state
        .limits
        .check(route, meta.cost, subject)
        .map_err(ApiError::rate_limited)?;

    if let Subject::Anonymous(ip) = subject {
        // The identity this client is limited under, for `Call`.
        request
            .extensions_mut()
            .insert(ClientAddr(limit::bucket(ip)));
    }
    request.extensions_mut().insert(caller);
    Ok(next.run(request).await)
}

/// Stamps the response with a fresh request id and writes one log line per
/// request. The id is generated here; a client-supplied one is ignored.
async fn request_log(request: Request, next: Next) -> Response {
    let id = request_id();
    let method = request.method().clone();
    // The route pattern, not the raw path: bounded cardinality, and no
    // caller-chosen text in the log.
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_string(), |path| path.as_str().to_string());
    let started = Instant::now();
    let span = tracing::info_span!("request", request_id = %id);
    let mut response = next.run(request).instrument(span).await;
    if let Ok(value) = HeaderValue::from_str(&id) {
        response.headers_mut().insert(X_REQUEST_ID, value);
    }
    tracing::info!(
        request_id = %id,
        %method,
        route = %route,
        status = response.status().as_u16(),
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "request"
    );
    response
}

/// 16 hex digits from the OS RNG; a process-wide counter if that fails, so
/// an id is always present and still unique within the process.
fn request_id() -> String {
    static FALLBACK: AtomicU64 = AtomicU64::new(1);
    let mut bytes = [0u8; 8];
    let value = match getrandom::fill(&mut bytes) {
        Ok(()) => u64::from_be_bytes(bytes),
        Err(_) => FALLBACK.fetch_add(1, Ordering::Relaxed),
    };
    format!("{value:016x}")
}

/// Browser access: `GET` only, no credentials, and only the configured
/// origins. An empty list sends no CORS headers at all.
fn cors_layer(origins: &CorsOrigins) -> CorsLayer {
    let allow = match origins {
        CorsOrigins::None => AllowOrigin::list(Vec::new()),
        CorsOrigins::Any => AllowOrigin::any(),
        CorsOrigins::List(list) => AllowOrigin::list(list.clone()),
    };
    CorsLayer::new()
        .allow_methods([Method::GET])
        .allow_origin(allow)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "healthy" }))
}

async fn not_found() -> ApiError {
    ApiError::not_found()
}

async fn method_not_allowed() -> ApiError {
    ApiError::method_not_allowed()
}

/// What a panicking handler's caller receives. The panic message goes to
/// stderr through the panic hook; nothing of it reaches the client.
fn panic_response(_: Box<dyn Any + Send + 'static>) -> Response {
    tracing::error!("a request handler panicked");
    ApiError::internal().into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::Call;
    use crate::edge::PathParams;
    use crate::test_support::{get, get_with_key, send, send_from};
    use crate::tier::Caller;
    use axum::http::{header, Method, StatusCode};
    use axum::Extension;
    use seer_core::config::ServerConfig;
    use seer_core::{SeerConfig, SeerError};
    use serde_json::{json, Value};
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    async fn echo(Extension(caller): Extension<Caller>) -> Json<Value> {
        Json(json!({ "caller": format!("{caller:?}") }))
    }

    async fn fail() -> Result<Json<Value>, ApiError> {
        Err(SeerError::Timeout("whois.internal:43 timed out".into()).into())
    }

    async fn boom() -> Json<Value> {
        panic!("handler bug")
    }

    /// Counts how often the "lookup" behind `/count/{name}` really ran.
    static COUNTED: AtomicUsize = AtomicUsize::new(0);

    async fn count(call: Call, PathParams(name): PathParams<String>) -> Result<Response, ApiError> {
        call.respond(&[&name], async {
            let run = COUNTED.fetch_add(1, Ordering::SeqCst) + 1;
            Ok::<_, SeerError>(json!({ "name": name, "run": run }))
        })
        .await
    }

    async fn fresh(call: Call) -> Result<Response, ApiError> {
        static RUNS: AtomicUsize = AtomicUsize::new(0);
        call.respond_fresh(async {
            Ok::<_, SeerError>(json!({ "run": RUNS.fetch_add(1, Ordering::SeqCst) + 1 }))
        })
        .await
    }

    async fn flaky(call: Call, PathParams(name): PathParams<String>) -> Result<Response, ApiError> {
        static RUNS: AtomicUsize = AtomicUsize::new(0);
        call.respond(&[&name], async {
            // Fails the first time, succeeds afterwards.
            if RUNS.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(SeerError::DnsError("resolver down".into()))
            } else {
                Ok(json!({ "ok": true }))
            }
        })
        .await
    }

    async fn hang(call: Call) -> Result<Response, ApiError> {
        call.respond_fresh(async {
            std::future::pending::<()>().await;
            Ok::<_, SeerError>(json!(null))
        })
        .await
    }

    /// A public stub server whose key is `k`, and its state.
    fn app_and_state(adjust: impl FnOnce(&mut Settings)) -> (Router, AppState) {
        let server = ServerConfig {
            public: true,
            ..ServerConfig::default()
        };
        let mut settings = Settings::new(&server, Some("k".to_string())).unwrap();
        adjust(&mut settings);
        let routes = stub_routes();
        let clients = Clients::from_config(&SeerConfig::default());
        let state = AppState::new(settings, clients, &routes);
        (assemble(state.clone(), routes), state)
    }

    fn stub_routes() -> Vec<Route> {
        vec![
            Route::public("/open/{name}", CostClass::Light, routing::get(echo)),
            Route::keyed("/locked/{name}", CostClass::Light, routing::get(echo)),
            Route::public("/fail", CostClass::Light, routing::get(fail)),
            Route::public("/boom", CostClass::Light, routing::get(boom)),
            Route::public("/heavy/{name}", CostClass::Heavy, routing::get(echo)),
            Route::public("/count/{name}", CostClass::Light, routing::get(count)),
            Route::public("/fresh", CostClass::Light, routing::get(fresh)),
            Route::public("/flaky/{name}", CostClass::Light, routing::get(flaky)),
            Route::public("/hang", CostClass::Light, routing::get(hang)),
        ]
    }

    fn app(public: bool, key: Option<&str>, origins: &[&str]) -> Router {
        app_with(public, key, origins, |_| {})
    }

    /// [`app`], with the settings adjusted before the router is built.
    fn app_with(
        public: bool,
        key: Option<&str>,
        origins: &[&str],
        adjust: impl FnOnce(&mut Settings),
    ) -> Router {
        let server = ServerConfig {
            bind: "127.0.0.1:0".to_string(),
            public,
            cors_origins: origins.iter().map(|s| s.to_string()).collect(),
            ..ServerConfig::default()
        };
        let mut settings = Settings::new(&server, key.map(str::to_string)).unwrap();
        adjust(&mut settings);
        let clients = Clients::from_config(&SeerConfig::default());
        router(settings, clients, stub_routes())
    }

    /// Sends `GET uri` from `peer` until the first refusal; returns how
    /// many were admitted and the refusal.
    async fn until_refused(
        app: &Router,
        peer: &str,
        uri: &str,
        headers: &[(&str, &[u8])],
    ) -> (u32, crate::test_support::Reply) {
        let mut admitted = 0;
        loop {
            let reply = send_from(app, peer, Method::GET, uri, headers).await;
            if reply.status != StatusCode::OK {
                return (admitted, reply);
            }
            admitted += 1;
            assert!(admitted < 10_000, "never refused");
        }
    }

    #[tokio::test]
    async fn an_anonymous_caller_is_limited_per_route_and_told_when_to_retry() {
        let app = app(true, None, &[]);
        let (admitted, refusal) = until_refused(&app, "198.51.100.1", "/heavy/x", &[]).await;
        assert_eq!(admitted, CostClass::Heavy.per_minute());
        assert_eq!(refusal.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(refusal.json, json!({ "detail": "Rate limit exceeded" }));
        let retry: u64 = refusal.headers[header::RETRY_AFTER]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=60).contains(&retry), "{retry}");
        // Another caller, and another route for the same caller, are fine.
        let other = send_from(&app, "198.51.100.2", Method::GET, "/heavy/x", &[]).await;
        assert_eq!(other.status, StatusCode::OK);
        let elsewhere = send_from(&app, "198.51.100.1", Method::GET, "/open/x", &[]).await;
        assert_eq!(elsewhere.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_keyed_caller_gets_the_multiplied_limit_whatever_its_address() {
        let app = app_with(true, Some("k"), &[], |s| s.keyed_rate_multiplier = 2);
        let auth: &[(&str, &[u8])] = &[("authorization", b"Bearer k")];
        let (admitted, refusal) = until_refused(&app, "198.51.100.1", "/heavy/x", auth).await;
        assert_eq!(admitted, CostClass::Heavy.per_minute() * 2);
        assert_eq!(refusal.status, StatusCode::TOO_MANY_REQUESTS);
        // The key is the identity: a different address does not help.
        let moved = send_from(&app, "198.51.100.99", Method::GET, "/heavy/x", auth).await;
        assert_eq!(moved.status, StatusCode::TOO_MANY_REQUESTS);
        // The anonymous tier has its own allowance.
        let anonymous = send_from(&app, "198.51.100.1", Method::GET, "/heavy/x", &[]).await;
        assert_eq!(anonymous.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_forged_forwarded_header_does_not_reset_the_limit() {
        // No trusted proxy: the socket peer is the client, whatever it says.
        let app = app(true, None, &[]);
        let (admitted, _) = until_refused(&app, "198.51.100.1", "/heavy/x", &[]).await;
        assert_eq!(admitted, CostClass::Heavy.per_minute());
        let forged = send_from(
            &app,
            "198.51.100.1",
            Method::GET,
            "/heavy/x",
            &[("x-forwarded-for", b"203.0.113.250")],
        )
        .await;
        assert_eq!(forged.status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn behind_a_trusted_proxy_each_visitor_has_their_own_limit() {
        let app = app_with(true, None, &[], |s| {
            s.trusted_proxies = vec!["10.0.0.1/32".parse().unwrap()];
        });
        let visitor_a: &[(&str, &[u8])] = &[("x-forwarded-for", b"6.6.6.6, 198.51.100.1")];
        let visitor_b: &[(&str, &[u8])] = &[("x-forwarded-for", b"198.51.100.2")];
        let (admitted, _) = until_refused(&app, "10.0.0.1", "/heavy/x", visitor_a).await;
        assert_eq!(admitted, CostClass::Heavy.per_minute());
        let b = send_from(&app, "10.0.0.1", Method::GET, "/heavy/x", visitor_b).await;
        assert_eq!(
            b.status,
            StatusCode::OK,
            "visitors must not share the proxy's bucket"
        );
        // Visitor A changing only the forged leftmost entry is still A.
        let a_again = send_from(
            &app,
            "10.0.0.1",
            Method::GET,
            "/heavy/x",
            &[("x-forwarded-for", b"7.7.7.7, 198.51.100.1")],
        )
        .await;
        assert_eq!(a_again.status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn ipv6_addresses_in_one_slash_64_share_a_limit() {
        let app = app(true, None, &[]);
        let (admitted, _) = until_refused(&app, "2001:db8:1:2::1", "/heavy/x", &[]).await;
        assert_eq!(admitted, CostClass::Heavy.per_minute());
        let neighbour = send_from(&app, "2001:db8:1:2:9::9", Method::GET, "/heavy/x", &[]).await;
        assert_eq!(neighbour.status, StatusCode::TOO_MANY_REQUESTS);
        let elsewhere = send_from(&app, "2001:db8:1:3::1", Method::GET, "/heavy/x", &[]).await;
        assert_eq!(elsewhere.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn refused_auth_and_health_are_not_rate_limited_into_a_429() {
        let app = app(false, Some("k"), &[]);
        for _ in 0..(CostClass::Heavy.per_minute() + 5) {
            // No key on a private server: always the 401, never a 429.
            let reply = get(&app, "/heavy/x").await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        }
        for _ in 0..200 {
            assert_eq!(get(&app, "/health").await.status, StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn a_request_with_no_peer_address_fails_closed() {
        // Only possible if the server is ever served without connect info.
        use tower::ServiceExt;
        let request = axum::http::Request::builder()
            .uri("/open/x")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app(true, None, &[]).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn health_needs_no_key_even_on_a_private_server() {
        let reply = get(&app(false, Some("k"), &[]), "/health").await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.json, json!({ "status": "healthy" }));
    }

    #[tokio::test]
    async fn anonymous_callers_reach_public_routes_on_a_public_server() {
        let reply = get(&app(true, Some("k"), &[]), "/open/x").await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.json, json!({ "caller": "Anonymous" }));
    }

    #[tokio::test]
    async fn anonymous_callers_are_refused_keyed_routes() {
        let reply = get(&app(true, Some("k"), &[]), "/locked/x").await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            reply.json,
            json!({ "detail": "This endpoint requires an API key" })
        );
        assert_eq!(reply.headers[header::WWW_AUTHENTICATE], "Bearer");
    }

    #[tokio::test]
    async fn anonymous_callers_are_refused_everything_on_a_private_server() {
        let reply = get(&app(false, Some("k"), &[]), "/open/x").await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.json, json!({ "detail": "API key required" }));
    }

    #[tokio::test]
    async fn the_key_opens_every_route() {
        for public in [true, false] {
            for path in ["/open/x", "/locked/x"] {
                let reply = get_with_key(&app(public, Some("k"), &[]), path, "k").await;
                assert_eq!(reply.status, StatusCode::OK, "{path} public={public}");
                assert_eq!(reply.json, json!({ "caller": "Keyed" }));
            }
        }
    }

    #[tokio::test]
    async fn a_wrong_key_is_refused_even_on_a_public_route() {
        let reply = get_with_key(&app(true, Some("k"), &[]), "/open/x", "wrong").await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.json, json!({ "detail": "Invalid API key" }));
    }

    #[tokio::test]
    async fn non_utf8_authorization_is_unauthorized() {
        let reply = send(
            &app(true, Some("k"), &[]),
            Method::GET,
            "/open/x",
            &[("authorization", b"Bearer \xff\xfe")],
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn more_than_one_authorization_header_is_refused() {
        // A proxy and this server could disagree about which one counts, so
        // neither order is accepted, even when one of them is the right key.
        let app = app(true, Some("k"), &[]);
        for pair in [["Bearer k", "Bearer wrong"], ["Bearer wrong", "Bearer k"]] {
            let reply = send(
                &app,
                Method::GET,
                "/open/x",
                &[
                    ("authorization", pair[0].as_bytes()),
                    ("authorization", pair[1].as_bytes()),
                ],
            )
            .await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{pair:?}");
        }
    }

    #[tokio::test]
    async fn a_core_error_becomes_its_status_and_sanitized_detail() {
        let reply = get(&app(true, None, &[]), "/fail").await;
        assert_eq!(reply.status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(reply.json, json!({ "detail": "Operation timed out" }));
        assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn a_panicking_handler_is_a_500_with_the_usual_headers() {
        let reply = get(&app(true, None, &[]), "/boom").await;
        assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(reply.json, json!({ "detail": "Internal server error" }));
        assert!(reply.headers.contains_key("x-request-id"));
        assert_eq!(reply.headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    }

    #[tokio::test]
    async fn an_unknown_path_is_a_json_404() {
        let reply = get(&app(true, None, &[]), "/nope").await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        assert_eq!(reply.json, json!({ "detail": "Not Found" }));
    }

    #[tokio::test]
    async fn only_get_is_routed() {
        let reply = send(&app(true, None, &[]), Method::POST, "/open/x", &[]).await;
        assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(reply.json, json!({ "detail": "Method Not Allowed" }));
        assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn every_response_is_stamped_with_a_fresh_request_id_and_nosniff() {
        let app = app(true, None, &[]);
        let mut ids = Vec::new();
        for path in ["/health", "/open/x", "/nope", "/fail"] {
            let reply = get(&app, path).await;
            assert_eq!(
                reply.headers[header::X_CONTENT_TYPE_OPTIONS],
                "nosniff",
                "{path}"
            );
            let id = reply.headers["x-request-id"].to_str().unwrap().to_string();
            assert_eq!(id.len(), 16, "{path}");
            assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "{path}");
            ids.push(id);
        }
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 4, "request ids repeat");
    }

    #[tokio::test]
    async fn a_client_supplied_request_id_is_not_echoed() {
        let reply = send(
            &app(true, None, &[]),
            Method::GET,
            "/health",
            &[("x-request-id", b"attacker-chosen")],
        )
        .await;
        assert_ne!(reply.headers["x-request-id"], "attacker-chosen");
    }

    #[tokio::test]
    async fn cors_allows_only_listed_origins() {
        let app = app(true, None, &["https://site.example"]);
        let allowed = send(
            &app,
            Method::GET,
            "/open/x",
            &[("origin", b"https://site.example")],
        )
        .await;
        assert_eq!(
            allowed.headers[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "https://site.example"
        );
        let other = send(
            &app,
            Method::GET,
            "/open/x",
            &[("origin", b"https://evil.example")],
        )
        .await;
        assert!(!other
            .headers
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
        assert_eq!(other.status, StatusCode::OK, "CORS is not access control");
    }

    #[tokio::test]
    async fn cors_is_off_by_default_and_a_star_allows_any_origin() {
        let off = send(
            &app(true, None, &[]),
            Method::GET,
            "/open/x",
            &[("origin", b"https://site.example")],
        )
        .await;
        assert!(!off
            .headers
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
        let any = send(
            &app(true, None, &["*"]),
            Method::GET,
            "/open/x",
            &[("origin", b"https://site.example")],
        )
        .await;
        assert_eq!(any.headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    }

    #[tokio::test]
    async fn preflight_is_answered_before_the_gate() {
        // A browser preflight carries no Authorization header. On a private
        // server it must still be answered by CORS, not refused 401.
        let reply = send(
            &app(false, Some("k"), &["https://site.example"]),
            Method::OPTIONS,
            "/open/x",
            &[
                ("origin", b"https://site.example"),
                ("access-control-request-method", b"GET"),
            ],
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(
            reply.headers[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "https://site.example"
        );
        assert_eq!(reply.headers[header::ACCESS_CONTROL_ALLOW_METHODS], "GET");
    }

    #[tokio::test]
    async fn a_success_is_served_from_the_cache_the_second_time() {
        let (app, _) = app_and_state(|_| {});
        let first = get(&app, "/count/cached-a").await;
        let second = get(&app, "/count/cached-a").await;
        assert_eq!(first.status, StatusCode::OK);
        assert_eq!(first.json, second.json, "the lookup ran twice");
        assert_eq!(first.headers[header::CACHE_CONTROL], "max-age=60");
        assert_eq!(second.headers[header::CACHE_CONTROL], "max-age=60");
        assert_eq!(second.headers[header::CONTENT_TYPE], "application/json");
        // A different name is a different entry.
        let other = get(&app, "/count/cached-b").await;
        assert_ne!(other.json["run"], first.json["run"]);
        assert_eq!(other.json["name"], "cached-b");
    }

    #[tokio::test]
    async fn the_cache_is_shared_by_both_tiers_but_still_rate_limited() {
        let (app, _) = app_and_state(|_| {});
        let anonymous = get(&app, "/count/shared").await;
        let keyed = get_with_key(&app, "/count/shared", "k").await;
        assert_eq!(anonymous.json, keyed.json);
        // Cached answers still count against the caller's allowance.
        let (admitted, refusal) = until_refused(&app, "198.51.100.44", "/count/shared", &[]).await;
        assert_eq!(admitted, CostClass::Light.per_minute());
        assert_eq!(refusal.status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn a_zero_ttl_runs_the_lookup_every_time_and_says_no_store() {
        let (app, _) = app_and_state(|s| s.cache_ttl = Duration::ZERO);
        let first = get(&app, "/count/uncached").await;
        let second = get(&app, "/count/uncached").await;
        assert_ne!(first.json["run"], second.json["run"]);
        assert_eq!(second.headers[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn respond_fresh_never_caches() {
        let (app, _) = app_and_state(|_| {});
        let first = get(&app, "/fresh").await;
        let second = get(&app, "/fresh").await;
        assert_ne!(first.json["run"], second.json["run"]);
        assert_eq!(second.headers[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn an_error_is_not_cached() {
        let (app, _) = app_and_state(|_| {});
        let failed = get(&app, "/flaky/x").await;
        assert_eq!(failed.status, StatusCode::BAD_GATEWAY);
        assert_eq!(failed.headers[header::CACHE_CONTROL], "no-store");
        // The failure did not stick: the next request runs and succeeds.
        let recovered = get(&app, "/flaky/x").await;
        assert_eq!(recovered.status, StatusCode::OK);
        assert_eq!(recovered.json, json!({ "ok": true }));
    }

    #[tokio::test]
    async fn a_call_past_its_deadline_is_a_504() {
        let (app, _) = app_and_state(|s| s.request_timeout = Duration::from_millis(100));
        let started = Instant::now();
        let reply = get(&app, "/hang").await;
        assert_eq!(reply.status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(reply.json, json!({ "detail": "Request timed out" }));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the deadline did not fire"
        );
    }

    #[tokio::test]
    async fn a_timed_out_call_returns_its_permits() {
        let (app, state) = app_and_state(|s| {
            s.request_timeout = Duration::from_millis(100);
            s.max_in_flight = 2;
        });
        let before = state.permits.available();
        for _ in 0..4 {
            assert_eq!(get(&app, "/hang").await.status, StatusCode::GATEWAY_TIMEOUT);
        }
        // Each timed-out call was dropped mid-flight; nothing stayed held.
        assert_eq!(state.permits.available(), before);
        assert_eq!(get(&app, "/fresh").await.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn no_free_slot_before_the_deadline_is_a_503_for_that_tier_only() {
        let (app, state) = app_and_state(|s| {
            s.request_timeout = Duration::from_millis(100);
            s.max_in_flight = 2;
        });
        // Hold the one anonymous slot, as a lookup in flight would.
        let held = state.permits.acquire(Caller::Anonymous).await.unwrap();
        let anonymous = get(&app, "/fresh").await;
        assert_eq!(anonymous.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            anonymous.json,
            json!({ "detail": "Server busy; retry shortly" })
        );
        assert_eq!(anonymous.headers[header::RETRY_AFTER], "1");
        // The keyed tier still has a slot.
        assert_eq!(
            get_with_key(&app, "/fresh", "k").await.status,
            StatusCode::OK
        );
        drop(held);
        assert_eq!(get(&app, "/fresh").await.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_cache_hit_needs_no_slot() {
        let (app, state) = app_and_state(|s| s.max_in_flight = 2);
        assert_eq!(get(&app, "/count/warm").await.status, StatusCode::OK);
        let _a = state.permits.acquire(Caller::Keyed).await.unwrap();
        let _b = state.permits.acquire(Caller::Keyed).await.unwrap();
        // Every slot is taken, yet the cached answer is served at once.
        assert_eq!(get(&app, "/count/warm").await.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn one_anonymous_client_cannot_hold_every_slot() {
        let (app, state) = app_and_state(|s| s.max_in_flight_per_client = 1);
        // The client already has its one lookup in flight.
        let client: std::net::IpAddr = crate::test_support::PEER.parse().unwrap();
        let held = state.per_client.enter(client).unwrap();
        let refused = get(&app, "/fresh").await;
        assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(refused.headers[header::RETRY_AFTER], "1");
        // Other clients, keyed callers and cached answers are unaffected.
        let other = send_from(&app, "198.51.100.9", Method::GET, "/fresh", &[]).await;
        assert_eq!(other.status, StatusCode::OK);
        assert_eq!(
            get_with_key(&app, "/fresh", "k").await.status,
            StatusCode::OK
        );
        drop(held);
        assert_eq!(get(&app, "/fresh").await.status, StatusCode::OK);
        assert_eq!(
            state.per_client.clients(),
            0,
            "finished lookups are forgotten"
        );
    }

    #[tokio::test]
    async fn a_timed_out_call_frees_its_clients_slot() {
        let (app, state) = app_and_state(|s| {
            s.request_timeout = Duration::from_millis(100);
            s.max_in_flight_per_client = 1;
        });
        for _ in 0..3 {
            assert_eq!(get(&app, "/hang").await.status, StatusCode::GATEWAY_TIMEOUT);
        }
        assert_eq!(state.per_client.clients(), 0);
    }
}
