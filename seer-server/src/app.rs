//! Builds the router: the route table, the tier gate and the layers every
//! response passes through.
//!
//! Layers, innermost first: the gate (who may call this route), panic
//! capture (a panicking handler is a 500, not a dropped connection),
//! `nosniff`, CORS, and the request log, which also stamps `X-Request-Id`.
//! `/health` sits outside the gate.

use std::any::Any;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{header, HeaderValue, Method};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{self, MethodRouter};
use axum::{Json, Router};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::Instrument;

use crate::error::ApiError;
use crate::settings::{CorsOrigins, Settings};
use crate::state::{AppState, Clients};
use crate::tier::{self, Tier};

/// The response header carrying the id that also tags the request's log
/// lines.
const X_REQUEST_ID: &str = "x-request-id";

/// One row of the route table: a path, who may call it, and its handler.
pub struct Route {
    /// The path pattern, as Axum spells it (`/lookup/{domain}`).
    pub path: &'static str,
    /// Who may call it.
    pub tier: Tier,
    /// The handler, already wrapped in its HTTP method.
    pub handler: MethodRouter<AppState>,
}

impl Route {
    /// A route anonymous callers may use when the server is public.
    pub fn public(path: &'static str, handler: MethodRouter<AppState>) -> Self {
        Self {
            path,
            tier: Tier::Public,
            handler,
        }
    }

    /// A route only keyed callers may use.
    pub fn keyed(path: &'static str, handler: MethodRouter<AppState>) -> Self {
        Self {
            path,
            tier: Tier::Keyed,
            handler,
        }
    }
}

/// Builds the application: every route in `routes` behind the tier gate,
/// plus `/health`, the JSON 404 and the response layers.
pub fn router(settings: Settings, clients: Clients, routes: Vec<Route>) -> Router {
    let state = AppState {
        tiers: Arc::new(
            routes
                .iter()
                .map(|route| (route.path, route.tier))
                .collect(),
        ),
        settings: Arc::new(settings),
        clients: Arc::new(clients),
    };
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

/// Refuses a request its caller's tier may not make; otherwise records the
/// caller for the handler.
async fn gate(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // A matched route missing from the table is a bug here: fail closed.
    let tier = request
        .extensions()
        .get::<MatchedPath>()
        .and_then(|path| state.tiers.get(path.as_str()).copied())
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
    tier::authorize(caller, tier, state.settings.public)?;
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
    use crate::test_support::{get, get_with_key, send};
    use crate::tier::Caller;
    use axum::http::{header, Method, StatusCode};
    use axum::Extension;
    use seer_core::config::ServerConfig;
    use seer_core::{SeerConfig, SeerError};
    use serde_json::{json, Value};

    async fn echo(Extension(caller): Extension<Caller>) -> Json<Value> {
        Json(json!({ "caller": format!("{caller:?}") }))
    }

    async fn fail() -> Result<Json<Value>, ApiError> {
        Err(SeerError::Timeout("whois.internal:43 timed out".into()).into())
    }

    async fn boom() -> Json<Value> {
        panic!("handler bug")
    }

    fn stub_routes() -> Vec<Route> {
        vec![
            Route::public("/open/{name}", routing::get(echo)),
            Route::keyed("/locked/{name}", routing::get(echo)),
            Route::public("/fail", routing::get(fail)),
            Route::public("/boom", routing::get(boom)),
        ]
    }

    fn app(public: bool, key: Option<&str>, origins: &[&str]) -> Router {
        let server = ServerConfig {
            bind: "127.0.0.1:0".to_string(),
            public,
            cors_origins: origins.iter().map(|s| s.to_string()).collect(),
            ..ServerConfig::default()
        };
        let settings = Settings::new(&server, key.map(str::to_string)).unwrap();
        let clients = Clients::from_config(&SeerConfig::default());
        router(settings, clients, stub_routes())
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
}
