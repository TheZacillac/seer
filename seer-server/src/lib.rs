//! `seer-server`: seer-core's lookups over HTTP, as JSON, for websites.
//!
//! It runs alongside the Python `seer-api` and serves the single-domain
//! operations; bulk jobs, SSE streams and MCP stay there. Callers are
//! anonymous (the public routes, when `[server] public = true`) or keyed
//! (`Authorization: Bearer $SEER_API_KEY`).
//!
//! Module map: [`settings`] validates the config and runs the startup
//! checks; [`state`] holds the shared seer-core clients; [`routes`] is the
//! route table and its handlers; [`edge`] holds the checks handlers run
//! before calling core; [`app`] builds the router and its layers; [`tier`]
//! decides who may call what; [`client_ip`] works out who the client is
//! behind a proxy; [`limit`] rate-limits each caller per route; [`cache`] is the
//! response cache; [`call`] runs a handler's lookup under the cache, the
//! permits and the deadline; [`error`] turns failures into
//! `{"detail": …}` responses.
//!
//! [`serve`] is the whole server: bind, route, and run until SIGTERM or
//! Ctrl-C, letting in-flight requests finish.

pub mod app;
pub mod cache;
pub mod call;
pub mod client_ip;
pub mod edge;
pub mod error;
pub mod limit;
pub mod routes;
pub mod settings;
pub mod state;
pub mod tier;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use seer_core::SeerConfig;
use tokio::net::TcpListener;

use crate::settings::Settings;
use crate::state::{AppState, Clients};

/// Binds `settings.bind` and serves until SIGTERM or Ctrl-C. In-flight
/// requests finish before it returns.
pub async fn serve(settings: Settings, config: &SeerConfig) -> std::io::Result<()> {
    let listener = TcpListener::bind(settings.bind).await?;
    serve_on(listener, settings, config, shutdown_signal()).await
}

/// Serves on an already-bound listener until `shutdown` completes.
pub async fn serve_on(
    listener: TcpListener,
    settings: Settings,
    config: &SeerConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    tracing::info!(
        address = %listener.local_addr()?,
        public = settings.public,
        keyed = settings.api_key.is_some(),
        "seer-server listening"
    );
    for warning in settings.warnings() {
        tracing::warn!("{warning}");
    }
    let routes = routes::routes();
    let state = AppState::new(settings, Clients::from_config(config), &routes);
    sweep_limits_periodically(&state);
    let app = app::assemble(state, routes);
    // Connect info gives the gate each request's socket peer, which is the
    // client's identity for rate limiting (or the proxy that names it).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

/// Forgets idle rate-limit entries once a minute, for as long as the
/// server's state is alive.
fn sweep_limits_periodically(state: &AppState) {
    let limits = Arc::downgrade(&state.limits);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            match limits.upgrade() {
                Some(limits) => limits.sweep(),
                // The server has stopped and dropped its state.
                None => break,
            }
        }
    });
}

/// Completes on Ctrl-C, or on SIGTERM where there is one.
async fn shutdown_signal() {
    let ctrl_c = async {
        // If the handler cannot be installed, never complete on this arm.
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutdown signal received; finishing in-flight requests");
}

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod tests {
    use super::*;
    use seer_core::config::ServerConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn settings(bind: &str) -> Settings {
        let server = ServerConfig {
            bind: bind.to_string(),
            public: true,
            ..ServerConfig::default()
        };
        Settings::new(&server, None).unwrap()
    }

    #[tokio::test]
    async fn serves_health_over_a_socket_and_stops_on_shutdown() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            serve_on(
                listener,
                settings("127.0.0.1:0"),
                &SeerConfig::default(),
                async {
                    let _ = stopped.await;
                },
            )
            .await
        });

        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains(r#"{"status":"healthy"}"#), "{response}");
        assert!(response.contains("x-request-id:"), "{response}");

        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_port_in_use_is_an_error_not_a_panic() {
        let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = taken.local_addr().unwrap().to_string();
        let error = serve(settings(&address), &SeerConfig::default())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
    }
}
