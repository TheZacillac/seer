//! `seer-server`: seer-core's lookups over HTTP, as JSON, for websites.
//!
//! It runs alongside the Python `seer-api` and serves every single-domain
//! operation; bulk jobs, SSE streams and MCP stay there. Callers are
//! anonymous (the public routes only, and only when `[server] public =
//! true`) or keyed
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
//! Ctrl-C, letting in-flight requests finish. It accepts connections
//! itself (`run`) so each one has a header timeout and their number a cap.

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
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Request};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use seer_core::SeerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tower::ServiceExt;

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
    let listening = Listening {
        header_timeout: state.settings.header_timeout,
        max_connections: state.settings.max_connections,
        // The longest a request already in flight may still run: a wait
        // for a slot, then an audit.
        grace: state.settings.request_timeout + state.clients.audit_deadline + SHUTDOWN_MARGIN,
    };
    run(listener, app::assemble(state, routes), listening, shutdown).await
}

/// Extra time allowed at shutdown, beyond the longest request, for
/// responses to be written out.
const SHUTDOWN_MARGIN: Duration = Duration::from_secs(5);

/// How long the accept loop pauses after an error that is not about one
/// connection (out of file descriptors, say), so it does not spin.
const ACCEPT_BACKOFF: Duration = Duration::from_secs(1);

/// The listener's own limits, apart from anything a request does.
struct Listening {
    /// How long a connection may take to send a complete request header.
    header_timeout: Duration,
    /// Connections open at once.
    max_connections: usize,
    /// How long shutdown waits for open connections to finish.
    grace: Duration,
}

/// The accept loop. `axum::serve` is not used because it sets no timeouts
/// and no connection limit: a client could hold a socket open for ever
/// without sending a request, and enough of them would exhaust the
/// process's file descriptors.
///
/// Each connection takes a slot before it is accepted, so at the cap new
/// connections wait in the kernel's listen queue. A connection must send
/// its whole request header within `header_timeout`, which also closes
/// idle keep-alive connections. On `shutdown` the loop stops accepting and
/// in-flight requests get `grace` to finish.
async fn run(
    listener: TcpListener,
    app: axum::Router,
    listening: Listening,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let slots = Arc::new(Semaphore::new(listening.max_connections));
    let graceful = GracefulShutdown::new();
    let mut shutdown = pin!(shutdown);
    loop {
        let accepted = tokio::select! {
            () = &mut shutdown => break,
            accepted = accept(&listener, &slots) => accepted,
        };
        let Some((stream, peer, slot)) = accepted else {
            continue;
        };
        // The gate reads the socket peer from the request's extensions: it
        // is the client's identity for rate limiting (or the proxy that
        // names it).
        let app = app.clone();
        let service = tower::service_fn(move |mut request: Request<Incoming>| {
            request.extensions_mut().insert(ConnectInfo(peer));
            app.clone().oneshot(request)
        });
        // hyper's HTTP/1 server directly, not hyper-util's protocol
        // detection: that reads the first bytes with no timeout, so a
        // connection that sent nothing would never be closed.
        let mut builder = http1::Builder::new();
        builder
            .timer(TokioTimer::new())
            .header_read_timeout(listening.header_timeout);
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            let connection =
                builder.serve_connection(TokioIo::new(stream), TowerToHyperService::new(service));
            // An error here is the client's (reset, timed out, bad
            // request); there is nobody to report it to.
            let _ = watcher.watch(connection).await;
            drop(slot);
        });
    }
    drop(listener);
    tracing::info!("shutdown signal received; finishing in-flight requests");
    if timeout(listening.grace, graceful.shutdown()).await.is_err() {
        tracing::warn!("shutdown grace period ended with connections still open");
    }
    Ok(())
}

/// Waits for a free connection slot, then for a connection. `None` after
/// an accept error, which has been logged or was one connection's problem.
async fn accept(
    listener: &TcpListener,
    slots: &Arc<Semaphore>,
) -> Option<(TcpStream, SocketAddr, OwnedSemaphorePermit)> {
    // The semaphore is never closed; were it, serve nothing rather than
    // serve without a limit.
    let slot = slots.clone().acquire_owned().await.ok()?;
    match listener.accept().await {
        Ok((stream, peer)) => Some((stream, peer, slot)),
        Err(error) => {
            // These are about the connection that failed, not the listener.
            let one_connection = matches!(
                error.kind(),
                ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::ConnectionReset
            );
            if !one_connection {
                tracing::error!(%error, "accept failed");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
            }
            None
        }
    }
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
}

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod tests {
    use super::*;
    use seer_core::config::ServerConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    /// Serves `/health` on a fresh port with the given listener limits.
    /// Returns the address, the shutdown trigger and the server task.
    async fn start(
        adjust: impl FnOnce(&mut Settings),
    ) -> (
        SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let mut settings = settings("127.0.0.1:0");
        adjust(&mut settings);
        let server = tokio::spawn(async move {
            serve_on(listener, settings, &SeerConfig::default(), async {
                let _ = stopped.await;
            })
            .await
        });
        (address, stop, server)
    }

    const HEALTH: &[u8] = b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    const WITHIN: Duration = Duration::from_secs(5);

    /// Reads until the peer closes; what it sent, or `None` if it had not
    /// closed within `limit`.
    async fn read_to_close(stream: &mut TcpStream, limit: Duration) -> Option<String> {
        let mut text = String::new();
        timeout(limit, stream.read_to_string(&mut text))
            .await
            .ok()
            .map(|_| text)
    }

    #[tokio::test]
    async fn a_connection_that_never_finishes_its_request_is_closed() {
        let (address, stop, server) =
            start(|s| s.header_timeout = Duration::from_millis(200)).await;
        let mut stalled = TcpStream::connect(address).await.unwrap();
        stalled
            .write_all(b"GET /health HTTP/1.1\r\nHost: loc")
            .await
            .unwrap();
        // The server gives up on it; it does not hold the socket for ever.
        assert!(
            read_to_close(&mut stalled, WITHIN).await.is_some(),
            "the stalled connection was left open"
        );
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_connection_that_sends_nothing_is_closed() {
        let (address, stop, server) =
            start(|s| s.header_timeout = Duration::from_millis(200)).await;
        let mut silent = TcpStream::connect(address).await.unwrap();
        assert!(
            read_to_close(&mut silent, WITHIN).await.is_some(),
            "the silent connection was left open"
        );
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn connections_past_the_cap_wait_for_one_to_close() {
        let (address, stop, server) = start(|s| {
            s.header_timeout = Duration::from_secs(30);
            s.max_connections = 1;
        })
        .await;
        // The one allowed connection, held open mid-request.
        let mut first = TcpStream::connect(address).await.unwrap();
        first.write_all(b"GET /health HTTP/1.1\r\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        // A second connects (the kernel queues it) but is not served yet.
        let mut second = TcpStream::connect(address).await.unwrap();
        second.write_all(HEALTH).await.unwrap();
        assert!(
            read_to_close(&mut second, Duration::from_millis(300))
                .await
                .is_none(),
            "the cap did not hold"
        );
        drop(first);
        let reply = read_to_close(&mut second, WITHIN).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn shutdown_is_not_held_up_by_a_stalled_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let table = routes::routes();
        let state = AppState::new(
            settings("127.0.0.1:0"),
            Clients::from_config(&SeerConfig::default()),
            &table,
        );
        let app = app::assemble(state, table);
        let listening = Listening {
            // Long enough that only the grace period can end the wait.
            header_timeout: Duration::from_secs(60),
            max_connections: 16,
            grace: Duration::from_millis(300),
        };
        let server = tokio::spawn(async move {
            run(listener, app, listening, async {
                let _ = stopped.await;
            })
            .await
        });
        let mut stalled = TcpStream::connect(address).await.unwrap();
        stalled
            .write_all(b"GET /health HTTP/1.1\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        stop.send(()).unwrap();
        let stopped = timeout(WITHIN, server).await;
        assert!(stopped.is_ok(), "shutdown waited on a stalled connection");
    }

    #[tokio::test]
    async fn a_port_in_use_is_an_error_not_a_panic() {
        let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = taken.local_addr().unwrap().to_string();
        let error = serve(settings(&address), &SeerConfig::default())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::AddrInUse);
    }
}
