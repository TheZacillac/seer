//! Arcanum suite logging initialisation.
//!
//! Reads `ARCANUM_LOG_LEVEL`, `ARCANUM_LOG_FORMAT`, `ARCANUM_LOG_DIR`,
//! `ARCANUM_LOG_FILE`, and `ARCANUM_OTEL_ENDPOINT` and installs a global
//! tracing subscriber.
//!
//! # Usage
//!
//! ```rust,no_run
//! let _guard = seer_core::logging::init_logging("seer", "error");
//! ```
//!
//! The returned guard **must** be kept alive for the lifetime of the process
//! so that the file appender can flush on exit.

use std::path::PathBuf;
use std::sync::OnceLock;

use tracing_subscriber::{
    fmt::{self, MakeWriter},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Layer,
};

static INITIALIZED: OnceLock<()> = OnceLock::new();

/// Guard returned by [`init_logging`] / [`init_logging_with_writer`].
///
/// Holds the file appender worker guard (if file logging is enabled).
/// Drop this only when the process is about to exit.
pub struct LogGuard {
    _file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

/// Initialise the global tracing subscriber for a CLI / standalone process.
///
/// Uses `stderr` as the console output destination. For a custom writer (e.g.
/// progress-bar aware), use [`init_logging_with_writer`].
///
/// `default_level` is used when neither `ARCANUM_LOG_LEVEL` nor `RUST_LOG`
/// is set. Typical values: `"error"` for CLIs, `"info"` for servers.
pub fn init_logging(app_name: &str, default_level: &str) -> LogGuard {
    init_logging_with_writer(app_name, default_level, std::io::stderr)
}

/// Initialise the global tracing subscriber with a custom console writer.
///
/// This is used by `seer-cli` to route log output through the progress bar.
/// See [`init_logging`] for the meaning of `default_level`.
pub fn init_logging_with_writer<W>(app_name: &str, default_level: &str, writer: W) -> LogGuard
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    // Guard against double-init (e.g. test harnesses).
    if INITIALIZED.set(()).is_err() {
        return LogGuard { _file_guard: None };
    }

    let env_filter = build_env_filter(default_level);
    let log_format = read_env("ARCANUM_LOG_FORMAT", "text");
    let file_enabled = matches!(
        read_env("ARCANUM_LOG_FILE", "").to_lowercase().as_str(),
        "1" | "true" | "yes"
    );

    let json_mode = log_format == "json";

    // Build file appender layer if enabled
    let (file_layer_json, file_layer_text, file_guard) = if file_enabled {
        let dir = log_dir();
        ensure_log_dir(&dir);
        let file_appender = tracing_appender::rolling::daily(&dir, format!("{app_name}.log"));
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        if json_mode {
            (
                Some(fmt::layer().json().with_writer(non_blocking).boxed()),
                None,
                Some(guard),
            )
        } else {
            (
                None,
                Some(fmt::layer().with_writer(non_blocking).boxed()),
                Some(guard),
            )
        }
    } else {
        (None, None, None)
    };

    // Build console layer
    let (console_json, console_text) = if json_mode {
        (Some(fmt::layer().json().with_writer(writer).boxed()), None)
    } else {
        (None, Some(fmt::layer().with_writer(writer).boxed()))
    };

    // Build optional OpenTelemetry OTLP layer (boxed for type erasure).
    // Compiled out entirely when the `otel` feature is disabled.
    #[cfg(feature = "otel")]
    let otel_layer = build_otel_layer(app_name).map(|l| l.boxed());

    // Use try_init() — if another subscriber is already registered (e.g.,
    // when both seer-core and tome-core are linked into the same process),
    // this silently succeeds without panicking.
    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(console_json)
        .with(console_text)
        .with(file_layer_json)
        .with(file_layer_text);

    #[cfg(feature = "otel")]
    let registry = registry.with(otel_layer);

    let _ = registry.try_init();

    // Silence unused-variable warning when `otel` is disabled — the layer
    // builder still consumes `app_name` in the feature-on path.
    #[cfg(not(feature = "otel"))]
    let _ = app_name;

    LogGuard {
        _file_guard: file_guard,
    }
}

/// Returns the resolved log directory.
///
/// Reads `ARCANUM_LOG_DIR`, falls back to `~/.arcanum/logs/`.
pub fn log_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("ARCANUM_LOG_DIR") {
        return PathBuf::from(dir);
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".arcanum")
        .join("logs")
}

/// Creates the log directory (best-effort) and restricts it to owner-only
/// (0700) on Unix. Log files carry internal-IP diagnostic detail that is
/// deliberately kept out of client-facing errors (e.g. the SSRF guard's
/// resolved-IP debug lines), so the directory gets the same owner-only
/// treatment as `~/.seer` (see history.rs / watchlist.rs). Non-unix keeps
/// platform-default permissions.
fn ensure_log_dir(dir: &std::path::Path) {
    let _ = std::fs::create_dir_all(dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Also tightens a pre-existing directory created by older versions
        // with default permissions.
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
}

// ---- internal helpers ----

fn build_env_filter(default_level: &str) -> EnvFilter {
    let level = read_env_chain(&["ARCANUM_LOG_LEVEL", "RUST_LOG"], default_level);
    EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new(default_level))
}

fn read_env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn read_env_chain(keys: &[&str], default: &str) -> String {
    for key in keys {
        if let Ok(val) = std::env::var(key) {
            if !val.is_empty() {
                return val;
            }
        }
    }
    default.to_string()
}

/// Build the OpenTelemetry OTLP tracing layer if `ARCANUM_OTEL_ENDPOINT` is
/// set. Returns `None` (zero cost) when the env var is absent. Only compiled
/// when the `otel` feature is enabled.
#[cfg(feature = "otel")]
fn build_otel_layer<S>(
    service_name: &str,
) -> Option<tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::SdkTracer>>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig as _;

    let endpoint = std::env::var("ARCANUM_OTEL_ENDPOINT").ok()?;
    if endpoint.is_empty() {
        return None;
    }

    // Build the OTLP exporter → tracer → layer.
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&endpoint)
        .build()
        .ok()?;

    let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name(service_name.to_string())
                .build(),
        )
        .build();

    let tracer = tracer_provider.tracer(service_name.to_string());

    // Keep the provider alive — leaking is acceptable here because it lives
    // for the process lifetime and must not be dropped before shutdown.
    std::mem::forget(tracer_provider);

    Some(tracing_opentelemetry::layer().with_tracer(tracer))
}

#[cfg(test)]
mod tests {
    use super::build_env_filter;

    // Serialize env-var tests so parallel runs don't collide on the shared
    // process env.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_clean_env<F: FnOnce() -> R, R>(f: F) -> R {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev_arcanum = std::env::var("ARCANUM_LOG_LEVEL").ok();
        let prev_rust = std::env::var("RUST_LOG").ok();
        std::env::remove_var("ARCANUM_LOG_LEVEL");
        std::env::remove_var("RUST_LOG");
        let result = f();
        match prev_arcanum {
            Some(v) => std::env::set_var("ARCANUM_LOG_LEVEL", v),
            None => std::env::remove_var("ARCANUM_LOG_LEVEL"),
        }
        match prev_rust {
            Some(v) => std::env::set_var("RUST_LOG", v),
            None => std::env::remove_var("RUST_LOG"),
        }
        result
    }

    #[test]
    fn test_default_level_used_when_no_env_set() {
        with_clean_env(|| {
            let filter = build_env_filter("error");
            // EnvFilter's Display renders the directive set.
            assert_eq!(format!("{}", filter), "error");
        });
    }

    #[test]
    fn test_arcanum_log_level_overrides_default() {
        with_clean_env(|| {
            std::env::set_var("ARCANUM_LOG_LEVEL", "debug");
            let filter = build_env_filter("error");
            assert_eq!(format!("{}", filter), "debug");
        });
    }

    #[test]
    fn test_rust_log_overrides_default() {
        with_clean_env(|| {
            std::env::set_var("RUST_LOG", "info");
            let filter = build_env_filter("error");
            assert_eq!(format!("{}", filter), "info");
        });
    }

    #[test]
    fn test_arcanum_log_level_takes_precedence_over_rust_log() {
        with_clean_env(|| {
            std::env::set_var("ARCANUM_LOG_LEVEL", "warn");
            std::env::set_var("RUST_LOG", "trace");
            let filter = build_env_filter("error");
            assert_eq!(format!("{}", filter), "warn");
        });
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_ensure_log_dir_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir =
            std::env::temp_dir().join(format!("seer-ensure-log-dir-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        // Fresh directory must come out owner-only.
        super::ensure_log_dir(&dir);
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "fresh log dir must be owner-only, got {:o}",
            mode & 0o777
        );

        // A pre-existing directory with loose permissions (e.g. created by an
        // older version with defaults) must be tightened, not left as-is.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        super::ensure_log_dir(&dir);
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "pre-existing log dir must be tightened to owner-only, got {:o}",
            mode & 0o777
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
