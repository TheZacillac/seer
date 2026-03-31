//! Arcanum suite logging initialisation.
//!
//! Reads `ARCANUM_LOG_LEVEL`, `ARCANUM_LOG_FORMAT`, `ARCANUM_LOG_DIR`,
//! `ARCANUM_LOG_FILE`, and `ARCANUM_OTEL_ENDPOINT` and installs a global
//! tracing subscriber.
//!
//! # Usage
//!
//! ```rust,no_run
//! let _guard = seer_core::logging::init_logging("seer");
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
pub fn init_logging(app_name: &str) -> LogGuard {
    init_logging_with_writer(app_name, std::io::stderr)
}

/// Initialise the global tracing subscriber with a custom console writer.
///
/// This is used by `seer-cli` to route log output through the progress bar.
pub fn init_logging_with_writer<W>(app_name: &str, writer: W) -> LogGuard
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    // Guard against double-init (e.g. test harnesses).
    if INITIALIZED.set(()).is_err() {
        return LogGuard { _file_guard: None };
    }

    let env_filter = build_env_filter();
    let log_format = read_env("ARCANUM_LOG_FORMAT", "text");
    let file_enabled = matches!(
        read_env("ARCANUM_LOG_FILE", "").to_lowercase().as_str(),
        "1" | "true" | "yes"
    );

    let json_mode = log_format == "json";

    // Build file appender layer if enabled
    let (file_layer_json, file_layer_text, file_guard) = if file_enabled {
        let dir = log_dir();
        std::fs::create_dir_all(&dir).ok();
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
    let otel_layer = build_otel_layer(app_name).map(|l| l.boxed());

    // Use try_init() — if another subscriber is already registered (e.g.,
    // when both seer-core and tome-core are linked into the same process),
    // this silently succeeds without panicking.
    let _ = tracing_subscriber::registry()
        .with(env_filter)
        .with(console_json)
        .with(console_text)
        .with(file_layer_json)
        .with(file_layer_text)
        .with(otel_layer)
        .try_init();

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

// ---- internal helpers ----

fn build_env_filter() -> EnvFilter {
    let level = read_env_chain(&["ARCANUM_LOG_LEVEL", "RUST_LOG"], "warn");
    EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new("warn"))
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
/// set.  Returns `None` (zero cost) when the env var is absent.
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
