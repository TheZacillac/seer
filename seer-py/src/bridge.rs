//! Rust→Python logging bridge via `pyo3-log`.
//!
//! Uses `tracing`'s `log` feature to forward tracing events to the `log`
//! crate, then `pyo3-log` to forward `log` records into Python's `logging`
//! module with efficient GIL caching.

use std::sync::OnceLock;

static BRIDGE_INSTALLED: OnceLock<()> = OnceLock::new();

/// Install the `pyo3-log` bridge.
///
/// This configures the Rust `log` crate to forward records to Python's
/// `logging` module. Combined with the `tracing/log` feature (enabled in
/// Cargo.toml), all `tracing` events are forwarded through `log` when no
/// tracing subscriber is installed — which is the case when running inside
/// a Python process.
///
/// Safe to call multiple times — only the first call takes effect.
pub fn install_bridge() {
    BRIDGE_INSTALLED.get_or_init(|| {
        // try_init avoids panicking if another log implementation is set.
        let _ = pyo3_log::try_init();
    });
}
