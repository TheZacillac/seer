# Logging Audit & Polish

**Status:** Draft
**Date:** 2026-04-17
**Scope:** `seer-core`, `seer-cli`, `seer-api` (FastAPI + MCP)

## Goal

Reclassify every `warn!` / `info!` / `debug!` call in `seer-core` against a project-wide rubric, change per-interface default log levels so each audience sees a sensible cut by default, and document the rubric under `docs/` so future PRs can reference it.

## Non-Goals

- Changing the logging backend (we keep `tracing` + `tracing-subscriber` + `pyo3-log` bridge).
- Adding new spans or span fields.
- Changing OTEL configuration.
- Introducing new structured-field conventions.

## Current State

- 35× `warn!`, 3× `info!`, 0× `error!`, ~100× `debug!` across `seer-core`.
- Default log level is `"warn"` for all interfaces via `seer-core/src/logging.rs:132`.
- `seer-cli` installs a tracing subscriber with an env filter.
- `seer-api` and `seer-mcp` (Python) bypass the Rust subscriber; tracing events flow through `pyo3-log` to Python's `logging` module, which `seer-api/main.py:27` already sets to `INFO`.
- Recent incident: 8× per-registry IANA bootstrap fetch failures were emitted at `warn!` on every cold start, cluttering CLI output while conveying no actionable signal.

## Rubric

Committed as `docs/logging-conventions.md`. One page. Rule + concrete example per level.

| Level | Rule | When to use |
|-------|------|-------------|
| `error!` | Failure that was silently swallowed | Effectively never. Errors propagate via `Result<T>`. |
| `warn!` | Handled degradation that affects the user's result, **or** evidence of misconfig/misuse | "all 4 IANA registries failed", "unsafe WHOIS server rejected", "circular referral", "partial WHOIS read", "lock poisoned (recovering)", "config parse failed, using defaults" |
| `info!` | Notable one-time operational milestone (not per-request) | "bootstrap loaded N/4 registries", "MCP server started on stdio" |
| `debug!` | Useful when troubleshooting; silent by default | per-registry fetch/parse failure when others succeed, retry-attempt notices, stale-cache served after refresh fail, "lookup successful for X" |
| `trace!` | Wire-level detail | "sent WHOIS query of N bytes" |

## Per-Interface Defaults

| Interface | Current default | New default | How |
|-----------|-----------------|-------------|-----|
| `seer-cli` | `warn` | `error` | Add `default_level` parameter to `init_logging` / `init_logging_with_writer`; CLI passes `"error"`. `ARCANUM_LOG_LEVEL` / `RUST_LOG` still override. |
| `seer-api` | `INFO` (`logging.basicConfig` at `main.py:27`) | `INFO` (no change) | Already correct. |
| `seer-mcp` | Python root default (`WARNING`) — `seer_api/mcp/server.py` only calls `logging.getLogger(__name__)`; no `basicConfig` | `INFO` | Add `logging.basicConfig(level=logging.INFO)` at module load. |
| `seer-py` (library) | host-controlled via `pyo3-log` | unchanged | Library consumers configure their own logging. |

### API change

```rust
pub fn init_logging(app_name: &str, default_level: &str) -> LogGuard
pub fn init_logging_with_writer<W>(app_name: &str, default_level: &str, writer: W) -> LogGuard
```

Call site `seer-cli/src/main.rs:253` passes `"error"`. Env vars still take precedence.

## Call-Site Reclassifications

### Downgrade to `debug!`

- `seer-core/src/rdap/client.rs` — 8 per-registry bootstrap `warn!` at lines 708, 713, 721, 726, 734, 739, 747, 752. Partial failure is handled; only the "all 4 failed" path stays at `warn`.
- `seer-core/src/rdap/client.rs:282` — stale-cache-served-after-refresh-error.
- `seer-core/src/rdap/client.rs:454` — stale-cache-served-when-refresh-succeeds-with-multiple-URLs.
- `seer-core/src/retry.rs:290` — per-attempt retry notice. Final failure surfaces via `Result`.
- `seer-core/src/whois/client.rs:194` — referral lookup failed, using registry response. Graceful fallback.
- `seer-core/src/bulk/executor.rs:197` — per-item operation failure. Already visible in per-item `BulkResult`.

### Keep as `warn!`

- `seer-core/src/cache.rs` — 12× `Cache*lock poisoned, recovering`. Poisoning means a panic happened elsewhere; worth surfacing.
- `seer-core/src/whois/client.rs:134, :143, :257, :321, :346` — circular/max-depth referral, unsafe server, partial reads.
- `seer-core/src/dns/propagation.rs:222` — resolver unreachable.
- `seer-core/src/config.rs:101` — config parse failure, using defaults.
- `seer-core/src/lookup.rs:560` — defensive unreachable branch.

### Add `info!`

- `seer-core/src/rdap/client.rs` — inside `load_bootstrap_data` after parsing, emit once per successful load:
  ```rust
  info!(
      dns_entries = dns.len(),
      ipv4_ranges = ipv4.len(),
      ipv6_ranges = ipv6.len(),
      asn_ranges = asn.len(),
      "RDAP bootstrap loaded"
  );
  ```
- `seer-api/seer_api/mcp/server.py` — Python-side `logging.info("MCP server started on stdio")` at startup.

## Testing Strategy

### Added tests

1. **`init_logging` default-level honored.** Extend `seer-core/src/logging.rs` tests to verify the `default_level` parameter is used when no env var is set, and that `ARCANUM_LOG_LEVEL` / `RUST_LOG` still override it.
2. **Bootstrap info log smoke test.** In `rdap/client.rs` tests, assert the new `info!` fires exactly once per successful load.

### Not tested

Individual level downgrades. Asserting a log statement emits at `debug` vs `warn` would test the framework, not behavior.

### Manual verification

- `seer lookup example.com` at default → no log output unless something actually fails.
- `RUST_LOG=warn seer lookup example.com` → surfaces real warnings (lock poisoning, unsafe server, etc.).
- `RUST_LOG=info seer lookup example.com` → surfaces bootstrap summary once.
- `seer-api` boot → `INFO`-level bootstrap summary visible in logs.

## Files Touched

| File | Change |
|------|--------|
| `seer-core/src/logging.rs` | Add `default_level` parameter to `init_logging` / `init_logging_with_writer`. Tests. |
| `seer-core/src/rdap/client.rs` | 10 level downgrades + 1 new `info!`. |
| `seer-core/src/retry.rs` | 1 level downgrade. |
| `seer-core/src/whois/client.rs` | 1 level downgrade. |
| `seer-core/src/bulk/executor.rs` | 1 level downgrade. |
| `seer-cli/src/main.rs` | Pass `"error"` to `init_logging_with_writer`. |
| `seer-api/seer_api/mcp/server.py` | Add `logging.basicConfig(level=logging.INFO)`; add startup info log. |
| `docs/logging-conventions.md` | **New.** Rubric doc. |
