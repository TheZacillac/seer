# Logging Audit & Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply a project-wide log-level rubric across `seer-core`, change per-interface default log levels (CLI → `error`, MCP → `INFO`, API already `INFO`), and ship a one-page convention doc.

**Architecture:** Mostly mechanical level-swaps at known call sites. One small API change to `seer-core::logging::init_logging*` adds a `default_level` parameter so the CLI can opt into a quieter default without affecting Python consumers (who go through `pyo3-log` and configure levels on the Python side). One new `info!` in the RDAP bootstrap path.

**Tech Stack:** Rust, `tracing`, `tracing-subscriber`, Python `logging`.

**Reference spec:** `docs/superpowers/specs/2026-04-17-logging-audit-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `docs/logging-conventions.md` | Create | Project-wide rubric for log levels |
| `seer-core/src/logging.rs` | Modify | Add `default_level` parameter to `init_logging`/`init_logging_with_writer`; test the override precedence |
| `seer-cli/src/main.rs:253` | Modify | Pass `"error"` as the default level |
| `seer-core/src/rdap/client.rs` | Modify | Downgrade 10 `warn!`→`debug!`; add 1 new `info!` on successful bootstrap load |
| `seer-core/src/retry.rs` | Modify | Downgrade 1 `warn!`→`debug!` |
| `seer-core/src/whois/client.rs` | Modify | Downgrade 1 `warn!`→`debug!` |
| `seer-core/src/bulk/executor.rs` | Modify | Downgrade 1 `warn!`→`debug!` |
| `seer-api/seer_api/mcp/server.py` | Modify | Add `logging.basicConfig(level=logging.INFO)` + startup info log |

---

### Task 1: Write the logging conventions doc

**Files:**
- Create: `docs/logging-conventions.md`

**Why:** One-page reference future PRs can cite. Mirrors the rubric approved in the spec.

- [ ] **Step 1: Create the file**

Write this exact content to `docs/logging-conventions.md`:

```markdown
# Logging Conventions

Project-wide rubric for log-level choice. Applies to all crates in the Arcanum suite.

## Rules

| Level | Rule | When to use |
|-------|------|-------------|
| `error!` | Failure that was silently swallowed | Effectively never. Errors propagate via `Result<T>`. |
| `warn!` | Handled degradation that affects the user's result, **or** evidence of misconfig/misuse | "all 4 IANA registries failed", "unsafe WHOIS server rejected", "circular referral", "partial WHOIS read", "lock poisoned (recovering)", "config parse failed, using defaults" |
| `info!` | Notable one-time operational milestone (not per-request) | "bootstrap loaded N/4 registries", "MCP server started on stdio" |
| `debug!` | Useful when troubleshooting; silent by default | per-registry fetch/parse failure when others succeed, retry-attempt notices, stale-cache served after refresh fail, "lookup successful for X" |
| `trace!` | Wire-level detail | "sent WHOIS query of N bytes" |

## Defaults

| Interface | Default level | Override |
|-----------|---------------|----------|
| `seer-cli` | `error` | `ARCANUM_LOG_LEVEL` or `RUST_LOG` |
| `seer-api` | `INFO` | standard Python `logging` config |
| `seer-mcp` | `INFO` | standard Python `logging` config |
| `seer-py` (library) | host-controlled via `pyo3-log` | host Python logger |

## Principles

- **Per-request events at `debug!`.** The default cut should be quiet on a successful run.
- **`warn!` must be actionable or surprising.** If a user can't act on it and it's expected to appear regularly in production, it belongs at `debug!`.
- **One `info!` per lifecycle event.** Bootstrap loads, server starts. Not per-request.
- **Errors propagate, they don't log.** A function that returns `Err(_)` should not also `error!`.
```

- [ ] **Step 2: Commit**

```bash
git add docs/logging-conventions.md
git commit -m "docs: add project-wide logging conventions"
```

---

### Task 2: Add `default_level` parameter to `init_logging`

**Files:**
- Modify: `seer-core/src/logging.rs`

**Why:** Lets CLI opt into a quieter default without a global change. Env vars still win.

- [ ] **Step 1: Write the failing test**

Add to the bottom of `seer-core/src/logging.rs` (before the final `}`):

```rust
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
            std::env::remove_var("ARCANUM_LOG_LEVEL");
        });
    }

    #[test]
    fn test_rust_log_overrides_default() {
        with_clean_env(|| {
            std::env::set_var("RUST_LOG", "info");
            let filter = build_env_filter("error");
            assert_eq!(format!("{}", filter), "info");
            std::env::remove_var("RUST_LOG");
        });
    }

    #[test]
    fn test_arcanum_log_level_takes_precedence_over_rust_log() {
        with_clean_env(|| {
            std::env::set_var("ARCANUM_LOG_LEVEL", "warn");
            std::env::set_var("RUST_LOG", "trace");
            let filter = build_env_filter("error");
            assert_eq!(format!("{}", filter), "warn");
            std::env::remove_var("ARCANUM_LOG_LEVEL");
            std::env::remove_var("RUST_LOG");
        });
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p seer-core logging::tests -- --nocapture`
Expected: FAIL with compile error — `build_env_filter` currently takes no arguments.

- [ ] **Step 3: Update `build_env_filter` to accept a default**

In `seer-core/src/logging.rs`, replace:

```rust
fn build_env_filter() -> EnvFilter {
    let level = read_env_chain(&["ARCANUM_LOG_LEVEL", "RUST_LOG"], "warn");
    EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new("warn"))
}
```

with:

```rust
fn build_env_filter(default_level: &str) -> EnvFilter {
    let level = read_env_chain(&["ARCANUM_LOG_LEVEL", "RUST_LOG"], default_level);
    EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new(default_level))
}
```

- [ ] **Step 4: Update the public `init_logging*` signatures**

In `seer-core/src/logging.rs`:

Replace the existing `init_logging` function with:

```rust
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
```

Replace the existing `init_logging_with_writer` function signature and its call to `build_env_filter()` with:

```rust
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
```

(The rest of the function body stays the same.)

- [ ] **Step 5: Update the docstring example at the top of the file**

Replace:

```rust
//! ```rust,no_run
//! let _guard = seer_core::logging::init_logging("seer");
//! ```
```

with:

```rust
//! ```rust,no_run
//! let _guard = seer_core::logging::init_logging("seer", "error");
//! ```
```

- [ ] **Step 6: Run the test**

Run: `cargo test -p seer-core logging::tests -- --nocapture`
Expected: PASS (all 4 tests).

- [ ] **Step 7: Build workspace to catch other callers**

Run: `cargo build --workspace`
Expected: fails on `seer-cli/src/main.rs:253` because it now needs a second argument. That's expected — Task 3 fixes it.

- [ ] **Step 8: Commit**

```bash
git add seer-core/src/logging.rs
git commit -m "feat(logging): add default_level parameter to init_logging

Callers can now opt into a quieter default without setting ARCANUM_LOG_LEVEL
or RUST_LOG. Env vars still take precedence."
```

---

### Task 3: Update CLI to pass `"error"` as its default level

**Files:**
- Modify: `seer-cli/src/main.rs:253`

**Why:** The CLI already has spinner + colored error output; Rust warnings add noise to interactive sessions. Users wanting more detail set `RUST_LOG=warn` (or lower).

- [ ] **Step 1: Update the callsite**

In `seer-cli/src/main.rs`, replace:

```rust
    let _log_guard =
        seer_core::logging::init_logging_with_writer("seer", display::ProgressWriterFactory::new());
```

with:

```rust
    let _log_guard = seer_core::logging::init_logging_with_writer(
        "seer",
        "error",
        display::ProgressWriterFactory::new(),
    );
```

- [ ] **Step 2: Verify it builds**

Run: `cargo build --workspace`
Expected: Success.

- [ ] **Step 3: Smoke-test the CLI**

Run: `./target/debug/seer lookup example.com 2>&1 | head -30`
Expected: No `WARN`-level log lines for the normal path (previously you'd see IANA http:// warnings before we changed them, and other routine warns).

Run: `RUST_LOG=warn ./target/debug/seer lookup example.com 2>&1 | head -30`
Expected: Warnings (if any) surface normally when explicitly requested.

- [ ] **Step 4: Commit**

```bash
git add seer-cli/src/main.rs
git commit -m "feat(cli): default log level to error

Interactive CLI users have the spinner and colored error output;
Rust-side warnings are noise by default. Set RUST_LOG=warn (or lower)
to surface them."
```

---

### Task 4: Downgrade 10 `warn!` calls in `seer-core/src/rdap/client.rs`

**Files:**
- Modify: `seer-core/src/rdap/client.rs`

**Why:** Per the rubric, these are routine/expected events handled gracefully — stale-cache fallback, per-registry partial failures, multi-candidate URL fallback. They belong at `debug!`.

- [ ] **Step 1: Downgrade the stale-cache-after-refresh-error log**

In `seer-core/src/rdap/client.rs` around line 282, replace:

```rust
                    warn!(
                        error = %e,
                        age_hours = cached.age().as_secs() / 3600,
                        "Bootstrap refresh failed, using stale data"
                    );
```

with:

```rust
                    debug!(
                        error = %e,
                        age_hours = cached.age().as_secs() / 3600,
                        "Bootstrap refresh failed, using stale data"
                    );
```

- [ ] **Step 2: Downgrade the RDAP-candidate-failed log**

Around line 454, replace:

```rust
                    if urls.len() > 1 {
                        warn!(
                            url = %url_str,
                            error = %e,
                            candidate = idx + 1,
                            total = urls.len(),
                            "RDAP candidate failed, trying next",
                        );
                    }
```

with:

```rust
                    if urls.len() > 1 {
                        debug!(
                            url = %url_str,
                            error = %e,
                            candidate = idx + 1,
                            total = urls.len(),
                            "RDAP candidate failed, trying next",
                        );
                    }
```

- [ ] **Step 3: Downgrade the 8 per-registry bootstrap warn! calls**

In `seer-core/src/rdap/client.rs`, in `load_bootstrap_data`, there are 8 `warn!` lines — 2 per registry (one for fetch failure, one for parse failure). The current lines look exactly like this (one pair shown; IPv4/IPv6/ASN are analogous):

```rust
                warn!(error = %e, "Failed to parse DNS bootstrap response");
```

and

```rust
            warn!(error = %e, "Failed to fetch DNS bootstrap from IANA");
```

Change the `warn!` token to `debug!` on each. The 8 replacements, in file order:

1. `warn!(error = %e, "Failed to parse DNS bootstrap response");` → `debug!(...)`
2. `warn!(error = %e, "Failed to fetch DNS bootstrap from IANA");` → `debug!(...)`
3. `warn!(error = %e, "Failed to parse IPv4 bootstrap response");` → `debug!(...)`
4. `warn!(error = %e, "Failed to fetch IPv4 bootstrap from IANA");` → `debug!(...)`
5. `warn!(error = %e, "Failed to parse IPv6 bootstrap response");` → `debug!(...)`
6. `warn!(error = %e, "Failed to fetch IPv6 bootstrap from IANA");` → `debug!(...)`
7. `warn!(error = %e, "Failed to parse ASN bootstrap response");` → `debug!(...)`
8. `warn!(error = %e, "Failed to fetch ASN bootstrap from IANA");` → `debug!(...)`

Each is a unique string in the file, so individual Edit calls work. Keep every other character identical — just swap `warn!` for `debug!`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p seer-core rdap:: -- --nocapture`
Expected: All PASS.

- [ ] **Step 5: Run clippy**

Run: `cargo clippy -p seer-core -- -D warnings`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add seer-core/src/rdap/client.rs
git commit -m "fix(rdap): downgrade routine fallback logs to debug

Per-registry bootstrap failures, stale-cache fallback, and multi-candidate
RDAP URL fallback are all handled gracefully and expected in production.
Emit them at debug rather than warn."
```

---

### Task 5: Add `info!` on successful bootstrap load

**Files:**
- Modify: `seer-core/src/rdap/client.rs`

**Why:** Server operators running `seer-api` / `seer-mcp` at INFO level want a one-time "bootstrap loaded, X/4 registries" summary so they can see partial-load posture without digging.

- [ ] **Step 1: Add `info` to the tracing import**

In `seer-core/src/rdap/client.rs` line 11, replace:

```rust
use tracing::{debug, instrument, warn};
```

with:

```rust
use tracing::{debug, info, instrument, warn};
```

- [ ] **Step 2: Emit the info log before returning**

In `seer-core/src/rdap/client.rs`, in `load_bootstrap_data`, replace:

```rust
    Ok(BootstrapData {
        dns,
        ipv4,
        ipv6,
        asn,
    })
}
```

with:

```rust
    info!(
        dns_entries = dns.len(),
        ipv4_ranges = ipv4.len(),
        ipv6_ranges = ipv6.len(),
        asn_ranges = asn.len(),
        "RDAP bootstrap loaded"
    );

    Ok(BootstrapData {
        dns,
        ipv4,
        ipv6,
        asn,
    })
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p seer-core rdap:: -- --nocapture`
Expected: All PASS.

- [ ] **Step 4: Commit**

```bash
git add seer-core/src/rdap/client.rs
git commit -m "feat(rdap): emit info log on successful bootstrap load

Surfaces the per-registry entry counts so operators running API/MCP
at INFO level can see bootstrap posture without enabling debug."
```

---

### Task 6: Downgrade 3 `warn!` calls in retry, whois, bulk

**Files:**
- Modify: `seer-core/src/retry.rs:290`
- Modify: `seer-core/src/whois/client.rs:194`
- Modify: `seer-core/src/bulk/executor.rs:197`

**Why:** All three are "expected outcome surfaced via another channel" — retry exhaustion propagates via `Result`, referral fallback is the documented path, bulk per-item failure is captured in `BulkResult`.

- [ ] **Step 1: Downgrade retry.rs:290**

In `seer-core/src/retry.rs`, replace:

```rust
                    if !is_retryable || attempts_remaining == 0 {
                        if attempt > 0 {
                            warn!(
                                attempt = attempt + 1,
                                max_attempts = self.policy.max_attempts,
                                error = %e,
                                "Operation failed after retries"
                            );
                        }
```

with:

```rust
                    if !is_retryable || attempts_remaining == 0 {
                        if attempt > 0 {
                            debug!(
                                attempt = attempt + 1,
                                max_attempts = self.policy.max_attempts,
                                error = %e,
                                "Operation failed after retries"
                            );
                        }
```

Check the import line at the top of `retry.rs`. If `debug` is not in the `use tracing::{...}` list, add it. If `warn` is no longer used anywhere else in the file (check with grep), remove it.

- [ ] **Step 2: Downgrade whois/client.rs:194**

In `seer-core/src/whois/client.rs`, replace:

```rust
                        Err(e) => {
                            warn!(referral = %referral, error = %e, "Referral lookup failed, using registry response");
                            return Ok(current_response);
                        }
```

with:

```rust
                        Err(e) => {
                            debug!(referral = %referral, error = %e, "Referral lookup failed, using registry response");
                            return Ok(current_response);
                        }
```

Check the `use tracing::{...}` import at the top. Add `debug` if not present; keep `warn` (other warn! calls remain in this file).

- [ ] **Step 3: Downgrade bulk/executor.rs:197**

In `seer-core/src/bulk/executor.rs`, replace:

```rust
                        Err(e) => {
                            warn!(error = %e, "Bulk operation failed");
```

with:

```rust
                        Err(e) => {
                            debug!(error = %e, "Bulk operation failed");
```

Check the `use tracing::{...}` import at the top. Add `debug` if not present; remove `warn` if no other uses remain.

- [ ] **Step 4: Run full workspace tests**

Run: `cargo test --workspace`
Expected: All PASS.

- [ ] **Step 5: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: PASS (if an unused `warn` import was left, this will fail — fix by removing it).

- [ ] **Step 6: Commit**

```bash
git add seer-core/src/retry.rs seer-core/src/whois/client.rs seer-core/src/bulk/executor.rs
git commit -m "fix(logging): downgrade retry/referral/bulk fallback logs to debug

Retry exhaustion surfaces via Result; WHOIS referral fallback is the
documented path; bulk per-item failures are captured in BulkResult.
None are actionable at warn level."
```

---

### Task 7: Configure MCP server to INFO and add startup log

**Files:**
- Modify: `seer-api/seer_api/mcp/server.py`

**Why:** The MCP server currently creates a module logger but never calls `logging.basicConfig`, so Python's root default (`WARNING`) applies. Servers deserve visibility into routine operation.

- [ ] **Step 1: Find the current logger setup**

Locate `logger = logging.getLogger(__name__)` (line 15) in `seer-api/seer_api/mcp/server.py`.

- [ ] **Step 2: Add basicConfig and startup log**

Replace:

```python
logger = logging.getLogger(__name__)
```

with:

```python
# Configure root logging to INFO so operational milestones are visible.
# Host environments can override via standard Python logging config.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)
```

- [ ] **Step 3: Find the main entrypoint**

In `seer-api/seer_api/mcp/server.py`, locate the `async def main()` (or similar) coroutine that calls `stdio_server()`. Use grep if unsure:

Run: `grep -n "stdio_server\|async def main\|def main" seer-api/seer_api/mcp/server.py`

- [ ] **Step 4: Add a startup info log inside main, before serving**

In the main coroutine, immediately before the line that calls `stdio_server()` (or equivalent), add:

```python
    logger.info("MCP server started on stdio")
```

Adjust indentation to match the surrounding code.

- [ ] **Step 5: Smoke-test by importing the module**

Run: `cd seer-api && python -c "import seer_api.mcp.server; print('ok')"`
Expected: prints `ok` without error. No startup log (main not invoked).

- [ ] **Step 6: Commit**

```bash
git add seer-api/seer_api/mcp/server.py
git commit -m "feat(mcp): default Python logging to INFO and log startup

The MCP server never called logging.basicConfig, so Python's WARNING
default applied. Bump to INFO and emit a startup milestone so operators
have baseline visibility."
```

---

### Task 8: Final workspace verification

**Files:**
- None modified

**Why:** Catch any missed tracing imports, lingering warn! calls we meant to change, or test regressions.

- [ ] **Step 1: Full cargo test**

Run: `cargo test --workspace`
Expected: All PASS.

- [ ] **Step 2: Full clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: PASS.

- [ ] **Step 3: Format check**

Run: `cargo fmt --all -- --check`
Expected: PASS.

- [ ] **Step 4: Manual verification — CLI default is quiet**

Run: `./target/debug/seer lookup example.com 2>&1 | head -30`
Expected: No log lines at all (other than normal CLI output).

- [ ] **Step 5: Manual verification — info level surfaces bootstrap summary**

Run: `RUST_LOG=info ./target/debug/seer lookup example.com 2>&1 | grep -i "bootstrap loaded" | head -1`
Expected: One line like `... INFO ... RDAP bootstrap loaded dns_entries=... ipv4_ranges=... ipv6_ranges=... asn_ranges=...`.

- [ ] **Step 6: Manual verification — warn level surfaces real warnings**

Run: `RUST_LOG=warn ./target/debug/seer lookup example.com 2>&1 | head -20`
Expected: No warnings on a healthy run. (If a warning appears, confirm it's one we intended to keep — circular referral, unsafe server, lock poisoning, etc.)

- [ ] **Step 7: Spot-check that intended files have zero remaining `warn!`**

Run: `grep -c "warn!(" seer-core/src/rdap/client.rs`
Expected: `0`

Run: `grep -c "warn!(" seer-core/src/bulk/executor.rs`
Expected: `0`

Run: `grep -c "warn!(" seer-core/src/retry.rs`
Expected: `0`

For `whois/client.rs`, several `warn!` calls are intentionally kept (circular referral, max depth, unsafe server, partial reads). Verify by inspection:

Run: `grep -n "warn!\|tracing::warn!" seer-core/src/whois/client.rs`
Expected: 5 lines — line numbers approximately 134, 143, 257, 321, 346. None should be on the "Referral lookup failed, using registry response" line (we downgraded that one).

- [ ] **Step 8: If everything passes, this task is complete.**

No commit needed — this is verification only.

---

## Summary

After execution:

- One new convention doc users can link to (`docs/logging-conventions.md`)
- 13 Rust-side level downgrades (10 in `rdap/client.rs`, 1 each in `retry.rs`, `whois/client.rs`, `bulk/executor.rs`)
- 1 new `info!` in `rdap/client.rs` for successful bootstrap loads
- 1 new Python `logger.info` startup message in the MCP server
- `init_logging` / `init_logging_with_writer` take a `default_level` parameter; CLI passes `"error"`
- MCP server calls `logging.basicConfig(level=logging.INFO)`
- All remaining `warn!` calls are intentional and match the rubric
