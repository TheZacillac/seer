# Bulk Operation Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the existing Rust progress callback through the CLI (new `--progress` flag with a live bar), the Python bindings (new optional `progress` kwarg on all 7 `bulk_*` functions), and the FastAPI server (new SSE streaming variants of the 5 existing `/bulk` endpoints).

**Architecture:** The Rust core's `BulkExecutor::execute` already accepts an `Option<ProgressCallback>`. All three interfaces construct their own callback and pass it through. The CLI uses `indicatif` (already wired into tracing via `display/progress.rs`) with a new `--progress <mode>` flag. The Python bindings accept a kwarg that the PyO3 wrapper converts to a Rust closure with GIL acquisition. The FastAPI server adds `/stream` variants that use `StreamingResponse` + an `asyncio.Queue` bridge driven by the Python callback.

**Tech Stack:** Rust (tokio, clap, indicatif, pyo3), Python (FastAPI, starlette.responses.StreamingResponse, pytest).

**Reference spec:** `docs/superpowers/specs/2026-04-17-bulk-observability-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `seer-cli/src/main.rs` | Modify | Add `--progress <mode>` to `Commands::Bulk`; construct callback + wire progress bar; TTY/`--format json` interaction |
| `seer-cli/tests/` (new) | Create | Clap integration tests for `--progress` parsing |
| `seer-py/src/lib.rs` | Modify | Add optional `progress` kwarg to all 7 `bulk_*` functions; PyO3 callback wrapper with GIL + exception swallowing |
| `seer-py/python/seer/__init__.py` | Modify | Update re-export type hints |
| `seer-py/tests/` (new) | Create | Integration tests for progress callback + exception handling |
| `seer-api/seer_api/routers/lookup.py` | Modify | Add `POST /lookup/bulk/stream` SSE route |
| `seer-api/seer_api/routers/whois.py` | Modify | Add `POST /whois/bulk/stream` SSE route |
| `seer-api/seer_api/routers/dns.py` | Modify | Add `POST /dns/bulk/stream` SSE route |
| `seer-api/seer_api/routers/propagation.py` | Modify | Add `POST /propagation/bulk/stream` SSE route |
| `seer-api/seer_api/routers/status.py` | Modify | Add `POST /status/bulk/stream` SSE route |
| `seer-api/seer_api/streaming.py` (new) | Create | Shared SSE helper: run bulk in executor, bridge callback → `asyncio.Queue`, yield SSE events |
| `seer-api/tests/test_streaming.py` (new) | Create | FastAPI TestClient SSE tests for one endpoint (others are mechanical copies) |

---

## Architecture notes the engineer needs

**Rust progress callback (already exists, do NOT change):**
```rust
pub type ProgressCallback = Box<dyn Fn(usize, usize, &str) + Send + Sync>;
```
Fires in `BulkExecutor::execute` (`seer-core/src/bulk/executor.rs:174`) **after** each item completes. Arguments: `(completed, total, current_domain)`. `completed` is 1-indexed — when the first of 100 items finishes, the callback gets `(1, 100, "example.com")`.

**Existing CLI progress infra (do NOT change):**
`seer-cli/src/display/progress.rs` exposes `set_bulk_progress_bar`, `clear_bulk_progress_bar`, `get_bulk_progress_bar`, and a `ProgressWriter`/`ProgressWriterFactory` already registered with the tracing subscriber via `init_logging_with_writer`. While a bar is "active" (set via `set_bulk_progress_bar`), tracing log output flows through `pb.println(...)` instead of stderr, keeping the bar stable.

**CLI bulk call site:**
`seer-cli/src/main.rs:574` currently reads `let results = executor.execute(operations, None).await;` — this is the single line that has to gain a progress callback.

**FastAPI pattern:**
Existing `/bulk` routes run the Python bulk call in a worker thread via `loop.run_in_executor(None, seer.bulk_*, ...)`. The streaming variants use the same pattern but wrap with `StreamingResponse` and feed events from an `asyncio.Queue`. The callback (a plain Python function) pushes events onto the queue; the async generator consumes from the queue. A sentinel `None` (or similar) signals completion.

---

### Task 1: Add `--progress` flag to the CLI

**Files:**
- Modify: `seer-cli/src/main.rs`

**Why:** Introduce the CLI surface and the `ProgressMode` enum without yet wiring callbacks or the progress bar. Keeps the first step small and testable.

- [ ] **Step 1: Add the ProgressMode enum**

Near the top of `seer-cli/src/main.rs`, after the existing `use clap_complete::...` line (around line 8), add a clap-derived enum:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "lowercase")]
enum ProgressMode {
    /// Progress bar only (default in a TTY)
    Bar,
    /// Progress bar plus per-item completion lines
    Verbose,
    /// Progress bar plus per-failure lines; successes silent
    Failures,
    /// No bar, no per-item output (default when piped or when --format json)
    None,
}
```

- [ ] **Step 2: Add `--progress` to the Bulk subcommand**

In the `Commands::Bulk { ... }` variant (around line 126), add a new field before the closing `}`:

```rust
        /// Progress display mode for bulk runs
        #[arg(long, value_enum)]
        progress: Option<ProgressMode>,
```

Note: `Option<ProgressMode>` (not `ProgressMode` with a default) so we can distinguish "user didn't pass --progress" from "user asked for bar". Default resolution happens at runtime based on TTY and `--format`.

- [ ] **Step 3: Accept the new field in the match arm without using it yet**

In the `Commands::Bulk { ... } => { ... }` arm at line 474, destructure the new field by extending the pattern:

```rust
        Commands::Bulk {
            operation,
            file,
            record_type,
            output,
            progress,
        } => {
```

Then inside the arm (right after destructuring, before any other logic), add a single line that silences an unused-variable warning for now:

```rust
            let _progress_mode = progress;
```

(This one-line parking lot will be replaced in Task 3.)

- [ ] **Step 4: Verify it builds**

Run: `cargo build -p seer-cli`
Expected: Success.

- [ ] **Step 5: Verify clap parses the flag**

Run: `./target/debug/seer bulk lookup --help 2>&1 | grep -i progress`
Expected: output contains `--progress` and lists the four values.

Run: `./target/debug/seer bulk --progress junk lookup /tmp/nonexistent 2>&1`
Expected: clap error mentioning invalid value for `--progress`.

- [ ] **Step 6: Commit**

```bash
git add seer-cli/src/main.rs
git commit -m "feat(cli): add --progress flag scaffold for bulk

Adds a ProgressMode enum (bar/verbose/failures/none) and wires it
through clap to Commands::Bulk. The flag is not yet consumed; that
lands in the next task."
```

---

### Task 2: Resolve the effective progress mode at runtime

**Files:**
- Modify: `seer-cli/src/main.rs`

**Why:** Decide the effective `ProgressMode` based on the flag, the TTY state of stderr, and the `--format` flag. Keeping this logic in one pure function makes it testable and isolates the policy from the wiring in Task 3.

- [ ] **Step 1: Write failing tests**

At the bottom of `seer-cli/src/main.rs` (before the final `}`), add:

```rust
#[cfg(test)]
mod progress_mode_tests {
    use super::{resolve_progress_mode, ProgressMode};

    #[test]
    fn explicit_mode_is_honored_on_tty() {
        assert_eq!(
            resolve_progress_mode(Some(ProgressMode::Verbose), true, "human"),
            ProgressMode::Verbose
        );
        assert_eq!(
            resolve_progress_mode(Some(ProgressMode::None), true, "human"),
            ProgressMode::None
        );
    }

    #[test]
    fn explicit_mode_is_honored_on_non_tty() {
        // User-explicit bar on non-TTY is honored even though auto would downgrade.
        assert_eq!(
            resolve_progress_mode(Some(ProgressMode::Bar), false, "human"),
            ProgressMode::Bar
        );
    }

    #[test]
    fn explicit_mode_overrides_json_format() {
        // Explicit --progress overrides the --format json implication.
        assert_eq!(
            resolve_progress_mode(Some(ProgressMode::Bar), true, "json"),
            ProgressMode::Bar
        );
    }

    #[test]
    fn default_is_bar_on_tty_with_human_format() {
        assert_eq!(
            resolve_progress_mode(None, true, "human"),
            ProgressMode::Bar
        );
    }

    #[test]
    fn default_is_none_on_non_tty() {
        assert_eq!(
            resolve_progress_mode(None, false, "human"),
            ProgressMode::None
        );
    }

    #[test]
    fn default_is_none_with_json_format() {
        assert_eq!(
            resolve_progress_mode(None, true, "json"),
            ProgressMode::None
        );
    }
}
```

- [ ] **Step 2: Run the tests (expected to fail)**

Run: `cargo test -p seer-cli progress_mode_tests`
Expected: compile error — `resolve_progress_mode` doesn't exist yet.

- [ ] **Step 3: Implement the resolver**

Near the `ProgressMode` enum in `seer-cli/src/main.rs`, add:

```rust
/// Resolves the effective progress mode given the user's flag, whether stderr
/// is a TTY, and the output format.
///
/// Rules:
/// - An explicit `--progress <mode>` always wins.
/// - Otherwise `--format json` implies `None` (JSON output must be clean).
/// - Otherwise on a non-TTY stderr, default to `None`.
/// - Otherwise default to `Bar`.
fn resolve_progress_mode(
    flag: Option<ProgressMode>,
    stderr_is_tty: bool,
    format: &str,
) -> ProgressMode {
    if let Some(mode) = flag {
        return mode;
    }
    if format.eq_ignore_ascii_case("json") {
        return ProgressMode::None;
    }
    if !stderr_is_tty {
        return ProgressMode::None;
    }
    ProgressMode::Bar
}
```

- [ ] **Step 4: Run the tests (expected to pass)**

Run: `cargo test -p seer-cli progress_mode_tests`
Expected: 6/6 PASS.

- [ ] **Step 5: Use the resolver in the Bulk arm**

In `seer-cli/src/main.rs` inside `Commands::Bulk { ... } => { ... }`, replace the Task 1 parking-lot line:

```rust
            let _progress_mode = progress;
```

with:

```rust
            let stderr_is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
            let progress_mode = resolve_progress_mode(progress, stderr_is_tty, &cli.format);
```

If `std::io::IsTerminal` is missing due to MSRV, use `atty::is(atty::Stream::Stderr)` instead — but `IsTerminal` has been stable since Rust 1.70 so this should work. `cli.format` refers to the outer `--format` flag defined on the `Cli` struct.

- [ ] **Step 6: Verify it still builds**

Run: `cargo build -p seer-cli`
Expected: Success.

- [ ] **Step 7: Commit**

```bash
git add seer-cli/src/main.rs
git commit -m "feat(cli): resolve progress mode from flag, TTY, and format

Pure function resolve_progress_mode(flag, stderr_is_tty, format) decides
the effective ProgressMode. Six unit tests cover the policy."
```

---

### Task 3: Wire the progress bar into the CLI bulk path

**Files:**
- Modify: `seer-cli/src/main.rs`

**Why:** This is the user-visible change: running `seer bulk lookup domains.txt` now shows a live bar, scrolled lines, or nothing, depending on the resolved mode.

- [ ] **Step 1: Add imports for the progress-bar pieces**

Near the top of `seer-cli/src/main.rs`, add:

```rust
use std::sync::Arc;
use indicatif::{ProgressBar, ProgressStyle};
```

(If `indicatif` is not already a direct dependency of `seer-cli`, verify by grep-ing `seer-cli/Cargo.toml` for `indicatif` — it's used by `display/progress.rs`, so it should already be a direct dep. If not, add `indicatif = "0.17"` under `[dependencies]`.)

- [ ] **Step 2: Build the progress callback inside the Bulk arm**

In `seer-cli/src/main.rs`, inside the `Commands::Bulk { ... } => { ... }` arm, find the line (after Task 2 integration):

```rust
            let results = executor.execute(operations, None).await;
```

Replace that single line with the block below. All bar/callback setup happens immediately before the `execute` call; cleanup happens immediately after.

```rust
            let total = operations.len();

            // Construct the progress bar (when applicable) and activate it for
            // tracing integration so log lines route through pb.println().
            let pb: Option<Arc<ProgressBar>> = match progress_mode {
                ProgressMode::None => None,
                ProgressMode::Bar | ProgressMode::Verbose | ProgressMode::Failures => {
                    let bar = ProgressBar::new(total as u64);
                    bar.set_style(
                        ProgressStyle::default_bar()
                            .template(
                                "{bar:40.cyan/blue} {pos}/{len} ({percent}%) eta {eta} {msg}",
                            )
                            .expect("valid progress bar template")
                            .progress_chars("=>-"),
                    );
                    display::progress::set_bulk_progress_bar(bar.clone());
                    Some(Arc::new(bar))
                }
            };

            let callback: Option<seer_core::bulk::ProgressCallback> = pb.as_ref().map(|bar| {
                let bar = bar.clone();
                let mode = progress_mode;
                Box::new(move |completed: usize, _total: usize, domain: &str| {
                    bar.set_position(completed as u64);
                    bar.set_message(domain.to_string());
                }) as seer_core::bulk::ProgressCallback
            });

            let results = executor.execute(operations, callback).await;

            // Emit per-item lines according to mode, then clear the bar.
            if let Some(bar) = pb.as_ref() {
                for r in &results {
                    let domain = match &r.operation {
                        seer_core::bulk::BulkOperation::Whois { domain }
                        | seer_core::bulk::BulkOperation::Rdap { domain }
                        | seer_core::bulk::BulkOperation::Dns { domain, .. }
                        | seer_core::bulk::BulkOperation::Propagation { domain, .. }
                        | seer_core::bulk::BulkOperation::Lookup { domain }
                        | seer_core::bulk::BulkOperation::Status { domain }
                        | seer_core::bulk::BulkOperation::Avail { domain }
                        | seer_core::bulk::BulkOperation::Info { domain } => domain.as_str(),
                    };
                    match (progress_mode, r.success) {
                        (ProgressMode::Verbose, true) => {
                            bar.println(format!("{} {} ({}ms)", "\u{2713}".ctp_green(), domain, r.duration_ms));
                        }
                        (ProgressMode::Verbose, false) | (ProgressMode::Failures, false) => {
                            let err = r.error.as_deref().unwrap_or("unknown error");
                            bar.println(format!("{} {} ({})", "\u{2717}".ctp_red(), domain, err));
                        }
                        _ => {}
                    }
                }
                bar.finish_and_clear();
                display::progress::clear_bulk_progress_bar();
            }
```

- [ ] **Step 3: Verify it builds**

Run: `cargo build -p seer-cli`
Expected: Success.

- [ ] **Step 4: Manual smoke tests**

Create a test input file:

```bash
cat > /tmp/seer-bulk-test.txt <<'EOF'
example.com
iana.org
google.com
EOF
```

Run each mode and eyeball the output on stderr (network access required):

```bash
./target/debug/seer bulk status /tmp/seer-bulk-test.txt --progress bar
./target/debug/seer bulk status /tmp/seer-bulk-test.txt --progress verbose
./target/debug/seer bulk status /tmp/seer-bulk-test.txt --progress failures
./target/debug/seer bulk status /tmp/seer-bulk-test.txt --progress none
./target/debug/seer bulk status /tmp/seer-bulk-test.txt            # default: bar on TTY
./target/debug/seer bulk status /tmp/seer-bulk-test.txt > /dev/null  # default: none (stdout piped, but we care about stderr TTY)
```

Expected: `bar` shows a bar that advances. `verbose` shows checkmark lines + bar. `failures` shows only failed-domain lines. `none` shows nothing on stderr.

- [ ] **Step 5: Verify `--format json` implies quiet**

Run: `./target/debug/seer --format json bulk status /tmp/seer-bulk-test.txt 2>&1 1>/dev/null`
Expected: stderr produces NO progress-bar or per-item lines. (The CSV is still written to disk; that's orthogonal.)

Run: `./target/debug/seer --format json bulk status /tmp/seer-bulk-test.txt --progress bar 2>&1 1>/dev/null | head -5`
Expected: explicit `--progress bar` overrides the json implication; the bar appears on stderr.

- [ ] **Step 6: Run workspace tests and clippy**

Run: `cargo test --workspace`
Expected: all PASS.

Run: `cargo clippy --workspace -- -D warnings`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add seer-cli/src/main.rs
git commit -m "feat(cli): show live progress during bulk runs

Wire a ProgressBar into the bulk command per the resolved ProgressMode.
--progress bar shows a live bar; verbose adds per-item success lines;
failures prints only failures; none disables all output. The existing
tracing-aware writer keeps log lines stable above the bar."
```

---

### Task 4: Add optional `progress` kwarg to Python bulk functions

**Files:**
- Modify: `seer-py/src/lib.rs`

**Why:** Expose progress to Python consumers (notebooks, `familiar`, `tower`). This is the bridge layer — the Rust side of the Python callable.

- [ ] **Step 1: Add a small helper that builds a Rust callback from an optional Python callable**

In `seer-py/src/lib.rs`, at the top-level scope (not inside any function), add:

```rust
/// Converts an optional Python callable into a Rust `ProgressCallback`.
///
/// The returned callback acquires the GIL on every invocation. Exceptions
/// raised from the Python callable are logged at `warn` and swallowed —
/// a broken progress callback must not kill a bulk run.
fn build_progress_callback(
    progress: Option<Py<PyAny>>,
) -> Option<seer_core::bulk::ProgressCallback> {
    progress.map(|py_cb| {
        Box::new(move |completed: usize, total: usize, domain: &str| {
            Python::with_gil(|py| {
                let bound = py_cb.bind(py);
                if let Err(err) = bound.call1((completed, total, domain)) {
                    tracing::warn!(error = %err, "bulk progress callback raised; ignoring");
                }
            });
        }) as seer_core::bulk::ProgressCallback
    })
}
```

Add `use pyo3::Py;` and `use pyo3::types::PyAny;` to the imports near the top of the file if not already imported (check the existing `use pyo3::...;` lines).

- [ ] **Step 2: Extend every `bulk_*` function signature**

Each existing `bulk_*` function has this pattern:

```rust
#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10))]
fn bulk_lookup(py: Python<'_>, domains: Vec<String>, concurrency: usize) -> PyResult<PyObject> {
    let rt = get_runtime();
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);
    ...
    let result =
        py.allow_threads(|| rt.block_on(async { executor.execute(operations, None).await }));
    ...
}
```

For **each of the 7 functions** (`bulk_lookup`, `bulk_whois`, `bulk_dig`, `bulk_propagation`, `bulk_status`, `bulk_availability`, `bulk_info`), apply the following two-line edit:

1. Extend the signature with a keyword-only `progress` parameter. The `#[pyo3(signature = ...)]` attribute gains `*, progress = None`. Example for `bulk_lookup`:

```rust
#[pyo3(signature = (domains, concurrency = 10, *, progress = None))]
fn bulk_lookup(
    py: Python<'_>,
    domains: Vec<String>,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
) -> PyResult<PyObject> {
```

2. Replace the `executor.execute(operations, None)` call with `executor.execute(operations, build_progress_callback(progress))`. Example:

```rust
    let cb = build_progress_callback(progress);
    let result =
        py.allow_threads(|| rt.block_on(async { executor.execute(operations, cb).await }));
```

**For functions with an intermediate parameter** (`bulk_dig` and `bulk_propagation` take `record_type: &str` between `domains` and `concurrency`), preserve parameter order and add `progress` at the very end:

```rust
#[pyo3(signature = (domains, record_type = "A", concurrency = 10, *, progress = None))]
fn bulk_dig(
    py: Python<'_>,
    domains: Vec<String>,
    record_type: &str,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
) -> PyResult<PyObject> {
```

Do this for all 7 functions: `bulk_lookup` (line ~265), `bulk_whois` (line ~283), `bulk_dig` (line ~301), `bulk_propagation` (line ~331), `bulk_status` (line ~378), `bulk_availability` (line ~396), `bulk_info` (line ~657).

- [ ] **Step 3: Verify it builds**

Run: `cd seer-py && cargo check`
Expected: Success.

- [ ] **Step 4: Build Python extension and smoke-test**

Run: `cd seer-py && maturin develop --release`
Expected: builds and installs.

Run:

```bash
cd /home/zac/Projects/arcanum_suite/seer
python -c "
import seer
calls = []
seer.bulk_whois(['example.com', 'iana.org'], concurrency=2, progress=lambda c, t, d: calls.append((c, t, d)))
print('calls:', calls)
assert len(calls) == 2, f'expected 2 calls, got {len(calls)}'
assert calls[-1][0] == 2, f'last completed should be 2, got {calls[-1][0]}'
print('OK')
"
```

Expected: prints the 2 callback tuples, then `OK`. Requires network.

- [ ] **Step 5: Commit**

```bash
git add seer-py/src/lib.rs
git commit -m "feat(py): add optional progress callback to bulk_* functions

All 7 bulk_* functions gain a keyword-only progress parameter. Python
exceptions from the callback are logged and swallowed so a broken
callback can't kill a bulk run."
```

---

### Task 5: Integration tests for the Python progress callback

**Files:**
- Create: `seer-py/tests/test_bulk_progress.py`
- Create: `seer-py/tests/conftest.py` (if it doesn't exist)
- Modify: `seer-py/pyproject.toml` (only if pytest isn't already declared)

**Why:** TDD coverage for the kwarg so future refactors don't silently drop it. The test uses `bulk_status` against a local loopback domain list so it exercises the callback machinery without relying on external network calls for its correctness-critical assertion.

- [ ] **Step 1: Ensure the tests directory exists**

```bash
mkdir -p /home/zac/Projects/arcanum_suite/seer/seer-py/tests
```

- [ ] **Step 2: Add pytest to the seer-py pyproject.toml (if missing)**

Open `seer-py/pyproject.toml`. If there's no `[project.optional-dependencies]` or `[dependency-groups]` section declaring pytest, add:

```toml
[dependency-groups]
dev = ["pytest>=7"]
```

If pytest is already declared somewhere, skip this step.

- [ ] **Step 3: Create `tests/conftest.py` (if missing)**

Create `/home/zac/Projects/arcanum_suite/seer/seer-py/tests/conftest.py` with:

```python
"""Shared pytest config for seer-py tests."""
```

(Empty marker file to make pytest discover the dir.)

- [ ] **Step 4: Write the progress-callback integration tests**

Create `/home/zac/Projects/arcanum_suite/seer/seer-py/tests/test_bulk_progress.py`:

```python
"""Integration tests for the optional progress= kwarg on bulk_* functions."""

import pytest

import seer


def test_progress_callback_invoked_once_per_item():
    """The callback should fire exactly once per completed item, 1-indexed."""
    calls = []
    domains = ["example.com", "iana.org"]

    seer.bulk_status(
        domains,
        concurrency=2,
        progress=lambda completed, total, domain: calls.append(
            (completed, total, domain)
        ),
    )

    assert len(calls) == len(domains), (
        f"expected {len(domains)} callback calls, got {len(calls)}: {calls}"
    )
    totals = {c[1] for c in calls}
    assert totals == {len(domains)}, f"total mismatch: {totals}"
    completed_values = sorted(c[0] for c in calls)
    assert completed_values == list(range(1, len(domains) + 1)), (
        f"completed values should be 1..N, got {completed_values}"
    )
    callback_domains = {c[2] for c in calls}
    assert callback_domains == set(domains), (
        f"domain set mismatch: {callback_domains} vs {set(domains)}"
    )


def test_progress_callback_exceptions_are_swallowed():
    """A raising callback must not kill the bulk run."""
    attempts = []

    def raising_cb(completed, total, domain):
        attempts.append(domain)
        raise RuntimeError("intentional test failure")

    results = seer.bulk_status(
        ["example.com", "iana.org"],
        concurrency=2,
        progress=raising_cb,
    )

    assert len(results) == 2, f"expected 2 results, got {len(results)}"
    assert len(attempts) == 2, (
        f"callback should still have been invoked twice, got {len(attempts)}"
    )


def test_progress_kwarg_is_optional():
    """Omitting progress= should preserve today's behavior."""
    results = seer.bulk_status(["example.com"], concurrency=1)
    assert len(results) == 1
```

- [ ] **Step 5: Run the tests**

Run:

```bash
cd /home/zac/Projects/arcanum_suite/seer/seer-py && pytest tests/test_bulk_progress.py -v
```

Expected: 3 PASS. Requires network (lookups against example.com and iana.org).

If the environment can't reach the network, tests may fail at the lookup step but the assertions on callback counts should still hold (the callback fires after completion regardless of success). If a test fails for an obviously-network reason (timeouts, DNS errors), note it in the report but do NOT mark the task BLOCKED on environment.

- [ ] **Step 6: Commit**

```bash
git add seer-py/tests/ seer-py/pyproject.toml
git commit -m "test(py): add integration tests for bulk progress callback

Cover: callback fires exactly once per item, exceptions are swallowed,
progress= is optional."
```

---

### Task 6: Shared SSE helper for the API

**Files:**
- Create: `seer-api/seer_api/streaming.py`

**Why:** All 5 streaming endpoints share the same bridge: push progress and item events onto an `asyncio.Queue` fed by a Python callback, yield them as SSE. Factor that out now so Task 7 is mechanical copies.

- [ ] **Step 1: Create the helper**

Write `/home/zac/Projects/arcanum_suite/seer/seer-api/seer_api/streaming.py`:

```python
"""Shared helpers for SSE-streaming bulk endpoints.

Every streaming endpoint has the same shape: run a blocking `seer.bulk_*`
call in a worker thread, feed progress + per-item events onto an asyncio
queue via a Python callback, yield them as text/event-stream events, and
close with a final `done` event.
"""

import asyncio
import json
import time
from collections.abc import AsyncGenerator, Callable
from typing import Any

from starlette.responses import StreamingResponse


_DONE = object()  # sentinel signalling bulk call completed


def _sse(event: str, data: dict) -> bytes:
    """Format a single Server-Sent Event."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


async def stream_bulk(
    bulk_call: Callable[..., list[dict]],
    *args: Any,
    **kwargs: Any,
) -> StreamingResponse:
    """Run `bulk_call(*args, progress=cb, **kwargs)` in a worker thread and
    return a StreamingResponse that emits SSE events as items complete.

    The callable must accept a `progress` keyword argument matching the
    shape `(completed: int, total: int, domain: str) -> None`.
    """
    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_running_loop()
    started_at = time.monotonic()

    def progress_cb(completed: int, total: int, domain: str) -> None:
        # Called from a worker thread — use call_soon_threadsafe.
        loop.call_soon_threadsafe(
            queue.put_nowait,
            ("progress", {"completed": completed, "total": total, "current_domain": domain}),
        )

    def run_and_finish() -> list[dict]:
        try:
            return bulk_call(*args, progress=progress_cb, **kwargs)
        finally:
            pass  # Results are emitted by the caller below after this returns.

    bulk_future = loop.run_in_executor(None, run_and_finish)

    async def event_stream() -> AsyncGenerator[bytes, None]:
        # Phase 1: stream progress events until the bulk call finishes.
        pending_results = None
        done = False
        while not done:
            get_task = asyncio.create_task(queue.get())
            completed_task = asyncio.ensure_future(bulk_future) if not bulk_future.done() else None
            wait_set = {get_task}
            if completed_task is not None:
                wait_set.add(completed_task)
            finished, _ = await asyncio.wait(wait_set, return_when=asyncio.FIRST_COMPLETED)
            if get_task in finished:
                event, payload = get_task.result()
                yield _sse(event, payload)
            else:
                get_task.cancel()
            if bulk_future.done():
                # Drain any queued progress events that arrived after the future
                # completed but before we noticed.
                while not queue.empty():
                    event, payload = queue.get_nowait()
                    yield _sse(event, payload)
                pending_results = bulk_future.result()
                done = True

        # Phase 2: emit one `item` event per result.
        succeeded = 0
        failed = 0
        assert pending_results is not None
        for item in pending_results:
            if item.get("success"):
                succeeded += 1
            else:
                failed += 1
            yield _sse("item", item)

        # Phase 3: emit the terminal `done` event.
        yield _sse(
            "done",
            {
                "total": len(pending_results),
                "succeeded": succeeded,
                "failed": failed,
                "duration_ms": int((time.monotonic() - started_at) * 1000),
            },
        )

    return StreamingResponse(event_stream(), media_type="text/event-stream")
```

- [ ] **Step 2: Verify the module imports**

Run: `cd /home/zac/Projects/arcanum_suite/seer/seer-api && python -c "import seer_api.streaming; print('ok')"`
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add seer-api/seer_api/streaming.py
git commit -m "feat(api): add SSE streaming helper for bulk endpoints

Shared stream_bulk() runs a bulk_* call in a worker thread, bridges
its progress callback onto an asyncio queue, and yields progress/item/
done Server-Sent Events."
```

---

### Task 7: Wire streaming endpoints into the 5 bulk routers

**Files:**
- Modify: `seer-api/seer_api/routers/lookup.py`
- Modify: `seer-api/seer_api/routers/whois.py`
- Modify: `seer-api/seer_api/routers/dns.py`
- Modify: `seer-api/seer_api/routers/propagation.py`
- Modify: `seer-api/seer_api/routers/status.py`

**Why:** Each router gets a `/bulk/stream` variant that delegates to `stream_bulk`. The 5 routers all follow the same pattern; do them together as a single commit for consistency.

- [ ] **Step 1: Add the streaming route to `lookup.py`**

At the bottom of `/home/zac/Projects/arcanum_suite/seer/seer-api/seer_api/routers/lookup.py`, add:

```python
from seer_api.streaming import stream_bulk


@router.post("/bulk/stream")
@limiter.limit("10/minute")
async def bulk_smart_lookup_stream(request: Request, body: BulkLookupRequest):
    """Stream bulk smart-lookup results as Server-Sent Events.

    Emits `progress`, `item`, and `done` events. Matches /bulk semantics;
    see the sync version for request/response details.
    """
    try:
        return await stream_bulk(seer.bulk_lookup, body.domains, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk lookup stream failed")
```

- [ ] **Step 2: Add the streaming route to `whois.py`**

Follow the same pattern in `seer-api/seer_api/routers/whois.py`:

```python
from seer_api.streaming import stream_bulk


@router.post("/bulk/stream")
@limiter.limit("10/minute")
async def bulk_whois_stream(request: Request, body: BulkWhoisRequest):
    """Stream bulk WHOIS lookups as Server-Sent Events."""
    try:
        return await stream_bulk(seer.bulk_whois, body.domains, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk WHOIS stream failed")
```

- [ ] **Step 3: Add the streaming route to `dns.py`**

Read the file first to identify the request body type and the seer function name. The sync `POST /bulk` calls `seer.bulk_dig(domains, record_type, concurrency)` (confirm by reading the existing handler). Add:

```python
from seer_api.streaming import stream_bulk


@router.post("/bulk/stream")
@limiter.limit("10/minute")
async def bulk_dns_stream(request: Request, body: BulkDnsRequest):
    """Stream bulk DNS queries as Server-Sent Events."""
    try:
        return await stream_bulk(
            seer.bulk_dig, body.domains, body.record_type, body.concurrency
        )
    except Exception as e:
        raise http_error(e, "Bulk DNS stream failed")
```

If the existing sync handler calls `seer.bulk_dig` with a different argument order, mirror whatever the sync route does. The body-attribute names (`body.domains`, `body.record_type`, `body.concurrency`) should already exist on `BulkDnsRequest`.

- [ ] **Step 4: Add the streaming route to `propagation.py`**

```python
from seer_api.streaming import stream_bulk


@router.post("/bulk/stream")
@limiter.limit("10/minute")
async def bulk_propagation_stream(request: Request, body: BulkPropagationRequest):
    """Stream bulk DNS-propagation checks as Server-Sent Events."""
    try:
        return await stream_bulk(
            seer.bulk_propagation, body.domains, body.record_type, body.concurrency
        )
    except Exception as e:
        raise http_error(e, "Bulk propagation stream failed")
```

Again, mirror the arg order used by the existing `POST /bulk` handler in the same file.

- [ ] **Step 5: Add the streaming route to `status.py`**

```python
from seer_api.streaming import stream_bulk


@router.post("/bulk/stream")
@limiter.limit("10/minute")
async def bulk_status_stream(request: Request, body: BulkStatusRequest):
    """Stream bulk status checks as Server-Sent Events."""
    try:
        return await stream_bulk(seer.bulk_status, body.domains, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk status stream failed")
```

- [ ] **Step 6: Verify all routers parse**

Run: `cd /home/zac/Projects/arcanum_suite/seer/seer-api && python -c "from seer_api.main import app; print('ok')"`
Expected: `ok` (imports the full app, which wires all routers).

- [ ] **Step 7: List the new routes to confirm they register**

Run:

```bash
cd /home/zac/Projects/arcanum_suite/seer/seer-api && python -c "
from seer_api.main import app
for route in app.routes:
    path = getattr(route, 'path', '')
    if 'stream' in path:
        print(path)
"
```

Expected output: 5 lines, one per new endpoint (e.g., `/lookup/bulk/stream`, `/whois/bulk/stream`, etc.). Exact paths depend on the routers' `prefix` configuration — verify the prefixes in `seer_api/main.py` and update the expected output accordingly.

- [ ] **Step 8: Commit**

```bash
git add seer-api/seer_api/routers/
git commit -m "feat(api): add SSE streaming variants for 5 bulk endpoints

Each of /lookup/bulk, /whois/bulk, /dns/bulk, /propagation/bulk, and
/status/bulk gains a /stream companion that emits progress/item/done
Server-Sent Events via the shared streaming helper."
```

---

### Task 8: Integration test for one SSE endpoint

**Files:**
- Create: `seer-api/tests/test_streaming.py`

**Why:** One end-to-end test covers the shared plumbing in `streaming.py`. Adding tests for the other 4 routers would be mechanical copies and is YAGNI — if `status/bulk/stream` works, the shared helper works.

- [ ] **Step 1: Check existing test infrastructure**

Read `/home/zac/Projects/arcanum_suite/seer/seer-api/tests/conftest.py` to see how the existing suite spins up a `TestClient`. Use the same fixture.

- [ ] **Step 2: Write the test file**

Create `/home/zac/Projects/arcanum_suite/seer/seer-api/tests/test_streaming.py`:

```python
"""SSE streaming bulk-endpoint integration test.

One end-to-end test over /status/bulk/stream proves the shared streaming
helper works. Other /bulk/stream endpoints use the same helper.
"""

import json


def _parse_sse(body: str) -> list[dict]:
    """Parse an SSE response body into a list of {event, data} dicts."""
    events = []
    for block in body.strip().split("\n\n"):
        event = None
        data = None
        for line in block.splitlines():
            if line.startswith("event: "):
                event = line[len("event: "):]
            elif line.startswith("data: "):
                data = line[len("data: "):]
        if event is None or data is None:
            continue
        events.append({"event": event, "data": json.loads(data)})
    return events


def test_status_bulk_stream_emits_expected_event_sequence(client):
    """Submitting 2 domains should produce 2 progress, 2 item, 1 done event."""
    resp = client.post(
        "/status/bulk/stream",
        json={"domains": ["example.com", "iana.org"], "concurrency": 2},
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/event-stream")

    events = _parse_sse(resp.text)
    event_types = [e["event"] for e in events]

    # Exactly 2 progress, 2 item, 1 done
    assert event_types.count("progress") == 2, event_types
    assert event_types.count("item") == 2, event_types
    assert event_types.count("done") == 1, event_types

    # `done` is the final event
    assert event_types[-1] == "done"

    # progress fields
    progresses = [e for e in events if e["event"] == "progress"]
    for p in progresses:
        assert set(p["data"].keys()) == {"completed", "total", "current_domain"}
        assert p["data"]["total"] == 2

    # item fields
    items = [e for e in events if e["event"] == "item"]
    for it in items:
        assert "success" in it["data"]
        assert "duration_ms" in it["data"]

    # done totals line up
    done = next(e for e in events if e["event"] == "done")
    assert done["data"]["total"] == 2
    assert done["data"]["succeeded"] + done["data"]["failed"] == 2
```

**Note on the `client` fixture:** use whatever fixture the existing tests use (likely from `conftest.py`). If `conftest.py` doesn't provide a `client` fixture, add the standard one to `conftest.py`:

```python
import pytest
from fastapi.testclient import TestClient
from seer_api.main import app


@pytest.fixture
def client():
    return TestClient(app)
```

- [ ] **Step 3: Run the test**

Run: `cd /home/zac/Projects/arcanum_suite/seer/seer-api && pytest tests/test_streaming.py -v`
Expected: PASS. Requires network (calls real `example.com` and `iana.org` status endpoints).

If the environment has no network, note a network-related failure in your report but do NOT mark the task BLOCKED — the event-count and shape assertions still exercise the streaming plumbing, only the underlying bulk call depends on network.

- [ ] **Step 4: Commit**

```bash
git add seer-api/tests/test_streaming.py seer-api/tests/conftest.py
git commit -m "test(api): integration test for SSE bulk streaming

Verify event sequence (progress × N, item × N, done × 1) and field
shapes against /status/bulk/stream."
```

---

### Task 9: Final workspace verification

**Files:**
- None modified

**Why:** Catch any missed imports, test regressions, or fmt/clippy issues across all three interfaces.

- [ ] **Step 1: Rust workspace test**

Run: `cd /home/zac/Projects/arcanum_suite/seer && cargo test --workspace`
Expected: all PASS.

- [ ] **Step 2: Rust clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: PASS.

- [ ] **Step 3: Rust fmt**

Run: `cargo fmt --all -- --check`
Expected: PASS (no output).

- [ ] **Step 4: Rebuild Python extension fresh**

Run: `cd seer-py && maturin develop --release`
Expected: builds and installs cleanly.

- [ ] **Step 5: Python bulk-progress tests**

Run: `cd seer-py && pytest tests/test_bulk_progress.py -v`
Expected: 3 PASS.

- [ ] **Step 6: API tests**

Run: `cd seer-api && pytest tests/ -v`
Expected: all PASS (includes the new streaming test).

- [ ] **Step 7: CLI smoke check**

Run: `./target/debug/seer bulk status /tmp/seer-bulk-test.txt --progress bar 2>&1 | head -5`
Expected: bar advances on stderr; process exits 0.

- [ ] **Step 8: Grep summary — confirm scope**

Run: `grep -rn "progress:" seer-cli/src/main.rs seer-py/src/lib.rs | grep -v "test\|doc" | wc -l`
Rough sanity check: should be a handful of matches (CLI arg definition + the 7 PyO3 signatures). Numbers don't have to be exact; just verify it's in the expected ballpark and nothing looks unreachable.

- [ ] **Step 9: If everything passes, task complete.**

No commit needed.

---

## Summary

After all 9 tasks:

- CLI gains `--progress {bar,verbose,failures,none}` with TTY + `--format json` auto-resolution
- Python `bulk_*` gain an optional `progress` callable kwarg; exceptions are logged + swallowed
- API gains 5 new `*/bulk/stream` endpoints emitting progress / item / done SSE events
- Test coverage: 6 unit tests (CLI resolver) + 3 integration tests (Python) + 1 SSE integration test (API)
- No changes to `seer-core`
- No changes to the MCP server
