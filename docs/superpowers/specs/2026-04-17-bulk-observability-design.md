# Bulk Operation Observability

**Status:** Draft
**Date:** 2026-04-17
**Scope:** `seer-cli`, `seer-py`, `seer-api`

## Goal

Surface real-time progress of bulk operations across three interfaces:
- **CLI** — wire the existing `indicatif` progress bar into the bulk path; add a `--progress <mode>` flag with four modes.
- **Python bindings** — accept an optional keyword-only `progress` callback on all `bulk_*` functions.
- **API** — add streaming SSE variants of the bulk endpoints alongside the current synchronous ones.

## Non-Goals

- Progress for MCP tools (tool calls are single request/response).
- Changes to the Rust core's `ProgressCallback` signature (already correct).
- Batched or throttled progress events.
- Cancellation mid-run.

## Current State

- `seer-core::bulk::BulkExecutor::execute` takes `Option<ProgressCallback>` where `ProgressCallback = Box<dyn Fn(usize, usize, &str) + Send + Sync>`; the callback fires per completed item with `(completed, total, current_domain)`.
- `seer-cli/src/display/progress.rs` provides `indicatif` + tracing-aware writer integration via `BULK_PROGRESS_BAR` and `ProgressWriter`; wired into `init_logging_with_writer` already.
- `seer-cli/src/main.rs:574` calls `executor.execute(operations, None)` — passes no callback, so the progress-bar infrastructure is built and unused.
- `seer-py` exposes 7 `bulk_*` functions (`bulk_lookup`, `bulk_whois`, `bulk_dig`, `bulk_propagation`, `bulk_status`, `bulk_availability`, `bulk_info`); all pass `None` for the progress callback.
- `seer-api` has synchronous bulk routes at `/bulk/*`; responses are JSON bodies sent after all items finish.

## CLI

### Flag

`--progress <mode>` — values:

| Mode | Behavior |
|------|----------|
| `bar` (default) | Single `indicatif` progress bar at the bottom of stderr: `[===>    ] 12/100 (12%) eta 00:45 — example.com`. No per-item lines. |
| `verbose` | Bar + each completed item prints a scrolled line above via `ProgressBar::println`: `✓ example.com (245ms)` on success, `✗ broken.tld (timeout after 15s)` on failure. |
| `failures` | Bar + only failed items print: `✗ broken.tld (timeout after 15s)`. Successes silent. |
| `none` | No bar, no per-item output. |

### Interactions

- `--format json` implies `--progress none` (JSON output must be clean on stdout). An explicit `--progress <mode>` alongside `--format json` overrides the implication; the bar goes to stderr.
- If stderr isn't a TTY, `--progress bar` auto-downgrades to `--progress none`. `verbose` and `failures` still print their per-item lines (no bar). User-explicit `--progress bar` on non-TTY is honored.

### Wiring

`seer-cli/src/main.rs` at the `executor.execute(operations, None)` call site (around line 574) constructs a `ProgressCallback` closure per mode and activates the bar via `display::progress::set_bulk_progress_bar` / `clear_bulk_progress_bar`. Existing `display/progress.rs` requires no changes — the tracing-aware writer is already wired into `init_logging_with_writer`, so log lines during bulk runs route through the bar correctly.

## Python

### API change

Extend every `bulk_*` function in `seer-py/python/seer/__init__.py` and the underlying PyO3 wrappers in `seer-py/src/lib.rs`:

```python
def bulk_whois(
    domains: list[str],
    concurrency: int = 10,
    *,
    progress: Callable[[int, int, str], None] | None = None,
) -> list[dict]: ...
```

The callback fires exactly once per completed item with `(completed_count, total, current_domain)`. `None` preserves today's behavior.

### PyO3 wrapper

- Converts the Python callable to `Box<dyn Fn(usize, usize, &str) + Send + Sync>`.
- Acquires the GIL inside the closure before invoking the Python callable (tokio worker threads don't hold the GIL).
- Exceptions raised from Python inside the callback are logged via `tracing::warn!` and swallowed. A broken progress callback must not kill a bulk run — progress is auxiliary, and losing a callback exception is less bad than losing N lookups mid-way.

### Functions affected

All 7: `bulk_lookup`, `bulk_whois`, `bulk_dig`, `bulk_propagation`, `bulk_status`, `bulk_availability`, `bulk_info`.

## API (FastAPI)

### New streaming endpoints

Add alongside the current synchronous routes:

| New endpoint | Mirrors |
|---|---|
| `POST /bulk/whois/stream` | `/bulk/whois` |
| `POST /bulk/rdap/stream` | `/bulk/rdap` |
| `POST /bulk/dns/stream` | `/bulk/dns` |
| `POST /bulk/propagation/stream` | `/bulk/propagation` |
| `POST /bulk/lookup/stream` | `/bulk/lookup` |
| `POST /bulk/status/stream` | `/bulk/status` |
| `POST /bulk/availability/stream` | `/bulk/availability` |

Request body: identical to the corresponding sync endpoint.
Response: `Content-Type: text/event-stream`.

### Event schema

Three event types:

```
event: progress
data: {"completed": 3, "total": 100, "current_domain": "example.com"}

event: item
data: {"operation": {...}, "success": true, "data": {...}, "error": null, "duration_ms": 245}

event: done
data: {"total": 100, "succeeded": 97, "failed": 3, "duration_ms": 12480}
```

- `progress` fires from the Rust callback hook after each item completes — a lightweight heartbeat (count/total/domain) that clients can consume without parsing full per-item payloads.
- `item` fires immediately after the corresponding `progress`, carrying the full `BulkResult` as JSON (same shape as an element in the current sync response's list).
- `done` fires once at the end with final totals and elapsed duration.

A simple progress-only consumer can listen to `progress` and `done`. A full-result consumer can listen to `item` and `done` (and derive progress from item count). Both events exist so each consumer picks the minimum they need.

### Implementation sketch

FastAPI `StreamingResponse` wrapping an `async def` generator that awaits from an `asyncio.Queue`. The Python bulk call runs on a worker thread (`asyncio.to_thread` or `run_in_executor`); its progress callback, written in Python, pushes events onto the queue. When the bulk call returns, iterate the per-item results, push `item` events, then `done`.

### Middleware

Streaming routes inherit the same auth, rate-limit, and correlation-id middleware as the sync endpoints. Existing caps (`MAX_BULK_DOMAINS = 100`, `MAX_CONCURRENCY = 50`) apply.

## Testing

### Rust core

No new tests — the callback hook already exists and is exercised by existing bulk tests.

### CLI

- Unit test: `--progress` parses all four valid values; errors on junk.
- Unit test: `--format json` implies `--progress none` unless explicit.
- Unit test: TTY detection degrades `bar` → `none` on non-TTY when the mode isn't explicit.
- Manual verification: run `seer bulk lookup domains.txt --progress {bar,verbose,failures,none}` and eyeball each.

### Python bindings

- Integration test in `seer-py/tests/`: call `bulk_whois(["example.com", "iana.org"], progress=cb)` with a mock; assert the callback was invoked exactly twice with `(completed, total, domain)` shape, final `completed == total == 2`.
- Integration test: a callback that raises is caught — the bulk call still returns results.

### API

- Integration test (FastAPI `TestClient`): `POST /bulk/whois/stream` with 2 domains; parse the SSE stream; assert event sequence contains exactly 2× `progress`, 2× `item`, 1× `done`, with `progress` immediately preceding its paired `item`.
- Integration test: auth/rate-limit middleware applies to streaming routes.

### Manual end-to-end

- `seer bulk lookup` with a 50-domain file, each of the four modes.
- `curl -N -X POST http://localhost:8000/bulk/lookup/stream -d '...'` and confirm events flow.

## Files Touched

| File | Change |
|------|--------|
| `seer-cli/src/main.rs` | Add `--progress <mode>` flag; construct callback at bulk call site; TTY detection; `--format json` implication. |
| `seer-cli/src/display/progress.rs` | No change expected (existing infra reused). |
| `seer-py/src/lib.rs` | Add optional `progress` kwarg to all 7 `bulk_*` functions; PyO3 callback wrapper with GIL handling + exception swallowing. |
| `seer-py/python/seer/__init__.py` | Type-hint the new kwarg on re-exported wrappers. |
| `seer-py/tests/` | New integration tests for progress + exception handling. |
| `seer-api/seer_api/routers/*.py` | Add `/stream` variant for each of the 7 bulk endpoints. |
| `seer-api/seer_api/main.py` | Register new streaming routes (automatic if per-router). |
| `seer-api/tests/` | SSE integration tests. |
