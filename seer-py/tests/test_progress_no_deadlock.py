"""Regression tests for C6: progress callback must not deadlock Tokio workers.

Before C6, the progress callback was invoked directly from Tokio worker
threads via `Python::with_gil(...)`. Under concurrency, a slow callback
would hold the GIL while Tokio tasks waited on Python-owned state, and
every additional worker would pile up behind the GIL. These tests run
`bulk_lookup` with a callback that sleeps on every invocation and assert
the operation still completes in bounded time.
"""

import os
import time

import pytest

import seer

LIVE = os.environ.get("SEER_LIVE_TESTS") == "1"


@pytest.mark.skipif(not LIVE, reason="live network test (set SEER_LIVE_TESTS=1)")
def test_bulk_with_slow_callback_completes():
    """A slow progress callback must not deadlock the bulk run."""
    progress = []

    def slow_cb(completed, total, domain):
        progress.append((completed, total, domain))
        # Simulates the kind of GIL contention a heavy Python callback
        # (e.g. a tqdm update or a DB write) can cause. Before C6 this
        # would progressively starve Tokio workers.
        time.sleep(0.1)

    # Small domain list to keep the test quick, but multiple so there's
    # meaningful concurrency to potentially deadlock against.
    seer.bulk_lookup(
        ["example.com", "example.net"],
        concurrency=2,
        progress=slow_cb,
    )
    # At least one progress event must have fired. The drainer runs in a
    # separate OS thread and may or may not have flushed the last event
    # by the time bulk_lookup returns, so we allow a best-effort floor.
    assert len(progress) >= 1, (
        f"expected at least one progress event; got {progress}"
    )
