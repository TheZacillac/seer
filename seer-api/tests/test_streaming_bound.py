"""Concurrent bulk-stream jobs must be bounded so a disconnect-flood can't
pin the whole dispatch pool (the blocking jobs cannot be cancelled)."""

from __future__ import annotations

import asyncio
import threading

from seer_api import streaming


async def test_stream_bulk_caps_concurrent_jobs(monkeypatch):
    # Force a single concurrent slot and a fresh per-loop semaphore.
    monkeypatch.setattr(streaming, "_MAX_CONCURRENT_STREAMS", 1, raising=False)
    monkeypatch.setattr(streaming, "_stream_semaphore", None, raising=False)
    monkeypatch.setattr(streaming, "_stream_semaphore_loop", None, raising=False)

    release = threading.Event()
    first_started = threading.Event()

    def blocking_bulk(domains, progress=None):
        first_started.set()
        release.wait(5.0)  # hold the dispatch thread until released
        return [{"success": True, "domain": domains[0]}]

    # First request takes the only slot; its job starts and blocks.
    await streaming.stream_bulk(blocking_bulk, ["a.com"])
    assert first_started.wait(2.0), "first job should start on the dispatch pool"

    # Second request must wait for a free slot — its stream_bulk coroutine
    # must not complete while the first job still holds the only permit.
    second = asyncio.ensure_future(streaming.stream_bulk(blocking_bulk, ["b.com"]))
    await asyncio.sleep(0.1)
    assert not second.done(), "second stream must block on the semaphore, not start immediately"

    # Releasing the first job frees the slot (via the future's done-callback),
    # which unblocks the second.
    release.set()
    resp = await asyncio.wait_for(second, 5.0)
    assert resp is not None
