"""guard_hosts_async must validate hosts concurrently, not serially.

The bulk endpoints can pass up to 100 (host, port) pairs to
``guard_hosts_async``. The original implementation awaited each
``guard_async`` in a ``for`` loop, serializing up to 100 blocking DNS
resolutions before any work started. These tests pin that the guards run
concurrently while preserving the contract: an offending host still raises
``HTTPException(status_code=400)`` and a fully-valid list passes.

Hermetic: ``guard_async`` is monkeypatched so no real DNS resolution occurs.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from fastapi import HTTPException

from seer_api import ssrf


def test_valid_hosts_all_pass(monkeypatch):
    """A list with no reserved hosts must not raise."""
    seen: list[str] = []

    async def _fake_guard(host: str, port: int = 443) -> None:
        seen.append(host)

    monkeypatch.setattr(ssrf, "guard_async", _fake_guard)

    hosts = [("a.example", 443), ("b.example", 443), ("c.example", 443)]
    asyncio.run(ssrf.guard_hosts_async(hosts))
    assert set(seen) == {"a.example", "b.example", "c.example"}


def test_one_reserved_host_still_raises_400(monkeypatch):
    """If any host is reserved, the same HTTPException(400) contract holds."""

    async def _fake_guard(host: str, port: int = 443) -> None:
        if host == "10.0.0.1":
            raise HTTPException(
                status_code=400,
                detail=f"Invalid input: refusing to connect to reserved address: {host}",
            )

    monkeypatch.setattr(ssrf, "guard_async", _fake_guard)

    hosts = [("good.example", 443), ("10.0.0.1", 443), ("also-good.example", 443)]
    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(ssrf.guard_hosts_async(hosts))
    assert excinfo.value.status_code == 400
    assert "reserved" in str(excinfo.value.detail).lower()


def test_guards_run_concurrently(monkeypatch):
    """Five guards each sleeping 0.15s must finish in ~max, not ~sum.

    Serial execution would take ~0.75s; concurrent execution should finish in
    close to a single delay. A 2x ceiling absorbs scheduler jitter while still
    catching the serial-vs-parallel regression.
    """
    per_call_delay = 0.15
    hosts = [(f"h{i}.example", 443) for i in range(5)]

    async def _slow_guard(host: str, port: int = 443) -> None:
        await asyncio.sleep(per_call_delay)

    monkeypatch.setattr(ssrf, "guard_async", _slow_guard)

    start = time.perf_counter()
    asyncio.run(ssrf.guard_hosts_async(hosts))
    elapsed = time.perf_counter() - start

    assert elapsed < per_call_delay * 2, (
        f"guard_hosts_async appears to serialize: {elapsed:.3f}s for "
        f"{len(hosts)} hosts (expected < {per_call_delay * 2:.3f}s)"
    )


def test_empty_host_list_is_noop(monkeypatch):
    async def _fake_guard(host: str, port: int = 443) -> None:  # pragma: no cover
        raise AssertionError("should not be called for empty list")

    monkeypatch.setattr(ssrf, "guard_async", _fake_guard)
    asyncio.run(ssrf.guard_hosts_async([]))
