"""Every bulk job — sync ``/bulk``, ``/bulk/stream`` and the MCP
``seer_bulk_*`` tools — takes a slot from one shared cap.

A bulk job holds a dispatch thread for its whole batch and cannot be
cancelled. Only the SSE streams used to be capped, so one client staying
inside every per-route rate limit could pin the whole dispatch pool with sync
``/bulk`` calls and stall every single-domain route.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading

import httpx
import pytest

import seer
from seer_api import _run
from seer_api.errors import ServerBusy
from seer_api.main import app
from seer_api.mcp import server as mcp_server

_BULK_BINDINGS = (
    "bulk_lookup",
    "bulk_whois",
    "bulk_dig",
    "bulk_status",
    "bulk_ssl",
    "bulk_propagation",
    "bulk_info",
    "bulk_availability",
)


@pytest.fixture
def one_bulk_slot(monkeypatch):
    """One bulk slot, a short deadline, and bulk bindings that return at once."""
    monkeypatch.setattr(_run, "_MAX_CONCURRENT_BULK", 1, raising=False)
    monkeypatch.setattr(_run, "_bulk_semaphore", None, raising=False)
    monkeypatch.setattr(_run, "_bulk_semaphore_loop", None, raising=False)
    monkeypatch.setattr(_run, "_REQUEST_TIMEOUT", 0.2)
    for name in _BULK_BINDINGS:
        monkeypatch.setattr(seer, name, lambda *a, **k: [], raising=False)


def _bulk_paths() -> list[str]:
    """Every bulk REST route, read from the app (no hand-kept list)."""
    return sorted(
        path
        for path in app.openapi()["paths"]
        if path.endswith("/bulk") or path.endswith("/bulk/stream")
    )


def _bulk_tools() -> list[str]:
    return sorted(name for name in mcp_server._TOOLS if name.startswith("seer_bulk_"))


def test_the_discovered_surfaces_are_the_whole_bulk_surface():
    # Guards the discovery above against silently matching nothing.
    assert len(_bulk_paths()) == 14
    assert len(_bulk_tools()) == 8


async def _hold_the_slot(release: threading.Event, started: threading.Event):
    def blocking(*_args):
        started.set()
        release.wait(5.0)
        return []

    async def hold():
        # The holder's own client gives up at the deadline; its job (and so
        # the slot) stays until `release`.
        with contextlib.suppress(TimeoutError):
            await _run.run_bulk(blocking)

    task = asyncio.ensure_future(hold())
    assert await asyncio.to_thread(started.wait, 2.0)
    return task


@pytest.mark.parametrize("path", _bulk_paths())
def test_bulk_route_waits_for_a_slot_and_then_answers_503(path, one_bulk_slot):
    """Regression: sync /bulk routes ran on the pool with no cap at all."""
    release, started = threading.Event(), threading.Event()

    async def scenario() -> httpx.Response:
        held = await _hold_the_slot(release, started)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as c:
            resp = await c.post(path, json={"domains": ["example.com"]})
        release.set()
        await held
        return resp

    resp = asyncio.run(scenario())
    assert resp.status_code == 503, resp.text
    assert "bulk" in resp.json()["detail"]


@pytest.mark.parametrize("tool", _bulk_tools())
def test_mcp_bulk_tool_shares_the_cap(tool, one_bulk_slot):
    release, started = threading.Event(), threading.Event()

    async def scenario():
        held = await _hold_the_slot(release, started)
        out = await mcp_server.call_tool(tool, {"domains": ["example.com"]})
        release.set()
        await held
        return out

    out = asyncio.run(scenario())
    assert out.is_error
    assert "busy" in out.content[0].text.lower()


def test_slot_is_freed_when_the_job_ends_not_when_the_client_leaves(one_bulk_slot):
    """A job that outlives the deadline keeps its slot (it is still running on
    a dispatch thread); the slot comes back only once the job itself ends."""
    release, started = threading.Event(), threading.Event()

    def blocking(*_args):
        started.set()
        release.wait(5.0)
        return ["done"]

    async def scenario():
        with pytest.raises(TimeoutError):
            await _run.run_bulk(blocking)  # client gives up at the deadline
        assert started.is_set()
        with pytest.raises(ServerBusy):
            await _run.run_bulk(lambda: ["next"])  # job still holds the slot
        release.set()
        _run._REQUEST_TIMEOUT = 0
        return await asyncio.wait_for(_run.run_bulk(lambda: ["next"]), 5.0)

    assert asyncio.run(scenario()) == ["next"]


def test_a_queued_bulk_job_runs_once_a_slot_frees(monkeypatch, one_bulk_slot):
    monkeypatch.setattr(_run, "_REQUEST_TIMEOUT", 0)
    release, started = threading.Event(), threading.Event()

    async def scenario():
        held = await _hold_the_slot(release, started)
        queued = asyncio.ensure_future(_run.run_bulk(lambda: ["queued"]))
        await asyncio.sleep(0.1)
        assert not queued.done(), "a second job must wait for the only slot"
        release.set()
        await held
        return await asyncio.wait_for(queued, 5.0)

    assert asyncio.run(scenario()) == ["queued"]


def test_single_domain_routes_keep_a_thread_while_bulk_is_saturated(monkeypatch):
    """The cap is below the pool size, so a saturated bulk cap still leaves
    dispatch threads for single-domain routes (the original stall)."""
    assert _run._MAX_CONCURRENT_BULK < _run._DISPATCH_THREADS


@pytest.mark.parametrize(
    ("env", "threads", "expected"),
    [
        ({}, 50, 8),
        ({"SEER_MAX_CONCURRENT_BULK": "20"}, 50, 20),
        # The old stream-only name is still honoured...
        ({"SEER_MAX_CONCURRENT_STREAMS": "12"}, 50, 12),
        # ...but the new name wins when both are set.
        ({"SEER_MAX_CONCURRENT_BULK": "3", "SEER_MAX_CONCURRENT_STREAMS": "12"}, 50, 3),
        # Clamped below the pool size so single-domain routes keep a thread.
        ({"SEER_MAX_CONCURRENT_BULK": "80"}, 50, 49),
        ({}, 4, 3),
        ({}, 2, 1),
    ],
)
def test_bulk_cap_setting(monkeypatch, env, threads, expected):
    monkeypatch.delenv("SEER_MAX_CONCURRENT_BULK", raising=False)
    monkeypatch.delenv("SEER_MAX_CONCURRENT_STREAMS", raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert _run._bulk_cap(threads) == expected
