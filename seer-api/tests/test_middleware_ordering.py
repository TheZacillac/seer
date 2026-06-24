"""Short-circuit rejections from the outer middlewares must be observable.

`RequestLoggingMiddleware` records every response in `metrics` and emits a log
line. It was registered first, making it the INNERMOST application middleware,
so the resolved order was:

    CORS -> auth -> body-size -> RequestLogging -> route

A 401 from auth, a 413 from the body-size cap, and the /mcp 403/429 guards all
short-circuit *outside* RequestLogging and were therefore never counted in
/metrics nor logged. On a public deployment an auth brute-force or /mcp flood
produced zero logs and zero counters. These tests pin that those rejections
flow back through the logging/metrics middleware.

Hermetic: no network, no real seer binding (the conftest stub is sufficient —
the requests are rejected before any router calls into seer).
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def auth_app(monkeypatch):
    """Reload the app with SEER_API_KEY set so auth is active."""
    monkeypatch.setenv("SEER_API_KEY", "s3cret")
    import seer_api.main as main

    importlib.reload(main)
    try:
        yield main
    finally:
        monkeypatch.delenv("SEER_API_KEY", raising=False)
        importlib.reload(main)


def test_unauthenticated_401_is_counted_in_metrics(auth_app):
    """A 401 from auth_middleware must reach RequestLoggingMiddleware and be
    recorded in the metrics snapshot (total_requests + a 401 status bucket)."""
    from seer_api.middleware import metrics

    client = TestClient(auth_app.app)

    before = metrics.snapshot()
    before_total = before["total_requests"]
    before_401 = before["status_codes"].get(401, 0)

    resp = client.get("/lookup/example.com")  # no Authorization header
    assert resp.status_code == 401, resp.text

    after = metrics.snapshot()
    assert after["total_requests"] == before_total + 1, (
        "the 401 short-circuit was not counted — RequestLoggingMiddleware is "
        "inside auth and never saw the rejection"
    )
    assert after["status_codes"].get(401, 0) == before_401 + 1, (
        "the 401 status code was not recorded in metrics"
    )
    assert after["total_errors"] == before["total_errors"] + 1


def test_unauthenticated_401_is_logged(auth_app, caplog):
    """The 401 rejection must also emit a request log line at WARNING."""
    import logging

    client = TestClient(auth_app.app)

    with caplog.at_level(logging.WARNING, logger="seer_api"):
        resp = client.get("/lookup/example.com")
    assert resp.status_code == 401

    matching = [
        r
        for r in caplog.records
        if r.name == "seer_api" and "status=401" in r.getMessage()
    ]
    assert matching, (
        "no request log line for the 401 — the logging middleware did not "
        "wrap the auth rejection"
    )


def test_401_response_still_carries_request_id_header(auth_app):
    """Reordering must not lose the X-Request-ID annotation: since logging now
    wraps auth, the short-circuit 401 should carry the request id header."""
    client = TestClient(auth_app.app)
    resp = client.get("/lookup/example.com")
    assert resp.status_code == 401
    assert resp.headers.get("X-Request-ID"), (
        "401 response is missing X-Request-ID; logging middleware must wrap "
        "the auth rejection"
    )


def test_mcp_browser_guard_403_is_counted(monkeypatch):
    """The /mcp cross-origin 403 guard (no API key, no allowlist) must also be
    metered — it short-circuits in auth_middleware, outside the inner stack."""
    # Unauthenticated dev posture so the browser-origin guard is active.
    monkeypatch.delenv("SEER_API_KEY", raising=False)
    monkeypatch.delenv("SEER_MCP_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("SEER_MCP_ALLOWED_ORIGINS", raising=False)
    import seer_api.main as main

    importlib.reload(main)
    from seer_api.middleware import metrics

    before = metrics.snapshot()
    before_total = before["total_requests"]

    with TestClient(main.app) as client:
        resp = client.post(
            "/mcp",
            headers={"Origin": "https://evil.example"},
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
    assert resp.status_code == 403, resp.text

    after = metrics.snapshot()
    assert after["total_requests"] == before_total + 1, (
        "the /mcp 403 guard was not counted in metrics"
    )

    importlib.reload(main)
