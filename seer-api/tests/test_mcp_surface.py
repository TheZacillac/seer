"""POST /mcp hardening: rate limiting + browser-reachability guard (issue #55).

In the default dev posture (no SEER_API_KEY, no SEER_MCP_ALLOWED_*), a site the
user visits could `fetch('http://127.0.0.1:8000/mcp', …)` and drive all MCP
tools against localhost; and /mcp (a raw Starlette Route) was the only
unthrottled surface. These tests pin both fixes.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def dev_app(monkeypatch):
    """Reload the app in the default dev posture (no key, no MCP allowlist)."""
    monkeypatch.delenv("SEER_API_KEY", raising=False)
    monkeypatch.delenv("SEER_MCP_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("SEER_MCP_ALLOWED_ORIGINS", raising=False)
    import seer_api.main as main

    importlib.reload(main)
    return main


def test_mcp_blocks_cross_origin_browser_request(dev_app):
    with TestClient(dev_app.app) as c:
        resp = c.post(
            "/mcp",
            headers={"Origin": "https://evil.example"},
            json={"jsonrpc": "2.0", "method": "ping", "id": 1},
        )
    assert resp.status_code == 403, (
        f"cross-origin /mcp must be blocked, got {resp.status_code}"
    )


def test_mcp_allows_localhost_origin(dev_app):
    with TestClient(dev_app.app) as c:
        resp = c.post(
            "/mcp",
            headers={"Origin": "http://localhost:3000"},
            json={"jsonrpc": "2.0", "method": "ping", "id": 1},
        )
    # A localhost-origin request passes the guard (it may still get an MCP-level
    # 4xx, but never the 403 from the guard).
    assert resp.status_code != 403


def test_mcp_allows_non_browser_client_without_origin(dev_app):
    with TestClient(dev_app.app) as c:
        resp = c.post(
            "/mcp",
            json={"jsonrpc": "2.0", "method": "ping", "id": 1},
        )
    assert resp.status_code != 403


def test_mcp_is_rate_limited(monkeypatch):
    monkeypatch.delenv("SEER_API_KEY", raising=False)
    monkeypatch.delenv("SEER_MCP_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("SEER_MCP_ALLOWED_ORIGINS", raising=False)
    monkeypatch.setenv("SEER_RATE_LIMIT", "2/minute")
    import seer_api.main as main

    importlib.reload(main)
    statuses = []
    with TestClient(main.app) as c:
        for _ in range(5):
            r = c.post("/mcp", json={"jsonrpc": "2.0", "method": "ping", "id": 1})
            statuses.append(r.status_code)
    assert 429 in statuses, f"/mcp must be rate-limited; saw {statuses}"
