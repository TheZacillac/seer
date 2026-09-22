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


def test_mcp_multi_limit_rate_string_enforces_every_limit(monkeypatch):
    """SEER_RATE_LIMIT may carry several limits; `limits.parse` kept only the
    first, so the tighter `2/hour` here was silently dropped."""
    monkeypatch.delenv("SEER_API_KEY", raising=False)
    monkeypatch.delenv("SEER_MCP_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("SEER_MCP_ALLOWED_ORIGINS", raising=False)
    monkeypatch.setenv("SEER_RATE_LIMIT", "100/minute;2/hour")
    import seer_api.main as main

    importlib.reload(main)
    with TestClient(main.app) as c:
        statuses = [
            c.post("/mcp", json={"jsonrpc": "2.0", "method": "ping", "id": 1}).status_code
            for _ in range(4)
        ]
    assert statuses[2:] == [429, 429], statuses
    monkeypatch.delenv("SEER_RATE_LIMIT")
    importlib.reload(main)


# --- root_path (`uvicorn --root-path /api`) ---------------------------------


def test_mcp_guards_apply_under_root_path(monkeypatch):
    """Under a root_path the request path is `/api/mcp` while the router
    matches `/mcp`; the guards compared the prefixed path and were skipped."""
    monkeypatch.delenv("SEER_API_KEY", raising=False)
    monkeypatch.delenv("SEER_MCP_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("SEER_MCP_ALLOWED_ORIGINS", raising=False)
    monkeypatch.setenv("SEER_RATE_LIMIT", "2/minute")
    import seer_api.main as main

    importlib.reload(main)
    body = {"jsonrpc": "2.0", "method": "ping", "id": 1}
    with TestClient(main.app, root_path="/api") as c:
        blocked = c.post("/api/mcp", headers={"Origin": "https://evil.example"}, json=body)
        assert blocked.status_code == 403, blocked.status_code
        statuses = [c.post("/api/mcp", json=body).status_code for _ in range(4)]
    assert 429 in statuses, f"/api/mcp must be rate-limited; saw {statuses}"
    monkeypatch.delenv("SEER_RATE_LIMIT")
    importlib.reload(main)


# --- SEER_MCP_ALLOWED_HOSTS / SEER_MCP_ALLOWED_ORIGINS ----------------------

_SSE_HEADERS = {"Accept": "application/json, text/event-stream"}
_TOOLS_LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}


def _reload_with(monkeypatch, **env):
    for name in ("SEER_API_KEY", "SEER_MCP_ALLOWED_HOSTS", "SEER_MCP_ALLOWED_ORIGINS"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    import seer_api.main as main

    importlib.reload(main)
    return main


def test_mcp_origins_only_allowlist_does_not_421_every_request(monkeypatch):
    """SEER_MCP_ALLOWED_ORIGINS alone used to switch on the SDK's DNS-rebinding
    protection with an EMPTY host list — which rejects every Host (421) — and
    to switch the local origin guard off. It must act as the Origin allowlist.
    """
    main = _reload_with(
        monkeypatch, SEER_MCP_ALLOWED_ORIGINS="https://app.example, http://localhost:*"
    )
    with TestClient(main.app) as c:
        def post(origin=None):
            headers = dict(_SSE_HEADERS)
            if origin:
                headers["Origin"] = origin
            return c.post("/mcp", json=_TOOLS_LIST, headers=headers)

        # Non-browser client (no Origin) and allowlisted origins pass.
        assert post().status_code == 200
        assert post("https://app.example").status_code == 200
        assert post("http://localhost:5173").status_code == 200  # `:*` port wildcard
        # Anything else is refused — including an unlisted local origin,
        # since an explicit allowlist is exact.
        assert post("https://evil.example").status_code == 403
        assert post("http://127.0.0.1:3000").status_code == 403
    importlib.reload(main)


def test_mcp_origins_allowlist_enforced_with_api_key(monkeypatch):
    """A configured origin allowlist stays in force when auth is on too."""
    main = _reload_with(
        monkeypatch, SEER_API_KEY="s3cret", SEER_MCP_ALLOWED_ORIGINS="https://app.example"
    )
    auth = {**_SSE_HEADERS, "Authorization": "Bearer s3cret"}
    with TestClient(main.app) as c:
        ok = c.post("/mcp", json=_TOOLS_LIST, headers={**auth, "Origin": "https://app.example"})
        assert ok.status_code == 200, ok.text
        evil = c.post(
            "/mcp", json=_TOOLS_LIST, headers={**auth, "Origin": "https://evil.example"}
        )
        assert evil.status_code == 403
    importlib.reload(main)


def test_mcp_allowed_hosts_enables_sdk_rebinding_protection(monkeypatch):
    """With a host list, the SDK validates Host (421) and Origin (403)."""
    main = _reload_with(
        monkeypatch,
        SEER_MCP_ALLOWED_HOSTS="testserver",
        SEER_MCP_ALLOWED_ORIGINS="https://app.example",
    )
    with TestClient(main.app) as c:
        ok = c.post(
            "/mcp", json=_TOOLS_LIST, headers={**_SSE_HEADERS, "Origin": "https://app.example"}
        )
        assert ok.status_code == 200, ok.text
        bad_host = c.post(
            "/mcp", json=_TOOLS_LIST, headers={**_SSE_HEADERS, "Host": "rebound.example"}
        )
        assert bad_host.status_code == 421
        bad_origin = c.post(
            "/mcp", json=_TOOLS_LIST, headers={**_SSE_HEADERS, "Origin": "https://evil.example"}
        )
        assert bad_origin.status_code == 403
    importlib.reload(main)
