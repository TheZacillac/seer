"""Tests for the Streamable HTTP MCP transport mounted at /mcp."""

from __future__ import annotations

import importlib
import json

import pytest
from fastapi.testclient import TestClient

_SSE_HEADERS = {"Accept": "application/json, text/event-stream"}


def _parse_sse(text: str) -> dict:
    """Extract the single JSON-RPC payload from an SSE response body."""
    for line in text.splitlines():
        if line.startswith("data: "):
            return json.loads(line[len("data: ") :])
    raise AssertionError(f"no SSE data frame in response: {text!r}")


@pytest.fixture
def client():
    # TestClient enters the lifespan, which is required for the MCP session
    # manager's run() context.
    from seer_api.main import app

    with TestClient(app) as c:
        yield c


def test_mcp_initialize_returns_server_info(client):
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "0"},
            },
        },
        headers=_SSE_HEADERS,
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    payload = _parse_sse(resp.text)
    assert payload["id"] == 1
    assert payload["result"]["serverInfo"]["name"] == "seer"
    assert "tools" in payload["result"]["capabilities"]


def test_mcp_tools_list_includes_seer_tools(client):
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        headers=_SSE_HEADERS,
    )
    assert resp.status_code == 200
    payload = _parse_sse(resp.text)
    names = {t["name"] for t in payload["result"]["tools"]}
    # A handful of representative tools — the full set is asserted in the
    # stdio MCP tests; here we just confirm the same registry is reachable
    # over HTTP.
    assert {"seer_lookup", "seer_whois", "seer_dig", "seer_bulk_info"} <= names


def test_mcp_no_redirect_on_post(client):
    """POST /mcp must answer 200 directly — no /mcp -> /mcp/ round trip."""
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        headers=_SSE_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 200


def test_mcp_auth_gated_when_api_key_set(monkeypatch):
    monkeypatch.setenv("SEER_API_KEY", "s3cret")
    import seer_api.main as main

    importlib.reload(main)
    try:
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        with TestClient(main.app) as c:
            # Missing token -> 401, no MCP processing
            r = c.post("/mcp", json=body, headers=_SSE_HEADERS)
            assert r.status_code == 401

            # Correct token -> 200, tools/list responds
            r = c.post(
                "/mcp",
                json=body,
                headers={**_SSE_HEADERS, "Authorization": "Bearer s3cret"},
            )
            assert r.status_code == 200
            payload = _parse_sse(r.text)
            assert "tools" in payload["result"]
    finally:
        monkeypatch.delenv("SEER_API_KEY")
        importlib.reload(main)


def test_mcp_listed_in_root_endpoint(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["endpoints"]["mcp"] == "/mcp"
