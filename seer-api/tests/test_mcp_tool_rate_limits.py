"""Per-tool MCP rate limits mirror the REST per-route limits.

The REST routers throttle the expensive fan-out endpoints individually
(``@limiter.limit("5/minute")`` on bulk_ssl/bulk_status/bulk_propagation/
confusables, ``10/minute`` on the other bulk endpoints), but ``/mcp`` only
applied the flat ``SEER_RATE_LIMIT`` (default 30/minute) to every tool call
equally — so an MCP client could drive ``seer_bulk_ssl`` 6x more often than
the REST API permits for the identical operation (2026-07-11 review).
"""

from __future__ import annotations

import asyncio

import seer

from seer_api.mcp import server


def _reset_limiter(monkeypatch):
    # Fresh in-memory window per test so counts don't leak between tests.
    monkeypatch.setattr(server, "_tool_rate_limiter", None)


def test_bulk_ssl_is_limited_to_five_per_minute(monkeypatch):
    _reset_limiter(monkeypatch)
    calls = {"n": 0}

    def fake_bulk_ssl(domains, concurrency):
        calls["n"] += 1
        return []

    def fake_guard(host, port=443):
        return None

    monkeypatch.setattr(seer, "bulk_ssl", fake_bulk_ssl, raising=False)
    monkeypatch.setattr(seer, "validate_public_host", fake_guard, raising=False)

    args = {"domains": ["example.com"]}
    for _ in range(5):
        out = asyncio.run(server.call_tool("seer_bulk_ssl", args))
        assert "rate limit" not in out[0].text.lower(), out[0].text
    out = asyncio.run(server.call_tool("seer_bulk_ssl", args))
    assert "rate limit" in out[0].text.lower(), out[0].text
    assert calls["n"] == 5, "the over-limit call must not reach the binding"


def test_confusables_is_limited_to_five_per_minute(monkeypatch):
    _reset_limiter(monkeypatch)
    calls = {"n": 0}

    def fake_confusables(*args, **kwargs):
        calls["n"] += 1
        return {"domain": args[0] if args else "", "registered": []}

    monkeypatch.setattr(seer, "confusables", fake_confusables, raising=False)

    args = {"domain": "example.com"}
    for _ in range(5):
        out = asyncio.run(server.call_tool("seer_confusables", args))
        assert "rate limit" not in out[0].text.lower(), out[0].text
    out = asyncio.run(server.call_tool("seer_confusables", args))
    assert "rate limit" in out[0].text.lower(), out[0].text
    assert calls["n"] == 5


def test_unlimited_tools_are_not_throttled_per_tool(monkeypatch):
    _reset_limiter(monkeypatch)

    def fake_lookup(domain):
        return {"domain": domain}

    monkeypatch.setattr(seer, "lookup", fake_lookup, raising=False)

    # Single-domain lookup carries no per-tool limit; the flat /mcp gate
    # (SEER_RATE_LIMIT) is the only throttle. 12 calls must all pass.
    for _ in range(12):
        out = asyncio.run(server.call_tool("seer_lookup", {"domain": "example.com"}))
        assert "rate limit" not in out[0].text.lower(), out[0].text
