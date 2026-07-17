"""MCP-over-HTTP tool dispatch honors the bounded dispatch pool (issue #48).

Previously the MCP server used `loop.run_in_executor(None, ...)` (asyncio's
unbounded default executor), so an operator who lowered SEER_DISPATCH_THREADS to
protect the host still saw MCP tool calls spill onto the default pool. The
dispatch must run on the `seer-dispatch` ThreadPoolExecutor like the REST path.
"""

from __future__ import annotations

import asyncio
import threading

import seer
from seer_api.mcp.server import execute_tool


def test_mcp_dispatch_runs_on_bounded_seer_dispatch_pool(monkeypatch):
    captured = {}

    def fake_lookup(domain):
        captured["thread"] = threading.current_thread().name
        return {"domain": domain, "available": False}

    monkeypatch.setattr(seer, "lookup", fake_lookup, raising=False)

    result = asyncio.run(execute_tool("seer_lookup", {"domain": "example.com"}))

    assert result["domain"] == "example.com"
    assert captured["thread"].startswith("seer-dispatch"), (
        f"MCP dispatch must use the bounded _DISPATCH_EXECUTOR, "
        f"ran on {captured['thread']!r}"
    )


def test_mcp_bulk_availability_dispatches_on_bounded_pool(monkeypatch):
    captured = {}

    def fake_bulk_availability(domains, concurrency):
        captured["args"] = (domains, concurrency)
        captured["thread"] = threading.current_thread().name
        return [{"success": True, "data": {"domain": d}} for d in domains]

    monkeypatch.setattr(seer, "bulk_availability", fake_bulk_availability, raising=False)

    result = asyncio.run(
        execute_tool(
            "seer_bulk_availability",
            {"domains": ["a.com", "b.com"], "concurrency": 3},
        )
    )

    assert len(result) == 2
    assert captured["args"] == (["a.com", "b.com"], 3)
    assert captured["thread"].startswith("seer-dispatch")


def test_mcp_bulk_availability_defaults_concurrency_to_ten(monkeypatch):
    captured = {}

    def fake_bulk_availability(domains, concurrency):
        captured["args"] = (domains, concurrency)
        return []

    monkeypatch.setattr(seer, "bulk_availability", fake_bulk_availability, raising=False)

    asyncio.run(execute_tool("seer_bulk_availability", {"domains": ["a.com"]}))
    assert captured["args"] == (["a.com"], 10)


def test_mcp_delegation_dispatches_on_bounded_pool(monkeypatch):
    captured = {}

    def fake_delegation(domain):
        captured["domain"] = domain
        captured["thread"] = threading.current_thread().name
        return {"domain": domain, "in_sync": True, "lame": []}

    monkeypatch.setattr(seer, "delegation", fake_delegation, raising=False)

    result = asyncio.run(execute_tool("seer_delegation", {"domain": "example.com"}))

    assert result["in_sync"] is True
    assert captured["domain"] == "example.com"
    assert captured["thread"].startswith("seer-dispatch")


def test_mcp_tld_info_dispatches_on_bounded_pool(monkeypatch):
    captured = {}

    def fake_tld_info(tld):
        captured["tld"] = tld
        captured["thread"] = threading.current_thread().name
        return {"tld": "com", "whois_server": "whois.verisign-grs.com"}

    monkeypatch.setattr(seer, "tld_info", fake_tld_info, raising=False)

    result = asyncio.run(execute_tool("seer_tld_info", {"tld": ".com"}))

    assert result["tld"] == "com"
    # The raw token (leading dot included) is passed through; seer-core
    # normalizes it.
    assert captured["tld"] == ".com"
    assert captured["thread"].startswith("seer-dispatch")
