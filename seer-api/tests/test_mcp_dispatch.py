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
