"""MCP tool failures must carry isError=True and the untrusted-data preamble.

Previously every failure branch in ``call_tool`` returned a bare
``list[TextContent]``, which the MCP SDK wraps as ``isError=False`` — so a
genuine WHOIS timeout was indistinguishable from data at the protocol level.
Error texts also skipped the prompt-injection preamble applied to success
payloads, even though they can embed registry/registrar-derived content.

Both transports share one ``Server`` registry (``main.py`` passes
``mcp.server.mcp`` to the StreamableHTTPSessionManager; ``server.main()``
runs the same object on stdio), so the SDK-handler tests below cover stdio
and streamable-HTTP alike.
"""

from __future__ import annotations

import asyncio

import mcp.types as types
import pytest

import seer
from seer_api.mcp import server as mcp_server


def _call_with_error(monkeypatch, exc: Exception):
    async def _boom(_name, _arguments):
        raise exc

    monkeypatch.setattr(mcp_server, "execute_tool", _boom)
    return asyncio.run(mcp_server.call_tool("seer_lookup", {"domain": "example.com"}))


@pytest.mark.parametrize(
    "exc",
    [
        ValueError("'domains' must be a non-empty list"),
        TimeoutError("Operation timed out"),
        ConnectionError("WHOIS connection failed"),
        RuntimeError("WHOIS server not found for this TLD"),  # permanent branch
        RuntimeError("Rate limited - please try again later"),  # rate-limited branch
        RuntimeError("RDAP lookup failed"),  # ambiguous branch
        Exception("unexpected internal failure"),  # catch-all branch
    ],
)
def test_every_failure_branch_sets_iserror_and_preamble(monkeypatch, exc):
    result = _call_with_error(monkeypatch, exc)
    assert isinstance(result, types.CallToolResult), (
        "failures must return CallToolResult, not a bare content list "
        "(which the SDK stamps isError=False)"
    )
    assert result.isError is True
    assert len(result.content) == 1
    assert result.content[0].text.startswith(mcp_server.UNTRUSTED_PREAMBLE)


def test_per_tool_rate_limit_throttle_sets_iserror(monkeypatch):
    monkeypatch.setattr(mcp_server, "_tool_rate_ok", lambda _name: False)
    result = asyncio.run(
        mcp_server.call_tool("seer_bulk_ssl", {"domains": ["example.com"]})
    )
    assert isinstance(result, types.CallToolResult)
    assert result.isError is True
    assert "rate limit" in result.content[0].text.lower()


def _run_sdk_handler(name: str, arguments: dict) -> types.CallToolResult:
    """Drive the registered SDK request handler — the exact code path both
    the stdio and streamable-HTTP transports invoke for tools/call."""
    handler = mcp_server.mcp.request_handlers[types.CallToolRequest]
    req = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(name=name, arguments=arguments),
    )
    result = asyncio.run(handler(req))
    ctr = result.root
    assert isinstance(ctr, types.CallToolResult)
    return ctr


def test_sdk_handler_stamps_iserror_on_failure(monkeypatch):
    async def _boom(_name, _arguments):
        raise TimeoutError("Operation timed out")

    monkeypatch.setattr(mcp_server, "execute_tool", _boom)
    ctr = _run_sdk_handler("seer_lookup", {"domain": "example.com"})
    assert ctr.isError is True
    assert ctr.content[0].text.startswith(mcp_server.UNTRUSTED_PREAMBLE)


def test_sdk_handler_success_is_not_error(monkeypatch):
    def _ok(domain):
        return {"domain": domain, "source": "rdap"}

    monkeypatch.setattr(seer, "lookup", _ok, raising=False)
    ctr = _run_sdk_handler("seer_lookup", {"domain": "example.com"})
    assert ctr.isError is False
    assert ctr.content[0].text.startswith(mcp_server.UNTRUSTED_PREAMBLE)
    assert "example.com" in ctr.content[0].text
