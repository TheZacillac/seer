"""MCP tests for the dig-style ``seer_dig`` and the ``seer_dns_trace`` tool.

``seer_dig`` now returns seer-core's ``DnsQueryResult`` object and
``seer_dns_trace`` a ``DnsTrace``; both are stubbed with the shapes seer-core
pins (conftest's ``dig_result`` / ``dns_trace_result``). Tests marked
``needs_binding`` let the compiled core reject input itself, which it does
before any network I/O.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from limits import parse as parse_rate_limit

import seer
from seer_api._contract import HEAVY_LIMIT
from seer_api.mcp import server
from seer_api.mcp.server import execute_tool

needs_binding = pytest.mark.skipif(
    getattr(seer, "_IS_STUB", False),
    reason="input validation lives in the compiled seer binding",
)


def _tool(name: str):
    return next(t for t in asyncio.run(server.list_tools()) if t.name == name)


def _payload(result) -> object:
    """The JSON a successful call_tool returned, preamble stripped."""
    text = result[0].text
    assert text.startswith(server.UNTRUSTED_PREAMBLE)
    return json.loads(text[len(server.UNTRUSTED_PREAMBLE) :])


def _record(captured: dict, value):
    def _stub(*args):
        captured["args"] = args
        return value

    return _stub


# ---------------------------------------------------------------------------
# seer_dig
# ---------------------------------------------------------------------------


def test_dig_returns_the_query_result_object(monkeypatch, dig_result):
    captured = {}
    monkeypatch.setattr(seer, "dig", _record(captured, dig_result), raising=False)
    result = asyncio.run(server.call_tool("seer_dig", {"domain": "www.seer.test"}))
    assert _payload(result) == dig_result
    assert captured["args"] == ("www.seer.test", "A", None)


def test_dig_description_explains_the_response():
    description = _tool("seer_dig").description
    for term in ("status", "NXDOMAIN", "NODATA", "CNAME chain", "SOA", "wildcard"):
        assert term in description, f"seer_dig description should mention {term!r}"


# ---------------------------------------------------------------------------
# seer_dns_trace
# ---------------------------------------------------------------------------


def test_dns_trace_is_listed_with_a_domain_and_record_type_schema():
    tool = _tool("seer_dns_trace")
    assert "dig +trace" in tool.description
    schema = tool.input_schema
    assert schema["required"] == ["domain"]
    assert set(schema["properties"]) == {"domain", "record_type"}
    # The shared record-type argument: the list rendered from the core.
    assert schema["properties"]["record_type"]["description"] == server._RECORD_TYPE_DESC


def test_dns_trace_dispatches_with_the_default_type(monkeypatch, dns_trace_result):
    captured = {}
    monkeypatch.setattr(seer, "dns_trace", _record(captured, dns_trace_result), raising=False)
    result = asyncio.run(server.call_tool("seer_dns_trace", {"domain": "www.example.com"}))
    assert _payload(result) == dns_trace_result
    assert captured["args"] == ("www.example.com", "A")


def test_dns_trace_passes_the_record_type(monkeypatch, dns_trace_result):
    captured = {}
    monkeypatch.setattr(seer, "dns_trace", _record(captured, dns_trace_result), raising=False)
    asyncio.run(execute_tool("seer_dns_trace", {"domain": "example.com", "record_type": "MX"}))
    assert captured["args"] == ("example.com", "MX")


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "Required argument 'domain'"),
        ({"domain": ""}, "Required argument 'domain'"),
        ({"domain": "example.com", "record_type": "mx"}, "'record_type'"),
        ({"domain": "example.com", "record_type": 28}, "'record_type'"),
    ],
)
def test_dns_trace_validates_arguments_before_dispatch(monkeypatch, arguments, message):
    def _must_not_run(*_args):  # pragma: no cover - guarded by validation
        raise AssertionError("seer.dns_trace must not be reached")

    monkeypatch.setattr(seer, "dns_trace", _must_not_run, raising=False)
    with pytest.raises(ValueError, match=message):
        asyncio.run(execute_tool("seer_dns_trace", arguments))


@needs_binding
def test_dns_trace_any_is_invalid_input():
    # The core refuses to trace ANY before any network I/O.
    result = asyncio.run(
        server.call_tool("seer_dns_trace", {"domain": "example.com", "record_type": "ANY"})
    )
    assert result.is_error is True
    text = result.content[0].text
    assert "Invalid input:" in text
    assert "single record type" in text


def test_dns_trace_mirrors_the_rest_rate_limit():
    # A trace can hold a dispatch thread for its whole core deadline, so it is
    # in the heavy class, and the REST route and the tool share that one
    # limit, so neither surface can outrun the other.
    assert server._TOOL_RATE_LIMITS["seer_dns_trace"] == HEAVY_LIMIT


def test_dns_trace_is_rate_limited_per_tool(monkeypatch, dns_trace_result):
    calls = {"n": 0}

    def _trace(*_args):
        calls["n"] += 1
        return dns_trace_result

    monkeypatch.setattr(seer, "dns_trace", _trace, raising=False)
    allowed = parse_rate_limit(HEAVY_LIMIT).amount
    args = {"domain": "example.com"}
    for _ in range(allowed):
        out = asyncio.run(server.call_tool("seer_dns_trace", args))
        assert not getattr(out, "is_error", False), out
    out = asyncio.run(server.call_tool("seer_dns_trace", args))
    assert out.is_error is True
    assert "rate limit" in out.content[0].text.lower()
    assert calls["n"] == allowed, "the over-limit call must not reach the binding"


# ---------------------------------------------------------------------------
# Record types
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("record_type", ["HTTPS", "SVCB", "CDS", "CDNSKEY"])
def test_new_record_types_are_advertised(record_type):
    # Rendered from the binding's record_types() (core's RecordType list),
    # never a hand-kept copy.
    assert record_type in seer.record_types()
    assert record_type in server._RECORD_TYPE_DESC
