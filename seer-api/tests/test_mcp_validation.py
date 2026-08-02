"""Unit tests for MCP argument validation helpers."""

from __future__ import annotations

import asyncio

import pytest

import seer
from seer_api.mcp import server
from seer_api.mcp.server import (
    MAX_BULK_DOMAINS,
    MAX_CONCURRENCY,
    _get_concurrency,
    _invalid_input_message,
    _require_tld,
    execute_tool,
)


def test_get_concurrency_default_when_absent() -> None:
    assert _get_concurrency({}) == 10


def test_get_concurrency_accepts_value_at_limit() -> None:
    assert _get_concurrency({"concurrency": MAX_CONCURRENCY}) == MAX_CONCURRENCY


def test_get_concurrency_rejects_over_limit() -> None:
    # MCP must REJECT an over-limit value (matching the REST layer's 422),
    # not silently clamp it to the maximum.
    with pytest.raises(ValueError, match="exceeds maximum"):
        _get_concurrency({"concurrency": MAX_CONCURRENCY + 1})


def test_get_concurrency_rejects_non_positive() -> None:
    with pytest.raises(ValueError, match="positive integer"):
        _get_concurrency({"concurrency": 0})


def test_get_concurrency_rejects_bool() -> None:
    # bool is a subclass of int in Python; it must not slip through.
    with pytest.raises(ValueError, match="positive integer"):
        _get_concurrency({"concurrency": True})


def test_invalid_input_message_prefixes_bare_error() -> None:
    # Server-side validators (e.g. _require_domains) raise bare messages; the
    # MCP layer must add the 'Invalid input:' marker exactly once.
    msg = _invalid_input_message(ValueError("'domains' must be a non-empty list"))
    assert msg == "Invalid input: 'domains' must be a non-empty list"


def test_invalid_input_message_does_not_double_existing_prefix() -> None:
    # seer-core's `InvalidInput` Display already prepends 'Invalid input:'
    # (e.g. the SSRF guard's reserved-address refusal), and PyO3 surfaces that
    # text verbatim. The MCP layer must not prepend a second copy.
    exc = ValueError(
        "Invalid input: refusing to connect to reserved address: 127.0.0.1"
    )
    msg = _invalid_input_message(exc)
    assert msg == "Invalid input: refusing to connect to reserved address: 127.0.0.1"
    assert msg.count("Invalid input:") == 1


def test_bulk_availability_rejects_over_limit_domains() -> None:
    domains = [f"d{i}.com" for i in range(MAX_BULK_DOMAINS + 1)]
    with pytest.raises(ValueError, match="exceeds maximum"):
        asyncio.run(execute_tool("seer_bulk_availability", {"domains": domains}))


def test_bulk_availability_rejects_empty_domains() -> None:
    with pytest.raises(ValueError, match="non-empty list"):
        asyncio.run(execute_tool("seer_bulk_availability", {"domains": []}))


def test_bulk_availability_rejects_non_string_domain() -> None:
    with pytest.raises(ValueError, match="non-empty string"):
        asyncio.run(execute_tool("seer_bulk_availability", {"domains": ["a.com", 7]}))


def test_bulk_availability_rejects_over_limit_concurrency() -> None:
    with pytest.raises(ValueError, match="exceeds maximum"):
        asyncio.run(
            execute_tool(
                "seer_bulk_availability",
                {"domains": ["a.com"], "concurrency": MAX_CONCURRENCY + 1},
            )
        )


def test_bulk_availability_mirrors_rest_rate_limit() -> None:
    # REST throttles POST /availability/bulk at 10/minute; the MCP per-tool
    # table must match so neither surface can outrun the other.
    assert server._TOOL_RATE_LIMITS["seer_bulk_availability"] == "10/minute"


@pytest.mark.parametrize("token", ["com", ".com", "xn--p1ai", "CO", "travel"])
def test_require_tld_accepts_plausible_tokens(token) -> None:
    assert _require_tld({"tld": token}) == token


@pytest.mark.parametrize(
    "junk", ["bad_tld", "-com", "com-", "..com", "com.net", "exa!mple", ""]
)
def test_require_tld_rejects_junk(junk) -> None:
    with pytest.raises(ValueError):
        _require_tld({"tld": junk})


def test_call_tool_tld_info_junk_is_invalid_input(monkeypatch) -> None:
    def _must_not_run(_tld):  # pragma: no cover - guarded by validation
        raise AssertionError("seer.tld_info must not be reached for junk input")

    monkeypatch.setattr(seer, "tld_info", _must_not_run, raising=False)
    result = asyncio.run(server.call_tool("seer_tld_info", {"tld": "not_a_tld!"}))
    assert result.is_error is True
    assert "Invalid input:" in result.content[0].text


def test_new_tools_are_listed() -> None:
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert "seer_bulk_availability" in names
    assert "seer_tld_info" in names
    assert "seer_delegation" in names


def test_call_tool_delegation_missing_domain_is_invalid_input() -> None:
    result = asyncio.run(server.call_tool("seer_delegation", {}))
    assert result.is_error is True
    assert "Required argument 'domain'" in result.content[0].text


def test_call_tool_ssrf_refusal_has_single_prefix(monkeypatch) -> None:
    """End-to-end: an SSRF refusal surfaced through call_tool must show the
    'Invalid input:' marker exactly once. The seer-core validator already
    prepends it (reproduced here), so call_tool must not add a second copy.
    """

    def _reserved(host: str, port: int) -> None:
        raise ValueError(
            f"Invalid input: refusing to connect to reserved address: {host}"
        )

    monkeypatch.setattr(seer, "validate_public_host", _reserved, raising=False)

    result = asyncio.run(server.call_tool("seer_rdap_ip", {"ip": "127.0.0.1"}))
    assert result.is_error is True
    text = result.content[0].text
    assert text == (
        server.UNTRUSTED_PREAMBLE
        + "Invalid input: refusing to connect to reserved address: 127.0.0.1"
    )
    assert text.count("Invalid input:") == 1


def test_record_type_description_covers_every_type_core_accepts() -> None:
    """Drift guard for the MCP tool schemas.

    The record-type list was hand-mirrored into the schema descriptions and
    drifted to 13 of 16 types, leaving NAPTR/TLSA/SSHFP queryable but
    undiscoverable by the AI clients that read these schemas. The description
    is now rendered from ``seer.record_types()`` (which is itself rendered from
    core's ``RecordType::ALL_NAMES``), so this asserts the rendering actually
    reaches the schema rather than that the two lists match.
    """
    types = seer.record_types()
    assert len(types) >= 16
    for name in types:
        assert name in server._RECORD_TYPE_DESC, f"{name} missing from schema description"


def test_every_record_type_argument_advertises_the_full_list() -> None:
    """No tool may carry a `record_type` argument with a hand-written
    description — all five must share the rendered constant, or the next one
    added will silently reintroduce the drift."""
    tools = asyncio.run(server.list_tools())
    described = [
        t.input_schema.get("properties", {}).get("record_type")
        for t in tools
        if "record_type" in t.input_schema.get("properties", {})
    ]
    assert described, "expected at least one tool with a record_type argument"
    for prop in described:
        assert prop["description"] == server._RECORD_TYPE_DESC
