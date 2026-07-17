"""Unit tests for MCP argument validation helpers."""

from __future__ import annotations

import asyncio

import pytest

import seer
from seer_api.mcp import server
from seer_api.mcp.server import (
    MAX_CONCURRENCY,
    _get_concurrency,
    _invalid_input_message,
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
    assert result.isError is True
    text = result.content[0].text
    assert text == (
        server.UNTRUSTED_PREAMBLE
        + "Invalid input: refusing to connect to reserved address: 127.0.0.1"
    )
    assert text.count("Invalid input:") == 1
