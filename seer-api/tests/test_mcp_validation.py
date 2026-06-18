"""Unit tests for MCP argument validation helpers."""

from __future__ import annotations

import pytest

from seer_api.mcp.server import MAX_CONCURRENCY, _get_concurrency


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
