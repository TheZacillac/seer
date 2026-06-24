"""Tests for the validated env_int helper (issue #50)."""

from __future__ import annotations

import pytest

from seer_api._env import env_int


def test_env_int_uses_default_when_unset(monkeypatch):
    monkeypatch.delenv("SEER_TEST_INT", raising=False)
    assert env_int("SEER_TEST_INT", 7) == 7


def test_env_int_parses_valid_integer(monkeypatch):
    monkeypatch.setenv("SEER_TEST_INT", "42")
    assert env_int("SEER_TEST_INT", 7) == 42


def test_env_int_blank_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("SEER_TEST_INT", "   ")
    assert env_int("SEER_TEST_INT", 7) == 7


def test_env_int_non_integer_raises_clear_runtime_error(monkeypatch):
    # The motivating case: WEB_CONCURRENCY=auto must fail with a clear,
    # actionable RuntimeError, not an opaque ValueError traceback.
    monkeypatch.setenv("SEER_TEST_INT", "auto")
    with pytest.raises(RuntimeError) as exc:
        env_int("SEER_TEST_INT", 7)
    assert "SEER_TEST_INT" in str(exc.value)
    assert "integer" in str(exc.value)


def test_env_int_clamps_below_min_value(monkeypatch):
    monkeypatch.setenv("SEER_TEST_INT", "0")
    assert env_int("SEER_TEST_INT", 7, min_value=1) == 1
