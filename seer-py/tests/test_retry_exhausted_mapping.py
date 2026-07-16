"""RetryExhausted must map to the INNER error's Python exception type.

``seer_err_to_py`` previously had no ``RetryExhausted`` arm, so a WHOIS/RDAP
timeout that went through the retry framework surfaced as a generic
``RuntimeError`` — breaking seer-api's type-based status mapping in
``errors.py`` (``TimeoutError`` -> 504, ``ConnectionError`` -> 502).

The hook ``_raise_retry_exhausted_for_test(kind)`` builds
``RetryExhausted { attempts: 3, last_error: <kind> }`` in Rust and raises it
through ``seer_err_to_py``. It is a ``#[pyfunction]`` because seer-py is a
cdylib and cannot run libpython-linked Rust unit tests (same pattern as
``_json_to_python_nested_for_test``).
"""

import pytest

# Internal test utility; not re-exported from the top-level `seer` package.
from seer._seer import _raise_retry_exhausted_for_test


def test_exhausted_timeout_is_timeout_error():
    with pytest.raises(TimeoutError):
        _raise_retry_exhausted_for_test("timeout")


def test_exhausted_connection_failure_is_connection_error():
    with pytest.raises(ConnectionError):
        _raise_retry_exhausted_for_test("connection")


def test_exhausted_rate_limited_stays_runtime_error():
    # No builtin maps RateLimited; it must remain RuntimeError carrying the
    # inner sanitized message (the MCP layer sniffs for "rate limited").
    with pytest.raises(RuntimeError, match="[Rr]ate limited"):
        _raise_retry_exhausted_for_test("rate_limited")


def test_layered_retry_wrappers_unwrap_to_leaf_type():
    with pytest.raises(TimeoutError):
        _raise_retry_exhausted_for_test("nested_timeout")


def test_unknown_kind_rejected():
    with pytest.raises(ValueError):
        _raise_retry_exhausted_for_test("bogus")
