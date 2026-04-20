"""Regression tests for C5: json_to_python recursion depth cap.

An adversarial WHOIS or RDAP response could nest `serde_json::Value`
deeply enough to overflow the thread stack during conversion, which
aborts the Python process unrecoverably. The cap in `json_to_python`
surfaces the failure as a catchable `ValueError` instead.

The test hook `_json_to_python_nested_for_test(depth)` is a
`#[pyfunction]` that builds a `depth`-deep nested array inside Rust and
runs it through `json_to_python`. It lives in the extension module
because `seer-py` is a `cdylib` crate and cannot run pyo3 code from a
Rust `#[cfg(test)]` block without linking libpython at test time.
"""

import pytest

# The hook is not re-exported from the top-level `seer` package because
# it's an internal test utility; import directly from the extension.
from seer._seer import _json_to_python_nested_for_test

# Must stay in sync with MAX_JSON_DEPTH in seer-py/src/lib.rs.
MAX_JSON_DEPTH = 128


def test_depth_at_limit_succeeds():
    """Exactly MAX_JSON_DEPTH levels must convert without error."""
    result = _json_to_python_nested_for_test(MAX_JSON_DEPTH)
    assert result is not None


def test_depth_over_limit_raises_value_error():
    """200 levels of nesting must raise ValueError, not crash the process."""
    with pytest.raises(ValueError) as exc_info:
        _json_to_python_nested_for_test(200)
    assert "max depth" in str(exc_info.value).lower()


def test_depth_just_over_limit_raises():
    """MAX_JSON_DEPTH + 1 is the boundary that must trip the guard."""
    with pytest.raises(ValueError):
        _json_to_python_nested_for_test(MAX_JSON_DEPTH + 1)
