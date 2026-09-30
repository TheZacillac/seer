"""SeerError variants map to typed Python exceptions, through RetryExhausted.

``seer_err_to_py`` classifies a ``RetryExhausted`` by its INNER error, so a
WHOIS/RDAP timeout that went through the retry framework still surfaces as
``TimeoutError`` (seer-api: 504) rather than a generic error. Every category
without a builtin equivalent has its own ``seer.SeerError`` subclass, which
seer-api maps by class — never by sniffing the message text.

The hook ``_raise_retry_exhausted_for_test(kind)`` builds
``RetryExhausted { attempts: 3, last_error: <kind> }`` in Rust and raises it
through ``seer_err_to_py``. It is a ``#[pyfunction]`` because seer-py is a
cdylib and cannot run libpython-linked Rust unit tests (same pattern as
``_json_to_python_nested_for_test``).
"""

import pytest

import seer

# Internal test utility; not re-exported from the top-level `seer` package.
from seer._seer import _raise_retry_exhausted_for_test

TYPED_ERRORS = (
    "RateLimitedError",
    "WhoisServerNotFoundError",
    "DnsError",
    "UpstreamError",
    "LookupFailedError",
    "ParseError",
    "TlsError",
    "ConfigError",
)


def test_exhausted_timeout_is_timeout_error():
    with pytest.raises(TimeoutError):
        _raise_retry_exhausted_for_test("timeout")


def test_exhausted_connection_failure_is_connection_error():
    with pytest.raises(ConnectionError):
        _raise_retry_exhausted_for_test("connection")


def test_layered_retry_wrappers_unwrap_to_leaf_type():
    with pytest.raises(TimeoutError):
        _raise_retry_exhausted_for_test("nested_timeout")


@pytest.mark.parametrize(
    "kind,exc_name,message",
    [
        ("rate_limited", "RateLimitedError", "Rate limited - please try again later"),
        (
            "whois_server_not_found",
            "WhoisServerNotFoundError",
            "WHOIS server not found for this TLD",
        ),
        ("dns", "DnsError", "DNS resolution failed"),
        ("upstream", "UpstreamError", "RDAP lookup failed"),
        ("lookup_failed", "LookupFailedError", "Lookup failed for example.com"),
        ("tls", "TlsError", "SSL inspection failed"),
        ("config", "ConfigError", "Configuration error"),
        ("other", "SeerError", "Operation failed"),
    ],
)
def test_typed_exception_per_category(kind, exc_name, message):
    exc_type = getattr(seer, exc_name)
    with pytest.raises(exc_type) as excinfo:
        _raise_retry_exhausted_for_test(kind)
    # Exactly the category's class (the base only for uncategorized errors),
    # carrying core's sanitized message — never the inner upstream detail.
    assert type(excinfo.value) is exc_type
    assert str(excinfo.value) == message


def test_typed_exceptions_share_a_runtime_error_base():
    # Code written against the old mapping (`except RuntimeError`) still works.
    assert issubclass(seer.SeerError, RuntimeError)
    assert "SeerError" in seer.__all__
    for name in TYPED_ERRORS:
        assert issubclass(getattr(seer, name), seer.SeerError), name
        assert name in seer.__all__, name


def test_unknown_kind_rejected():
    with pytest.raises(ValueError):
        _raise_retry_exhausted_for_test("bogus")
