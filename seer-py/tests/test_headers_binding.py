"""Real-binding tests for seer.headers.

The header audit issues a live HTTPS request to the queried domain, so the
end-to-end test is live-gated per repo convention. The hermetic tests cover
the binding surface: the callable is exported, and invalid input raises
ValueError (seer-core's ``normalize_domain`` rejects it before any network
I/O).
"""

import os

import pytest

import seer

_LIVE = pytest.mark.skipif(
    os.environ.get("SEER_LIVE_TESTS") != "1",
    reason="live network test; set SEER_LIVE_TESTS=1 to enable",
)


def test_headers_is_exported():
    assert callable(seer.headers)
    assert "headers" in seer.__all__


@pytest.mark.parametrize("bad", ["", "no-dots", "not a domain!!", "..double.dot"])
def test_headers_invalid_domain_raises_value_error(bad):
    # InvalidDomain maps to PyValueError via seer_err_to_py; validation runs
    # before any network I/O, so this stays hermetic.
    with pytest.raises(ValueError):
        seer.headers(bad)


@_LIVE
def test_headers_live_report_shape():
    report = seer.headers("example.com")
    assert report["domain"] == "example.com"
    assert isinstance(report["score"], int)
    assert 0 <= report["score"] <= 100
    assert report["grade"] in {"A+", "A", "B", "C", "D", "E", "F"}

    # Every weighted header is graded, present or not.
    graded = {h["header"] for h in report["headers"]}
    assert "strict-transport-security" in graded
    assert "content-security-policy" in graded
    for h in report["headers"]:
        assert h["verdict"] in {"absent", "weak", "moderate", "strict", "present"}
