"""Real-binding tests for seer.takeover.

The takeover scan enumerates subdomains via Certificate Transparency logs and
then resolves (and may fetch) each candidate, so the end-to-end test is
live-gated per repo convention. The hermetic tests cover the binding surface:
the callable is exported, invalid input raises ValueError, and an
out-of-range concurrency is rejected before any network I/O.
"""

import os

import pytest

import seer

_LIVE = pytest.mark.skipif(
    os.environ.get("SEER_LIVE_TESTS") != "1",
    reason="live network test; set SEER_LIVE_TESTS=1 to enable",
)


def test_takeover_is_exported():
    assert callable(seer.takeover)
    assert "takeover" in seer.__all__


@pytest.mark.parametrize("bad", ["", "no-dots", "not a domain!!", "..double.dot"])
def test_takeover_invalid_domain_raises_value_error(bad):
    with pytest.raises(ValueError):
        seer.takeover(bad)


@pytest.mark.parametrize("bad_concurrency", [-1, 51, 1000])
def test_takeover_rejects_out_of_range_concurrency(bad_concurrency):
    # validate_concurrency rejects before any enumeration, keeping this
    # hermetic even though the domain itself is valid. A negative value fails
    # earlier still, in the usize conversion (OverflowError).
    with pytest.raises((ValueError, OverflowError)):
        seer.takeover("example.com", bad_concurrency)


@_LIVE
def test_takeover_live_report_shape():
    report = seer.takeover("example.com")
    assert report["domain"] == "example.com"
    assert isinstance(report["hosts_checked"], int)
    assert isinstance(report["vulnerable"], int)
    assert isinstance(report["potential"], int)

    for finding in report["findings"]:
        assert finding["verdict"] in {"vulnerable", "potential", "safe"}
        # A vulnerable verdict must always carry the fingerprint that
        # confirmed it — that is the whole contract of the module.
        if finding["verdict"] == "vulnerable":
            assert finding.get("evidence")
