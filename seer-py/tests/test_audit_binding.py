"""Real-binding tests for seer.audit.

The audit makes live DNS and HTTPS requests, so the end-to-end test is
live-gated. The hermetic tests cover the binding surface: the callable is
exported, and invalid input raises ValueError before any network I/O.
"""

import pytest

import seer


def test_audit_is_exported():
    assert callable(seer.audit)
    assert "audit" in seer.__all__


@pytest.mark.parametrize("bad", ["", "no-dots", "not a domain!!", "..double.dot"])
def test_audit_invalid_domain_raises_value_error(bad):
    # InvalidDomain maps to PyValueError via seer_err_to_py; validation runs
    # before any network I/O, so this stays hermetic.
    with pytest.raises(ValueError):
        seer.audit(bad)


@pytest.mark.live
def test_audit_live_report_shape():
    report = seer.audit("example.com")
    assert report["domain"] == "example.com"
    assert [c["category"] for c in report["categories"]] == [
        "email",
        "web",
        "tls",
        "dns",
        "takeover",
        "registration",
    ]
    assert isinstance(report["passed"], bool)
    for finding in report["findings"]:
        assert finding["severity"] in {"critical", "high", "medium", "low", "info"}
        assert finding["id"].count(".") == 2
