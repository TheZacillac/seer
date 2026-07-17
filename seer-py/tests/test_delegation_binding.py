"""Real-binding tests for seer.delegation.

The delegation health check always queries parent-zone nameservers and
probes the delegated NS hosts over the network, so its end-to-end test is
live-gated per repo convention. The hermetic tests cover the binding
surface: the callable is exported, and invalid input raises ValueError
(seer-core's ``normalize_domain`` rejects it before any network I/O).
"""

import os

import pytest

import seer

_LIVE = pytest.mark.skipif(
    os.environ.get("SEER_LIVE_TESTS") != "1",
    reason="live network test; set SEER_LIVE_TESTS=1 to enable",
)


def test_delegation_is_exported():
    assert callable(seer.delegation)
    assert "delegation" in seer.__all__


@pytest.mark.parametrize("bad", ["", "no-dots", "not a domain!!", "..double.dot"])
def test_delegation_invalid_domain_raises_value_error(bad):
    # InvalidDomain maps to PyValueError via seer_err_to_py; validation runs
    # before any network I/O, so this stays hermetic.
    with pytest.raises(ValueError):
        seer.delegation(bad)


@_LIVE
def test_delegation_live_report_shape():
    # NOTE: requires outbound IPv6 OR a resolver returning IPv4 for the
    # gtld-servers: seer-core's resolve_host_ip may pick an AAAA address
    # for the parent servers, and on an IPv6-less host every direct parent
    # query is then unreachable, so check() errors with DnsError
    # ("DNS resolution failed") rather than producing a report.
    report = seer.delegation("example.com")
    assert report["domain"] == "example.com"
    assert report["parent_zone"] == "com"
    assert report["parent_server_queried"]  # singular "server", per core spec
    assert isinstance(report["delegated_ns"], list) and report["delegated_ns"]
    assert isinstance(report["zone_ns"], list)
    assert isinstance(report["in_sync"], bool)
    assert isinstance(report["missing_from_zone"], list)
    assert isinstance(report["missing_from_parent"], list)
    assert isinstance(report["lame"], list)
    assert isinstance(report["warnings"], list)
