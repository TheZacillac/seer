"""Live-network test for seer.bulk_ssl. Opt-in via SEER_LIVE_TESTS=1."""

import pytest

import seer


@pytest.mark.live
def test_bulk_ssl_cloudflare_chain_non_empty():
    results = seer.bulk_ssl(["cloudflare.com"])
    assert len(results) == 1
    r = results[0]
    assert r["success"] is True, r
    envelope = r["data"]
    assert envelope["result_type"] == "ssl", envelope
    report = envelope["data"]
    assert isinstance(report["chain"], list)
    assert len(report["chain"]) >= 1
