"""Live-network test for seer.bulk_ssl. Opt-in via SEER_LIVE_TESTS=1."""

import os

import pytest

import seer


@pytest.mark.skipif(
    os.environ.get("SEER_LIVE_TESTS") != "1",
    reason="live network test; set SEER_LIVE_TESTS=1 to enable",
)
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
