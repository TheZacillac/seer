"""Real-binding tests for seer.all_tlds / seer.tld_info.

``all_tlds`` is purely embedded data (no network), so it runs hermetically.
``tld_info`` always attempts the IANA RDAP bootstrap fetch for the RDAP URL
(the WHOIS server / registry URL / classification come from the embedded
map), so its end-to-end test is live-gated per repo convention.
"""

import os

import pytest

import seer

_LIVE = pytest.mark.skipif(
    os.environ.get("SEER_LIVE_TESTS") != "1",
    reason="live network test; set SEER_LIVE_TESTS=1 to enable",
)


def test_all_tlds_returns_embedded_catalog():
    tlds = seer.all_tlds()
    assert isinstance(tlds, list)
    # The embedded map covers the full IANA root zone (~1,400 TLDs).
    assert len(tlds) > 1000
    assert all(isinstance(t, str) and t for t in tlds)
    assert "com" in tlds
    assert "xn--p1ai" in tlds  # punycode ccTLDs are included
    # Contract from seer_core::all_tlds: sorted and deduplicated.
    assert tlds == sorted(tlds)
    assert len(tlds) == len(set(tlds))


@_LIVE
def test_tld_info_com_has_embedded_and_bootstrap_data():
    info = seer.tld_info("com")
    assert info["tld"] == "com"
    assert info["tld_type"] == "generic"
    assert info["whois_server"] == "whois.verisign-grs.com"
    assert info["registry_url"]
    # Live IANA bootstrap: .com must have an RDAP base URL.
    assert info["rdap_url"] and info["rdap_url"].startswith("https://")


@_LIVE
def test_tld_info_normalizes_dot_and_case():
    info = seer.tld_info(".COM")
    assert info["tld"] == "com"
    assert info["whois_server"] == "whois.verisign-grs.com"
