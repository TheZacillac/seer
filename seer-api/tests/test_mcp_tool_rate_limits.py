"""Per-tool MCP rate limits mirror the REST per-route limits.

The REST routers throttle the expensive fan-out endpoints individually
(``@limiter.limit("5/minute")`` on bulk_ssl/bulk_status/bulk_propagation/
confusables, ``10/minute`` on the other bulk endpoints), but ``/mcp`` only
applied the flat ``SEER_RATE_LIMIT`` (default 30/minute) to every tool call
equally — so an MCP client could drive ``seer_bulk_ssl`` 6x more often than
the REST API permits for the identical operation (2026-07-11 review).
"""

from __future__ import annotations

import asyncio

from limits import parse

import seer
from seer_api._contract import BULK_LIMIT, HEAVY_LIMIT
from seer_api.limiting import limiter
from seer_api.mcp import server
from seer_api.routers import dns, intel, lookup, propagation, rdap, ssl, status, tld, whois


def _text(out) -> str:
    """Text body from either call_tool result shape.

    Success is a content list (the SDK stamps isError=False); failures are a
    CallToolResult with isError=True.
    """
    content = out.content if hasattr(out, "content") else out
    return content[0].text


def test_bulk_ssl_is_limited_to_five_per_minute(monkeypatch):
    calls = {"n": 0}

    def fake_bulk_ssl(domains, concurrency):
        calls["n"] += 1
        return []

    def fake_guard(host, port=443):
        return None

    monkeypatch.setattr(seer, "bulk_ssl", fake_bulk_ssl, raising=False)
    monkeypatch.setattr(seer, "validate_public_host", fake_guard, raising=False)

    args = {"domains": ["example.com"]}
    for _ in range(5):
        out = asyncio.run(server.call_tool("seer_bulk_ssl", args))
        assert "rate limit" not in _text(out).lower(), _text(out)
    out = asyncio.run(server.call_tool("seer_bulk_ssl", args))
    assert out.is_error is True
    assert "rate limit" in _text(out).lower(), _text(out)
    assert calls["n"] == 5, "the over-limit call must not reach the binding"


def test_confusables_is_limited_to_five_per_minute(monkeypatch):
    calls = {"n": 0}

    def fake_confusables(*args, **kwargs):
        calls["n"] += 1
        return {"domain": args[0] if args else "", "registered": []}

    monkeypatch.setattr(seer, "confusables", fake_confusables, raising=False)

    args = {"domain": "example.com"}
    for _ in range(5):
        out = asyncio.run(server.call_tool("seer_confusables", args))
        assert "rate limit" not in _text(out).lower(), _text(out)
    out = asyncio.run(server.call_tool("seer_confusables", args))
    assert out.is_error is True
    assert "rate limit" in _text(out).lower(), _text(out)
    assert calls["n"] == 5


def test_bulk_availability_is_limited_to_ten_per_minute(monkeypatch):
    calls = {"n": 0}

    def fake_bulk_availability(domains, concurrency):
        calls["n"] += 1
        return []

    monkeypatch.setattr(seer, "bulk_availability", fake_bulk_availability, raising=False)

    args = {"domains": ["example.com"]}
    for _ in range(10):
        out = asyncio.run(server.call_tool("seer_bulk_availability", args))
        assert "rate limit" not in _text(out).lower(), _text(out)
    out = asyncio.run(server.call_tool("seer_bulk_availability", args))
    assert out.is_error is True
    assert "rate limit" in _text(out).lower(), _text(out)
    assert calls["n"] == 10, "the over-limit call must not reach the binding"


def test_unlimited_tools_are_not_throttled_per_tool(monkeypatch):

    def fake_lookup(domain):
        return {"domain": domain}

    monkeypatch.setattr(seer, "lookup", fake_lookup, raising=False)

    # Single-domain lookup carries no per-tool limit; the flat /mcp gate
    # (SEER_RATE_LIMIT) is the only throttle. 12 calls must all pass.
    for _ in range(12):
        out = asyncio.run(server.call_tool("seer_lookup", {"domain": "example.com"}))
        assert "rate limit" not in _text(out).lower(), _text(out)


# --- REST/MCP parity ------------------------------------------------------
# Every MCP tool and the REST route(s) running the same operation (a bulk
# tool: the sync and the streaming route). Must name every tool (enforced
# below), so a new tool cannot skip the parity check.
_REST_TWINS = {
    "seer_lookup": (lookup.smart_lookup,),
    "seer_whois": (whois.whois_lookup,),
    "seer_rdap_domain": (rdap.rdap_domain_lookup,),
    "seer_rdap_ip": (rdap.rdap_ip_lookup,),
    "seer_rdap_asn": (rdap.rdap_asn_lookup,),
    "seer_dig": (dns.dns_lookup,),
    "seer_dns_trace": (dns.dns_trace,),
    "seer_dns_compare": (dns.dns_compare,),
    "seer_propagation": (propagation.propagation_check,),
    "seer_status": (status.check_status,),
    "seer_ssl": (ssl.ssl_inspect,),
    "seer_availability": (intel.availability,),
    "seer_info": (intel.info,),
    "seer_subdomains": (intel.subdomains,),
    "seer_dnssec": (intel.dnssec,),
    "seer_delegation": (intel.delegation,),
    "seer_diff": (intel.diff,),
    "seer_caa": (intel.caa,),
    "seer_posture": (intel.posture,),
    "seer_headers": (intel.headers,),
    "seer_audit": (intel.audit,),
    "seer_takeover": (intel.takeover,),
    "seer_confusables": (intel.confusables,),
    "seer_tld_info": (tld.tld_info,),
    "seer_tld_list": (tld.tld_list,),
    "seer_bulk_lookup": (lookup.bulk_smart_lookup, lookup.bulk_smart_lookup_stream),
    "seer_bulk_whois": (whois.bulk_whois_lookup, whois.bulk_whois_stream),
    "seer_bulk_dig": (dns.bulk_dns_lookup, dns.bulk_dns_stream),
    "seer_bulk_propagation": (
        propagation.bulk_propagation_check,
        propagation.bulk_propagation_stream,
    ),
    "seer_bulk_status": (status.bulk_status, status.bulk_status_stream),
    "seer_bulk_ssl": (ssl.bulk_ssl, ssl.bulk_ssl_stream),
    "seer_bulk_info": (intel.bulk_info,),
    "seer_bulk_availability": (intel.bulk_availability,),
}


def _rest_limits(endpoint) -> list:
    """The limits slowapi registered for a REST endpoint function."""
    name = f"{endpoint.__module__}.{endpoint.__name__}"
    return [lim.limit for lim in limiter._route_limits[name]]


def test_every_mcp_tool_names_its_rest_twin():
    assert set(_REST_TWINS) == set(server._TOOLS)


def test_contract_limits_match_across_rest_and_mcp():
    """Regression: REST /subdomains was a literal 20/minute while
    seer_subdomains carried HEAVY_LIMIT (5/minute) for the same resolve=true
    fan-out. An operation on a contract limit (`_contract.BULK_LIMIT` /
    `HEAVY_LIMIT`) on either surface must carry exactly that limit on both."""
    contract = {parse(BULK_LIMIT), parse(HEAVY_LIMIT)}
    mismatched = {}
    for tool, endpoints in _REST_TWINS.items():
        mcp_limit = server._TOOLS[tool].rate_limit
        mcp = [parse(mcp_limit)] if mcp_limit else []
        for endpoint in endpoints:
            rest = _rest_limits(endpoint)
            if (contract & set(rest) or contract & set(mcp)) and rest != mcp:
                mismatched[f"{tool} / {endpoint.__name__}"] = (rest, mcp)
    assert not mismatched, mismatched
