"""Router tests for the dig-style DNS query and the DNS trace.

``GET /dns/{domain}/{record_type}`` returns seer-core's ``DnsQueryResult``
object (status, flags, CNAME chain, authority, wildcard probe) rather than a
list of records, and ``GET /dns/trace/{domain}`` returns a ``DnsTrace``. Each
test stubs the binding with the shape seer-core pins (the ``dig_result`` /
``dns_trace_result`` fixtures in conftest), except the few marked
``needs_binding``, which let the compiled core reject input itself — still
hermetic, since the core validates before any network I/O.
"""

from __future__ import annotations

import pytest
from limits import parse as parse_rate_limit

import seer
from seer_api._contract import TRACE_LIMIT

needs_binding = pytest.mark.skipif(
    getattr(seer, "_IS_STUB", False),
    reason="input validation lives in the compiled seer binding",
)


def _must_not_run(name):
    def _fail(*_args):
        raise AssertionError(f"seer.{name} must not be reached")

    return _fail


# ---------------------------------------------------------------------------
# GET /dns/{domain}/{record_type}: the dig result object
# ---------------------------------------------------------------------------


def test_dns_lookup_returns_the_query_result_object(client, monkeypatch, dig_result):
    captured = {}

    def _dig(*args):
        captured["args"] = args
        return dig_result

    monkeypatch.setattr(seer, "dig", _dig, raising=False)
    resp = client.get("/dns/www.seer.test/A")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # An object, not a list of records: the response as dig reports it.
    assert body == dig_result
    assert [r["name"] for r in body["answers"]] == ["www.seer.test", "edge.cdn.test"]
    assert captured["args"] == ("www.seer.test", "A", None)


@pytest.mark.parametrize("status", ["NXDOMAIN", "SERVFAIL", "REFUSED"])
def test_dns_lookup_negative_status_is_a_200_result(client, monkeypatch, dig_result, status):
    # A negative or error rcode is a result the binding returns, not an
    # exception, so the route passes it through as a 200.
    dig_result.update(status=status, flags=[], answers=[], wildcard=None)
    monkeypatch.setattr(seer, "dig", lambda *_a: dig_result, raising=False)
    resp = client.get("/dns/www.seer.test/A")
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == status


# ---------------------------------------------------------------------------
# GET /dns/trace/{domain}
# ---------------------------------------------------------------------------


def test_trace_route_dispatches_to_dns_trace(client, monkeypatch, dns_trace_result):
    captured = {}

    def _trace(*args):
        captured["args"] = args
        return dns_trace_result

    monkeypatch.setattr(seer, "dns_trace", _trace, raising=False)
    # Route order: `/trace/...` is registered before the two-segment
    # `/{domain}/{record_type}` lookup, which would otherwise take it as the
    # domain "trace" with record type "www.example.com".
    monkeypatch.setattr(seer, "dig", _must_not_run("dig"), raising=False)
    resp = client.get("/dns/trace/www.example.com")
    assert resp.status_code == 200, resp.text
    assert resp.json() == dns_trace_result
    assert captured["args"] == ("www.example.com", "A")


def test_trace_route_passes_the_record_type(client, monkeypatch, dns_trace_result):
    captured = {}

    def _trace(*args):
        captured["args"] = args
        return dns_trace_result

    monkeypatch.setattr(seer, "dns_trace", _trace, raising=False)
    resp = client.get("/dns/trace/example.com", params={"record_type": "HTTPS"})
    assert resp.status_code == 200, resp.text
    assert captured["args"] == ("example.com", "HTTPS")


def test_trace_route_does_not_guard_the_queried_name(client, monkeypatch, dns_trace_result):
    # The name is a DNS question, not a connect target: every server the walk
    # queries is vetted by seer-core. An API-layer guard would only refuse
    # legitimate traces of names that resolve to private addresses.
    monkeypatch.setattr(seer, "dns_trace", lambda *_a: dns_trace_result, raising=False)
    monkeypatch.setattr(
        seer, "validate_public_host", _must_not_run("validate_public_host"), raising=False
    )
    assert client.get("/dns/trace/127.0.0.1").status_code == 200


@pytest.mark.parametrize(
    "path",
    [
        "/dns/trace/example.com?record_type=aaaa",  # lowercase
        "/dns/trace/example.com?record_type=AAAAAAAAAAA",  # 11 characters
        "/dns/trace/example.com?record_type=A%20B",
        "/dns/trace/" + "a" * 300,
    ],
)
def test_trace_route_validates_input_before_dispatch(client, monkeypatch, path):
    monkeypatch.setattr(seer, "dns_trace", _must_not_run("dns_trace"), raising=False)
    assert client.get(path).status_code == 422


@pytest.mark.parametrize(
    "exc,status,detail",
    [
        (ValueError("Invalid domain name: bad_name"), 400, "Invalid domain name: bad_name"),
        (TimeoutError("Operation timed out"), 504, "request timed out"),
        # A DnsError (no root server responded) arrives as RuntimeError: the
        # detail is the route's fixed fallback, never the internal message.
        (RuntimeError("DNS resolution failed: a.root-servers.net"), 500, "DNS trace failed"),
    ],
)
def test_trace_route_maps_errors(client, monkeypatch, exc, status, detail):
    def _raising(*_args):
        raise exc

    monkeypatch.setattr(seer, "dns_trace", _raising, raising=False)
    resp = client.get("/dns/trace/example.com")
    assert resp.status_code == status
    assert resp.json()["detail"] == detail


@needs_binding
def test_trace_route_rejects_any_as_a_client_error(client):
    # ANY is a fan-out over several queries; the core refuses to trace it
    # before any network I/O, and the ValueError surfaces as a 400.
    resp = client.get("/dns/trace/example.com", params={"record_type": "ANY"})
    assert resp.status_code == 400
    assert "single record type" in resp.json()["detail"]


@needs_binding
def test_trace_route_rejects_a_bare_srv_name_as_a_client_error(client):
    resp = client.get("/dns/trace/example.com", params={"record_type": "SRV"})
    assert resp.status_code == 400
    assert "_service._proto" in resp.json()["detail"]


def test_trace_route_declares_the_shared_trace_limit(client, monkeypatch, dns_trace_result):
    calls = {"n": 0}

    def _trace(*_args):
        calls["n"] += 1
        return dns_trace_result

    monkeypatch.setattr(seer, "dns_trace", _trace, raising=False)
    allowed = parse_rate_limit(TRACE_LIMIT).amount
    # One budget per route, whatever the domain.
    statuses = [client.get(f"/dns/trace/d{i}.example.com").status_code for i in range(allowed)]
    assert statuses == [200] * allowed
    assert client.get("/dns/trace/example.com").status_code == 429
    assert calls["n"] == allowed, "the over-limit request must not reach the binding"


def test_trace_route_is_in_the_root_index(client):
    assert client.get("/").json()["endpoints"]["dns_trace"] == "/dns/trace/{domain}"
