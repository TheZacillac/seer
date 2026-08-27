"""Router tests for the intel endpoints and single-domain /ssl.

The intel family (availability / info / subdomains / dnssec / diff / caa /
posture / confusables) and ``GET /ssl/{domain}`` previously had zero test
coverage. Each test monkeypatches the underlying seer binding function and
asserts the route dispatches to it with the expected arguments and returns
its payload — the same hermetic pattern as test_hardening's
non-connecting-routes test.
"""

from __future__ import annotations

import pytest

import seer

# ---------------------------------------------------------------------------
# Dispatch: each route must call its seer binding with the right arguments.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,seer_fn,expected_args",
    [
        ("/availability/example.com", "availability", ("example.com",)),
        ("/info/example.com", "info", ("example.com",)),
        ("/subdomains/example.com", "subdomains", ("example.com",)),
        ("/dnssec/example.com", "dnssec", ("example.com",)),
        ("/delegation/example.com", "delegation", ("example.com",)),
        ("/caa/example.com", "caa", ("example.com",)),
        ("/posture/example.com", "posture", ("example.com",)),
        ("/headers/example.com", "headers", ("example.com",)),
        ("/takeover/example.com", "takeover", ("example.com", 10)),
        ("/confusables/example.com", "confusables", ("example.com", 10)),
        ("/diff/example.com/example.org", "diff", ("example.com", "example.org")),
    ],
)
def test_intel_get_routes_dispatch(client, monkeypatch, path, seer_fn, expected_args):
    captured = {}

    def _stub(*args):
        captured["args"] = args
        return {"ok": True, "fn": seer_fn}

    monkeypatch.setattr(seer, seer_fn, _stub, raising=False)
    resp = client.get(path)
    assert resp.status_code == 200, (path, resp.text)
    assert resp.json() == {"ok": True, "fn": seer_fn}
    assert captured["args"] == expected_args


def test_subdomains_resolve_flag_dispatches_to_classify(client, monkeypatch):
    called = {}

    def _classify(domain, concurrency):
        called["classify"] = (domain, concurrency)
        return {"ok": True}

    def _plain(*_args):
        raise AssertionError("resolve=true must not call seer.subdomains")

    monkeypatch.setattr(seer, "subdomains_classify", _classify, raising=False)
    monkeypatch.setattr(seer, "subdomains", _plain, raising=False)
    resp = client.get("/subdomains/example.com?resolve=true&concurrency=7")
    assert resp.status_code == 200, resp.text
    assert called["classify"] == ("example.com", 7)


@pytest.mark.parametrize(
    "path,seer_fn",
    [
        ("/availability/bulk", "bulk_availability"),
        ("/info/bulk", "bulk_info"),
    ],
)
def test_intel_bulk_routes_dispatch(client, monkeypatch, path, seer_fn):
    captured = {}

    def _stub(domains, concurrency):
        captured["args"] = (domains, concurrency)
        return [{"success": True, "data": {"domain": d}} for d in domains]

    monkeypatch.setattr(seer, seer_fn, _stub, raising=False)
    resp = client.post(path, json={"domains": ["a.com", "b.com"], "concurrency": 3})
    assert resp.status_code == 200, (path, resp.text)
    assert captured["args"] == (["a.com", "b.com"], 3)


# ---------------------------------------------------------------------------
# Validation: pydantic/Query bounds must reject out-of-range parameters.
# ---------------------------------------------------------------------------


def test_subdomains_concurrency_over_limit_rejected(client):
    assert client.get("/subdomains/example.com?concurrency=51").status_code == 422


def test_confusables_concurrency_zero_rejected(client):
    assert client.get("/confusables/example.com?concurrency=0").status_code == 422


def test_bulk_availability_domain_cap(client):
    domains = [f"d{i}.com" for i in range(101)]
    resp = client.post("/availability/bulk", json={"domains": domains})
    assert resp.status_code == 422


def test_intel_domain_length_cap(client):
    assert client.get("/posture/" + "a" * 300).status_code == 422


# ---------------------------------------------------------------------------
# Error mapping: http_error must classify by exception type.
# ---------------------------------------------------------------------------


def test_intel_route_maps_timeout_to_504(client, monkeypatch):
    def _raising(*_args):
        raise TimeoutError("upstream hung")

    monkeypatch.setattr(seer, "posture", _raising, raising=False)
    resp = client.get("/posture/example.com")
    assert resp.status_code == 504
    assert resp.json()["detail"] == "request timed out"


def test_intel_route_maps_runtime_error_to_500_with_fallback(client, monkeypatch):
    def _raising(*_args):
        raise RuntimeError("internal detail must not leak")

    monkeypatch.setattr(seer, "caa", _raising, raising=False)
    resp = client.get("/caa/example.com")
    assert resp.status_code == 500
    detail = resp.json()["detail"]
    assert detail == "CAA lookup failed"
    assert "internal detail" not in detail


def test_delegation_maps_value_error_to_400(client, monkeypatch):
    """seer-core validates the domain before any network I/O; the resulting
    ValueError (PyValueError from InvalidDomain) must surface as a 400."""

    def _raising(*_args):
        raise ValueError("Invalid domain: bad_domain")

    monkeypatch.setattr(seer, "delegation", _raising, raising=False)
    resp = client.get("/delegation/bad_domain")
    assert resp.status_code == 400
    assert "Invalid domain" in resp.json()["detail"]


def test_delegation_maps_runtime_error_to_500_with_fallback(client, monkeypatch):
    """DnsError (no responsive parent server) arrives as RuntimeError; the
    detail must be the fixed fallback, never the internal message."""

    def _raising(*_args):
        raise RuntimeError("no parent-zone (com) nameserver answered")

    monkeypatch.setattr(seer, "delegation", _raising, raising=False)
    resp = client.get("/delegation/example.com")
    assert resp.status_code == 500
    assert resp.json()["detail"] == "Delegation check failed"


# ---------------------------------------------------------------------------
# GET /ssl/{domain}: guarded connect target, dispatch, and error mapping.
# ---------------------------------------------------------------------------


def test_ssl_single_dispatches(client, monkeypatch):
    captured = {}

    def _stub_ssl(domain):
        captured["domain"] = domain
        return {"domain": domain, "chain": [], "is_valid": True}

    # The route SSRF-guards the domain (it IS the connect target); stub the
    # validator so the test never resolves DNS, real binding or stub.
    monkeypatch.setattr(seer, "validate_public_host", lambda h, p: None, raising=False)
    monkeypatch.setattr(seer, "ssl", _stub_ssl, raising=False)
    resp = client.get("/ssl/example.com")
    assert resp.status_code == 200, resp.text
    assert resp.json()["domain"] == "example.com"
    assert captured["domain"] == "example.com"


def test_ssl_single_maps_connection_error_to_502(client, monkeypatch):
    def _raising(_domain):
        raise ConnectionError("refused")

    monkeypatch.setattr(seer, "validate_public_host", lambda h, p: None, raising=False)
    monkeypatch.setattr(seer, "ssl", _raising, raising=False)
    resp = client.get("/ssl/example.com")
    assert resp.status_code == 502
    assert resp.json()["detail"] == "upstream connection failed"


def test_ssl_single_rejects_reserved_target(client, monkeypatch):
    """The domain is the TLS connect target — reserved IPs must 400 before
    any seer.ssl dispatch."""

    def _reserved(host: str, port: int) -> None:
        raise ValueError(
            f"Invalid input: refusing to connect to reserved address: {host}"
        )

    def _must_not_run(_domain):
        raise AssertionError("seer.ssl must not be reached for a reserved target")

    monkeypatch.setattr(seer, "validate_public_host", _reserved, raising=False)
    monkeypatch.setattr(seer, "ssl", _must_not_run, raising=False)
    resp = client.get("/ssl/127.0.0.1")
    assert resp.status_code == 400
    assert "reserved" in resp.json()["detail"].lower()
