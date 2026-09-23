"""Tests for Batch 12 API hardening: auth, correlation-ID, path caps, validation."""

from __future__ import annotations

import importlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import seer

# Nameserver specs are parsed by seer-core through `seer.nameserver_target`;
# the conftest stub (no compiled binding) cannot supply that parser.
needs_ns_parser = pytest.mark.skipif(
    not hasattr(seer, "nameserver_target"),
    reason="nameserver specs are parsed by the compiled seer binding",
)


@pytest.fixture
def app_module():
    """Re-import the FastAPI app fresh so env-var-driven config is picked up."""
    import seer_api.main as main

    importlib.reload(main)
    return main


@pytest.fixture
def client(app_module):
    return TestClient(app_module.app)


# ---------------------------------------------------------------------------
# M3: X-Correlation-ID sanitization
# ---------------------------------------------------------------------------


def test_correlation_id_strips_control_chars(client):
    """Injected CR/LF and non-printable bytes must never reach response headers."""
    resp = client.get(
        "/health",
        headers={"X-Correlation-ID": "abc\r\nInjected: evil\tdef"},
    )
    assert resp.status_code == 200
    request_id = resp.headers.get("X-Request-ID", "")
    assert "\r" not in request_id
    assert "\n" not in request_id
    assert "\t" not in request_id
    # Printable-only content is kept (spaces are 0x20 which is outside the
    # 0x21-0x7E range and thus also stripped — that is intentional).
    assert request_id == "abcInjected:evildef"


def test_correlation_id_length_capped(client):
    resp = client.get("/health", headers={"X-Correlation-ID": "a" * 500})
    assert resp.status_code == 200
    assert len(resp.headers.get("X-Request-ID", "")) <= 64


def test_correlation_id_defaulted_when_missing(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.headers.get("X-Request-ID")


# ---------------------------------------------------------------------------
# M2: optional bearer auth
# ---------------------------------------------------------------------------


def test_api_key_required_when_set(monkeypatch):
    monkeypatch.setenv("SEER_API_KEY", "s3cret")
    # Enable docs so the exemption path can be exercised. Without this
    # /docs returns 404 (see test_docs_off_by_default).
    monkeypatch.setenv("SEER_DOCS_ENABLED", "true")
    import seer_api.main as main

    importlib.reload(main)
    c = TestClient(main.app)

    # Missing auth -> 401
    assert c.get("/").status_code == 401
    # Wrong token -> 401
    assert c.get("/", headers={"Authorization": "Bearer nope"}).status_code == 401
    # Correct token -> 200
    assert c.get("/", headers={"Authorization": "Bearer s3cret"}).status_code == 200
    # /health exempt
    assert c.get("/health").status_code == 200
    # /docs exempt (only when SEER_DOCS_ENABLED=true)
    assert c.get("/docs").status_code == 200

    monkeypatch.delenv("SEER_API_KEY")
    monkeypatch.delenv("SEER_DOCS_ENABLED")
    importlib.reload(main)


def test_preflight_options_bypasses_auth(monkeypatch):
    """CORS preflight OPTIONS must bypass auth so browsers get CORS headers."""
    monkeypatch.setenv("SEER_API_KEY", "secret")
    monkeypatch.setenv("SEER_CORS_ORIGINS", "https://example.org")
    import seer_api.main as main

    importlib.reload(main)
    c = TestClient(main.app)

    response = c.options(
        "/lookup/example.com",
        headers={
            "Origin": "https://example.org",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code != 401, response.text
    assert "access-control-allow-origin" in {k.lower() for k in response.headers}

    monkeypatch.delenv("SEER_API_KEY")
    monkeypatch.delenv("SEER_CORS_ORIGINS")
    importlib.reload(main)


def test_non_ascii_bearer_token_is_401_not_500(monkeypatch):
    """`hmac.compare_digest(str, str)` raises TypeError on non-ASCII input, so
    an unauthenticated `Authorization: Bearer été` used to crash into a 500."""
    monkeypatch.setenv("SEER_API_KEY", "s3cret")
    import seer_api.main as main

    importlib.reload(main)
    c = TestClient(main.app)
    # httpx only sends str header values as ASCII; send raw bytes the way a
    # hostile client can (latin-1 and UTF-8 spellings).
    for raw in ("Bearer été".encode("latin-1"), "Bearer été".encode()):
        resp = c.get("/", headers={"Authorization": raw})
        assert resp.status_code == 401, (raw, resp.status_code)

    monkeypatch.delenv("SEER_API_KEY")
    importlib.reload(main)


def test_non_ascii_api_key_is_usable(monkeypatch):
    """A non-ASCII SEER_API_KEY must not break every request: the token a
    client sends (UTF-8 on the wire) authenticates, anything else is 401."""
    monkeypatch.setenv("SEER_API_KEY", "clé")
    import seer_api.main as main

    importlib.reload(main)
    c = TestClient(main.app)
    assert c.get("/").status_code == 401
    assert c.get("/", headers={"Authorization": b"Bearer cl"}).status_code == 401
    ok = c.get("/", headers={"Authorization": "Bearer clé".encode()})  # UTF-8 on the wire
    assert ok.status_code == 200

    monkeypatch.delenv("SEER_API_KEY")
    importlib.reload(main)


def test_auth_exemption_honors_root_path(monkeypatch):
    """Under `--root-path /api` the request path carries the prefix while the
    router strips it; the /health exemption must still match."""
    monkeypatch.setenv("SEER_API_KEY", "s3cret")
    import seer_api.main as main

    importlib.reload(main)
    c = TestClient(main.app, root_path="/api")
    assert c.get("/api/health").status_code == 200
    # Everything else is still authenticated under the prefix.
    assert c.get("/api/").status_code == 401
    ok = c.get("/api/", headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code == 200

    monkeypatch.delenv("SEER_API_KEY")
    importlib.reload(main)


# ---------------------------------------------------------------------------
# M6: path param length caps
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/lookup/{d}",
        "/whois/{d}",
        "/rdap/domain/{d}",
        "/dns/{d}/A",
        "/propagation/{d}/A",
        "/status/{d}",
    ],
)
def test_domain_length_cap(client, path):
    too_long = "a" * 300
    resp = client.get(path.format(d=too_long))
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# M7: ASN upper bound
# ---------------------------------------------------------------------------


def test_asn_upper_bound(client):
    resp = client.get("/rdap/asn/99999999999999999")
    assert resp.status_code == 422


def test_asn_negative_rejected(client):
    resp = client.get("/rdap/asn/-1")
    # FastAPI returns 404 for a leading `-` (doesn't match int) or 422 for ge=0
    assert resp.status_code in (404, 422)


# ---------------------------------------------------------------------------
# M8: record_type validation (REST)
# ---------------------------------------------------------------------------


def test_record_type_rejects_invalid_chars(client):
    resp = client.get("/dns/example.com/INVALIDLONG_TYPE")
    assert resp.status_code == 422


def test_record_type_rejects_long(client):
    resp = client.get("/dns/example.com/AAAAAAAAAAA")  # 11 chars
    assert resp.status_code == 422


def test_bulk_dns_record_type_validated(client):
    resp = client.post(
        "/dns/bulk",
        json={"domains": ["example.com"], "record_type": "badlowercase"},
    )
    assert resp.status_code == 422


def test_bulk_propagation_record_type_validated(client):
    resp = client.post(
        "/propagation/bulk",
        json={"domains": ["example.com"], "record_type": "LONG_INVALID"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# M8: record_type validation (MCP)
# ---------------------------------------------------------------------------


def test_mcp_record_type_rejected():
    from seer_api.mcp.server import _require_record_type

    with pytest.raises(ValueError):
        _require_record_type({"record_type": "INVALIDLONG_TYPE"})
    with pytest.raises(ValueError):
        _require_record_type({"record_type": "lowercase"})
    with pytest.raises(ValueError):
        _require_record_type({"record_type": 123})
    # Valid cases pass through.
    assert _require_record_type({"record_type": "A"}) == "A"
    assert _require_record_type({"record_type": "AAAA"}) == "AAAA"
    assert _require_record_type({}) == "A"  # default


# ---------------------------------------------------------------------------
# C7 / M7: SSRF guard on user-supplied host/IP parameters
#
# These tests require the real seer.validate_public_host (not the conftest
# stub) to exercise IP-literal rejection. The conftest stubs *other* seer
# functions but leaves validate_public_host on the stub undefined; the
# _real_seer_validator fixture patches the attribute onto whatever seer
# module is loaded (real or stub) so the router-side guard calls succeed.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _real_seer_validator(monkeypatch):
    """Ensure seer.validate_public_host points at the real validator.

    If the real compiled seer extension is installed it already has the
    symbol — this fixture is a no-op. If the conftest stub is in place,
    we import the real validator lazily and attach it to the stub so the
    ssrf.guard helper can call through correctly.
    """
    import sys

    seer_mod = sys.modules.get("seer")
    if seer_mod is None:
        return
    if hasattr(seer_mod, "validate_public_host"):
        return
    # Stub mode without the real validator — reject reserved addresses in
    # Python so the guard still behaves as the real validator would for
    # the narrow set of IPs we assert on below.
    def _fake_validate(host: str, port: int) -> None:
        from ipaddress import ip_address

        try:
            ip = ip_address(host)
        except ValueError:
            return  # hostnames — assume public in stub mode
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise ValueError(
                f"Invalid input: refusing to connect to reserved address: {host}"
            )

    monkeypatch.setattr(seer_mod, "validate_public_host", _fake_validate, raising=False)


@pytest.mark.parametrize(
    "path",
    [
        # Status actually HTTP-connects to the target → guard the target.
        "/status/127.0.0.1",
        "/status/169.254.169.254",
        "/status/10.0.0.1",
        "/status/192.168.1.1",
        # SSL inspection TLS-connects to the target (port 443) → guard it.
        "/ssl/127.0.0.1",
        # dig's nameserver parameter is the actual connect target.
        pytest.param("/dns/example.com/A?nameserver=169.254.169.254", marks=needs_ns_parser),
        pytest.param("/dns/example.com/A?nameserver=127.0.0.1", marks=needs_ns_parser),
        # rdap/ip rejects reserved IP literals as input validation (the
        # looked-up IP is not a connect target, but asking RDAP about a
        # private IP is nonsensical).
        "/rdap/ip/127.0.0.1",
        "/rdap/ip/10.0.0.1",
        "/rdap/ip/169.254.169.254",
    ],
)
def test_ssrf_guard_rejects_reserved(client, path):
    """Routes whose call path connects to the target must return 400 for reserved IPs."""
    resp = client.get(path)
    assert resp.status_code == 400, (path, resp.status_code, resp.text)
    detail = resp.json().get("detail", "").lower()
    assert "reserved" in detail or "invalid" in detail, (path, detail)


# Nameserver *specs* the core accepts (seer-core dns/nameserver.rs) and the
# (host, port) each one connects to — the address the SSRF guard must check.
NAMESERVER_SPECS = [
    ("8.8.8.8", ("8.8.8.8", 53)),
    ("dns.google", ("dns.google", 53)),
    ("9.9.9.9:5353", ("9.9.9.9", 5353)),
    ("2606:4700:4700::1111", ("2606:4700:4700::1111", 53)),
    ("[2606:4700:4700::1111]", ("2606:4700:4700::1111", 53)),
    ("[2606:4700:4700::1111]:5353", ("2606:4700:4700::1111", 5353)),
    ("tls://1.1.1.1", ("1.1.1.1", 853)),
    ("TLS://dns.quad9.net:8853", ("dns.quad9.net", 8853)),
    ("https://cloudflare-dns.com/dns-query", ("cloudflare-dns.com", 443)),
    ("https://dns.google:8443", ("dns.google", 8443)),
]


@needs_ns_parser
@pytest.mark.parametrize("spec,target", NAMESERVER_SPECS)
def test_nameserver_target_parses_core_spec_forms(spec, target):
    assert seer.nameserver_target(spec) == target


@pytest.mark.parametrize(
    "spec",
    [
        "",
        "   ",
        "8.8.8.8 extra",
        "ftp://1.1.1.1",
        "tls://1.1.1.1/dns-query",
        "https://user:pw@dns.google/dns-query",
        "[::1",
        "[not-v6]",
        "[::1]53",
        "dns.google:0",
        "dns.google:99999",
        "dns.google:+53",
        "a:b:c",
        ":53",
        # Forms the old Python mirror of the parser accepted but the core
        # rejects: DoH to an IPv6 literal (bracketed or not) and a scoped
        # IPv6 address.
        "https://[2606:4700:4700::1111]/dns-query",
        "https://2606:4700:4700::1111/dns-query",
        "fe80::1%eth0",
    ],
)
@needs_ns_parser
def test_nameserver_target_returns_none_for_malformed_specs(spec):
    """Malformed specs are left for the core to reject (Invalid input -> 400)."""
    assert seer.nameserver_target(spec) is None


def _record_validator(monkeypatch):
    """Replace the SSRF validator with one that records (host, port) and
    accepts — keeps hostname specs hermetic (no DNS resolution)."""
    import seer as seer_mod

    checked: list[tuple[str, int]] = []
    monkeypatch.setattr(
        seer_mod,
        "validate_public_host",
        lambda host, port: checked.append((host, port)),
        raising=False,
    )
    return checked


@needs_ns_parser
@pytest.mark.parametrize("spec,target", NAMESERVER_SPECS)
def test_dns_route_accepts_every_nameserver_spec_form(monkeypatch, client, spec, target):
    """Regression: the API guard treated the whole spec as a hostname, so
    `tls://`, `https://`, `host:port` and bracketed-IPv6 nameservers — all
    supported by the core — were refused with 400 before reaching it."""
    import seer as seer_mod

    checked = _record_validator(monkeypatch)
    seen: dict = {}

    def _dig(domain, record_type, nameserver):
        seen["nameserver"] = nameserver
        return []

    monkeypatch.setattr(seer_mod, "dig", _dig, raising=False)
    resp = client.get("/dns/example.com/A", params={"nameserver": spec})
    assert resp.status_code == 200, (spec, resp.text)
    assert checked == [target]
    # The core still receives the original spec (it parses it itself).
    assert seen["nameserver"] == spec


@needs_ns_parser
def test_dns_compare_accepts_nameserver_spec_forms(monkeypatch, client):
    import seer as seer_mod

    checked = _record_validator(monkeypatch)
    seen: dict = {}

    def _compare(domain, record_type, server_a, server_b):
        seen["servers"] = (server_a, server_b)
        return {"ok": True}

    monkeypatch.setattr(seer_mod, "dns_compare", _compare, raising=False)
    resp = client.get(
        "/dns/compare/example.com",
        params={"server_a": "tls://1.1.1.1", "server_b": "https://dns.google/dns-query"},
    )
    assert resp.status_code == 200, resp.text
    assert checked == [("1.1.1.1", 853), ("dns.google", 443)]
    assert seen["servers"] == ("tls://1.1.1.1", "https://dns.google/dns-query")


RESERVED_NAMESERVER_SPECS = [
    "127.0.0.1",
    "tls://127.0.0.1",
    "127.0.0.1:5353",
    "[::1]",
    "[::1]:53",
    "https://169.254.169.254/dns-query",
    "https://10.0.0.1:8443/dns-query",
]


@needs_ns_parser
@pytest.mark.parametrize("spec", RESERVED_NAMESERVER_SPECS)
def test_dns_route_refuses_reserved_nameserver_in_any_spec_form(monkeypatch, client, spec):
    """Parsing the spec must not open a hole: a reserved address behind any
    transport prefix / port / brackets is still a sanitized 400."""
    import seer as seer_mod

    def _never(*_a, **_kw):
        raise AssertionError("seer.dig reached with a reserved nameserver")

    monkeypatch.setattr(seer_mod, "dig", _never, raising=False)
    resp = client.get("/dns/example.com/A", params={"nameserver": spec})
    assert resp.status_code == 400, (spec, resp.status_code, resp.text)
    assert "reserved" in resp.json()["detail"].lower()

    monkeypatch.setattr(seer_mod, "dns_compare", _never, raising=False)
    resp = client.get(
        "/dns/compare/example.com", params={"server_a": "1.1.1.1", "server_b": spec}
    )
    assert resp.status_code == 400, (spec, resp.status_code, resp.text)
    assert "reserved" in resp.json()["detail"].lower()


def test_malformed_nameserver_spec_rejected_by_core_with_400(client):
    """A spec the API layer can't parse is passed through; the core's own
    parser rejects it as Invalid input -> 400 (needs the real binding)."""
    pytest.importorskip("seer._seer")
    resp = client.get("/dns/example.com/A", params={"nameserver": "ftp://1.1.1.1"})
    assert resp.status_code == 400, resp.text
    assert "invalid input" in resp.json()["detail"].lower()


@needs_ns_parser
def test_mcp_nameserver_spec_forms(monkeypatch):
    """seer_dig / seer_dns_compare share the spec-aware guard."""
    import asyncio

    import seer as seer_mod
    from seer_api.mcp.server import execute_tool

    checked = _record_validator(monkeypatch)
    monkeypatch.setattr(seer_mod, "dig", lambda *a: {"ok": True}, raising=False)
    monkeypatch.setattr(seer_mod, "dns_compare", lambda *a: {"ok": True}, raising=False)

    asyncio.run(
        execute_tool("seer_dig", {"domain": "example.com", "nameserver": "tls://1.1.1.1"})
    )
    asyncio.run(
        execute_tool(
            "seer_dns_compare",
            {
                "domain": "example.com",
                "server_a": "9.9.9.9:5353",
                "server_b": "https://cloudflare-dns.com/dns-query",
            },
        )
    )
    assert checked == [("1.1.1.1", 853), ("9.9.9.9", 5353), ("cloudflare-dns.com", 443)]


@needs_ns_parser
@pytest.mark.parametrize("spec", RESERVED_NAMESERVER_SPECS)
def test_mcp_refuses_reserved_nameserver_in_any_spec_form(spec):
    import asyncio

    from seer_api.mcp.server import execute_tool

    with pytest.raises(ValueError, match="reserved"):
        asyncio.run(
            execute_tool("seer_dig", {"domain": "example.com", "nameserver": spec})
        )
    with pytest.raises(ValueError, match="reserved"):
        asyncio.run(
            execute_tool(
                "seer_dns_compare",
                {"domain": "example.com", "server_a": spec, "server_b": "1.1.1.1"},
            )
        )


@pytest.mark.parametrize(
    "path,body",
    [
        # Bulk endpoints where every domain is an actual outbound connect
        # target must guard each domain against reserved addresses.
        ("/status/bulk", {"domains": ["127.0.0.1", "example.com"], "concurrency": 2}),
        ("/ssl/bulk", {"domains": ["127.0.0.1", "example.com"], "concurrency": 2}),
    ],
)
def test_ssrf_guard_bulk_rejects_reserved(client, path, body):
    """Bulk endpoints refuse any body whose domains list contains a reserved IP."""
    resp = client.post(path, json=body)
    assert resp.status_code == 400, (path, resp.status_code, resp.text)


@pytest.mark.parametrize(
    "path,seer_fn",
    [
        # WHOIS/RDAP-domain/lookup/propagation/DNS(target) never connect to
        # the queried host — the network goes to the registry or a DNS
        # resolver. Guarding the query there rejects legitimate lookups of
        # parked or unresolvable domains (e.g., a registered domain with no
        # A record). These routes must NOT reject reserved hosts at the API
        # layer; the inner seer call is responsible for guarding its own
        # outbound legs (e.g., the WHOIS server it contacts).
        ("/whois/127.0.0.1", "whois"),
        ("/lookup/127.0.0.1", "lookup"),
        ("/rdap/domain/127.0.0.1", "rdap_domain"),
        ("/propagation/127.0.0.1/A", "propagation"),
        ("/dns/127.0.0.1/A", "dig"),
    ],
)
def test_non_connecting_routes_do_not_reject_at_api_layer(monkeypatch, client, path, seer_fn):
    """Regression: API layer must pass reserved/unresolvable targets through
    to the inner seer call for routes whose network target is not the
    queried host. Guarding these was a bug that blocked lookups of parked
    or DNS-less registered domains (e.g., ``johnternus.com``).
    """
    import seer as seer_mod

    called = {"hit": False}

    def _stub(*args, **kwargs):
        called["hit"] = True
        return {"ok": True}

    monkeypatch.setattr(seer_mod, seer_fn, _stub, raising=False)
    resp = client.get(path)
    assert called["hit"], (
        f"{path} was rejected at the API layer "
        f"(status={resp.status_code}, body={resp.text!r}) — the inner "
        f"seer.{seer_fn} must be called"
    )


def test_guard_async_yields_event_loop(monkeypatch):
    """H1: guard_async must offload the blocking validator to the executor
    so concurrent requests do not serialize on the event loop.

    The inner `seer.validate_public_host` is a PyO3 function that calls
    `block_on` — running it bare from an async def pins the event loop
    thread. We monkeypatch it to a blocking `time.sleep` so the effect is
    deterministic, then verify that 5 concurrent `guard_async` calls
    complete in close to max(durations), not sum(durations).
    """
    import asyncio
    import time

    import seer

    per_call_delay = 0.15  # seconds
    concurrency = 5

    def _slow_validate(host: str, port: int) -> None:
        time.sleep(per_call_delay)

    monkeypatch.setattr(seer, "validate_public_host", _slow_validate, raising=False)

    from seer_api.ssrf import guard_async

    async def run_all():
        await asyncio.gather(
            *(guard_async("example.com", 443) for _ in range(concurrency))
        )

    start = time.perf_counter()
    asyncio.run(run_all())
    elapsed = time.perf_counter() - start

    # Serial execution would take ~per_call_delay * concurrency = 0.75s.
    # Parallel execution on the default thread pool should finish in
    # close to per_call_delay. Use 2x per_call_delay as a generous ceiling
    # to absorb scheduler jitter on loaded CI runners while still catching
    # the serial-vs-parallel regression.
    assert elapsed < per_call_delay * 2, (
        f"guard_async appears to serialize: {elapsed:.3f}s for {concurrency} "
        f"concurrent calls (expected < {per_call_delay * 2:.3f}s)"
    )


def test_mcp_ssrf_guard_rejects_reserved():
    """MCP tool handlers must reject reserved IPs for the tools whose call
    path actually connects to the host parameter.
    """
    import asyncio

    from seer_api.mcp.server import execute_tool

    # seer_status HTTP-connects to the target — must guard. (A reserved
    # seer_dig nameserver is covered by
    # test_mcp_refuses_reserved_nameserver_in_any_spec_form.)
    with pytest.raises(ValueError, match="reserved"):
        asyncio.run(execute_tool("seer_status", {"domain": "127.0.0.1"}))

    # seer_rdap_ip with a private IP — input validation for IP literals.
    with pytest.raises(ValueError, match="reserved"):
        asyncio.run(execute_tool("seer_rdap_ip", {"ip": "10.0.0.1"}))


@pytest.mark.parametrize(
    "tool,args,seer_fn",
    [
        # Non-connecting tools keep reserved-IP arguments: they must pass the
        # queried host through to the inner seer call unguarded (regression —
        # guarding these blocked lookups of parked/DNS-less domains).
        ("seer_lookup", {"domain": "127.0.0.1"}, "lookup"),
        ("seer_whois", {"domain": "127.0.0.1"}, "whois"),
        ("seer_rdap_domain", {"domain": "127.0.0.1"}, "rdap_domain"),
        ("seer_info", {"domain": "127.0.0.1"}, "info"),
        ("seer_propagation", {"domain": "127.0.0.1", "record_type": "A"}, "propagation"),
        ("seer_dig", {"domain": "127.0.0.1", "record_type": "A"}, "dig"),
        ("seer_rdap_asn", {"asn": 15169}, "rdap_asn"),
        ("seer_availability", {"domain": "example.com"}, "availability"),
        ("seer_dnssec", {"domain": "example.com"}, "dnssec"),
        ("seer_caa", {"domain": "example.com"}, "caa"),
        ("seer_posture", {"domain": "example.com"}, "posture"),
        ("seer_headers", {"domain": "example.com"}, "headers"),
        ("seer_takeover", {"domain": "example.com"}, "takeover"),
        ("seer_subdomains", {"domain": "example.com"}, "subdomains"),
        (
            "seer_subdomains",
            {"domain": "example.com", "resolve": True},
            "subdomains_classify",
        ),
        ("seer_confusables", {"domain": "example.com"}, "confusables"),
        ("seer_diff", {"domain_a": "example.com", "domain_b": "example.org"}, "diff"),
        ("seer_bulk_lookup", {"domains": ["example.com"]}, "bulk_lookup"),
        ("seer_bulk_whois", {"domains": ["example.com"]}, "bulk_whois"),
        ("seer_bulk_dig", {"domains": ["example.com"]}, "bulk_dig"),
        ("seer_bulk_propagation", {"domains": ["example.com"]}, "bulk_propagation"),
        ("seer_bulk_info", {"domains": ["example.com"]}, "bulk_info"),
        # Connecting tools use public IP literals: the SSRF guard validates
        # IP literals without a DNS round-trip, keeping the test hermetic
        # under both the stub and the real compiled binding.
        ("seer_status", {"domain": "1.1.1.1"}, "status"),
        ("seer_ssl", {"domain": "1.1.1.1"}, "ssl"),
        ("seer_rdap_ip", {"ip": "1.1.1.1"}, "rdap_ip"),
        ("seer_bulk_status", {"domains": ["1.1.1.1"]}, "bulk_status"),
        ("seer_bulk_ssl", {"domains": ["1.1.1.1"]}, "bulk_ssl"),
        pytest.param(
            "seer_dns_compare",
            {"domain": "example.com", "server_a": "8.8.8.8", "server_b": "1.1.1.1"},
            "dns_compare",
            marks=needs_ns_parser,
        ),
    ],
)
def test_mcp_dispatch_table_reaches_seer_binding(monkeypatch, tool, args, seer_fn):
    """Every tool arm in execute_tool must dispatch to its seer binding
    function. Covers all 27 dispatch arms (seer_subdomains has two paths).
    """
    import asyncio

    import seer as seer_mod
    from seer_api.mcp.server import execute_tool

    called = {"hit": False}

    def _stub(*a, **kw):
        called["hit"] = True
        return {"ok": True}

    monkeypatch.setattr(seer_mod, seer_fn, _stub, raising=False)
    asyncio.run(execute_tool(tool, args))
    assert called["hit"], f"{tool} was rejected at the MCP layer before reaching seer.{seer_fn}"


def test_mcp_call_tool_returns_invalid_input_for_ssrf():
    """End-to-end: MCP call_tool dispatch surfaces a ValueError as 'Invalid input'
    with the MCP error flag set and the untrusted-data preamble applied."""
    import asyncio

    from seer_api.mcp.server import UNTRUSTED_PREAMBLE, call_tool

    result = asyncio.run(call_tool("seer_status", {"domain": "127.0.0.1"}))
    assert result.is_error is True
    assert len(result.content) == 1
    text = result.content[0].text
    assert text.startswith(UNTRUSTED_PREAMBLE)
    body = text[len(UNTRUSTED_PREAMBLE):]
    assert body.startswith("Invalid input:")
    assert "reserved" in body.lower()


# ---------------------------------------------------------------------------
# MCP retry-hint classification: permanent RuntimeErrors must NOT be labelled
# retryable. seer-core's retry.rs::is_retryable classifies several
# RuntimeError-mapped variants (WhoisServerNotFound, JsonError parse failures,
# LookupFailed, certificate/SSL errors) as permanent.
# ---------------------------------------------------------------------------


def _run_call_tool_with_error(monkeypatch, exc: Exception) -> str:
    """Drive call_tool's error handler by making execute_tool raise `exc`.

    Every failure must come back as a CallToolResult with isError=True and
    the untrusted-data preamble; returns the text after the preamble.
    """
    import asyncio

    from seer_api.mcp import server as mcp_server

    async def _boom(_name, _arguments):
        raise exc

    monkeypatch.setattr(mcp_server, "execute_tool", _boom)
    result = asyncio.run(mcp_server.call_tool("seer_lookup", {"domain": "x.test"}))
    assert result.is_error is True
    assert len(result.content) == 1
    text = result.content[0].text
    assert text.startswith(mcp_server.UNTRUSTED_PREAMBLE)
    return text[len(mcp_server.UNTRUSTED_PREAMBLE):]


@pytest.mark.parametrize(
    "message",
    [
        "WHOIS server not found for this TLD",
        "Response parsing failed",
        "Lookup failed for example.invalidtld",
        "Certificate validation failed",
        "SSL inspection failed",
        "Configuration error",
        "Bulk operation partially failed: ssl",
    ],
)
def test_mcp_permanent_runtimeerror_not_labelled_retryable(monkeypatch, message):
    text = _run_call_tool_with_error(monkeypatch, RuntimeError(message))
    assert "permanent failure" in text.lower()
    assert "do not retry" in text.lower()


def test_mcp_rate_limited_runtimeerror_is_retryable(monkeypatch):
    text = _run_call_tool_with_error(
        monkeypatch, RuntimeError("Rate limited - please try again later")
    )
    assert "retry" in text.lower()
    assert "permanent failure" not in text.lower()


def test_mcp_ambiguous_runtimeerror_is_cautious(monkeypatch):
    # Generic transport failures collapse to one sanitized string; we must
    # not over-promise a successful retry.
    text = _run_call_tool_with_error(monkeypatch, RuntimeError("RDAP lookup failed"))
    assert "permanent failure" not in text.lower()
    assert "at most once" in text.lower()


def test_mcp_timeout_is_retryable(monkeypatch):
    text = _run_call_tool_with_error(monkeypatch, TimeoutError("Operation timed out"))
    assert "transient" in text.lower()
    assert "retry suggested" in text.lower()


# ---------------------------------------------------------------------------
# D1 (C6): fail-closed startup — public bind requires SEER_API_KEY
# ---------------------------------------------------------------------------


def test_refuses_public_bind_without_auth(monkeypatch):
    """Binding to a non-loopback host without an API key must fail the lifespan."""
    monkeypatch.setenv("SEER_HOST", "0.0.0.0")
    monkeypatch.delenv("SEER_API_KEY", raising=False)
    import seer_api.main as main

    importlib.reload(main)
    with pytest.raises(RuntimeError, match="public bind without auth"), TestClient(main.app):
        pass  # lifespan runs on __enter__

    monkeypatch.delenv("SEER_HOST")
    importlib.reload(main)


def test_public_bind_with_auth_starts(monkeypatch):
    """With SEER_API_KEY set, public bind is allowed."""
    monkeypatch.setenv("SEER_HOST", "0.0.0.0")
    monkeypatch.setenv("SEER_API_KEY", "secret")
    import seer_api.main as main

    importlib.reload(main)
    # Should not raise
    with TestClient(main.app) as c:
        assert c.get("/health").status_code == 200

    monkeypatch.delenv("SEER_HOST")
    monkeypatch.delenv("SEER_API_KEY")
    importlib.reload(main)


def test_loopback_bind_without_auth_starts(monkeypatch):
    """Loopback bind without SEER_API_KEY is the safe default."""
    monkeypatch.setenv("SEER_HOST", "127.0.0.1")
    monkeypatch.delenv("SEER_API_KEY", raising=False)
    import seer_api.main as main

    importlib.reload(main)
    with TestClient(main.app) as c:
        assert c.get("/health").status_code == 200

    monkeypatch.delenv("SEER_HOST")
    importlib.reload(main)


@pytest.mark.parametrize("host", ["::1", "[::1]", "localhost", "127.0.0.2", "::ffff:127.0.0.1"])
def test_other_loopback_forms_start_without_auth(monkeypatch, host):
    """Every loopback spelling is as private as 127.0.0.1 and must start.

    The guard used to be a literal `!= "127.0.0.1"`, so binding to IPv6
    loopback refused to start with a "public bind without auth" error that
    misdescribed the bind. Covers IPv6 loopback (bare and bracketed), the
    `localhost` hostname, the rest of 127.0.0.0/8, and the IPv4-mapped form.
    """
    monkeypatch.setenv("SEER_HOST", host)
    monkeypatch.delenv("SEER_API_KEY", raising=False)
    import seer_api.main as main

    importlib.reload(main)
    with TestClient(main.app) as c:
        assert c.get("/health").status_code == 200

    monkeypatch.delenv("SEER_HOST")
    importlib.reload(main)


@pytest.mark.parametrize("buggy_stdlib", [False, True])
def test_ipv4_mapped_loopback_bind_does_not_depend_on_python_version(monkeypatch, buggy_stdlib):
    """`IPv6Address("::ffff:127.0.0.1").is_loopback` is False on CPython
    3.12.0-3.12.3 (later releases consult the mapped IPv4 address), so the
    bind check must unwrap `ipv4_mapped` itself. `buggy_stdlib` simulates the
    old stdlib behavior on whatever Python runs the suite."""
    import ipaddress

    from seer_api.main import _is_loopback_bind

    if buggy_stdlib:
        monkeypatch.setattr(
            ipaddress.IPv6Address,
            "is_loopback",
            property(lambda self: self._ip == 1),
        )
        assert not ipaddress.IPv6Address("::ffff:127.0.0.1").is_loopback

    assert _is_loopback_bind("::ffff:127.0.0.1")
    assert _is_loopback_bind("[::ffff:127.0.0.2]")
    assert _is_loopback_bind("::1")
    # Mapped non-loopback addresses stay non-loopback (fail closed).
    assert not _is_loopback_bind("::ffff:10.0.0.1")
    assert not _is_loopback_bind("::ffff:0.0.0.0")


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "example.com", "10.0.0.5", "not-an-ip!"])
def test_non_loopback_binds_still_refused_without_auth(monkeypatch, host):
    """The widened check must not become permissive.

    A wildcard bind (`0.0.0.0` / `::`) *includes* loopback but is reachable
    off-box, and an unparseable value must fail closed rather than be waved
    through as "probably local".
    """
    monkeypatch.setenv("SEER_HOST", host)
    monkeypatch.delenv("SEER_API_KEY", raising=False)
    import seer_api.main as main

    importlib.reload(main)
    with pytest.raises(RuntimeError, match="public bind without auth"), TestClient(main.app):
        pass

    monkeypatch.delenv("SEER_HOST")
    importlib.reload(main)


# ---------------------------------------------------------------------------
# Root index must advertise every mounted route
# ---------------------------------------------------------------------------


# Every prefix main.py mounts a router under. Independent of how routes are
# introspected, which is the point: the index regressed precisely because
# `app.routes` stopped containing router endpoints in FastAPI 0.141, and a
# test that derived its expectation the same way could not have caught it.
MOUNTED_PREFIXES = [
    "/lookup", "/whois", "/rdap", "/dns", "/propagation", "/status", "/ssl",
    "/availability", "/info", "/subdomains", "/dnssec", "/delegation",
    "/diff", "/caa", "/posture", "/confusables", "/tld",
]


def test_root_index_lists_every_registered_route(client):
    """Drift guard: `/` must advertise every mounted endpoint.

    The hand-written literal it replaces listed 10 entries against 20 mounted
    routers, so most of the API was undiscoverable from the index whose entire
    job is to advertise it.
    """
    body = client.get("/").json()

    assert "endpoints" in body, f"root returned no endpoint index: {body}"
    index = body["endpoints"]

    # Independent expectation: every mounted router must contribute at least
    # one endpoint, and the raw non-router routes must be present too.
    for prefix in MOUNTED_PREFIXES:
        assert any(path.startswith(prefix + "/") for path in index.values()), (
            f"no endpoint advertised under {prefix}; index={sorted(index.values())}"
        )
    for path in ("/mcp", "/health", "/metrics"):
        assert path in index.values(), f"{path} missing from the index"

    assert len(index) > 30, f"index looks truncated: {sorted(index.values())}"
    # Every route must get its OWN key: a derived name that collides would
    # silently displace another entry instead of failing. Compare against the
    # distinct route paths recomputed here — `len(index) ==
    # len(set(index.values()))` could never fail, because a collision drops
    # the displaced path from the keys AND the values alike.
    app = client.app
    route_paths = set(app.openapi().get("paths", {})) | {
        path for route in app.routes if (path := getattr(route, "path", None))
    }
    route_paths.discard("/")
    assert len(index) == len(route_paths), (
        "derived endpoint names collided: "
        f"{sorted(route_paths - set(index.values()))} missing from the index"
    )
    # Key scheme preserved from the hand-written index it replaces.
    assert index["lookup"] == "/lookup/{domain}"
    assert index["rdap_domain"] == "/rdap/domain/{domain}"
    assert index["ssl_bulk"] == "/ssl/bulk"
    assert index["mcp"] == "/mcp"
    # Collection vs item route disambiguation.
    assert index["tld_index"] == "/tld/"
    assert index["tld"] == "/tld/{tld}"
    # Bulk + streaming variants, absent from the old literal.
    assert index["lookup_bulk"] == "/lookup/bulk"
    assert index["lookup_bulk_stream"] == "/lookup/bulk/stream"


def test_root_index_describes_the_serving_app_not_module_state(monkeypatch):
    """`/` must describe the app handling the request, even after a reload.

    `_endpoint_index` used to read the module-global `app`. Reloading the
    module rebinds that global while an already-built client keeps serving the
    original app, so the index would describe a DIFFERENT app than the caller
    is talking to.
    """
    import seer_api.main as main

    serving_app = main.app
    with TestClient(serving_app) as c:
        before = c.get("/").json()["endpoints"]

    # Rebind the module global to a DIFFERENT, near-empty app.
    monkeypatch.setattr(main, "app", FastAPI())
    with TestClient(serving_app) as c:
        after = c.get("/").json()["endpoints"]

    assert after == before, (
        "index followed the module global instead of the serving app"
    )
    assert "lookup" in after


def test_metrics_labels_keep_the_router_prefix(monkeypatch):
    """Distinct endpoints must not share a metrics bucket.

    As of FastAPI 0.141 a route reached via `include_router(prefix=...)`
    reports its template WITHOUT the prefix, so `/info/{domain}`,
    `/availability/{domain}` and `/posture/{domain}` all arrived as
    `/{domain}` and collapsed into one bucket — silently wrong per-endpoint
    metrics, not merely coarse ones. Older FastAPI reported absolute
    templates, so this only appears against a current release.
    """
    import seer
    from seer_api.main import app
    from seer_api.middleware import metrics

    monkeypatch.setattr(seer, "info", lambda d: {"d": d}, raising=False)
    monkeypatch.setattr(seer, "availability", lambda d: {"d": d}, raising=False)
    monkeypatch.setattr(seer, "posture", lambda d: {"d": d}, raising=False)

    before = dict(metrics.snapshot()["endpoints"])
    with TestClient(app) as c:
        c.get("/info/a.com")
        c.get("/availability/b.com")
        c.get("/posture/c.com")
    after = metrics.snapshot()["endpoints"]
    added = {k: after[k] - before.get(k, 0) for k in after if after[k] - before.get(k, 0)}

    assert set(added) == {
        "/info/{domain}",
        "/availability/{domain}",
        "/posture/{domain}",
    }, f"router prefix lost from metrics labels: {added}"


# ---------------------------------------------------------------------------
# D7 (H10): multi-worker without shared rate-limit store is refused
# ---------------------------------------------------------------------------


def test_refuses_multi_worker_without_shared_store(monkeypatch):
    """WEB_CONCURRENCY>1 with memory:// storage must hard-fail at startup."""
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    monkeypatch.delenv("SEER_RATE_LIMIT_STORAGE", raising=False)
    import seer_api.main as main

    importlib.reload(main)
    with pytest.raises(RuntimeError, match="SEER_RATE_LIMIT_STORAGE"), TestClient(main.app):
        pass

    monkeypatch.delenv("WEB_CONCURRENCY")
    importlib.reload(main)


def test_web_concurrency_shadows_unparseable_uvicorn_workers(monkeypatch):
    """UVICORN_WORKERS is only a fallback; when WEB_CONCURRENCY is set, a junk
    UVICORN_WORKERS (e.g. `auto`) must not abort startup. It used to, because
    the fallback was evaluated eagerly as WEB_CONCURRENCY's default."""
    monkeypatch.setenv("WEB_CONCURRENCY", "1")
    monkeypatch.setenv("UVICORN_WORKERS", "auto")
    monkeypatch.delenv("SEER_RATE_LIMIT_STORAGE", raising=False)
    import seer_api.main as main

    importlib.reload(main)
    with TestClient(main.app) as c:
        assert c.get("/health").status_code == 200

    monkeypatch.delenv("WEB_CONCURRENCY")
    monkeypatch.delenv("UVICORN_WORKERS")
    importlib.reload(main)


@pytest.mark.parametrize("web_concurrency", [None, "", "  "])
def test_unparseable_uvicorn_workers_rejected_when_it_is_the_fallback(
    monkeypatch, web_concurrency
):
    """With WEB_CONCURRENCY unset/blank, UVICORN_WORKERS is the value in force
    and a non-integer is still the clear startup error (issue #50)."""
    if web_concurrency is None:
        monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    else:
        monkeypatch.setenv("WEB_CONCURRENCY", web_concurrency)
    monkeypatch.setenv("UVICORN_WORKERS", "auto")
    import seer_api.main as main

    importlib.reload(main)
    with pytest.raises(RuntimeError, match="UVICORN_WORKERS"), TestClient(main.app):
        pass

    monkeypatch.delenv("UVICORN_WORKERS")
    importlib.reload(main)


def test_multi_worker_with_shared_store_starts(monkeypatch):
    """WEB_CONCURRENCY>1 with a non-memory storage URI is allowed."""
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    monkeypatch.setenv("SEER_RATE_LIMIT_STORAGE", "redis://localhost:6379")
    import seer_api.main as main

    importlib.reload(main)
    with TestClient(main.app) as c:
        assert c.get("/health").status_code == 200

    monkeypatch.delenv("WEB_CONCURRENCY")
    monkeypatch.delenv("SEER_RATE_LIMIT_STORAGE")
    importlib.reload(main)


# ---------------------------------------------------------------------------
# D5 (H14): docs disabled by default, enabled via SEER_DOCS_ENABLED
# ---------------------------------------------------------------------------


def test_docs_off_by_default(client):
    """The default conftest client has no SEER_DOCS_ENABLED set."""
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_docs_enabled_when_flag_set(monkeypatch):
    monkeypatch.setenv("SEER_DOCS_ENABLED", "true")
    import seer_api.main as main

    importlib.reload(main)
    with TestClient(main.app) as c:
        assert c.get("/docs").status_code == 200
        assert c.get("/openapi.json").status_code == 200

    monkeypatch.delenv("SEER_DOCS_ENABLED")
    importlib.reload(main)


# ---------------------------------------------------------------------------
# D8 (M8): typed exception classification — ValueError -> 400,
# TimeoutError -> 504, ConnectionError -> 502, else -> 500.
# ---------------------------------------------------------------------------


def test_http_status_for_classifies_by_type():
    from seer_api.errors import http_status_for

    assert http_status_for(ValueError("bad input")) == 400
    assert http_status_for(TimeoutError("upstream timed out")) == 504
    assert http_status_for(ConnectionError("upstream unreachable")) == 502
    assert http_status_for(RuntimeError("something broke")) == 500
    assert http_status_for(Exception("other")) == 500


def test_safe_error_message_strips_unknown_types():
    from seer_api.errors import safe_error_message

    # Known exception types pass through with typed mapping.
    assert safe_error_message(ValueError("missing field foo")) == "missing field foo"
    assert safe_error_message(TimeoutError("connection hung")) == "request timed out"
    assert (
        safe_error_message(ConnectionError("refused"))
        == "upstream connection failed"
    )
    # Unknown types fall back — the internal detail is NOT leaked.
    msg = safe_error_message(RuntimeError("/home/secret/path was leaked"))
    assert msg == "Request failed"
    assert "secret" not in msg


def test_value_error_returns_400(client, monkeypatch):
    """A ValueError raised from the underlying seer call surfaces as 400."""
    import seer

    def _raising(*args, **kwargs):
        raise ValueError("invalid domain format: ' '")

    monkeypatch.setattr(seer, "lookup", _raising, raising=False)
    resp = client.get("/lookup/example.com")
    assert resp.status_code == 400
    assert "invalid domain" in resp.json()["detail"].lower()


def test_timeout_returns_504(client, monkeypatch):
    """A TimeoutError surfaces as 504 Gateway Timeout."""
    import seer

    def _raising(*args, **kwargs):
        raise TimeoutError("upstream whois server did not respond")

    monkeypatch.setattr(seer, "lookup", _raising, raising=False)
    resp = client.get("/lookup/example.com")
    assert resp.status_code == 504
    assert resp.json()["detail"] == "request timed out"


def test_connection_error_returns_502(client, monkeypatch):
    """A ConnectionError surfaces as 502 Bad Gateway."""
    import seer

    def _raising(*args, **kwargs):
        raise ConnectionError("upstream refused")

    monkeypatch.setattr(seer, "lookup", _raising, raising=False)
    resp = client.get("/lookup/example.com")
    assert resp.status_code == 502
    assert resp.json()["detail"] == "upstream connection failed"


def test_runtime_error_returns_500(client, monkeypatch):
    """An unclassified RuntimeError surfaces as 500 without leaking detail."""
    import seer

    def _raising(*args, **kwargs):
        raise RuntimeError("secret internal path /tmp/abc123 exploded")

    monkeypatch.setattr(seer, "lookup", _raising, raising=False)
    resp = client.get("/lookup/example.com")
    assert resp.status_code == 500
    detail = resp.json()["detail"]
    assert "secret" not in detail
    assert "/tmp" not in detail
    assert detail == "Lookup failed"


# ---------------------------------------------------------------------------
# D3 (H11): X-Forwarded-For is trusted only when the socket peer is in
# the SEER_TRUSTED_PROXY_IPS allowlist.
# ---------------------------------------------------------------------------


def test_xff_ignored_when_trust_proxy_disabled(monkeypatch):
    from fastapi import Request

    from seer_api.limiting import get_client_ip

    monkeypatch.delenv("SEER_TRUST_PROXY", raising=False)
    monkeypatch.delenv("SEER_TRUSTED_PROXY_IPS", raising=False)
    scope = {
        "type": "http",
        "client": ("203.0.113.5", 1234),
        "headers": [(b"x-forwarded-for", b"1.2.3.4")],
    }
    req = Request(scope)
    assert get_client_ip(req) == "203.0.113.5"


def test_xff_ignored_from_untrusted_peer(monkeypatch):
    """With SEER_TRUST_PROXY=true and an allowlist that does NOT
    include the socket peer, the XFF header must be ignored."""
    from fastapi import Request

    from seer_api.limiting import get_client_ip

    monkeypatch.setenv("SEER_TRUST_PROXY", "true")
    monkeypatch.setenv("SEER_TRUSTED_PROXY_IPS", "10.0.0.1")
    scope = {
        "type": "http",
        "client": ("203.0.113.5", 1234),
        "headers": [(b"x-forwarded-for", b"1.2.3.4")],
    }
    req = Request(scope)
    # Peer 203.0.113.5 is not in trusted list -> XFF ignored -> returns peer.
    assert get_client_ip(req) == "203.0.113.5"


def test_xff_trusted_from_allowlisted_peer(monkeypatch):
    """With SEER_TRUST_PROXY=true and the socket peer in the allowlist,
    the XFF header's first value is used as the client IP."""
    from fastapi import Request

    from seer_api.limiting import get_client_ip

    monkeypatch.setenv("SEER_TRUST_PROXY", "true")
    monkeypatch.setenv("SEER_TRUSTED_PROXY_IPS", "10.0.0.1,10.0.0.2")
    scope = {
        "type": "http",
        "client": ("10.0.0.1", 1234),
        "headers": [(b"x-forwarded-for", b"1.2.3.4, 10.0.0.1")],
    }
    req = Request(scope)
    assert get_client_ip(req) == "1.2.3.4"


def test_xff_uses_rightmost_untrusted_entry(monkeypatch):
    """A spoofed leftmost XFF entry must be ignored. With a chain of
    proxies appending the real client IP, the rightmost entry that is NOT
    itself a trusted proxy is the genuine client."""
    from fastapi import Request

    from seer_api.limiting import get_client_ip

    monkeypatch.setenv("SEER_TRUST_PROXY", "true")
    monkeypatch.setenv("SEER_TRUSTED_PROXY_IPS", "10.0.0.1,10.0.0.2")
    scope = {
        "type": "http",
        "client": ("10.0.0.1", 1234),
        # Attacker forged "1.1.1.1" as the leftmost value; the real client
        # is 203.0.113.9, appended by the edge proxy, then forwarded
        # through trusted hops 10.0.0.2 / 10.0.0.1.
        "headers": [(b"x-forwarded-for", b"1.1.1.1, 203.0.113.9, 10.0.0.2, 10.0.0.1")],
    }
    req = Request(scope)
    assert get_client_ip(req) == "203.0.113.9"


def test_xff_multiple_header_lines_are_joined(monkeypatch):
    """A proxy that adds its hop as a SEPARATE X-Forwarded-For line (HAProxy
    `option forwardfor`) must not let the client's own first line win:
    `headers.get()` only returned that first, client-controlled line."""
    from fastapi import Request

    from seer_api.limiting import get_client_ip

    monkeypatch.setenv("SEER_TRUST_PROXY", "true")
    monkeypatch.setenv("SEER_TRUSTED_PROXY_IPS", "10.0.0.1")
    scope = {
        "type": "http",
        "client": ("10.0.0.1", 1234),
        "headers": [
            # Sent by the client (spoofed).
            (b"x-forwarded-for", b"1.1.1.1"),
            # Added by the trusted proxy: the real client.
            (b"x-forwarded-for", b"203.0.113.9"),
        ],
    }
    assert get_client_ip(Request(scope)) == "203.0.113.9"


def test_trusted_proxy_cidr_warning_logged_once(monkeypatch, caplog):
    """The CIDR-entry warning must not be re-logged on every request."""
    import logging

    from fastapi import Request

    from seer_api import limiting

    monkeypatch.setenv("SEER_TRUST_PROXY", "true")
    monkeypatch.setenv("SEER_TRUSTED_PROXY_IPS", "10.0.0.1,10.0.0.0/8")
    limiting._parse_trusted_proxies.cache_clear()
    scope = {
        "type": "http",
        "client": ("10.0.0.1", 1234),
        "headers": [(b"x-forwarded-for", b"203.0.113.9")],
    }
    with caplog.at_level(logging.WARNING, logger="seer_api"):
        for _ in range(5):
            assert limiting.get_client_ip(Request(scope)) == "203.0.113.9"
    cidr_warnings = [r for r in caplog.records if "10.0.0.0/8" in r.getMessage()]
    assert len(cidr_warnings) == 1, [r.getMessage() for r in cidr_warnings]
    # The CIDR entry is still ignored, not trusted.
    assert limiting._trusted_proxies() == frozenset({"10.0.0.1"})


def test_run_disables_uvicorn_proxy_headers(monkeypatch):
    """uvicorn's default proxy_headers=True rewrites the client address from
    X-Forwarded-For (for FORWARDED_ALLOW_IPS peers) before the app runs, a
    second XFF trust path around SEER_TRUST_PROXY/SEER_TRUSTED_PROXY_IPS."""
    import uvicorn

    import seer_api.main as main

    captured: dict = {}
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: captured.update(kw))
    main.run()
    assert captured.get("proxy_headers") is False


def test_xff_all_trusted_falls_back_to_peer(monkeypatch):
    """If every XFF entry is a trusted proxy, fall back to the socket peer
    rather than attributing the request to a proxy IP."""
    from fastapi import Request

    from seer_api.limiting import get_client_ip

    monkeypatch.setenv("SEER_TRUST_PROXY", "true")
    monkeypatch.setenv("SEER_TRUSTED_PROXY_IPS", "10.0.0.1,10.0.0.2")
    scope = {
        "type": "http",
        "client": ("10.0.0.1", 1234),
        "headers": [(b"x-forwarded-for", b"10.0.0.2, 10.0.0.1")],
    }
    req = Request(scope)
    assert get_client_ip(req) == "10.0.0.1"


def test_xff_ignored_when_allowlist_empty(monkeypatch):
    """SEER_TRUST_PROXY=true but no trusted IPs configured — XFF must
    not be honored; without an allowlist there is no safe proxy to trust."""
    from fastapi import Request

    from seer_api.limiting import get_client_ip

    monkeypatch.setenv("SEER_TRUST_PROXY", "true")
    monkeypatch.delenv("SEER_TRUSTED_PROXY_IPS", raising=False)
    scope = {
        "type": "http",
        "client": ("10.0.0.1", 1234),
        "headers": [(b"x-forwarded-for", b"1.2.3.4")],
    }
    req = Request(scope)
    assert get_client_ip(req) == "10.0.0.1"


# ---------------------------------------------------------------------------
# D4 (H12, M9): /metrics uses socket peer, rate-limited
# ---------------------------------------------------------------------------


def _clear_limiter_storage():
    """Reset slowapi state so each test starts from a clean slate.

    Three sources of bleed need to be cleared:
      1. ``limiter._storage`` — the per-key increment counters.
      2. ``limiter._route_limits`` — ``importlib.reload(main)`` re-runs
         the ``@limiter.limit`` decorators, which *append* to this dict
         rather than replace. Without clearing, a reloaded route accrues
         multiple identical limits and each request increments the
         counter N times.
      3. ``limiter._exempt_routes`` — same accumulation risk.
    """
    from seer_api.limiting import limiter

    limiter.reset()
    storage = getattr(limiter, "_storage", None)
    if storage is not None:
        try:
            storage.reset()
        except Exception:
            inner = getattr(storage, "storage", None)
            if inner is not None:
                inner.clear()
    # Deduplicate route limits: keep only one Limit per function name so
    # that reloads of main don't stack multiple identical decorators.
    route_limits = getattr(limiter, "_route_limits", None)
    if route_limits is not None:
        for key, limits in list(route_limits.items()):
            # Keep the first registered Limit per route
            route_limits[key] = limits[:1]


@pytest.fixture
def reset_limiter():
    """Clear the rate limiter state so each test starts fresh.

    The limiter is module-scoped and persists counters across tests;
    without a reset the 10/minute metrics cap bleeds between tests.
    """
    _clear_limiter_storage()
    yield
    _clear_limiter_storage()


def test_metrics_localhost_only_socket_peer(reset_limiter, app_module):
    """The default TestClient reports client.host as 'testclient', not
    127.0.0.1 — verify that the metrics gate uses the socket peer
    directly (not the spoofable X-Forwarded-For) and rejects non-loopback."""
    c = TestClient(app_module.app)
    resp = c.get("/metrics", headers={"X-Forwarded-For": "127.0.0.1"})
    # TestClient's synthetic peer is 'testclient' — not in the allowlist,
    # so we should be rejected. Importantly, the XFF header must not
    # trick the gate into letting us through.
    assert resp.status_code == 403


def test_metrics_allows_real_loopback(reset_limiter, app_module):
    """When the socket peer is 127.0.0.1 the gate lets the request through."""
    # Force the TestClient to appear as 127.0.0.1
    c = TestClient(app_module.app, client=("127.0.0.1", 12345))
    resp = c.get("/metrics")
    assert resp.status_code == 200
    assert "total_requests" in resp.json()


def test_metrics_rate_limited(reset_limiter, monkeypatch):
    """/metrics is now rate-limited to 10/minute (was exempt)."""
    import seer_api.main as main

    importlib.reload(main)
    c = TestClient(main.app, client=("127.0.0.1", 12345))
    # Send > 10 requests in a burst; at least one must be 429.
    statuses = [c.get("/metrics").status_code for _ in range(15)]
    assert 429 in statuses, f"expected rate-limit in {statuses}"


def test_rate_limit_is_per_route_not_per_url(reset_limiter, monkeypatch, client):
    """Distinct path parameters on one route share its budget.

    slowapi's default key_style="url" keyed buckets on the concrete path, so
    `/takeover/a0.com`, `/takeover/a1.com`, … — or case / trailing-dot
    spellings of one domain — each got a fresh "5/minute" and the limit
    bounded nothing.
    """
    import seer as seer_mod

    monkeypatch.setattr(seer_mod, "takeover", lambda *a: {"ok": True}, raising=False)
    paths = [f"/takeover/a{i}.com" for i in range(4)] + [
        "/takeover/EXAMPLE.com",
        "/takeover/example.com.",
        "/takeover/example.com",
    ]
    statuses = [client.get(p).status_code for p in paths]
    assert statuses == [200] * 5 + [429] * 2, statuses
    # A different route keeps its own budget.
    monkeypatch.setattr(seer_mod, "confusables", lambda *a: {"ok": True}, raising=False)
    assert client.get("/confusables/example.com").status_code == 200


# ---------------------------------------------------------------------------
# D2 (M6): request body size cap — 64KB default, 413 on overflow.
# ---------------------------------------------------------------------------


def test_large_body_rejected_by_content_length(client):
    """A request with Content-Length > 64KB must get 413 before routing."""
    big = {"domains": ["example.com"] * 10000, "concurrency": 1}
    resp = client.post("/lookup/bulk", json=big)
    assert resp.status_code == 413
    assert resp.json()["detail"] == "request body too large"


def test_small_body_accepted(client):
    """A normal-sized bulk payload must pass the body cap."""
    resp = client.post(
        "/status/bulk",
        json={"domains": ["example.com"], "concurrency": 1},
    )
    # Could be 200 (succeeded via stub) or a validation/SSRF error — but
    # NOT 413.
    assert resp.status_code != 413


def test_middleware_class_rejects_large_chunked_body():
    """Unit-level: the middleware itself rejects a stream that pushes
    past the cap in successive chunks (no Content-Length header)."""
    import asyncio

    from seer_api.middleware import MaxBodySizeMiddleware

    received: list = []

    async def inner_app(scope, receive, send):
        # Drain the stream; upstream middleware should short-circuit us
        # once the cap is blown.
        while True:
            msg = await receive()
            received.append(msg)
            if not msg.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = MaxBodySizeMiddleware(inner_app, max_bytes=32)
    sent: list = []

    messages = iter(
        [
            {"type": "http.request", "body": b"a" * 20, "more_body": True},
            {"type": "http.request", "body": b"b" * 20, "more_body": False},
        ]
    )

    async def receive():
        return next(messages)

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "headers": []}
    asyncio.run(mw(scope, receive, send))
    # First message sent must be status 413.
    assert sent, "no response messages"
    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 413
