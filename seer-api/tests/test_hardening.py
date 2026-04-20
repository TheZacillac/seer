"""Tests for Batch 12 API hardening: auth, correlation-ID, path caps, validation."""

from __future__ import annotations

import importlib
import os

import pytest
from fastapi.testclient import TestClient


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
    assert "access-control-allow-origin" in {
        k.lower() for k in response.headers.keys()
    }

    monkeypatch.delenv("SEER_API_KEY")
    monkeypatch.delenv("SEER_CORS_ORIGINS")
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
        "/status/127.0.0.1",
        "/status/169.254.169.254",
        "/status/10.0.0.1",
        "/status/192.168.1.1",
        "/whois/127.0.0.1",
        "/whois/169.254.169.254",
        "/dns/example.com/A?nameserver=169.254.169.254",
        "/dns/example.com/A?nameserver=127.0.0.1",
        "/dns/127.0.0.1/A",
    ],
)
def test_ssrf_guard_rejects_reserved(client, path):
    """All SSRF-capable routes must return 400 for reserved IPs."""
    resp = client.get(path)
    assert resp.status_code == 400, (path, resp.status_code, resp.text)
    detail = resp.json().get("detail", "").lower()
    assert "reserved" in detail or "invalid" in detail, (path, detail)


def test_ssrf_guard_bulk_status_rejects_reserved(client):
    resp = client.post(
        "/status/bulk", json={"domains": ["127.0.0.1", "example.com"], "concurrency": 2}
    )
    assert resp.status_code == 400


def test_ssrf_guard_bulk_whois_rejects_reserved(client):
    resp = client.post(
        "/whois/bulk", json={"domains": ["10.0.0.1"], "concurrency": 1}
    )
    assert resp.status_code == 400


def test_ssrf_guard_bulk_dns_rejects_reserved(client):
    resp = client.post(
        "/dns/bulk",
        json={"domains": ["169.254.169.254"], "record_type": "A", "concurrency": 1},
    )
    assert resp.status_code == 400


def test_mcp_ssrf_guard_rejects_reserved():
    """MCP tool handlers must reject reserved IPs before dispatching to seer."""
    import asyncio

    from seer_api.mcp.server import execute_tool

    # seer_status with a loopback IP must fail before any seer call
    with pytest.raises(ValueError, match="reserved"):
        asyncio.run(execute_tool("seer_status", {"domain": "127.0.0.1"}))

    # seer_whois with a metadata IP must fail
    with pytest.raises(ValueError, match="reserved"):
        asyncio.run(execute_tool("seer_whois", {"domain": "169.254.169.254"}))

    # seer_dig with a reserved nameserver must fail
    with pytest.raises(ValueError, match="reserved"):
        asyncio.run(
            execute_tool(
                "seer_dig",
                {"domain": "example.com", "nameserver": "127.0.0.1"},
            )
        )

    # seer_rdap_ip with a private IP must fail
    with pytest.raises(ValueError, match="reserved"):
        asyncio.run(execute_tool("seer_rdap_ip", {"ip": "10.0.0.1"}))


def test_mcp_call_tool_returns_invalid_input_for_ssrf():
    """End-to-end: MCP call_tool dispatch surfaces a ValueError as 'Invalid input'."""
    import asyncio

    from seer_api.mcp.server import call_tool

    result = asyncio.run(call_tool("seer_status", {"domain": "127.0.0.1"}))
    assert len(result) == 1
    assert result[0].text.startswith("Invalid input:")
    assert "reserved" in result[0].text.lower()


# ---------------------------------------------------------------------------
# D1 (C6): fail-closed startup — public bind requires SEER_API_KEY
# ---------------------------------------------------------------------------


def test_refuses_public_bind_without_auth(monkeypatch):
    """Binding to a non-loopback host without an API key must fail the lifespan."""
    monkeypatch.setenv("SEER_HOST", "0.0.0.0")
    monkeypatch.delenv("SEER_API_KEY", raising=False)
    import seer_api.main as main

    importlib.reload(main)
    with pytest.raises(RuntimeError, match="public bind without auth"):
        with TestClient(main.app):
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


# ---------------------------------------------------------------------------
# D7 (H10): multi-worker without shared rate-limit store is refused
# ---------------------------------------------------------------------------


def test_refuses_multi_worker_without_shared_store(monkeypatch):
    """WEB_CONCURRENCY>1 with memory:// storage must hard-fail at startup."""
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    monkeypatch.delenv("SEER_RATE_LIMIT_STORAGE", raising=False)
    import seer_api.main as main

    importlib.reload(main)
    with pytest.raises(RuntimeError, match="SEER_RATE_LIMIT_STORAGE"):
        with TestClient(main.app):
            pass

    monkeypatch.delenv("WEB_CONCURRENCY")
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
