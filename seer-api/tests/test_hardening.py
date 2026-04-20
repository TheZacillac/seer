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
