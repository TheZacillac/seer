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
    # /docs exempt
    assert c.get("/docs").status_code == 200

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
