"""Request-level guards, error typing, deadlines and rate-limit scoping.

Hermetic: every seer binding a request reaches is monkeypatched.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time

import pytest
from fastapi.testclient import TestClient

import seer
from seer_api import _run, streaming
from seer_api.main import app
from seer_api.mcp import server as mcp_server

# ---------------------------------------------------------------------------
# SSRF pre-check: only a reserved-address refusal blocks the request
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        seer.DnsError("DNS resolution failed"),
        TimeoutError("Operation timed out"),
    ],
)
def test_inconclusive_ssrf_precheck_falls_through_to_core(monkeypatch, client, exc):
    """Regression: an unresolvable target made the pre-check raise a non-
    ValueError that escaped as a bare 500. Core re-vets (and pins) the target
    itself and reports its own error, so the request must reach it."""

    def _inconclusive(host, port):
        raise exc

    calls: list = []
    monkeypatch.setattr(seer, "validate_public_host", _inconclusive, raising=False)
    monkeypatch.setattr(seer, "status", lambda d: calls.append(d) or {"domain": d}, raising=False)
    resp = client.get("/status/does-not-resolve.example")
    assert resp.status_code == 200, resp.text
    assert calls == ["does-not-resolve.example"]

    monkeypatch.setattr(seer, "ssl", lambda d: calls.append(d) or {"domain": d}, raising=False)
    out = asyncio.run(mcp_server.call_tool("seer_ssl", {"domain": "does-not-resolve.example"}))
    assert not getattr(out, "is_error", False), out


def test_mcp_bulk_leaves_reserved_hosts_to_core(monkeypatch):
    """MCP bulk status/SSL no longer pre-check (sequentially, up to 100
    hosts): core refuses a reserved host per row."""

    def _no_precheck(*_a, **_kw):
        raise AssertionError("bulk tools must not pre-check hosts")

    seen: list = []
    monkeypatch.setattr(seer, "validate_public_host", _no_precheck, raising=False)
    monkeypatch.setattr(
        seer, "bulk_status", lambda domains, c: seen.append(domains) or [], raising=False
    )
    out = asyncio.run(mcp_server.call_tool("seer_bulk_status", {"domains": ["10.0.0.1"]}))
    assert not getattr(out, "is_error", False), out
    assert seen == [["10.0.0.1"]]


def test_precheck_and_work_share_one_deadline(monkeypatch, client):
    """Regression: the pre-check and the core call each got a full
    SEER_REQUEST_TIMEOUT (MCP: up to three), so a request could take a
    multiple of the configured deadline. Now they run in one dispatch."""
    monkeypatch.setattr(_run, "_REQUEST_TIMEOUT", 0.5)

    def _slow_validate(host, port):
        time.sleep(0.3)

    def _slow_status(domain):
        time.sleep(0.3)
        return {"domain": domain}

    monkeypatch.setattr(seer, "validate_public_host", _slow_validate, raising=False)
    monkeypatch.setattr(seer, "status", _slow_status, raising=False)
    resp = client.get("/status/example.com")
    assert resp.status_code == 504, resp.text


# ---------------------------------------------------------------------------
# SEER_REQUEST_TIMEOUT bounds SSE streams
# ---------------------------------------------------------------------------


@pytest.fixture
def one_stream_slot(monkeypatch):
    monkeypatch.setattr(streaming, "_MAX_CONCURRENT_STREAMS", 1, raising=False)
    monkeypatch.setattr(streaming, "_stream_semaphore", None, raising=False)
    monkeypatch.setattr(streaming, "_stream_semaphore_loop", None, raising=False)


def test_stream_wait_for_a_slot_is_bounded(monkeypatch, one_stream_slot):
    """Regression: a stream queued behind busy slots waited forever."""
    monkeypatch.setattr(_run, "_REQUEST_TIMEOUT", 0.2)
    release = threading.Event()

    def blocking_bulk(domains, progress=None):
        release.wait(5.0)
        return []

    async def scenario() -> None:
        await streaming.stream_bulk(blocking_bulk, ["a.com"])  # takes the slot
        with pytest.raises(TimeoutError):
            await streaming.stream_bulk(blocking_bulk, ["b.com"])
        release.set()

    asyncio.run(scenario())


def test_stream_outliving_the_deadline_ends_with_an_error_event(monkeypatch, one_stream_slot):
    """Regression: SSE streams ignored SEER_REQUEST_TIMEOUT entirely."""
    monkeypatch.setattr(_run, "_REQUEST_TIMEOUT", 0.2)
    release = threading.Event()

    def slow_bulk(domains, progress=None):
        release.wait(5.0)
        return [{"success": True}]

    async def scenario() -> list[bytes]:
        resp = await streaming.stream_bulk(slow_bulk, ["a.com"])
        chunks = [chunk async for chunk in resp.body_iterator]
        release.set()
        return chunks

    start = time.monotonic()
    chunks = asyncio.run(scenario())
    assert time.monotonic() - start < 2
    assert chunks[-1].startswith(b"event: error\n")
    assert b"request timed out" in chunks[-1]


# ---------------------------------------------------------------------------
# Unauthenticated posture: loopback listener only, no cross-origin drive-by
# ---------------------------------------------------------------------------


def _no_key(monkeypatch):
    monkeypatch.delenv("SEER_API_KEY", raising=False)
    monkeypatch.delenv("SEER_CORS_ORIGINS", raising=False)
    monkeypatch.delenv("SEER_MCP_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("SEER_MCP_ALLOWED_ORIGINS", raising=False)


def test_request_on_public_interface_without_key_is_refused(monkeypatch):
    """Regression: `uvicorn seer_api.main:app --host 0.0.0.0` never sets
    SEER_HOST, so the startup check passed and the API served the network
    unauthenticated. scope["server"] is the interface the request came in on."""
    _no_key(monkeypatch)
    resp = TestClient(app, base_url="http://192.0.2.10:8000").get("/health")
    assert resp.status_code == 503
    assert "SEER_API_KEY" in resp.json()["detail"]
    # Loopback listeners (v4 and v6) keep working without a key.
    assert TestClient(app, base_url="http://127.0.0.1:8000").get("/health").status_code == 200
    assert TestClient(app, base_url="http://[::1]:8000").get("/health").status_code == 200


def test_request_on_public_interface_with_key_is_served(monkeypatch):
    monkeypatch.setenv("SEER_API_KEY", "k")
    c = TestClient(app, base_url="http://192.0.2.10:8000")
    assert c.get("/health").status_code == 200
    assert c.get("/lookup/example.com").status_code == 401


def test_cross_origin_rest_request_blocked_without_key(monkeypatch, client):
    """Regression: with no key, REST sent `Access-Control-Allow-Origin: *`
    and checked no Origin, so any web page could drive the API from the
    operator's browser. /mcp already had this guard; REST now shares it."""
    _no_key(monkeypatch)
    monkeypatch.setattr(seer, "lookup", lambda d: {"domain": d}, raising=False)
    resp = client.get("/lookup/example.com", headers={"Origin": "https://evil.example"})
    assert resp.status_code == 403
    assert "access-control-allow-origin" not in {k.lower() for k in resp.headers}
    for origin in ("http://localhost:3000", "http://127.0.0.1:8000"):
        resp = client.get("/lookup/example.com", headers={"Origin": origin})
        assert resp.status_code == 200, (origin, resp.text)
    # No Origin (curl, SDKs): allowed, and no CORS headers are sent by default.
    resp = client.get("/lookup/example.com")
    assert resp.status_code == 200
    assert "access-control-allow-origin" not in {k.lower() for k in resp.headers}


def test_cors_allowlist_admits_its_origins(monkeypatch):
    import importlib

    import seer_api.main as main

    _no_key(monkeypatch)
    monkeypatch.setenv("SEER_CORS_ORIGINS", "https://app.example")
    monkeypatch.setattr(seer, "lookup", lambda d: {"domain": d}, raising=False)
    importlib.reload(main)
    try:
        c = TestClient(main.app)
        resp = c.get("/lookup/example.com", headers={"Origin": "https://app.example"})
        assert resp.status_code == 200
        assert resp.headers["access-control-allow-origin"] == "https://app.example"
        resp = c.get("/lookup/example.com", headers={"Origin": "https://evil.example"})
        assert resp.status_code == 403
    finally:
        monkeypatch.delenv("SEER_CORS_ORIGINS")
        importlib.reload(main)


def test_cross_origin_rest_request_allowed_with_key(monkeypatch, client):
    monkeypatch.setenv("SEER_API_KEY", "k")
    monkeypatch.delenv("SEER_CORS_ORIGINS", raising=False)
    monkeypatch.setattr(seer, "lookup", lambda d: {"domain": d}, raising=False)
    resp = client.get(
        "/lookup/example.com",
        headers={"Origin": "https://evil.example", "Authorization": "Bearer k"},
    )
    assert resp.status_code == 200


@pytest.mark.parametrize("scheme", ["Bearer", "bearer", "BEARER", "bEaReR"])
def test_bearer_scheme_is_case_insensitive(monkeypatch, client, scheme):
    """RFC 9110 §11.1: auth schemes are case-insensitive; the token is not."""
    monkeypatch.setenv("SEER_API_KEY", "s3cret")
    monkeypatch.setattr(seer, "lookup", lambda d: {"domain": d}, raising=False)
    ok = client.get("/lookup/example.com", headers={"Authorization": f"{scheme} s3cret"})
    assert ok.status_code == 200
    bad = client.get("/lookup/example.com", headers={"Authorization": f"{scheme} S3CRET"})
    assert bad.status_code == 401
    other = client.get("/lookup/example.com", headers={"Authorization": "Basic s3cret"})
    assert other.status_code == 401


# ---------------------------------------------------------------------------
# Typed core errors -> HTTP status, by class
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc,status",
    [
        (seer.RateLimitedError("Rate limited - please try again later"), 429),
        (seer.WhoisServerNotFoundError("WHOIS server not found for this TLD"), 404),
        (seer.UpstreamError("RDAP lookup failed"), 502),
        (seer.DnsError("DNS resolution failed"), 502),
        (seer.LookupFailedError("Lookup failed for example.com"), 502),
        (seer.SeerError("Operation failed"), 500),
        (seer.ConfigError("Configuration error"), 500),
    ],
)
def test_typed_core_errors_map_to_status(monkeypatch, client, exc, status):
    """Regression: every non-builtin core error was a 500 — a rate-limited
    upstream or an unsupported TLD included."""

    def _raising(_domain):
        raise exc

    monkeypatch.setattr(seer, "whois", _raising, raising=False)
    resp = client.get("/whois/example.zz")
    assert resp.status_code == status, resp.text
    # Core's sanitized message is surfaced (it is safe by construction).
    assert resp.json()["detail"] == str(exc)


def test_client_errors_are_logged_without_traceback(monkeypatch, client, caplog):
    """Regression: every 4xx was logged with `logger.exception` and a full
    traceback."""

    def _raising(_domain):
        raise ValueError("Invalid domain name: x")

    monkeypatch.setattr(seer, "whois", _raising, raising=False)
    with caplog.at_level(logging.INFO, logger="seer_api"):
        assert client.get("/whois/x").status_code == 400
    records = [r for r in caplog.records if "rejected" in r.getMessage()]
    assert records and all(r.exc_info is None for r in records)
    assert all(r.levelno == logging.INFO for r in records)


# ---------------------------------------------------------------------------
# Rate limits
# ---------------------------------------------------------------------------


def test_bulk_and_stream_share_one_budget(monkeypatch, client):
    """Regression: /x/bulk and /x/bulk/stream each carried their own limit,
    doubling the budget for one operation."""
    monkeypatch.setattr(seer, "bulk_status", lambda domains, c, progress=None: [], raising=False)
    body = {"domains": ["example.com"]}
    for _ in range(5):  # HEAVY_LIMIT
        assert client.post("/status/bulk", json=body).status_code == 200
    assert client.post("/status/bulk/stream", json=body).status_code == 429


def test_root_index_is_rate_limited(client):
    for _ in range(60):
        assert client.get("/").status_code == 200
    assert client.get("/").status_code == 429


def test_mcp_tool_limit_is_per_client(monkeypatch):
    """Regression: per-tool limits were keyed per process, so one client
    exhausting seer_confusables locked every other client out of it."""
    monkeypatch.setattr(seer, "confusables", lambda d, c: {"domain": d}, raising=False)
    args = {"domain": "example.com"}
    for _ in range(5):
        out = asyncio.run(mcp_server.call_tool("seer_confusables", args, "198.51.100.1"))
        assert not getattr(out, "is_error", False)
    out = asyncio.run(mcp_server.call_tool("seer_confusables", args, "198.51.100.1"))
    assert out.is_error is True
    out = asyncio.run(mcp_server.call_tool("seer_confusables", args, "198.51.100.2"))
    assert not getattr(out, "is_error", False), "another client shared the budget"


def test_mcp_client_key_comes_from_the_http_request(monkeypatch):
    """Over Streamable HTTP the SDK attaches the Starlette request; the key is
    the same client IP the /mcp gate uses. Without one (stdio), a fixed key."""
    from types import SimpleNamespace

    from starlette.requests import Request

    request = Request({"type": "http", "headers": [], "client": ("203.0.113.9", 5000)})
    assert mcp_server._client_key(SimpleNamespace(request=request)) == "203.0.113.9"
    assert mcp_server._client_key(SimpleNamespace(request=None)) == "stdio"


def test_mcp_subdomains_has_a_per_tool_limit():
    assert mcp_server._TOOL_RATE_LIMITS["seer_subdomains"] == "5/minute"


# ---------------------------------------------------------------------------
# MCP input caps and the TLD catalog tool
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool,args",
    [
        ("seer_lookup", {"domain": "a" * 254}),
        ("seer_bulk_lookup", {"domains": ["a" * 254]}),
        ("seer_rdap_ip", {"ip": "1" * 46}),
        ("seer_dig", {"domain": "example.com", "nameserver": "x" * 513}),
    ],
)
def test_mcp_string_arguments_are_capped_like_rest(tool, args):
    """Regression: `_require_str` had no length cap (REST caps a domain at 253)."""
    with pytest.raises(ValueError, match="characters"):
        asyncio.run(mcp_server.execute_tool(tool, args))


def test_mcp_tld_list_tool(monkeypatch):
    monkeypatch.setattr(seer, "all_tlds", lambda: ["com", "net"], raising=False)
    assert asyncio.run(mcp_server.execute_tool("seer_tld_list", {})) == ["com", "net"]
