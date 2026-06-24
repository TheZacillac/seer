"""FastAPI application for Seer domain utilities."""

import hmac
import logging
import os
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, ORJSONResponse
from limits import parse as _parse_rate_limit
from limits.storage import storage_from_string as _rate_storage_from_string
from limits.strategies import MovingWindowRateLimiter
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.routing import Route

from . import __version__
from ._env import env_int
from .limiting import get_client_ip, limiter
from .mcp.server import mcp as mcp_server
from .middleware import MaxBodySizeMiddleware, RequestLoggingMiddleware, metrics
from .routers import dns, lookup, propagation, rdap, ssl, status, whois

# Configure structured logging via the unified Arcanum logging module.
try:
    from arcanum._logging import configure_logging
    configure_logging("seer-api")
except ImportError:
    # Fallback if arcanum is not installed.
    log_level = os.environ.get("ARCANUM_LOG_LEVEL",
                               os.environ.get("SEER_LOG_LEVEL", "INFO")).upper()
    logging.basicConfig(level=getattr(logging, log_level, logging.INFO))

log = logging.getLogger(__name__)

# Optional bearer-token auth. When SEER_API_KEY is set, every request must
# carry `Authorization: Bearer <key>` (except /health, which is always open).
# Docs endpoints (/docs, /redoc, /openapi.json) are gated behind
# SEER_DOCS_ENABLED; when enabled they are also exempted from auth so the
# interactive UIs remain usable for operators.
#
# `DOCS_ENABLED` is read at import time because it gates `docs_url=` /
# `redoc_url=` / `openapi_url=` on the FastAPI() constructor; those args
# can't change at runtime. `SEER_API_KEY`, by contrast, is consulted on
# every request via `auth_middleware` so tests and rotating-secret deploys
# don't need an import reload to pick up changes.
DOCS_ENABLED = os.environ.get("SEER_DOCS_ENABLED", "").lower() in ("1", "true", "yes")
_AUTH_EXEMPT_PATHS: frozenset[str] = (
    frozenset({"/health", "/docs", "/openapi.json", "/redoc"})
    if DOCS_ENABLED
    else frozenset({"/health"})
)


def _build_mcp_session_manager() -> StreamableHTTPSessionManager:
    """Construct the Streamable HTTP MCP session manager.

    Built fresh per lifespan entry — ``StreamableHTTPSessionManager.run()``
    refuses to re-enter on the same instance, so a long-lived module-level
    singleton would break uvicorn restarts and TestClient re-use.

    Runs in stateless mode so it can scale across uvicorn workers without a
    shared session store. DNS-rebinding protection is opt-in via
    ``SEER_MCP_ALLOWED_HOSTS`` / ``SEER_MCP_ALLOWED_ORIGINS`` (the SDK
    middleware blocks all requests unless at least one host pattern is
    configured, so we only enable it when the operator provides one).
    """
    allowed_hosts_env = os.environ.get("SEER_MCP_ALLOWED_HOSTS", "")
    allowed_origins_env = os.environ.get("SEER_MCP_ALLOWED_ORIGINS", "")
    if allowed_hosts_env or allowed_origins_env:
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[h.strip() for h in allowed_hosts_env.split(",") if h.strip()],
            allowed_origins=[o.strip() for o in allowed_origins_env.split(",") if o.strip()],
        )
    else:
        security = None
    return StreamableHTTPSessionManager(
        app=mcp_server,
        stateless=True,
        json_response=False,
        security_settings=security,
    )


class _McpAsgiApp:
    """ASGI3 callable that delegates to the active MCP session manager.

    Defined as a class (not a plain function) so Starlette's ``Route``
    treats it as a raw ASGI app instead of wrapping it as a request /
    response endpoint — which lets the session manager own the SSE stream.

    Holds the manager via a mutable attribute so the lifespan can swap in a
    fresh instance on each entry (the SDK forbids re-entering ``run()`` on
    the same instance) without rebuilding the route table.
    """

    def __init__(self) -> None:
        self.manager: StreamableHTTPSessionManager | None = None

    async def __call__(self, scope, receive, send) -> None:
        if self.manager is None:
            raise RuntimeError("MCP session manager not started; lifespan did not run")
        await self.manager.handle_request(scope, receive, send)


_mcp_asgi_app = _McpAsgiApp()


# --- POST /mcp hardening (issue #55) ---------------------------------------
# /mcp is a raw Starlette Route, so the per-route `@limiter.limit` decorators do
# not cover it, and slowapi has no SlowAPIMiddleware registered (decorator mode).
# Rate-limit the highest-fan-out surface (it can drive seer_bulk_* = up to 100
# domains x concurrency) explicitly here, using the same env config as the REST
# limiter so an operator's SEER_RATE_LIMIT / SEER_RATE_LIMIT_STORAGE applies.
#
# Built lazily on first /mcp request (not at import) so that configuring a
# backend whose driver isn't installed — e.g. SEER_RATE_LIMIT_STORAGE=redis://
# without the redis package — doesn't crash module import; it surfaces only if
# /mcp is actually used, mirroring slowapi's own lazy storage behavior.
_mcp_rate_limiter: MovingWindowRateLimiter | None = None
_mcp_rate_value = None


def _mcp_rate_ok(client_ip: str) -> bool:
    """Record a hit for ``client_ip`` against the /mcp limit; False if over."""
    global _mcp_rate_limiter, _mcp_rate_value
    if _mcp_rate_limiter is None:
        _mcp_rate_value = _parse_rate_limit(
            os.environ.get("SEER_RATE_LIMIT", "30/minute")
        )
        _mcp_rate_limiter = MovingWindowRateLimiter(
            _rate_storage_from_string(
                os.environ.get("SEER_RATE_LIMIT_STORAGE", "memory://")
            )
        )
    return _mcp_rate_limiter.hit(_mcp_rate_value, "mcp", client_ip)


_LOCALHOST_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _header_host(value: str) -> str:
    """Lowercased hostname of an Origin/Host header value, or '' if absent."""
    if not value:
        return ""
    parsed = urlsplit(value if "://" in value else "//" + value)
    return (parsed.hostname or "").lower()


def _mcp_browser_guard_active() -> bool:
    """Whether the default localhost-Origin guard for /mcp applies.

    Only in the unauthenticated dev posture with no explicit MCP allowlist: when
    SEER_API_KEY is set, auth already blocks a drive-by (no bearer token); when
    SEER_MCP_ALLOWED_HOSTS/_ORIGINS is set, the SDK's DNS-rebinding protection
    covers it.
    """
    api_key = (os.environ.get("SEER_API_KEY") or "").strip()
    allowlist = (
        os.environ.get("SEER_MCP_ALLOWED_HOSTS", "")
        or os.environ.get("SEER_MCP_ALLOWED_ORIGINS", "")
    ).strip()
    return not api_key and not allowlist

# Rate limiter configuration is handled in limiting.py at construction time
# via SEER_RATE_LIMIT env var (default: "30/minute")

@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Fail-closed startup checks.

    Refuses to start when the combination of settings would create an obvious
    footgun deployment:
      * Non-loopback bind without SEER_API_KEY would expose the API publicly
        with no auth. We hard-fail rather than log a warning (C6).
      * Multi-worker deployment with the default in-memory rate-limit store
        would silently multiply the effective rate limit by the worker count.
        We hard-fail to force operators to configure a shared store (H10).
    """
    # H10: in-memory rate limit with multiple workers is per-worker and
    # therefore bypassable by rotating through workers. Refuse to start.
    storage_uri = os.environ.get("SEER_RATE_LIMIT_STORAGE", "memory://")
    # WEB_CONCURRENCY wins; UVICORN_WORKERS is the fallback; default 1. A
    # non-integer (e.g. the PaaS convention WEB_CONCURRENCY=auto) raises a clear
    # RuntimeError here instead of an opaque ValueError traceback (issue #50).
    workers = env_int(
        "WEB_CONCURRENCY",
        env_int("UVICORN_WORKERS", 1, min_value=1),
        min_value=1,
    )
    if workers > 1 and storage_uri == "memory://":
        log.error(
            "Multi-worker deployment (WEB_CONCURRENCY=%d) requires "
            "SEER_RATE_LIMIT_STORAGE (e.g. redis://host:6379). Refusing to "
            "start with an in-memory limiter that would be bypassed "
            "per-worker.",
            workers,
        )
        raise RuntimeError(
            "refusing to start: multi-worker deployment requires "
            "SEER_RATE_LIMIT_STORAGE"
        )

    # C6: bound to a non-loopback interface without any API key is an open
    # proxy. Hard-fail rather than warn. Read SEER_API_KEY directly from
    # the environment here (not from a module-level constant) so a deploy
    # that sets the key just before startup is honoured. Use `.strip()`
    # so a blank value from a secrets-manager placeholder
    # (`SEER_API_KEY=""`) still trips the guard instead of silently
    # disabling auth.
    host = os.environ.get("SEER_HOST", "127.0.0.1")
    if host != "127.0.0.1" and not (os.environ.get("SEER_API_KEY") or "").strip():
        log.error(
            "seer-api is bound to %s with no SEER_API_KEY set. Refusing to "
            "start. Set SEER_API_KEY or SEER_HOST=127.0.0.1.",
            host,
        )
        raise RuntimeError("refusing to start: public bind without auth")

    # Streamable HTTP MCP transport needs its own task group to manage
    # per-request transports. Build a fresh session manager per lifespan
    # entry — the SDK forbids re-running an instance — and expose it to
    # the mounted ASGI handler for the duration of the run.
    manager = _build_mcp_session_manager()
    _mcp_asgi_app.manager = manager
    try:
        async with manager.run():
            log.info("MCP Streamable HTTP transport mounted at /mcp (stateless)")
            yield
    finally:
        _mcp_asgi_app.manager = None


app = FastAPI(
    title="Seer API",
    description="Domain name helper API - WHOIS, RDAP, DNS lookups, and propagation checking",
    version=__version__,
    docs_url="/docs" if DOCS_ENABLED else None,
    redoc_url="/redoc" if DOCS_ENABLED else None,
    openapi_url="/openapi.json" if DOCS_ENABLED else None,
    lifespan=lifespan,
    default_response_class=ORJSONResponse,
)

# Add rate limiter to app state and exception handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Body size cap — reject oversized payloads with 413 before they hit
# any router. Default 64KB is generous for a 100-domain bulk request
# (see middleware.DEFAULT_MAX_BODY_BYTES). M6.
#
# RequestLoggingMiddleware is intentionally registered LATER (just before
# CORS) so it wraps both this body-size cap and auth_middleware. Starlette
# runs the most-recently-added middleware first, so registering logging here
# (innermost) would let the 413/401/403/429 short-circuits from the outer
# middlewares bypass it — they would never be logged or counted in /metrics.
app.add_middleware(MaxBodySizeMiddleware, max_bytes=64 * 1024)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Enforce optional bearer-token auth when SEER_API_KEY is set.

    Reads `SEER_API_KEY` per request rather than from a module-level
    constant, so tests and rotating-secret deployments don't need an import
    reload to pick up the current key.
    """
    # POST /mcp hardening (issue #55), applied before auth so an unauthenticated
    # flood is throttled and a drive-by is refused regardless of credentials.
    if request.url.path == "/mcp":
        # Browser drive-by guard: a malicious page's fetch() carries a non-local
        # Origin; non-browser MCP clients (curl, stdio bridges) send none.
        if _mcp_browser_guard_active():
            origin = request.headers.get("origin", "")
            if origin and _header_host(origin) not in _LOCALHOST_HOSTS:
                return JSONResponse(
                    {
                        "detail": "cross-origin /mcp blocked; set "
                        "SEER_MCP_ALLOWED_ORIGINS or SEER_API_KEY to allow"
                    },
                    status_code=403,
                )
        # Rate-limit the raw /mcp route that the @limiter.limit decorators miss.
        if not _mcp_rate_ok(get_client_ip(request)):
            return JSONResponse(
                {"detail": "rate limit exceeded"}, status_code=429
            )

    # Treat a blank value (e.g. `SEER_API_KEY=""` from a misconfigured
    # secrets-manager placeholder) as "no key set" rather than letting
    # it silently disable auth via Python's empty-string falsy check.
    api_key = (os.environ.get("SEER_API_KEY") or "").strip()
    if api_key:
        # Public endpoints are exempt. OPTIONS preflight is handled by the
        # outer CORSMiddleware and never reaches here, but we still short
        # the rare OPTIONS that falls through (non-preflight) so it isn't
        # spuriously rejected.
        if request.method == "OPTIONS" or request.url.path in _AUTH_EXEMPT_PATHS:
            return await call_next(request)
        provided = request.headers.get("Authorization", "")
        expected = f"Bearer {api_key}"
        if not hmac.compare_digest(provided, expected):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return await call_next(request)


# CORS middleware - configure allowed origins via SEER_CORS_ORIGINS env var
# For production, set SEER_CORS_ORIGINS to comma-separated list of allowed origins
# e.g., SEER_CORS_ORIGINS="https://example.com,https://app.example.com"
#
# Registered LAST so it is the OUTERMOST middleware, wrapping both
# auth_middleware and MaxBodySizeMiddleware. This matters because Starlette
# runs the most-recently-added middleware first: CORSMiddleware therefore
# attaches `Access-Control-Allow-Origin` to the short-circuit error
# responses (401 from auth, 413 from the body-size cap) for allowed
# origins, instead of those errors arriving at the browser opaque. Auth
# still runs before any route handler — CORS only adds response headers and
# answers preflight; it does not bypass downstream middleware for real
# requests.
cors_origins_env = os.environ.get("SEER_CORS_ORIGINS", "")
# Filter empty entries first so `SEER_CORS_ORIGINS=",,"` and trailing
# commas land in the dev-mode branch instead of producing a list of
# empty strings that CORSMiddleware silently never matches.
_cors_parsed = [o for o in (s.strip() for s in cors_origins_env.split(",")) if o]
if _cors_parsed:
    allowed_origins = _cors_parsed
    allow_credentials = True
    # `Access-Control-Allow-Origin: *` with `allow_credentials=True` is a
    # CORS spec violation — browsers reject it and Starlette raises a
    # ValueError on first preflight. Catch the misconfig at startup so the
    # operator gets a clear message instead of an opaque 500 later.
    if "*" in allowed_origins:
        raise RuntimeError(
            "SEER_CORS_ORIGINS cannot contain '*' (credentials would be "
            "exposed to any origin). List explicit origins, or unset the "
            "variable to use the credential-less development mode."
        )
else:
    # Development mode: allow all origins but disable credentials
    allowed_origins = ["*"]
    allow_credentials = False

# Request logging / metrics middleware. Registered here — AFTER
# auth_middleware and MaxBodySizeMiddleware, but BEFORE CORS below — so it
# wraps the auth + body-size + /mcp-guard logic. Starlette runs the
# most-recently-added middleware first, so this becomes the OUTERMOST
# application middleware just inside CORS. The resolved order is therefore:
#
#   CORS -> RequestLogging -> auth -> body-size -> route
#
# which means the short-circuit rejections that never reach a route handler
# — the 401 from auth, the 413 from the body-size cap, and the /mcp 403/429
# guards — all flow back out through RequestLogging and are logged + counted
# in /metrics (previously they were registered innermost and were silently
# unobservable). CORS stays outermost so it can annotate those error
# responses with Access-Control-Allow-Origin headers.
app.add_middleware(RequestLoggingMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(lookup.router, prefix="/lookup", tags=["Lookup"])
app.include_router(whois.router, prefix="/whois", tags=["WHOIS"])
app.include_router(rdap.router, prefix="/rdap", tags=["RDAP"])
app.include_router(dns.router, prefix="/dns", tags=["DNS"])
app.include_router(propagation.router, prefix="/propagation", tags=["Propagation"])
app.include_router(status.router, prefix="/status", tags=["Status"])
app.include_router(ssl.router, prefix="/ssl", tags=["SSL"])

# MCP Streamable HTTP transport. Registered as a Starlette Route (not
# FastAPI mount) so the session manager owns the full request lifecycle,
# including SSE streaming for tools/call responses, with no /mcp -> /mcp/
# redirect. Auth, body-size cap, and request logging wrap it transparently
# via the middleware stack.
app.router.routes.append(Route("/mcp", endpoint=_mcp_asgi_app))


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Seer API",
        "version": __version__,
        "description": "Domain name helper API",
        "endpoints": {
            "lookup": "/lookup/{domain}",
            "whois": "/whois/{domain}",
            "rdap_domain": "/rdap/domain/{domain}",
            "rdap_ip": "/rdap/ip/{ip}",
            "rdap_asn": "/rdap/asn/{asn}",
            "dns": "/dns/{domain}/{record_type}",
            "propagation": "/propagation/{domain}/{record_type}",
            "status": "/status/{domain}",
            "ssl_bulk": "/ssl/bulk",
            "mcp": "/mcp",
        },
        "docs": "/docs",
    }


@app.get("/health")
@limiter.exempt
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/metrics")
@limiter.limit("10/minute")
async def get_metrics(request: Request):
    """Request metrics endpoint for observability.

    Restricted to localhost when SEER_METRICS_ENABLED is not set. The
    localhost gate checks ``request.client.host`` directly (the socket
    peer) rather than routing through ``get_client_ip``, because the
    proxy-aware helper trusts X-Forwarded-For and is therefore
    spoofable by remote clients. Metrics must remain tied to the actual
    TCP peer. Rate-limited independently of the auth gate to prevent
    trivial stats-scraping amplification (H12, M9).
    """
    metrics_enabled = os.environ.get("SEER_METRICS_ENABLED", "").lower() in ("1", "true", "yes")
    if not metrics_enabled:
        peer = request.client.host if request.client else ""
        if peer not in ("127.0.0.1", "::1"):
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="Metrics endpoint is disabled")
    return metrics.snapshot()


def run():
    """Run the API server.

    Defaults to binding on the loopback interface (127.0.0.1). Set
    SEER_HOST=0.0.0.0 to bind publicly — but note that doing so also
    requires SEER_API_KEY to be set, or the lifespan hook will refuse
    to start.
    """
    import uvicorn

    host = os.environ.get("SEER_HOST", "127.0.0.1")
    port = int(os.environ.get("SEER_PORT", "8000"))
    reload = os.environ.get("SEER_RELOAD", "false").lower() in ("true", "1", "yes")

    uvicorn.run(
        "seer_api.main:app",
        host=host,
        port=port,
        reload=reload,
    )


if __name__ == "__main__":
    run()
