"""FastAPI application for Seer domain utilities."""

import hmac
import ipaddress
import logging
import os
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, ORJSONResponse
from limits import parse_many as _parse_rate_limits
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.routing import Route

from . import __version__
from ._env import env_int
from .limiting import get_client_ip, limiter
from .mcp.server import mcp as mcp_server
from .mcp.server import rate_limiter as mcp_rate_limiter
from .middleware import MaxBodySizeMiddleware, RequestLoggingMiddleware, metrics
from .routers import dns, intel, lookup, propagation, rdap, ssl, status, tld, whois

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


def _csv_env(name: str) -> list[str]:
    """Non-empty, stripped entries of comma-separated env var ``name``."""
    return [v.strip() for v in os.environ.get(name, "").split(",") if v.strip()]


def _api_key() -> str:
    """The configured ``SEER_API_KEY``, read per call; '' means auth is off.

    Stripped, so a blank value (e.g. ``SEER_API_KEY=""`` from a
    secrets-manager placeholder) counts as unset rather than as a key.
    """
    return (os.environ.get("SEER_API_KEY") or "").strip()


def _build_mcp_session_manager() -> StreamableHTTPSessionManager:
    """Construct the Streamable HTTP MCP session manager.

    Built fresh per lifespan entry — ``StreamableHTTPSessionManager.run()``
    refuses to re-enter on the same instance, so a long-lived module-level
    singleton would break uvicorn restarts and TestClient re-use.

    Runs in stateless mode so it can scale across uvicorn workers without a
    shared session store. The SDK's DNS-rebinding protection is enabled only
    when ``SEER_MCP_ALLOWED_HOSTS`` names at least one host: with it on, the
    SDK rejects every ``Host`` not in ``allowed_hosts`` — so enabling it with
    an empty host list (``SEER_MCP_ALLOWED_ORIGINS`` alone) answered every
    /mcp request with 421. ``SEER_MCP_ALLOWED_ORIGINS`` is passed along when
    hosts are set; when it is set on its own, ``auth_middleware`` enforces it
    as the Origin allowlist instead (see ``_mcp_origin_blocked``).
    """
    allowed_hosts = _csv_env("SEER_MCP_ALLOWED_HOSTS")
    if allowed_hosts:
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=_csv_env("SEER_MCP_ALLOWED_ORIGINS"),
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
# domains x concurrency) explicitly here with SEER_RATE_LIMIT, stored in
# SEER_RATE_LIMIT_STORAGE. SEER_RATE_LIMIT applies to /mcp ONLY: the REST
# routes each carry an explicit `@limiter.limit(...)`, which overrides the
# limiter's default (see limiting.py).
#
# The limiter is the MCP server's shared one (built lazily on first use); the
# limits themselves are parsed on the first /mcp request.
_mcp_rate_values: list | None = None


def _mcp_rate_ok(client_ip: str) -> bool:
    """Record a hit for ``client_ip`` against the /mcp limits; False if over.

    ``SEER_RATE_LIMIT`` may hold several limits (``"30/minute;500/day"``, the
    same multi-limit syntax slowapi accepts); every one is enforced. Parsing
    with ``limits.parse`` kept only the first and silently dropped the rest.
    Evaluated in order, stopping at the first exhausted limit — slowapi's own
    semantics for a multi-limit string.
    """
    global _mcp_rate_values
    if _mcp_rate_values is None:
        _mcp_rate_values = _parse_rate_limits(
            os.environ.get("SEER_RATE_LIMIT", "30/minute")
        )
    window = mcp_rate_limiter()
    return all(window.hit(item, "mcp", client_ip) for item in _mcp_rate_values)


_LOCALHOST_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _is_loopback_bind(host: str) -> bool:
    """Whether ``SEER_HOST`` names an interface that is unreachable off-box.

    Covers the whole IPv4 loopback range (127.0.0.0/8, not just 127.0.0.1),
    IPv6 loopback (``::1``, and the IPv4-mapped ``::ffff:127.0.0.1``), and the
    ``localhost`` hostname. The previous check was a literal ``!=
    "127.0.0.1"``, which refused to start on ``SEER_HOST=::1`` — a bind that
    is exactly as private as the default — with a "public bind without auth"
    error that misdescribed the situation.

    **Fails closed**: anything that isn't provably loopback (a real address, a
    hostname, ``0.0.0.0``, ``::``, or junk) returns False and therefore still
    requires ``SEER_API_KEY``. A wildcard bind like ``0.0.0.0`` is emphatically
    not loopback even though it *includes* the loopback interface.
    """
    candidate = host.strip().strip("[]").lower()
    if not candidate:
        return False
    if candidate == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        # A hostname we can't resolve to a literal — treat as public.
        return False
    # Unwrap IPv4-mapped IPv6 (``::ffff:127.0.0.1``) explicitly:
    # `IPv6Address.is_loopback` only learned to consult the mapped IPv4
    # address in later CPython releases (it is False on 3.12.0-3.12.3), so
    # relying on it made startup depend on the patch version.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback


def _header_host(value: str) -> str:
    """Lowercased hostname of an Origin/Host header value, or '' if absent."""
    if not value:
        return ""
    parsed = urlsplit(value if "://" in value else "//" + value)
    return (parsed.hostname or "").lower()


def _origin_allowed(origin: str, allowed: list[str]) -> bool:
    """Whether ``origin`` matches an ``allowed`` entry.

    Same matching rules as the MCP SDK's DNS-rebinding check, so an
    ``SEER_MCP_ALLOWED_ORIGINS`` value means the same thing whichever layer
    enforces it: an exact match, or a ``scheme://host:*`` entry matching any
    port on that origin.
    """
    if origin in allowed:
        return True
    return any(
        entry.endswith(":*") and origin.startswith(entry[:-2] + ":")
        for entry in allowed
    )


def _mcp_origin_blocked(origin: str) -> bool:
    """Whether the local browser-origin guard refuses this /mcp request.

    Non-browser MCP clients (curl, stdio bridges) send no Origin and always
    pass. Otherwise, in precedence order:

    * ``SEER_MCP_ALLOWED_HOSTS`` set → the SDK's DNS-rebinding protection is
      on and validates Host and Origin itself; nothing to do here.
    * ``SEER_MCP_ALLOWED_ORIGINS`` set on its own → enforce it here as the
      Origin allowlist. The SDK protection can't be enabled without a host
      list (it would 421 every request), and this keeps an explicitly
      configured origin policy in force even when ``SEER_API_KEY`` is set.
    * ``SEER_API_KEY`` set → auth already blocks a drive-by (no bearer token).
    * Otherwise (unauthenticated dev posture) → only localhost origins.
    """
    if not origin:
        return False
    if _csv_env("SEER_MCP_ALLOWED_HOSTS"):
        return False
    allowed_origins = _csv_env("SEER_MCP_ALLOWED_ORIGINS")
    if allowed_origins:
        return not _origin_allowed(origin, allowed_origins)
    if _api_key():
        return False
    return _header_host(origin) not in _LOCALHOST_HOSTS


def _route_path(request: Request) -> str:
    """The request path as the router matches it: ``root_path`` stripped.

    Under ``--root-path /api`` (ASGI ``root_path``) ``scope["path"]`` — and so
    ``request.url.path`` — carries the ``/api`` prefix, while Starlette routes
    on the path with the prefix removed. Comparing ``request.url.path``
    against route paths therefore missed: the /mcp guards were skipped for
    ``/api/mcp`` and ``/api/health`` lost its auth exemption. Mirrors
    Starlette's own (private) ``get_route_path``.
    """
    path: str = request.scope.get("path", "")
    root_path: str = request.scope.get("root_path", "")
    if root_path and path.startswith(root_path):
        rest = path[len(root_path):]
        if rest == "" or rest.startswith("/"):
            return rest
    return path


# REST rate limits are the per-route `@limiter.limit(...)` decorators (limiter
# built in limiting.py); SEER_RATE_LIMIT (default "30/minute") applies to the
# raw /mcp route only, via `_mcp_rate_ok` above.

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
    # UVICORN_WORKERS is parsed only when it is actually the fallback: passing
    # `env_int("UVICORN_WORKERS", ...)` as WEB_CONCURRENCY's default evaluated
    # it eagerly, so `WEB_CONCURRENCY=1 UVICORN_WORKERS=auto` refused to start
    # over a variable that was being overridden anyway.
    if (os.environ.get("WEB_CONCURRENCY") or "").strip():
        workers = env_int("WEB_CONCURRENCY", 1, min_value=1)
    else:
        workers = env_int("UVICORN_WORKERS", 1, min_value=1)
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
    # proxy. Hard-fail rather than warn. The key is read from the environment
    # here (not a module-level constant) so a deploy that sets it just before
    # startup is honoured, and a blank placeholder still trips the guard.
    host = os.environ.get("SEER_HOST", "127.0.0.1")
    if not _is_loopback_bind(host) and not _api_key():
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
    # Match paths the way the router does (root_path stripped); comparing
    # `request.url.path` skipped every check below under `--root-path`.
    route_path = _route_path(request)

    # POST /mcp hardening (issue #55), applied before auth so an unauthenticated
    # flood is throttled and a drive-by is refused regardless of credentials.
    if route_path == "/mcp":
        # Browser drive-by guard: a malicious page's fetch() carries a
        # disallowed Origin; non-browser MCP clients (curl, stdio bridges) send
        # none. See `_mcp_origin_blocked` for which policy applies when.
        if _mcp_origin_blocked(request.headers.get("origin", "")):
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

    api_key = _api_key()
    if api_key:
        # Public endpoints are exempt. OPTIONS preflight is handled by the
        # outer CORSMiddleware and never reaches here, but we still short
        # the rare OPTIONS that falls through (non-preflight) so it isn't
        # spuriously rejected.
        if request.method == "OPTIONS" or route_path in _AUTH_EXEMPT_PATHS:
            return await call_next(request)
        # Compare BYTES: `hmac.compare_digest` raises TypeError for str
        # operands containing non-ASCII characters, so an unauthenticated
        # `Authorization: Bearer été` was a 500 (and a non-ASCII key broke
        # every request). Starlette decodes header values as latin-1, so
        # re-encoding latin-1 recovers the exact wire bytes; the key is
        # encoded UTF-8 — what an HTTP client sends for a non-ASCII token —
        # with surrogateescape so an undecodable env value round-trips.
        provided = request.headers.get("Authorization", "").encode("latin-1")
        expected = f"Bearer {api_key}".encode("utf-8", "surrogateescape")
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
# Empty entries are dropped, so `SEER_CORS_ORIGINS=",,"` and trailing commas
# land in the dev-mode branch instead of producing a list of empty strings
# that CORSMiddleware silently never matches.
allowed_origins = _csv_env("SEER_CORS_ORIGINS")
if allowed_origins:
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
app.include_router(intel.availability_router, prefix="/availability", tags=["Availability"])
app.include_router(intel.info_router, prefix="/info", tags=["Info"])
app.include_router(intel.subdomains_router, prefix="/subdomains", tags=["Subdomains"])
app.include_router(intel.dnssec_router, prefix="/dnssec", tags=["DNSSEC"])
app.include_router(intel.delegation_router, prefix="/delegation", tags=["Delegation"])
app.include_router(intel.diff_router, prefix="/diff", tags=["Diff"])
app.include_router(intel.caa_router, prefix="/caa", tags=["CAA"])
app.include_router(intel.posture_router, prefix="/posture", tags=["Posture"])
app.include_router(intel.headers_router, prefix="/headers", tags=["Headers"])
app.include_router(intel.takeover_router, prefix="/takeover", tags=["Takeover"])
app.include_router(intel.confusables_router, prefix="/confusables", tags=["Confusables"])
app.include_router(tld.router, prefix="/tld", tags=["TLD"])

# MCP Streamable HTTP transport. Registered as a Starlette Route (not
# FastAPI mount) so the session manager owns the full request lifecycle,
# including SSE streaming for tools/call responses, with no /mcp -> /mcp/
# redirect. Auth, body-size cap, and request logging wrap it transparently
# via the middleware stack.
app.router.routes.append(Route("/mcp", endpoint=_mcp_asgi_app))


def _endpoint_name(path: str) -> str:
    """Derive the index key for a route template.

    Joins the literal (non-parameter) segments with ``_``, which reproduces
    the keys the old hand-written index used: ``/lookup/{domain}`` -> ``lookup``,
    ``/rdap/domain/{domain}`` -> ``rdap_domain``, ``/ssl/bulk`` -> ``ssl_bulk``.
    A collection route (trailing slash, e.g. ``/tld/``) gets an ``_index``
    suffix so it does not collide with its item route ``/tld/{tld}``.
    """
    segments = [s for s in path.split("/") if s and not s.startswith("{")]
    name = "_".join(segments) or "root"
    if path.endswith("/") and path != "/":
        name = f"{name}_index"
    return name


def _endpoint_index(target: FastAPI) -> dict[str, str]:
    """Map a stable name to every route template registered on ``target``.

    Generated from the route table rather than hand-maintained: the literal
    this replaces listed 10 entries against 20 mounted routers, so most of the
    API (availability, info, subdomains, dnssec, delegation, diff, caa,
    posture, confusables, tld, and every bulk/stream route) was undiscoverable
    from the index whose whole job is to advertise it.

    Takes the app explicitly — the caller passes ``request.app`` — rather than
    closing over the module-global ``app``. The two are not always the same
    object: anything that rebuilds the module (``importlib.reload``, which the
    hardening tests do ~30 times) rebinds the global while already-constructed
    clients keep serving the original app, so a module-global lookup would
    describe an app the caller is not talking to. Introspecting the app that
    is actually handling the request is the only answer that is always right.

    Keys match the previous scheme so existing consumers keep working. A
    hardening test asserts every route appears exactly once, so a future route
    whose derived name collides fails loudly instead of silently displacing
    another entry.

    Two sources, because neither alone is complete:

    * ``openapi()["paths"]`` for the documented API routes. Walking
      ``target.routes`` is NOT sufficient — as of FastAPI 0.141 an included
      router stays a lazy ``_IncludedRouter`` wrapper that exposes no ``path``
      and never flattens into ``routes``, so every router-mounted endpoint is
      invisible there. Older FastAPI did flatten, which is why this only shows
      up against a current release. The OpenAPI schema is the public,
      version-stable inventory and is cached on the app after first build.
    * ``target.routes`` entries that expose a plain ``path``, for raw
      Starlette routes the schema omits — today that is the ``/mcp`` ASGI
      mount, plus ``/health`` and ``/metrics``.
    """
    paths: set[str] = set(target.openapi().get("paths", {}))
    paths.update(
        path for route in target.routes if (path := getattr(route, "path", None))
    )
    index: dict[str, str] = {}
    for path in paths:
        if path == "/":
            continue
        index[_endpoint_name(path)] = path
    return dict(sorted(index.items()))


@app.get("/")
async def root(request: Request):
    """Root endpoint with API information."""
    return {
        "name": "Seer API",
        "version": __version__,
        "description": "Domain name helper API",
        "endpoints": _endpoint_index(request.app),
        "docs": "/docs" if DOCS_ENABLED else None,
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
    # env_int, not a bare int(): a non-numeric SEER_PORT should give the same
    # readable RuntimeError the other tunables do (issue #50), not an opaque
    # ValueError traceback out of the entry point.
    port = env_int("SEER_PORT", 8000, min_value=1)
    reload = os.environ.get("SEER_RELOAD", "false").lower() in ("true", "1", "yes")

    uvicorn.run(
        "seer_api.main:app",
        host=host,
        port=port,
        reload=reload,
        # Uvicorn's default (proxy_headers=True, FORWARDED_ALLOW_IPS=127.0.0.1)
        # rewrites scope["client"] from X-Forwarded-For before the app sees
        # the request, bypassing SEER_TRUST_PROXY / SEER_TRUSTED_PROXY_IPS.
        # Keep the socket peer so `limiting.get_client_ip` is the only place
        # XFF is trusted.
        proxy_headers=False,
    )


if __name__ == "__main__":
    run()
