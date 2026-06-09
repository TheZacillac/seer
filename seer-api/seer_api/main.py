"""FastAPI application for Seer domain utilities."""

import hmac
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, ORJSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from . import __version__
from .limiting import limiter
from .middleware import MaxBodySizeMiddleware, RequestLoggingMiddleware, metrics
from .routers import lookup, whois, rdap, dns, propagation, status, ssl

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
    workers = int(
        os.environ.get("WEB_CONCURRENCY", os.environ.get("UVICORN_WORKERS", "1"))
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
    yield


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

# Add request logging middleware
app.add_middleware(RequestLoggingMiddleware)

# Body size cap — reject oversized payloads with 413 before they hit
# any router. Default 64KB is generous for a 100-domain bulk request
# (see middleware.DEFAULT_MAX_BODY_BYTES). M6.
app.add_middleware(MaxBodySizeMiddleware, max_bytes=64 * 1024)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Enforce optional bearer-token auth when SEER_API_KEY is set.

    Reads `SEER_API_KEY` per request rather than from a module-level
    constant, so tests and rotating-secret deployments don't need an import
    reload to pick up the current key.
    """
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
