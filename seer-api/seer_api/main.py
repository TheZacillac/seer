"""FastAPI application for Seer domain utilities."""

import hmac
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from . import __version__
from .limiting import get_client_ip, limiter
from .middleware import RequestLoggingMiddleware, metrics
from .routers import lookup, whois, rdap, dns, propagation, status

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
API_KEY = os.environ.get("SEER_API_KEY")
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
    # proxy. Hard-fail rather than warn.
    host = os.environ.get("SEER_HOST", "127.0.0.1")
    if host != "127.0.0.1" and not API_KEY:
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
)

# Add rate limiter to app state and exception handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware - configure allowed origins via SEER_CORS_ORIGINS env var
# For production, set SEER_CORS_ORIGINS to comma-separated list of allowed origins
# e.g., SEER_CORS_ORIGINS="https://example.com,https://app.example.com"
cors_origins_env = os.environ.get("SEER_CORS_ORIGINS", "")
if cors_origins_env:
    allowed_origins = [origin.strip() for origin in cors_origins_env.split(",")]
    allow_credentials = True
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

# Add request logging middleware
app.add_middleware(RequestLoggingMiddleware)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Enforce optional bearer-token auth when SEER_API_KEY is set."""
    if API_KEY:
        # Skip CORS preflight (OPTIONS) and public endpoints. The auth
        # middleware runs outermost (wrapping CORSMiddleware), so rejecting
        # OPTIONS here would strip CORS headers and break browser clients.
        if request.method == "OPTIONS" or request.url.path in _AUTH_EXEMPT_PATHS:
            return await call_next(request)
        provided = request.headers.get("Authorization", "")
        expected = f"Bearer {API_KEY}"
        if not hmac.compare_digest(provided, expected):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return await call_next(request)

# Include routers
app.include_router(lookup.router, prefix="/lookup", tags=["Lookup"])
app.include_router(whois.router, prefix="/whois", tags=["WHOIS"])
app.include_router(rdap.router, prefix="/rdap", tags=["RDAP"])
app.include_router(dns.router, prefix="/dns", tags=["DNS"])
app.include_router(propagation.router, prefix="/propagation", tags=["Propagation"])
app.include_router(status.router, prefix="/status", tags=["Status"])


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
        },
        "docs": "/docs",
    }


@app.get("/health")
@limiter.exempt
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/metrics")
@limiter.exempt
async def get_metrics(request: Request):
    """Request metrics endpoint for observability.

    Restricted to localhost when SEER_METRICS_ENABLED is not set.
    """
    metrics_enabled = os.environ.get("SEER_METRICS_ENABLED", "").lower() in ("1", "true", "yes")
    if not metrics_enabled:
        # Use the same proxy-aware client-IP resolution as the rate limiter,
        # so deployments behind a reverse proxy with SEER_TRUST_PROXY=true
        # see the real client IP instead of 127.0.0.1.
        client_host = get_client_ip(request)
        if client_host not in ("127.0.0.1", "::1", "localhost"):
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
