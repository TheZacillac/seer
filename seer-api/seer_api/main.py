"""FastAPI application for Seer domain utilities."""

import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from . import __version__
from .limiting import limiter
from .routers import lookup, whois, rdap, dns, propagation, status

# Rate limiter configuration
# Configure via SEER_RATE_LIMIT env var (default: "30/minute")
rate_limit = os.environ.get("SEER_RATE_LIMIT", "30/minute")
limiter.default_limits = [rate_limit]

app = FastAPI(
    title="Seer API",
    description="Domain name helper API - WHOIS, RDAP, DNS lookups, and propagation checking",
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
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
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


def run():
    """Run the API server."""
    import uvicorn

    uvicorn.run(
        "seer_api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )


if __name__ == "__main__":
    run()
