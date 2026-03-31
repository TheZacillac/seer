"""Shared rate limiting configuration."""

from __future__ import annotations

import os

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address


def get_client_ip(request: Request) -> str:
    """Resolve the client IP with optional trusted proxy support."""
    trust_proxy = os.environ.get("SEER_TRUST_PROXY", "").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if trust_proxy:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            # Use the first (leftmost) value — the original client IP.
            # The outermost trusted proxy must strip/overwrite any
            # client-supplied X-Forwarded-For before appending the real IP.
            return forwarded.split(",")[0].strip()
    return get_remote_address(request)


# NOTE: In-memory rate limiting is per-worker. With multiple uvicorn workers,
# the effective rate limit is multiplied by the worker count.
# For multi-worker deployments, set SEER_RATE_LIMIT_STORAGE to a Redis URL:
#   export SEER_RATE_LIMIT_STORAGE="redis://localhost:6379"
_storage_uri = os.environ.get("SEER_RATE_LIMIT_STORAGE", "memory://")
_default_rate_limit = os.environ.get("SEER_RATE_LIMIT", "30/minute")
limiter = Limiter(
    key_func=get_client_ip,
    default_limits=[_default_rate_limit],
    storage_uri=_storage_uri,
)
