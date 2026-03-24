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
            # Use the last (rightmost) value — the one added by the proxy
            # closest to the server — to prevent client spoofing.
            return forwarded.split(",")[-1].strip()
    return get_remote_address(request)


_default_rate_limit = os.environ.get("SEER_RATE_LIMIT", "30/minute")
limiter = Limiter(key_func=get_client_ip, default_limits=[_default_rate_limit])
