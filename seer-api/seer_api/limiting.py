"""Shared rate limiting configuration."""

from __future__ import annotations

import ipaddress
import logging
import os

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

log = logging.getLogger("seer_api")


def _trusted_proxies() -> set[str]:
    """Parse ``SEER_TRUSTED_PROXY_IPS`` into a set of trusted peer IPs.

    Only literal IPv4/IPv6 addresses are accepted — CIDR-style entries
    (`10.0.0.0/8`) silently never match `request.client.host` (always a
    bare IP) and would fail open. Reject them at parse time with a log
    warning rather than silently disabling proxy trust.

    Evaluated on every request (not cached at import time) so that tests
    can set the env var via monkeypatch without reloading the module.
    """
    out: set[str] = set()
    for raw in os.environ.get("SEER_TRUSTED_PROXY_IPS", "").split(","):
        entry = raw.strip()
        if not entry:
            continue
        try:
            ipaddress.ip_address(entry)
        except ValueError:
            log.warning(
                "SEER_TRUSTED_PROXY_IPS entry %r is not a bare IP address; "
                "ignoring (CIDR ranges are not supported)",
                entry,
            )
            continue
        out.add(entry)
    return out


def _proxy_trust_enabled() -> bool:
    return os.environ.get("SEER_TRUST_PROXY", "").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def get_client_ip(request: Request) -> str:
    """Resolve the client IP, trusting ``X-Forwarded-For`` only when
    the socket peer is in the ``SEER_TRUSTED_PROXY_IPS`` allowlist.

    Previously we trusted ``X-Forwarded-For`` whenever
    ``SEER_TRUST_PROXY=true``, which meant any client hitting the API
    directly could spoof their IP with a forged header and bypass the
    per-IP rate limit. Now the header is only honored when the socket
    peer itself is a known reverse proxy. Without that pin, any remote
    request gets attributed to its real ``request.client.host``.
    """
    peer = request.client.host if request.client else ""
    if _proxy_trust_enabled():
        trusted = _trusted_proxies()
        if peer and peer in trusted:
            forwarded = request.headers.get("x-forwarded-for", "")
            if forwarded:
                # Standard reverse proxies (e.g. nginx
                # `$proxy_add_x_forwarded_for`) APPEND the real client IP to
                # any existing X-Forwarded-For, so the LEFTMOST entry is
                # client-supplied and spoofable. Walk the list from the
                # RIGHT, skipping entries that are themselves trusted
                # proxies, and return the first untrusted entry — the real
                # client as seen by the innermost proxy we trust. If every
                # entry is a trusted proxy or the header is malformed, fall
                # back to the direct socket peer.
                for raw in reversed(forwarded.split(",")):
                    entry = raw.strip()
                    if not entry or entry in trusted:
                        continue
                    return entry
        # Either no allowlist set or the peer is not in it: ignore XFF.
    return get_remote_address(request) if not peer else peer


# NOTE: In-memory rate limiting is per-worker. With multiple uvicorn workers,
# the effective rate limit is multiplied by the worker count. The application
# lifespan refuses to start with WEB_CONCURRENCY>1 and the default memory://
# store; for multi-worker deployments set SEER_RATE_LIMIT_STORAGE to a Redis URL:
#   export SEER_RATE_LIMIT_STORAGE="redis://localhost:6379"
_storage_uri = os.environ.get("SEER_RATE_LIMIT_STORAGE", "memory://")
_default_rate_limit = os.environ.get("SEER_RATE_LIMIT", "30/minute")
limiter = Limiter(
    key_func=get_client_ip,
    default_limits=[_default_rate_limit],
    storage_uri=_storage_uri,
)
