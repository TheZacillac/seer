"""SSRF guard for user-supplied host/IP parameters before calling seer.

Every outbound leg that accepts a user-provided host (WHOIS/RDAP/DNS/status
and custom DNS nameservers) must run through this guard so that requests
cannot be weaponized to reach loopback, RFC1918, CGNAT, cloud-metadata, or
link-local addresses.
"""

from __future__ import annotations

from fastapi import HTTPException

import seer


def guard(host: str, port: int = 443) -> None:
    """Raise HTTPException(400) if host resolves to a reserved address.

    Delegates to ``seer.validate_public_host``, which rejects IP literals in
    reserved ranges and hostnames that resolve to such addresses. The raised
    HTTPException carries the underlying validator's message so operators can
    diagnose why a request was rejected without leaking internal details.
    """
    try:
        seer.validate_public_host(host, port)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
