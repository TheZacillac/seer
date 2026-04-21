"""SSRF guard for user-supplied host/IP parameters before calling seer.

Every outbound leg that accepts a user-provided host (WHOIS/RDAP/DNS/status
and custom DNS nameservers) must run through this guard so that requests
cannot be weaponized to reach loopback, RFC1918, CGNAT, cloud-metadata, or
link-local addresses.
"""

from __future__ import annotations

import asyncio

from fastapi import HTTPException

import seer


def guard(host: str, port: int = 443) -> None:
    """Raise HTTPException(400) if host resolves to a reserved address.

    Delegates to ``seer.validate_public_host``, which rejects IP literals in
    reserved ranges and hostnames that resolve to such addresses. The raised
    HTTPException carries the underlying validator's message so operators can
    diagnose why a request was rejected without leaking internal details.

    Blocking. The underlying ``seer.validate_public_host`` performs a DNS
    resolution inside a Tokio ``block_on``; calling this directly from an
    ``async def`` FastAPI handler pins the event loop thread. Use
    :func:`guard_async` from async contexts. This sync entry point remains
    for sync callers such as the MCP server.
    """
    try:
        seer.validate_public_host(host, port)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


async def guard_async(host: str, port: int = 443) -> None:
    """Async wrapper around :func:`guard` for use in FastAPI routes.

    Runs the blocking DNS-resolution leg on the default thread pool executor
    so the event loop is free to service other requests while the lookup is
    in flight. Without this, bare ``guard()`` calls serialize concurrent
    requests because the PyO3 ``block_on`` inside ``validate_public_host``
    pins the single event-loop thread.
    """
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, guard, host, port)


async def guard_hosts_async(hosts: list[tuple[str, int]]) -> None:
    """Run :func:`guard_async` against every (host, port) pair.

    Used by bulk endpoints to validate every user-supplied domain before
    dispatching the work to the Rust core. Preserves per-host error
    granularity: the first offending host raises HTTPException(400) and
    the bulk call short-circuits.
    """
    for host, port in hosts:
        await guard_async(host, port)
