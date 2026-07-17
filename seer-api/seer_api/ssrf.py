"""SSRF guard for user-supplied connect targets before calling seer.

Only guard hosts that are the *actual outbound connection target*, not hosts
that appear as query parameters. WHOIS/RDAP/propagation/DNS-lookup accept a
domain to *ask about* — the network connection goes to the registry WHOIS
server, the registry RDAP URL, or a (fixed or user-supplied) DNS resolver,
not the queried domain itself. Guarding the queried domain there is both a
no-op (no SSRF vector) and a footgun (rejects legitimate lookups of parked
or unresolvable domains).

Call the guard on:
- ``status`` endpoints (directly HTTP-connect to the target)
- ``rdap/ip`` input (reject reserved IP literals as input validation)
- user-supplied DNS nameservers (the resolver we actually send packets to)

Do NOT call the guard on the queried domain for WHOIS/RDAP-domain/DNS-lookup
target/propagation target — those paths don't connect to that host.
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
        raise HTTPException(status_code=400, detail=str(exc)) from exc


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
    """Run :func:`guard_async` against every (host, port) pair concurrently.

    Used by bulk endpoints to validate every user-supplied domain before
    dispatching the work to the Rust core. A bulk request can carry up to 100
    hosts; awaiting each guard in sequence would serialize up to 100 blocking
    DNS resolutions before any work starts. ``asyncio.gather`` fans them out
    onto the executor at once.

    Error contract is preserved: ``gather`` re-raises the first exception it
    observes, so an offending host still raises ``HTTPException(400)`` and the
    bulk call short-circuits. (Ordering of *which* offending host is reported
    is no longer strictly first-in-list, but the exception class and status
    code are identical.)
    """
    await asyncio.gather(*(guard_async(host, port) for host, port in hosts))
