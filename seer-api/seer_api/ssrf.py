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
- user-supplied DNS nameservers (the resolver we actually send packets to) —
  via :func:`guard_nameserver_async`, which first extracts the host from the
  nameserver *spec* (see :func:`nameserver_target`)

Do NOT call the guard on the queried domain for WHOIS/RDAP-domain/DNS-lookup
target/propagation target — those paths don't connect to that host.
"""

from __future__ import annotations

import asyncio
import ipaddress

from fastapi import HTTPException

import seer

# Default ports per nameserver transport — mirror seer-core's NameserverSpec.
_NS_UDP_PORT = 53
_NS_TLS_PORT = 853
_NS_HTTPS_PORT = 443


def _parse_ns_port(value: str) -> int | None:
    if not value.isascii() or not value.isdigit():
        return None
    port = int(value)
    return port if 0 < port <= 65535 else None


def _split_ns_host_port(authority: str, default_port: int) -> tuple[str, int] | None:
    if not authority:
        return None
    # Bracketed IPv6: [addr] or [addr]:port
    if authority.startswith("["):
        addr, closed, after = authority[1:].partition("]")
        if not closed:
            return None
        try:
            ipaddress.IPv6Address(addr)
        except ValueError:
            return None
        if not after:
            return addr, default_port
        if not after.startswith(":"):
            return None
        port = _parse_ns_port(after[1:])
        return (addr, port) if port else None
    # A full IP literal (IPv4, or unbracketed IPv6) never carries a port.
    try:
        ipaddress.ip_address(authority)
        return authority, default_port
    except ValueError:
        pass
    host, sep, port_str = authority.rpartition(":")
    if sep:
        if not host or ":" in host:
            return None
        port = _parse_ns_port(port_str)
        return (host, port) if port else None
    return authority, default_port


def nameserver_target(spec: str) -> tuple[str, int] | None:
    """The ``(host, port)`` a nameserver spec makes the core resolver contact.

    A user-supplied nameserver is a *spec*, not a hostname: seer-core accepts a
    bare IP/hostname with an optional port (UDP, ``9.9.9.9:5353``,
    ``[2606:4700:4700::1111]``), ``tls://host[:port]`` (DoT) and
    ``https://host[:port][/path]`` (DoH). Guarding the raw string as a
    hostname rejected every form but the bare one. This mirrors the host/port
    extraction of seer-core's ``NameserverSpec::parse`` so the guard checks
    the address actually connected to.

    Returns ``None`` for a spec the core parser would reject: the caller then
    leaves it to the core, which fails it with its own ``Invalid input``
    (ValueError → 400). The core also refuses reserved nameserver addresses on
    its own, so this pre-check is defense in depth that turns a reserved
    target into a clear 400 — never the only SSRF gate.
    """
    s = spec.strip()
    if not s or any(c.isspace() or c < " " or "\x7f" <= c <= "\x9f" for c in s):
        return None
    scheme, sep, rest = s.partition("://")
    if not sep:
        return _split_ns_host_port(s, _NS_UDP_PORT)
    scheme = scheme.lower()
    if scheme == "tls":
        if "/" in rest:
            return None
        return _split_ns_host_port(rest, _NS_TLS_PORT)
    if scheme == "https":
        authority = rest.split("/", 1)[0]
        if "@" in authority:
            return None
        return _split_ns_host_port(authority, _NS_HTTPS_PORT)
    return None


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


async def guard_nameserver_async(spec: str) -> None:
    """:func:`guard_async` the host a nameserver spec connects to.

    See :func:`nameserver_target`: a malformed spec is passed through for the
    core to reject rather than guessed at here.
    """
    target = nameserver_target(spec)
    if target is not None:
        await guard_async(*target)


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
