"""SSRF pre-check for user-supplied connect targets before calling seer.

Only guard hosts that are the *actual outbound connection target*, not hosts
that appear as query parameters. WHOIS/RDAP/propagation/DNS-lookup accept a
domain to *ask about* — the network connection goes to the registry WHOIS
server, the registry RDAP URL, or a (fixed or user-supplied) DNS resolver,
not the queried domain itself. Guarding the queried domain there is both a
no-op (no SSRF vector) and a footgun (rejects legitimate lookups of parked
or unresolvable domains).

Guard:
- the ``status`` and ``ssl`` single-host routes/tools (they HTTP/TLS-connect
  to the target), to answer a reserved IP literal with a clear 400
- ``rdap/ip`` input (reject reserved IP literals as input validation)
- user-supplied DNS nameservers (the resolver we actually send packets to) —
  via :func:`vet_nameserver`, which first extracts the host from the
  nameserver *spec*

This is a pre-check, never the SSRF gate: seer-core resolves, vets and pins
every address itself before connecting (``net::resolve_public_host``,
``DnsResolver::custom_upstream_config``). So the pre-check only refuses an
**IP literal** in a reserved range — the caller already knows that address,
so saying so leaks nothing. A **hostname** is never pre-checked: answering
"resolves to a non-public address" (400) for an internal name and "DNS
resolution failed" (502) for a missing one let any caller probe which
internal names exist. Core refuses such a host itself and reports it the
same way as a host that does not resolve (``ssl``: a TLS failure, ``status``:
a report with generic errors, a nameserver: a DNS failure). Bulk routes skip
the pre-check entirely: core refuses a reserved host per row, which becomes a
failed row instead of failing the whole batch.

:func:`guarded` runs the check in the same ``run_seer`` dispatch as the work
it protects, under the same ``SEER_REQUEST_TIMEOUT``.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable, Iterable
from typing import Any

import seer

from .errors import ServiceUnavailable

logger = logging.getLogger(__name__)


def nameserver_target(spec: str) -> tuple[str, int] | None:
    """``seer.nameserver_target``, failing clearly on bindings that predate it.

    A stale local build (e.g. a dev venv from before the function existed)
    can lack it even though the ``domain-seer`` floor keeps such bindings out
    of normal installs; without this check every nameserver request would
    die on a bare ``AttributeError``. Raises :class:`ServiceUnavailable` (503).
    """
    parse = getattr(seer, "nameserver_target", None)
    if parse is None:
        logger.error(
            "installed domain-seer bindings lack nameserver_target; "
            "rebuild seer-py from the same checkout as seer-api"
        )
        raise ServiceUnavailable("Nameserver validation is unavailable")
    return parse(spec)


def vet_host(host: str, port: int = 443) -> None:
    """Raise ``ValueError`` if ``host`` is an IP literal in a reserved range.

    A hostname passes unchecked; see the module docs for why. The literal is
    recognized here and vetted by ``seer.validate_public_host`` (core's one
    reserved-range policy), which resolves nothing for a literal.
    """
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return
    seer.validate_public_host(host, port)


def vet_nameserver(spec: str) -> None:
    """:func:`vet_host` the address a nameserver spec connects to.

    A user-supplied nameserver is a *spec*, not a hostname: a bare
    IP/hostname with an optional port (UDP, ``9.9.9.9:5353``,
    ``[2606:4700:4700::1111]``), ``tls://host[:port]`` (DoT) or
    ``https://host[:port][/path]`` (DoH). ``seer.nameserver_target`` extracts
    the ``(host, port)`` with seer-core's own ``NameserverSpec::parse``, so the
    check covers exactly the address the resolver would contact.

    A spec the core rejects yields ``None`` and is passed through: the core
    then fails it with its own ``Invalid input`` (ValueError -> 400).
    """
    target = nameserver_target(spec)
    if target is not None:
        vet_host(*target)


def guarded(
    fn: Callable[..., Any],
    *,
    hosts: Iterable[str] = (),
    nameservers: Iterable[str] = (),
) -> Callable[..., Any]:
    """``fn`` preceded by the pre-check of each HTTPS host and nameserver spec
    (IP literals only; see :func:`vet_host`).

    Pass the result to ``run_seer``: check and work then run in one dispatch,
    under one deadline. A refusal raises ``ValueError`` before ``fn`` runs.
    """
    hosts, nameservers = tuple(hosts), tuple(nameservers)

    def call(*args: Any) -> Any:
        for host in hosts:
            vet_host(host, 443)
        for spec in nameservers:
            vet_nameserver(spec)
        return fn(*args)

    return call
