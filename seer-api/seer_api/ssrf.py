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
  to the target), to answer a reserved target with a clear 400
- ``rdap/ip`` input (reject reserved IP literals as input validation)
- user-supplied DNS nameservers (the resolver we actually send packets to) —
  via :func:`vet_nameserver`, which first extracts the host from the
  nameserver *spec*

This is a pre-check, never the SSRF gate: seer-core resolves, vets and pins
every address itself before connecting (``net::resolve_public_host``,
``DnsResolver::custom_upstream_config``). So only a *refusal* — the target is
or resolves to a reserved address — blocks the request here. Any other
failure of the check (the name does not resolve, the lookup timed out) falls
through to core, which reports its own error. Bulk routes skip the pre-check
entirely: core refuses a reserved host per row, which becomes a failed row
instead of failing the whole batch.

The checks resolve DNS inside PyO3, so they are blocking: :func:`guarded`
runs them in the same ``run_seer`` dispatch as the work they protect, under
the same ``SEER_REQUEST_TIMEOUT``.
"""

from __future__ import annotations

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
    """Raise ``ValueError`` if ``host`` is, or resolves to, a reserved address.

    ``seer.validate_public_host`` raises ``ValueError`` (core's
    ``InvalidInput``) only for that refusal; its other failures (DNS error,
    timeout) are logged and swallowed — see the module docs. Blocking.
    """
    try:
        seer.validate_public_host(host, port)
    except ValueError:
        raise
    except (RuntimeError, OSError) as exc:  # seer.SeerError, TimeoutError, ...
        logger.debug("SSRF pre-check inconclusive for %s:%d (%s); core re-vets", host, port, exc)


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
    """``fn`` preceded by the pre-check of each HTTPS host and nameserver spec.

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
