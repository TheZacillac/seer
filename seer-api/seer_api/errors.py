"""API error handling utilities.

Three responsibilities:

1. ``clean_message(msg)`` — the one sanitizer for error text put on the wire
   (REST bodies, SSE events, MCP tool results): control/ANSI bytes stripped,
   length capped.

2. ``safe_error_message(exc, fallback)`` — a client-safe message for an
   exception, chosen by exception *type* (never by sniffing message text).

3. ``http_status_for(exc)`` / ``http_error(exc, message)`` — classify the
   exception and pick the HTTP status code: invalid input 400, a rate-limited
   upstream 429, an unsupported TLD 404, upstream failures 502, timeouts 504.
   Route handlers wrap their core call in ``as_http``, which applies it.

The binding raises builtins for invalid input (``ValueError``), timeouts
(``TimeoutError``) and WHOIS connect failures (``ConnectionError``), and a
``seer.SeerError`` subclass for every other core failure.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Awaitable
from typing import TypeVar

from fastapi import HTTPException

import seer

T = TypeVar("T")

logger = logging.getLogger("seer_api")

# Maximum characters of error text surfaced to a client. The Rust core's
# ``sanitized_message`` is already conservative, but we cap the length here
# as defense-in-depth against a hypothetical verbose error.
_MAX_MESSAGE_LEN = 200

# C0/C1 control characters (incl. CR/LF and the ESC that begins an ANSI
# escape sequence). Mirrors the CR/LF stripping done for the correlation id
# in middleware.py — a future verbose core error could carry ANSI colour
# codes or an embedded NUL that must never land in a REST body or SSE event.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class ServiceUnavailable(Exception):
    """A deployment fault (e.g. stale bindings): HTTP 503 with this message.

    The message is written by seer-api itself and is safe to surface.
    """


def clean_message(msg: str) -> str:
    """Strip control/ANSI bytes from ``msg``, then cap its length.

    Stripping happens *before* the length cap so that a message padded with
    control bytes cannot push its visible content past the cap.
    """
    return _CONTROL_CHARS_RE.sub("", msg)[:_MAX_MESSAGE_LEN]


# (exception type, HTTP status) in match order: the first isinstance wins.
# The builtins come first; a `seer.SeerError` subclass not listed (the base
# itself: an uncategorized core failure, or a config error) is a 500.
_STATUS_BY_TYPE: tuple[tuple[type[BaseException], int], ...] = (
    (ValueError, 400),
    (TimeoutError, 504),
    (ConnectionError, 502),
    (ServiceUnavailable, 503),
    (seer.RateLimitedError, 429),
    (seer.WhoisServerNotFoundError, 404),
    (seer.DnsError, 502),
    (seer.UpstreamError, 502),
    (seer.LookupFailedError, 502),
    (seer.ParseError, 502),
    (seer.TlsError, 502),
)


def safe_error_message(exc: BaseException, fallback: str = "Request failed") -> str:
    """Return a client-safe message for ``exc``.

    ``ValueError``, ``seer.SeerError`` and ``ServiceUnavailable`` carry text
    that is safe to show (the caller's own input echoed back, or core's
    ``sanitized_message``), surfaced through :func:`clean_message`;
    ``TimeoutError`` and ``ConnectionError`` map to canonical strings;
    anything else — an unexpected exception whose text nobody vetted —
    returns ``fallback``.
    """
    if isinstance(exc, ValueError | seer.SeerError | ServiceUnavailable):
        return clean_message(str(exc))
    if isinstance(exc, TimeoutError):
        return "request timed out"
    if isinstance(exc, ConnectionError):
        return "upstream connection failed"
    return fallback


def http_status_for(exc: BaseException) -> int:
    """Pick an HTTP status code for ``exc`` (see ``_STATUS_BY_TYPE``); 500
    for anything unclassified."""
    for exc_type, status in _STATUS_BY_TYPE:
        if isinstance(exc, exc_type):
            return status
    return 500


def http_error(exc: Exception, message: str = "Request failed") -> HTTPException:
    """Log ``exc`` internally and return a sanitized HTTPException.

    A client-caused 4xx is logged at info, a classified upstream/deployment
    failure at warning, both without a traceback; only an unexpected
    exception (an unclassified 500) is logged with its traceback.
    """
    status = http_status_for(exc)
    if status < 500:
        logger.info("API request rejected (%d): %s", status, exc)
    elif isinstance(exc, TimeoutError | ConnectionError | seer.SeerError | ServiceUnavailable):
        logger.warning("API request failed (%d): %s", status, exc)
    else:
        logger.exception("API request failed: %s", exc)
    return HTTPException(status_code=status, detail=safe_error_message(exc, message))


async def as_http(call: Awaitable[T], message: str) -> T:
    """Await a handler's core call, re-raising any failure via :func:`http_error`.

    Pass the un-awaited ``run_seer(...)`` / ``stream_bulk(...)`` coroutine.
    An SSRF refusal inside it (``ssrf.guarded``) is a ``ValueError`` and so
    a 400 like any other invalid input.
    """
    try:
        return await call
    except Exception as e:
        raise http_error(e, message) from e
