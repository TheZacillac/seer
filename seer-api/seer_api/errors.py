"""API error handling utilities.

Three responsibilities:

1. ``clean_message(msg)`` — the one sanitizer for error text put on the wire
   (REST bodies, SSE events, MCP tool results): control/ANSI bytes stripped,
   length capped. It is seer-core's (``_core.py``), re-exported here.

2. ``safe_error_message(exc, fallback)`` — a client-safe message for an
   exception, chosen by exception *type* (never by sniffing message text).

3. ``http_status_for(exc)`` / ``http_error(exc, message)`` — classify the
   exception and pick the HTTP status code: invalid input 400, a rate-limited
   upstream 429, an unsupported TLD 404, upstream failures 502, no free bulk slot 503, timeouts 504.
   Route handlers wrap their core call in ``as_http``, which applies it.
   The statuses for the binding's exceptions are seer-core's table
   (``_core.ERROR_STATUS_TABLE``); only seer-api's own exceptions are
   listed here.

The binding raises builtins for invalid input (``ValueError``), timeouts
(``TimeoutError``) and WHOIS connect failures (``ConnectionError``), and a
``seer.SeerError`` subclass for every other core failure.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable
from typing import TypeVar

from fastapi import HTTPException

import seer

from ._core import CONTRACT, ERROR_STATUS_TABLE, clean_message

T = TypeVar("T")

logger = logging.getLogger("seer_api")

# Maximum characters of error text surfaced to a client (seer-core's cap).
_MAX_MESSAGE_LEN: int = CONTRACT["message_max_length"]


class ServiceUnavailable(Exception):
    """A deployment fault (e.g. stale bindings): HTTP 503 with this message.

    The message is written by seer-api itself and is safe to surface.
    """


class ServerBusy(Exception):
    """Every bulk job slot stayed busy until the request deadline: HTTP 503.

    Nothing was started, so the client can retry. The message is written by
    seer-api itself and is safe to surface.
    """


# (exception type, HTTP status) in match order: the first isinstance wins.
# seer-api's own exceptions, then seer-core's table for everything the
# binding raises (builtins first, `seer.SeerError` — an uncategorized core
# failure — last). Anything matching no row is a 500.
_STATUS_BY_TYPE: tuple[tuple[type[BaseException], int], ...] = (
    (ServiceUnavailable, 503),
    (ServerBusy, 503),
    *ERROR_STATUS_TABLE,
)


def safe_error_message(exc: BaseException, fallback: str = "Request failed") -> str:
    """Return a client-safe message for ``exc``.

    ``ValueError``, ``seer.SeerError``, ``ServiceUnavailable`` and
    ``ServerBusy`` carry text that is safe to show (the caller's own input
    echoed back, core's ``sanitized_message``, or seer-api's own text),
    surfaced through :func:`clean_message`;
    ``TimeoutError`` and ``ConnectionError`` map to canonical strings;
    anything else — an unexpected exception whose text nobody vetted —
    returns ``fallback``.
    """
    if isinstance(exc, ValueError | seer.SeerError | ServiceUnavailable | ServerBusy):
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
    # The text can echo the caller's own input (an invalid domain keeps its
    # percent-decoded newlines), so it is cleaned before it reaches a log
    # line: one record per event, no control bytes.
    text = clean_message(str(exc))
    if status < 500:
        logger.info("API request rejected (%d): %s", status, text)
    elif isinstance(
        exc, TimeoutError | ConnectionError | seer.SeerError | ServiceUnavailable | ServerBusy
    ):
        logger.warning("API request failed (%d): %s", status, text)
    else:
        logger.exception("API request failed: %s", text)
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
