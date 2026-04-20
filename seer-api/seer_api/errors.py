"""API error handling utilities.

Two responsibilities:

1. ``safe_error_message(exc, fallback)`` — strip implementation detail
   from an exception before putting it on the wire. Matches on exception
   *type* (not substrings of the message string), so a ``TimeoutError``
   surfaces uniformly even if its message differs by underlying library.

2. ``http_status_for(exc)`` / ``http_error(exc, message)`` — classify
   the exception and pick the right HTTP status code. Callers that
   previously hardcoded 500 should use ``http_error`` so upstream
   transients (timeout, connection) surface as 504/502 rather than 500.
"""

from __future__ import annotations

import logging

from fastapi import HTTPException

logger = logging.getLogger("seer_api")

# Maximum characters to surface from a ValueError's message. The Rust
# core's ``sanitized_message`` is already conservative, but we cap the
# length here as defense-in-depth against a hypothetical verbose
# validation error.
_MAX_VALUE_ERROR_LEN = 200


def safe_error_message(exc: BaseException, fallback: str = "Request failed") -> str:
    """Return a client-safe message for ``exc``.

    Rather than matching on substrings of ``str(exc)`` (which is fragile
    and can leak implementation detail when the message contains known
    keywords as incidental text), this inspects the exception *type*.
    ``ValueError`` is trusted as a validation error and surfaces directly
    (capped to 200 chars); ``TimeoutError`` and ``ConnectionError`` are
    mapped to canonical strings; anything else returns ``fallback``.
    """
    if isinstance(exc, ValueError):
        return str(exc)[:_MAX_VALUE_ERROR_LEN]
    if isinstance(exc, TimeoutError):
        return "request timed out"
    if isinstance(exc, ConnectionError):
        return "upstream connection failed"
    return fallback


def http_status_for(exc: BaseException) -> int:
    """Pick an HTTP status code for ``exc``.

    ``ValueError`` -> 400 (client error, invalid input).
    ``TimeoutError`` -> 504 (gateway timeout).
    ``ConnectionError`` -> 502 (upstream unreachable).
    Everything else -> 500.
    """
    if isinstance(exc, ValueError):
        return 400
    if isinstance(exc, TimeoutError):
        return 504
    if isinstance(exc, ConnectionError):
        return 502
    return 500


def http_error(exc: Exception, message: str = "Request failed") -> HTTPException:
    """Log ``exc`` internally and return a sanitized HTTPException."""
    logger.exception("API request failed: %s", exc)
    return HTTPException(
        status_code=http_status_for(exc),
        detail=safe_error_message(exc, message),
    )
