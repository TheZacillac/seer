"""API error handling utilities."""

from __future__ import annotations

import logging

from fastapi import HTTPException

logger = logging.getLogger("seer_api")


def safe_error_message(exc: Exception, fallback: str = "Operation failed") -> str:
    """Return a safe error message for API consumers, hiding internal details."""
    msg = str(exc)
    # Map known error patterns to safe messages
    if "WHOIS" in msg:
        return "WHOIS lookup failed"
    if "RDAP" in msg:
        return "RDAP lookup failed"
    if "DNS" in msg:
        return "DNS resolution failed"
    if "timed out" in msg.lower() or "timeout" in msg.lower():
        return "Operation timed out"
    if "Invalid domain" in msg or "invalid domain" in msg:
        return "Invalid domain name"
    if "rate limit" in msg.lower():
        return "Rate limited — please try again later"
    return fallback


def http_error(exc: Exception, message: str = "Request failed") -> HTTPException:
    """Log internal errors and return a sanitized HTTPException.

    Returns 400 for client errors (ValueError), 502 for upstream/runtime failures,
    and 500 for unexpected internal errors.
    """
    logger.exception("API request failed: %s", exc)
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=safe_error_message(exc, message))
    if isinstance(exc, (RuntimeError, ConnectionError, TimeoutError, OSError)):
        return HTTPException(status_code=502, detail=safe_error_message(exc, message))
    return HTTPException(status_code=500, detail=message)
