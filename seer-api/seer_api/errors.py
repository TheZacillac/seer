"""API error handling utilities."""

from __future__ import annotations

import logging

from fastapi import HTTPException

logger = logging.getLogger("seer_api")


def http_error(exc: Exception, message: str = "Request failed") -> HTTPException:
    """Log internal errors and return a sanitized HTTPException.

    Returns 400 for client errors (ValueError) and 502 for upstream/server failures.
    """
    logger.exception("API request failed: %s", exc)
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=message)
    return HTTPException(status_code=502, detail=message)
