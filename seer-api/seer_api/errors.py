"""API error handling utilities."""

from __future__ import annotations

import logging

from fastapi import HTTPException

logger = logging.getLogger("seer_api")


def http_error(exc: Exception, message: str = "Request failed") -> HTTPException:
    """Log internal errors and return a sanitized HTTPException."""
    logger.exception("API request failed: %s", exc)
    return HTTPException(status_code=400, detail=message)
