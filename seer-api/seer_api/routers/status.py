"""Domain status API endpoints."""

from typing import List

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address

import seer

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

# Bulk operation limits
MAX_BULK_DOMAINS = 100
MAX_CONCURRENCY = 50


class BulkStatusRequest(BaseModel):
    """Request model for bulk status check."""

    domains: List[str] = Field(..., max_length=MAX_BULK_DOMAINS)
    concurrency: int = Field(default=10, ge=1, le=MAX_CONCURRENCY)


@router.get("/{domain}")
@limiter.limit("20/minute")
async def check_status(request: Request, domain: str):
    """
    Check the status of a domain.

    Returns HTTP status, site title, SSL certificate info, and domain expiration.

    Args:
        domain: Domain name to check

    Returns:
        Status information including:
        - HTTP status code and text
        - Site title (from HTML)
        - SSL certificate details (issuer, validity, days until expiry)
        - Domain registration expiration (days until expiry, registrar)
    """
    try:
        result = seer.status(domain)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/bulk")
@limiter.limit("5/minute")
async def bulk_status(request: Request, body: BulkStatusRequest):
    """
    Check status for multiple domains.

    Args:
        body: BulkStatusRequest with list of domains and optional concurrency

    Returns:
        List of status results for each domain
    """
    try:
        results = seer.bulk_status(body.domains, body.concurrency)
        return results
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
