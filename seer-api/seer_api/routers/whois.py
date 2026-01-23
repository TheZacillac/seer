"""WHOIS API endpoints."""

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


class BulkWhoisRequest(BaseModel):
    """Request model for bulk WHOIS lookup."""

    domains: List[str] = Field(..., max_length=MAX_BULK_DOMAINS)
    concurrency: int = Field(default=10, ge=1, le=MAX_CONCURRENCY)


@router.get("/{domain}")
@limiter.limit("30/minute")
async def whois_lookup(request: Request, domain: str):
    """
    Look up WHOIS information for a domain.

    Args:
        domain: Domain name to look up

    Returns:
        WHOIS response with registrar, dates, nameservers, and status information
    """
    try:
        result = seer.whois(domain)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/bulk")
@limiter.limit("10/minute")
async def bulk_whois_lookup(request: Request, body: BulkWhoisRequest):
    """
    Look up WHOIS information for multiple domains.

    Args:
        body: BulkWhoisRequest with list of domains and optional concurrency

    Returns:
        List of WHOIS results for each domain
    """
    try:
        results = seer.bulk_whois(body.domains, body.concurrency)
        return results
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
