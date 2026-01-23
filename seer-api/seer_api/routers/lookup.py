"""Smart lookup API endpoints."""

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


class BulkLookupRequest(BaseModel):
    """Request model for bulk lookup."""

    domains: List[str] = Field(..., max_length=MAX_BULK_DOMAINS)
    concurrency: int = Field(default=10, ge=1, le=MAX_CONCURRENCY)


@router.get("/{domain}")
@limiter.limit("30/minute")
async def smart_lookup(request: Request, domain: str):
    """
    Smart lookup for a domain (tries RDAP first, falls back to WHOIS).

    Args:
        domain: Domain name to look up

    Returns:
        Lookup result with source indicator (rdap or whois) and registration data
    """
    try:
        result = seer.lookup(domain)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/bulk")
@limiter.limit("10/minute")
async def bulk_smart_lookup(request: Request, body: BulkLookupRequest):
    """
    Smart lookup for multiple domains.

    Args:
        body: BulkLookupRequest with list of domains and optional concurrency

    Returns:
        List of lookup results for each domain
    """
    try:
        results = seer.bulk_lookup(body.domains, body.concurrency)
        return results
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
