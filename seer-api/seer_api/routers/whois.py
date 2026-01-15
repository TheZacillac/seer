"""WHOIS API endpoints."""

from typing import List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

import seer

router = APIRouter()

# Bulk operation limits
MAX_BULK_DOMAINS = 100
MAX_CONCURRENCY = 50


class BulkWhoisRequest(BaseModel):
    """Request model for bulk WHOIS lookup."""

    domains: List[str] = Field(..., max_length=MAX_BULK_DOMAINS)
    concurrency: int = Field(default=10, ge=1, le=MAX_CONCURRENCY)


@router.get("/{domain}")
async def whois_lookup(domain: str):
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
async def bulk_whois_lookup(request: BulkWhoisRequest):
    """
    Look up WHOIS information for multiple domains.

    Args:
        request: BulkWhoisRequest with list of domains and optional concurrency

    Returns:
        List of WHOIS results for each domain
    """
    try:
        results = seer.bulk_whois(request.domains, request.concurrency)
        return results
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
