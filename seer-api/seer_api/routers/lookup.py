"""Smart lookup API endpoints."""

import asyncio
from typing import Annotated

from fastapi import APIRouter, Path, Request
from pydantic import BaseModel, Field
from seer_api.errors import http_error
from seer_api.limiting import limiter

import seer

router = APIRouter()

# Bulk operation limits
MAX_BULK_DOMAINS = 100
MAX_CONCURRENCY = 50


class BulkLookupRequest(BaseModel):
    """Request model for bulk lookup."""

    domains: list[Annotated[str, Field(max_length=253)]] = Field(..., min_length=1, max_length=MAX_BULK_DOMAINS)
    concurrency: int = Field(default=10, ge=1, le=MAX_CONCURRENCY)


@router.get("/{domain}")
@limiter.limit("30/minute")
async def smart_lookup(
    request: Request,
    domain: str = Path(..., min_length=1, max_length=253),
):
    """
    Smart lookup for a domain (tries RDAP first, falls back to WHOIS).

    Args:
        domain: Domain name to look up

    Returns:
        Lookup result with source indicator (rdap or whois) and registration data
    """
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, seer.lookup, domain)
        return result
    except Exception as e:
        raise http_error(e, "Lookup failed")


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
        loop = asyncio.get_running_loop()
        results = await loop.run_in_executor(
            None, seer.bulk_lookup, body.domains, body.concurrency
        )
        return results
    except Exception as e:
        raise http_error(e, "Bulk lookup failed")
