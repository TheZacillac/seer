"""Smart lookup API endpoints."""

from typing import Annotated

from fastapi import APIRouter, Path, Request
from pydantic import BaseModel, Field

import seer
from seer_api._run import run_seer
from seer_api.errors import http_error
from seer_api.limiting import limiter
from seer_api.ssrf import guard_async as ssrf_guard_async
from seer_api.ssrf import guard_hosts_async
from seer_api.streaming import stream_bulk

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
    await ssrf_guard_async(domain, 443)
    try:
        return await run_seer(seer.lookup, domain)
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
    await guard_hosts_async([(d, 443) for d in body.domains])
    try:
        return await run_seer(seer.bulk_lookup, body.domains, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk lookup failed")


@router.post("/bulk/stream")
@limiter.limit("10/minute")
async def bulk_smart_lookup_stream(request: Request, body: BulkLookupRequest):
    """Stream bulk smart-lookup results as Server-Sent Events.

    Emits `progress`, `item`, and `done` events. Matches the sync /bulk
    semantics — see that handler for request/response body shape.
    """
    await guard_hosts_async([(d, 443) for d in body.domains])
    try:
        return await stream_bulk(seer.bulk_lookup, body.domains, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk lookup stream failed")
