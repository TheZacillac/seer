"""Smart lookup API endpoints."""

from fastapi import APIRouter, Request

import seer
from seer_api._contract import BULK_LIMIT, BulkRequest, Domain
from seer_api._run import run_seer
from seer_api.errors import http_error
from seer_api.limiting import limiter
from seer_api.streaming import stream_bulk

router = APIRouter()


@router.get("/{domain}")
@limiter.limit("30/minute")
async def smart_lookup(request: Request, domain: Domain):
    """
    Smart lookup for a domain (tries RDAP first, falls back to WHOIS).

    Args:
        domain: Domain name to look up

    Returns:
        Lookup result with source indicator (rdap or whois) and registration data
    """
    try:
        return await run_seer(seer.lookup, domain)
    except Exception as e:
        raise http_error(e, "Lookup failed") from e


@router.post("/bulk")
@limiter.limit(BULK_LIMIT)
async def bulk_smart_lookup(request: Request, body: BulkRequest):
    """
    Smart lookup for multiple domains.

    Args:
        body: BulkRequest with list of domains and optional concurrency

    Returns:
        List of lookup results for each domain
    """
    try:
        return await run_seer(seer.bulk_lookup, body.domains, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk lookup failed") from e


@router.post("/bulk/stream")
@limiter.limit(BULK_LIMIT)
async def bulk_smart_lookup_stream(request: Request, body: BulkRequest):
    """Stream bulk smart-lookup results as Server-Sent Events.

    Emits `progress`, `item`, and `done` events. Matches the sync /bulk
    semantics — see that handler for request/response body shape.
    """
    try:
        return await stream_bulk(seer.bulk_lookup, body.domains, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk lookup stream failed") from e
