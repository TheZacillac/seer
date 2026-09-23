"""Smart lookup API endpoints."""

from fastapi import APIRouter, Request

import seer
from seer_api._contract import BULK_LIMIT, BulkRequest, Domain
from seer_api._run import run_seer
from seer_api.errors import as_http
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
    return await as_http(run_seer(seer.lookup, domain), "Lookup failed")


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
    return await as_http(
        run_seer(seer.bulk_lookup, body.domains, body.concurrency),
        "Bulk lookup failed",
    )


@router.post("/bulk/stream")
@limiter.limit(BULK_LIMIT)
async def bulk_smart_lookup_stream(request: Request, body: BulkRequest):
    """Stream bulk smart-lookup results as Server-Sent Events.

    Emits `progress`, `item`, and `done` events. Matches the sync /bulk
    semantics — see that handler for request/response body shape.
    """
    return await as_http(
        stream_bulk(seer.bulk_lookup, body.domains, body.concurrency),
        "Bulk lookup stream failed",
    )
