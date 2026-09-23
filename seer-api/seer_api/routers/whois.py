"""WHOIS API endpoints."""

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
async def whois_lookup(request: Request, domain: Domain):
    """
    Look up WHOIS information for a domain.

    Args:
        domain: Domain name to look up

    Returns:
        WHOIS response with registrar, dates, nameservers, and status information
    """
    try:
        return await run_seer(seer.whois, domain)
    except Exception as e:
        raise http_error(e, "WHOIS lookup failed") from e


@router.post("/bulk")
@limiter.limit(BULK_LIMIT)
async def bulk_whois_lookup(request: Request, body: BulkRequest):
    """
    Look up WHOIS information for multiple domains.

    Args:
        body: BulkRequest with list of domains and optional concurrency

    Returns:
        List of WHOIS results for each domain
    """
    try:
        return await run_seer(seer.bulk_whois, body.domains, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk WHOIS lookup failed") from e


@router.post("/bulk/stream")
@limiter.limit(BULK_LIMIT)
async def bulk_whois_stream(request: Request, body: BulkRequest):
    """Stream bulk WHOIS lookups as Server-Sent Events."""
    try:
        return await stream_bulk(seer.bulk_whois, body.domains, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk WHOIS stream failed") from e
