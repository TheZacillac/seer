"""WHOIS API endpoints."""

import asyncio
from typing import Annotated

from fastapi import APIRouter, Path, Request
from pydantic import BaseModel, Field
from seer_api.errors import http_error
from seer_api.limiting import limiter
from seer_api.ssrf import guard as ssrf_guard
from seer_api.streaming import stream_bulk

import seer

router = APIRouter()

# Bulk operation limits
MAX_BULK_DOMAINS = 100
MAX_CONCURRENCY = 50


class BulkWhoisRequest(BaseModel):
    """Request model for bulk WHOIS lookup."""

    domains: list[Annotated[str, Field(max_length=253)]] = Field(..., min_length=1, max_length=MAX_BULK_DOMAINS)
    concurrency: int = Field(default=10, ge=1, le=MAX_CONCURRENCY)


@router.get("/{domain}")
@limiter.limit("30/minute")
async def whois_lookup(
    request: Request,
    domain: str = Path(..., min_length=1, max_length=253),
):
    """
    Look up WHOIS information for a domain.

    Args:
        domain: Domain name to look up

    Returns:
        WHOIS response with registrar, dates, nameservers, and status information
    """
    # WHOIS uses TCP port 43, but the SSRF guard only inspects the host's
    # resolved IPs — the port argument is a nominal hint for lookup_host.
    ssrf_guard(domain, 43)
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, seer.whois, domain)
        return result
    except Exception as e:
        raise http_error(e, "WHOIS lookup failed")


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
    for d in body.domains:
        ssrf_guard(d, 43)
    try:
        loop = asyncio.get_running_loop()
        results = await loop.run_in_executor(
            None, seer.bulk_whois, body.domains, body.concurrency
        )
        return results
    except Exception as e:
        raise http_error(e, "Bulk WHOIS lookup failed")


@router.post("/bulk/stream")
@limiter.limit("10/minute")
async def bulk_whois_stream(request: Request, body: BulkWhoisRequest):
    """Stream bulk WHOIS lookups as Server-Sent Events."""
    for d in body.domains:
        ssrf_guard(d, 43)
    try:
        return await stream_bulk(seer.bulk_whois, body.domains, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk WHOIS stream failed")
