"""DNS API endpoints."""

import asyncio
from typing import Annotated, Optional

from fastapi import APIRouter, Path, Query, Request
from pydantic import BaseModel, Field
from seer_api.errors import http_error
from seer_api.limiting import limiter
from seer_api.ssrf import guard_async as ssrf_guard_async
from seer_api.streaming import stream_bulk

import seer

router = APIRouter()

# Bulk operation limits
MAX_BULK_DOMAINS = 100
MAX_CONCURRENCY = 50


class BulkDnsRequest(BaseModel):
    """Request model for bulk DNS lookup."""

    domains: list[Annotated[str, Field(max_length=253)]] = Field(..., min_length=1, max_length=MAX_BULK_DOMAINS)
    record_type: str = Field("A", max_length=10, pattern=r"^[A-Z0-9]+$")
    concurrency: int = Field(default=10, ge=1, le=MAX_CONCURRENCY)


@router.get("/{domain}/{record_type}")
@limiter.limit("60/minute")
async def dns_lookup(
    request: Request,
    domain: str = Path(..., min_length=1, max_length=253),
    record_type: str = Path(..., max_length=10, pattern=r"^[A-Z0-9]+$"),
    nameserver: Optional[str] = Query(None, description="Nameserver to query"),
):
    """
    Query DNS records for a domain.

    Args:
        domain: Domain name to query
        record_type: Record type (A, AAAA, MX, TXT, NS, SOA, CNAME, CAA, etc.)
        nameserver: Optional nameserver to query (e.g., 8.8.8.8)

    Returns:
        List of DNS records
    """
    # A DNS query uses port 53 on the resolver. The domain being queried is
    # not a target of an outbound connection (we look it up via our resolver),
    # but the nameserver param IS — it's where our resolver sends packets.
    # Validate both: the domain in case the resolver chases it, and the
    # nameserver explicitly at port 53.
    await ssrf_guard_async(domain, 53)
    if nameserver is not None:
        await ssrf_guard_async(nameserver, 53)
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None, seer.dig, domain, record_type, nameserver
        )
        return result
    except Exception as e:
        raise http_error(e, "DNS lookup failed")


@router.post("/bulk")
@limiter.limit("10/minute")
async def bulk_dns_lookup(request: Request, body: BulkDnsRequest):
    """
    Query DNS records for multiple domains.

    Args:
        body: BulkDnsRequest with list of domains, record type, and concurrency

    Returns:
        List of DNS results for each domain
    """
    for d in body.domains:
        await ssrf_guard_async(d, 53)
    try:
        loop = asyncio.get_running_loop()
        results = await loop.run_in_executor(
            None, seer.bulk_dig, body.domains, body.record_type, body.concurrency
        )
        return results
    except Exception as e:
        raise http_error(e, "Bulk DNS lookup failed")


@router.post("/bulk/stream")
@limiter.limit("10/minute")
async def bulk_dns_stream(request: Request, body: BulkDnsRequest):
    """Stream bulk DNS queries as Server-Sent Events."""
    for d in body.domains:
        await ssrf_guard_async(d, 53)
    try:
        return await stream_bulk(
            seer.bulk_dig, body.domains, body.record_type, body.concurrency
        )
    except Exception as e:
        raise http_error(e, "Bulk DNS stream failed")
