"""DNS API endpoints."""

import asyncio
from typing import Annotated, Optional

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field
from seer_api.errors import http_error
from seer_api.limiting import limiter

import seer

router = APIRouter()

# Bulk operation limits
MAX_BULK_DOMAINS = 100
MAX_CONCURRENCY = 50


class BulkDnsRequest(BaseModel):
    """Request model for bulk DNS lookup."""

    domains: list[Annotated[str, Field(max_length=253)]] = Field(..., min_length=1, max_length=MAX_BULK_DOMAINS)
    record_type: str = "A"
    concurrency: int = Field(default=10, ge=1, le=MAX_CONCURRENCY)


@router.get("/{domain}/{record_type}")
@limiter.limit("60/minute")
async def dns_lookup(
    request: Request,
    domain: str,
    record_type: str,
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
    try:
        loop = asyncio.get_running_loop()
        results = await loop.run_in_executor(
            None, seer.bulk_dig, body.domains, body.record_type, body.concurrency
        )
        return results
    except Exception as e:
        raise http_error(e, "Bulk DNS lookup failed")
