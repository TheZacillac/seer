"""DNS API endpoints."""

from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

import seer

router = APIRouter()

# Bulk operation limits
MAX_BULK_DOMAINS = 100
MAX_CONCURRENCY = 50


class BulkDnsRequest(BaseModel):
    """Request model for bulk DNS lookup."""

    domains: List[str] = Field(..., max_length=MAX_BULK_DOMAINS)
    record_type: str = "A"
    concurrency: int = Field(default=10, ge=1, le=MAX_CONCURRENCY)


@router.get("/{domain}/{record_type}")
async def dns_lookup(
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
        result = seer.dig(domain, record_type, nameserver)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/bulk")
async def bulk_dns_lookup(request: BulkDnsRequest):
    """
    Query DNS records for multiple domains.

    Args:
        request: BulkDnsRequest with list of domains, record type, and concurrency

    Returns:
        List of DNS results for each domain
    """
    try:
        results = seer.bulk_dig(request.domains, request.record_type, request.concurrency)
        return results
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
