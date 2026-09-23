"""DNS API endpoints."""

from fastapi import APIRouter, Path, Query, Request

import seer
from seer_api._contract import (
    BULK_LIMIT,
    RECORD_TYPE_MAX_LENGTH,
    RECORD_TYPE_PATTERN,
    BulkRecordRequest,
    Domain,
)
from seer_api._run import run_seer
from seer_api.errors import http_error
from seer_api.limiting import limiter
from seer_api.ssrf import guard_nameserver_async
from seer_api.streaming import stream_bulk

router = APIRouter()


# NOTE: registered before `/{domain}/{record_type}` so `/compare/...` is not
# swallowed by the two-segment record-lookup route.
@router.get("/compare/{domain}")
@limiter.limit("30/minute")
async def dns_compare(
    request: Request,
    domain: Domain,
    server_a: str = Query(..., description="First nameserver (e.g. 8.8.8.8)"),
    server_b: str = Query(..., description="Second nameserver (e.g. 1.1.1.1)"),
    record_type: str = Query(
        "A", max_length=RECORD_TYPE_MAX_LENGTH, pattern=RECORD_TYPE_PATTERN
    ),
):
    """Compare DNS records for a domain across two nameservers."""
    # Both servers are actual connect targets, so guard them. Each is a
    # nameserver spec (UDP / tls:// / https://), not a bare hostname.
    await guard_nameserver_async(server_a)
    await guard_nameserver_async(server_b)
    try:
        return await run_seer(seer.dns_compare, domain, record_type, server_a, server_b)
    except Exception as e:
        raise http_error(e, "DNS comparison failed") from e


@router.get("/{domain}/{record_type}")
@limiter.limit("60/minute")
async def dns_lookup(
    request: Request,
    domain: Domain,
    record_type: str = Path(
        ..., max_length=RECORD_TYPE_MAX_LENGTH, pattern=RECORD_TYPE_PATTERN
    ),
    nameserver: str | None = Query(None, description="Nameserver to query"),
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
    # Guard the nameserver (it's the actual connect target) but NOT the
    # queried domain — the domain is a DNS question, not a destination. The
    # nameserver is a spec (UDP / tls:// / https://), not a bare hostname.
    if nameserver is not None:
        await guard_nameserver_async(nameserver)
    try:
        return await run_seer(seer.dig, domain, record_type, nameserver)
    except Exception as e:
        raise http_error(e, "DNS lookup failed") from e


@router.post("/bulk")
@limiter.limit(BULK_LIMIT)
async def bulk_dns_lookup(request: Request, body: BulkRecordRequest):
    """
    Query DNS records for multiple domains.

    Args:
        body: BulkRecordRequest with list of domains, record type, and concurrency

    Returns:
        List of DNS results for each domain
    """
    try:
        return await run_seer(seer.bulk_dig, body.domains, body.record_type, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk DNS lookup failed") from e


@router.post("/bulk/stream")
@limiter.limit(BULK_LIMIT)
async def bulk_dns_stream(request: Request, body: BulkRecordRequest):
    """Stream bulk DNS queries as Server-Sent Events."""
    try:
        return await stream_bulk(
            seer.bulk_dig, body.domains, body.record_type, body.concurrency
        )
    except Exception as e:
        raise http_error(e, "Bulk DNS stream failed") from e
