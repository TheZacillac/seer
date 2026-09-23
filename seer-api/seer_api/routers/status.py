"""Domain status API endpoints."""

from fastapi import APIRouter, Request

import seer
from seer_api._contract import HEAVY_LIMIT, BulkRequest, Domain
from seer_api._run import run_seer
from seer_api.errors import as_http
from seer_api.limiting import limiter
from seer_api.ssrf import guard_async as ssrf_guard_async
from seer_api.ssrf import guard_hosts_async
from seer_api.streaming import stream_bulk

router = APIRouter()


@router.get("/{domain}")
@limiter.limit("20/minute")
async def check_status(request: Request, domain: Domain):
    """
    Check the status of a domain.

    Returns HTTP status, site title, SSL certificate info, and domain expiration.

    Args:
        domain: Domain name to check

    Returns:
        Status information including:
        - HTTP status code and text
        - Site title (from HTML)
        - SSL certificate details (issuer, validity, days until expiry)
        - Domain registration expiration (days until expiry, registrar)
    """
    await ssrf_guard_async(domain, 443)
    return await as_http(run_seer(seer.status, domain), "Status check failed")


@router.post("/bulk")
@limiter.limit(HEAVY_LIMIT)
async def bulk_status(request: Request, body: BulkRequest):
    """
    Check status for multiple domains.

    Args:
        body: BulkRequest with list of domains and optional concurrency

    Returns:
        List of status results for each domain
    """
    await guard_hosts_async([(d, 443) for d in body.domains])
    return await as_http(
        run_seer(seer.bulk_status, body.domains, body.concurrency),
        "Bulk status check failed",
    )


@router.post("/bulk/stream")
@limiter.limit(HEAVY_LIMIT)
async def bulk_status_stream(request: Request, body: BulkRequest):
    """Stream bulk status checks as Server-Sent Events."""
    await guard_hosts_async([(d, 443) for d in body.domains])
    return await as_http(
        stream_bulk(seer.bulk_status, body.domains, body.concurrency),
        "Bulk status stream failed",
    )
