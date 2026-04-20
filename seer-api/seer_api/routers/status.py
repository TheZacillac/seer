"""Domain status API endpoints."""

import asyncio
from typing import Annotated

from fastapi import APIRouter, Path, Request
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


class BulkStatusRequest(BaseModel):
    """Request model for bulk status check."""

    domains: list[Annotated[str, Field(max_length=253)]] = Field(..., min_length=1, max_length=MAX_BULK_DOMAINS)
    concurrency: int = Field(default=10, ge=1, le=MAX_CONCURRENCY)


@router.get("/{domain}")
@limiter.limit("20/minute")
async def check_status(
    request: Request,
    domain: str = Path(..., min_length=1, max_length=253),
):
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
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, seer.status, domain)
        return result
    except Exception as e:
        raise http_error(e, "Status check failed")


@router.post("/bulk")
@limiter.limit("5/minute")
async def bulk_status(request: Request, body: BulkStatusRequest):
    """
    Check status for multiple domains.

    Args:
        body: BulkStatusRequest with list of domains and optional concurrency

    Returns:
        List of status results for each domain
    """
    for d in body.domains:
        await ssrf_guard_async(d, 443)
    try:
        loop = asyncio.get_running_loop()
        results = await loop.run_in_executor(
            None, seer.bulk_status, body.domains, body.concurrency
        )
        return results
    except Exception as e:
        raise http_error(e, "Bulk status check failed")


@router.post("/bulk/stream")
@limiter.limit("5/minute")
async def bulk_status_stream(request: Request, body: BulkStatusRequest):
    """Stream bulk status checks as Server-Sent Events."""
    for d in body.domains:
        await ssrf_guard_async(d, 443)
    try:
        return await stream_bulk(seer.bulk_status, body.domains, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk status stream failed")
