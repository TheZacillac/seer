"""DNS Propagation API endpoints."""

import asyncio
from typing import Annotated

from fastapi import APIRouter, Path, Request
from pydantic import BaseModel, Field
from seer_api.errors import http_error
from seer_api.limiting import limiter

import seer

router = APIRouter()

# Bulk operation limits
MAX_BULK_DOMAINS = 100
MAX_CONCURRENCY = 50


class BulkPropagationRequest(BaseModel):
    """Request model for bulk propagation check."""

    domains: list[Annotated[str, Field(max_length=253)]] = Field(..., min_length=1, max_length=MAX_BULK_DOMAINS)
    record_type: str = Field("A", max_length=10, pattern=r"^[A-Z0-9]+$")
    concurrency: int = Field(default=5, ge=1, le=MAX_CONCURRENCY)


@router.get("/{domain}/{record_type}")
@limiter.limit("20/minute")
async def propagation_check(
    request: Request,
    domain: str = Path(..., min_length=1, max_length=253),
    record_type: str = Path(..., max_length=10, pattern=r"^[A-Z0-9]+$"),
):
    """
    Check DNS propagation for a domain across global DNS servers.

    Args:
        domain: Domain name to check
        record_type: Record type to check (default: A)

    Returns:
        Propagation result with percentage and per-server results
    """
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None, seer.propagation, domain, record_type
        )
        return result
    except Exception as e:
        raise http_error(e, "Propagation check failed")


@router.post("/bulk")
@limiter.limit("5/minute")
async def bulk_propagation_check(request: Request, body: BulkPropagationRequest):
    """
    Check DNS propagation for multiple domains.

    Args:
        body: BulkPropagationRequest with list of domains, record type, and concurrency

    Returns:
        List of propagation results for each domain
    """
    try:
        loop = asyncio.get_running_loop()
        results = await loop.run_in_executor(
            None, seer.bulk_propagation, body.domains, body.record_type, body.concurrency
        )
        return results
    except Exception as e:
        raise http_error(e, "Bulk propagation check failed")
