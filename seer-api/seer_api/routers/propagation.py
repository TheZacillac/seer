"""DNS Propagation API endpoints."""

from typing import List

from fastapi import APIRouter, Request
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

    domains: List[str] = Field(..., max_length=MAX_BULK_DOMAINS)
    record_type: str = "A"
    concurrency: int = Field(default=5, ge=1, le=MAX_CONCURRENCY)


@router.get("/{domain}/{record_type}")
@limiter.limit("20/minute")
async def propagation_check(request: Request, domain: str, record_type: str = "A"):
    """
    Check DNS propagation for a domain across global DNS servers.

    Args:
        domain: Domain name to check
        record_type: Record type to check (default: A)

    Returns:
        Propagation result with percentage and per-server results
    """
    try:
        result = seer.propagation(domain, record_type)
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
        results = seer.bulk_propagation(
            body.domains, body.record_type, body.concurrency
        )
        return results
    except Exception as e:
        raise http_error(e, "Bulk propagation check failed")
