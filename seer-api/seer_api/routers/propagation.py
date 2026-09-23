"""DNS Propagation API endpoints."""

from fastapi import APIRouter, Path, Request

import seer
from seer_api._contract import (
    HEAVY_LIMIT,
    RECORD_TYPE_MAX_LENGTH,
    RECORD_TYPE_PATTERN,
    BulkPropagationRequest,
    Domain,
)
from seer_api._run import run_seer
from seer_api.errors import as_http
from seer_api.limiting import limiter
from seer_api.streaming import stream_bulk

router = APIRouter()


@router.get("/{domain}/{record_type}")
@limiter.limit("20/minute")
async def propagation_check(
    request: Request,
    domain: Domain,
    record_type: str = Path(
        ..., max_length=RECORD_TYPE_MAX_LENGTH, pattern=RECORD_TYPE_PATTERN
    ),
):
    """
    Check DNS propagation for a domain across global DNS servers.

    Args:
        domain: Domain name to check
        record_type: Record type to check (default: A)

    Returns:
        Propagation result with percentage and per-server results
    """
    return await as_http(
        run_seer(seer.propagation, domain, record_type),
        "Propagation check failed",
    )


@router.post("/bulk")
@limiter.limit(HEAVY_LIMIT)
async def bulk_propagation_check(request: Request, body: BulkPropagationRequest):
    """
    Check DNS propagation for multiple domains.

    Args:
        body: BulkPropagationRequest with list of domains, record type, and concurrency

    Returns:
        List of propagation results for each domain
    """
    return await as_http(
        run_seer(seer.bulk_propagation, body.domains, body.record_type, body.concurrency),
        "Bulk propagation check failed",
    )


@router.post("/bulk/stream")
@limiter.limit(HEAVY_LIMIT)
async def bulk_propagation_stream(request: Request, body: BulkPropagationRequest):
    """Stream bulk DNS-propagation checks as Server-Sent Events."""
    return await as_http(
        stream_bulk(seer.bulk_propagation, body.domains, body.record_type, body.concurrency),
        "Bulk propagation stream failed",
    )
