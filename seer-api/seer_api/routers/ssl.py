"""SSL chain inspection API endpoints (single + bulk)."""

from typing import Annotated

from fastapi import APIRouter, Path, Request
from pydantic import BaseModel, Field

import seer
from seer_api._run import run_seer
from seer_api.errors import http_error
from seer_api.limiting import limiter
from seer_api.ssrf import guard_async as ssrf_guard_async
from seer_api.ssrf import guard_hosts_async
from seer_api.streaming import stream_bulk

router = APIRouter()

# Bulk operation limits — mirrors status.py.
MAX_BULK_DOMAINS = 100
MAX_CONCURRENCY = 50


@router.get("/{domain}")
@limiter.limit("30/minute")
async def ssl_inspect(
    request: Request,
    domain: Annotated[str, Path(min_length=1, max_length=253)],
):
    """Inspect the SSL/TLS certificate chain for a single domain.

    Returns the full report including the derived security-posture warnings.
    """
    # The domain IS the connect target here (port 443), so guard it.
    await ssrf_guard_async(domain, 443)
    try:
        return await run_seer(seer.ssl, domain)
    except Exception as e:
        raise http_error(e, "SSL inspection failed") from e


class BulkSslRequest(BaseModel):
    """Request model for bulk SSL chain inspection."""

    domains: list[Annotated[str, Field(max_length=253)]] = Field(
        ..., min_length=1, max_length=MAX_BULK_DOMAINS
    )
    concurrency: int = Field(default=10, ge=1, le=MAX_CONCURRENCY)


@router.post("/bulk")
@limiter.limit("5/minute")
async def bulk_ssl(request: Request, body: BulkSslRequest):
    """
    Inspect SSL certificate chains for multiple domains.

    Returns the full SSL report per domain (chain, SANs, key details,
    signature algorithm).
    """
    await guard_hosts_async([(d, 443) for d in body.domains])
    try:
        return await run_seer(seer.bulk_ssl, body.domains, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk SSL inspection failed") from e


@router.post("/bulk/stream")
@limiter.limit("5/minute")
async def bulk_ssl_stream(request: Request, body: BulkSslRequest):
    """Stream bulk SSL inspection results as Server-Sent Events."""
    await guard_hosts_async([(d, 443) for d in body.domains])
    try:
        return await stream_bulk(seer.bulk_ssl, body.domains, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk SSL stream failed") from e
