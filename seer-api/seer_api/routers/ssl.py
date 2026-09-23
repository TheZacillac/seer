"""SSL chain inspection API endpoints (single + bulk)."""

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
@limiter.limit("30/minute")
async def ssl_inspect(request: Request, domain: Domain):
    """Inspect the SSL/TLS certificate chain for a single domain.

    Returns the full report including the derived security-posture warnings.
    """
    # The domain IS the connect target here (port 443), so guard it.
    await ssrf_guard_async(domain, 443)
    return await as_http(run_seer(seer.ssl, domain), "SSL inspection failed")


@router.post("/bulk")
@limiter.limit(HEAVY_LIMIT)
async def bulk_ssl(request: Request, body: BulkRequest):
    """
    Inspect SSL certificate chains for multiple domains.

    Returns the full SSL report per domain (chain, SANs, key details,
    signature algorithm).
    """
    await guard_hosts_async([(d, 443) for d in body.domains])
    return await as_http(
        run_seer(seer.bulk_ssl, body.domains, body.concurrency),
        "Bulk SSL inspection failed",
    )


@router.post("/bulk/stream")
@limiter.limit(HEAVY_LIMIT)
async def bulk_ssl_stream(request: Request, body: BulkRequest):
    """Stream bulk SSL inspection results as Server-Sent Events."""
    await guard_hosts_async([(d, 443) for d in body.domains])
    return await as_http(
        stream_bulk(seer.bulk_ssl, body.domains, body.concurrency),
        "Bulk SSL stream failed",
    )
