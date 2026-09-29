"""DNS API endpoints."""

from fastapi import APIRouter, Path, Query, Request

import seer
from seer_api._contract import (
    BULK_LIMIT,
    HEAVY_LIMIT,
    RECORD_TYPE_MAX_LENGTH,
    RECORD_TYPE_PATTERN,
    BulkRecordRequest,
    Domain,
)
from seer_api._run import run_seer
from seer_api.errors import as_http
from seer_api.limiting import limiter
from seer_api.ssrf import guard_nameserver_async
from seer_api.streaming import stream_bulk

router = APIRouter()


# NOTE: `/trace/...` and `/compare/...` are registered before
# `/{domain}/{record_type}` so the two-segment record-lookup route does not
# swallow them.
@router.get("/trace/{domain}")
@limiter.limit(HEAVY_LIMIT)
async def dns_trace(
    request: Request,
    domain: Domain,
    record_type: str = Query(
        "A", max_length=RECORD_TYPE_MAX_LENGTH, pattern=RECORD_TYPE_PATTERN
    ),
):
    """
    Trace a name's resolution from the root servers down, like ``dig +trace``.

    Each hop is one delegation level: the zone, the server asked (directly,
    recursion off), its status, and the referral it gave or its answers. The
    walk stops at the first answer (a CNAME is reported, not followed), at
    NXDOMAIN or NODATA; ``error`` says why it stopped early, if it did.

    Args:
        domain: Name to trace
        record_type: One record type (default A); ANY is rejected with 400

    Returns:
        The trace: hops (root first), final status and answers, and error
    """
    # No API-layer SSRF guard: the name is a DNS question, and the servers
    # queried come from the root hints and referrals, each of which seer-core
    # vets (and skips when reserved) before sending a query.
    return await as_http(run_seer(seer.dns_trace, domain, record_type), "DNS trace failed")


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
    return await as_http(
        run_seer(seer.dns_compare, domain, record_type, server_a, server_b),
        "DNS comparison failed",
    )


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
    Query DNS for a domain, reporting the response the way ``dig`` does.

    NXDOMAIN, NODATA (NOERROR without records of the type), SERVFAIL and
    REFUSED are results with that ``status``, not errors. Behind a CNAME
    chain in ``answers``, NXDOMAIN or NODATA is about the chain's last
    target (NXDOMAIN there is a dangling CNAME), so a negative answer's
    ``answers`` need not be empty. NOERROR with no answers, no ``aa`` flag
    and only NS records (no SOA) in ``authority`` is a referral from a
    server that is not authoritative for the name and does not recurse: it
    says nothing about whether the name exists.

    Args:
        domain: Domain name to query
        record_type: Record type (A, AAAA, MX, TXT, NS, SOA, CNAME, CAA, etc.)
        nameserver: Optional nameserver to query (e.g., 8.8.8.8)

    Returns:
        The query result: status, header flags, answers (CNAME chain first,
        each record under its owner name), authority (the AUTHORITY section
        as the server sent it), wildcard probe
    """
    # Guard the nameserver (it's the actual connect target) but NOT the
    # queried domain — the domain is a DNS question, not a destination. The
    # nameserver is a spec (UDP / tls:// / https://), not a bare hostname.
    if nameserver is not None:
        await guard_nameserver_async(nameserver)
    return await as_http(run_seer(seer.dig, domain, record_type, nameserver), "DNS lookup failed")


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
    return await as_http(
        run_seer(seer.bulk_dig, body.domains, body.record_type, body.concurrency),
        "Bulk DNS lookup failed",
    )


@router.post("/bulk/stream")
@limiter.limit(BULK_LIMIT)
async def bulk_dns_stream(request: Request, body: BulkRecordRequest):
    """Stream bulk DNS queries as Server-Sent Events."""
    return await as_http(
        stream_bulk(seer.bulk_dig, body.domains, body.record_type, body.concurrency),
        "Bulk DNS stream failed",
    )
