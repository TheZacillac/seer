"""Single-domain intelligence endpoints.

Reaches parity with the CLI/library surface (availability, subdomains, DNSSEC,
diff, info) and exposes the newer intelligence features (CAA policy, email
security posture, typosquat look-alikes). Each router is mounted under its own
prefix in ``main.py``.

The queried domain is a DNS/RDAP/WHOIS *question*, not a connect target, so —
like ``dns.dns_lookup`` — these routes do not apply an API-layer SSRF guard;
the seer-core network layer guards the eventual connect targets itself.
"""

from typing import Annotated

from fastapi import APIRouter, Path, Query, Request
from pydantic import BaseModel, Field

import seer
from seer_api._run import run_seer
from seer_api.errors import http_error
from seer_api.limiting import limiter

MAX_BULK_DOMAINS = 100
MAX_CONCURRENCY = 50

_Domain = Annotated[str, Path(min_length=1, max_length=253)]


class _BulkRequest(BaseModel):
    """Shared request model for the bulk intelligence endpoints."""

    domains: list[Annotated[str, Field(max_length=253)]] = Field(
        ..., min_length=1, max_length=MAX_BULK_DOMAINS
    )
    concurrency: int = Field(default=10, ge=1, le=MAX_CONCURRENCY)


# --- availability --------------------------------------------------------

availability_router = APIRouter()


@availability_router.get("/{domain}")
@limiter.limit("60/minute")
async def availability(request: Request, domain: _Domain):
    """Check whether a domain appears to be available for registration."""
    try:
        return await run_seer(seer.availability, domain)
    except Exception as e:
        raise http_error(e, "Availability check failed")


@availability_router.post("/bulk")
@limiter.limit("10/minute")
async def bulk_availability(request: Request, body: _BulkRequest):
    """Check availability for multiple domains at once."""
    try:
        return await run_seer(seer.bulk_availability, body.domains, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk availability check failed")


# --- info ----------------------------------------------------------------

info_router = APIRouter()


@info_router.get("/{domain}")
@limiter.limit("60/minute")
async def info(request: Request, domain: _Domain):
    """Merged RDAP + WHOIS domain info as flat fields."""
    try:
        return await run_seer(seer.info, domain)
    except Exception as e:
        raise http_error(e, "Info lookup failed")


@info_router.post("/bulk")
@limiter.limit("10/minute")
async def bulk_info(request: Request, body: _BulkRequest):
    """Merged domain info for multiple domains at once."""
    try:
        return await run_seer(seer.bulk_info, body.domains, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk info lookup failed")


# --- subdomains ----------------------------------------------------------

subdomains_router = APIRouter()


@subdomains_router.get("/{domain}")
@limiter.limit("20/minute")
async def subdomains(
    request: Request,
    domain: _Domain,
    resolve: bool = Query(
        False, description="Resolve and classify each name (live/dead + takeover risk)"
    ),
    concurrency: int = Query(10, ge=1, le=MAX_CONCURRENCY),
):
    """Enumerate subdomains via Certificate Transparency logs.

    With ``resolve=true`` each discovered name is resolved and classified
    (live/dead/wildcard) and dangling CNAMEs to takeover-prone providers are
    flagged.
    """
    try:
        if resolve:
            return await run_seer(seer.subdomains_classify, domain, concurrency)
        return await run_seer(seer.subdomains, domain)
    except Exception as e:
        raise http_error(e, "Subdomain enumeration failed")


# --- dnssec --------------------------------------------------------------

dnssec_router = APIRouter()


@dnssec_router.get("/{domain}")
@limiter.limit("60/minute")
async def dnssec(request: Request, domain: _Domain):
    """DNSSEC validation report (DS/DNSKEY digest consistency)."""
    try:
        return await run_seer(seer.dnssec, domain)
    except Exception as e:
        raise http_error(e, "DNSSEC check failed")


# --- diff ----------------------------------------------------------------

diff_router = APIRouter()


@diff_router.get("/{domain_a}/{domain_b}")
@limiter.limit("30/minute")
async def diff(
    request: Request,
    domain_a: Annotated[str, Path(min_length=1, max_length=253)],
    domain_b: Annotated[str, Path(min_length=1, max_length=253)],
):
    """Compare two domains side-by-side (registration, DNS, SSL)."""
    try:
        return await run_seer(seer.diff, domain_a, domain_b)
    except Exception as e:
        raise http_error(e, "Domain diff failed")


# --- caa -----------------------------------------------------------------

caa_router = APIRouter()


@caa_router.get("/{domain}")
@limiter.limit("60/minute")
async def caa(request: Request, domain: _Domain):
    """CAA (Certification Authority Authorization) policy, incl. iodef and
    wildcard-vs-base consistency analysis."""
    try:
        return await run_seer(seer.caa, domain)
    except Exception as e:
        raise http_error(e, "CAA lookup failed")


# --- posture -------------------------------------------------------------

posture_router = APIRouter()


@posture_router.get("/{domain}")
@limiter.limit("30/minute")
async def posture(request: Request, domain: _Domain):
    """Email/DNS security posture (SPF, DMARC, MTA-STS, BIMI, DANE)."""
    try:
        return await run_seer(seer.posture, domain)
    except Exception as e:
        raise http_error(e, "Posture check failed")


# --- confusables ---------------------------------------------------------

confusables_router = APIRouter()


@confusables_router.get("/{domain}")
@limiter.limit("5/minute")
async def confusables(
    request: Request,
    domain: _Domain,
    concurrency: int = Query(10, ge=1, le=MAX_CONCURRENCY),
):
    """Find registered typosquat / look-alike domains for a domain."""
    try:
        return await run_seer(seer.confusables, domain, concurrency)
    except Exception as e:
        raise http_error(e, "Confusables scan failed")
