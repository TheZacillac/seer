"""Single-domain intelligence endpoints.

Reaches parity with the CLI/library surface (availability, subdomains, DNSSEC,
diff, info) and exposes the newer intelligence features (CAA policy, email
security posture, HTTP header audit, subdomain-takeover scan, typosquat
look-alikes). Each router is mounted under its own prefix in ``main.py``.

For most routes here the queried domain is a DNS/RDAP/WHOIS *question*, not a
connect target, so — like ``dns.dns_lookup`` — they apply no API-layer SSRF
guard. ``headers`` and ``takeover`` are the exceptions: they do connect to the
queried host over HTTPS. They still apply no API-layer guard, for the same
reason ``ssl`` does not — seer-core resolves and vets every target itself and
pins the validated addresses, so a second check here would add nothing but its
own TOCTOU window.
"""

from fastapi import APIRouter, Query, Request

import seer
from seer_api._contract import BULK_LIMIT, HEAVY_LIMIT, MAX_CONCURRENCY, BulkRequest, Domain
from seer_api._run import run_seer
from seer_api.errors import as_http
from seer_api.limiting import limiter

# --- availability --------------------------------------------------------

availability_router = APIRouter()


@availability_router.get("/{domain}")
@limiter.limit("60/minute")
async def availability(request: Request, domain: Domain):
    """Check whether a domain appears to be available for registration."""
    return await as_http(run_seer(seer.availability, domain), "Availability check failed")


@availability_router.post("/bulk")
@limiter.limit(BULK_LIMIT)
async def bulk_availability(request: Request, body: BulkRequest):
    """Check availability for multiple domains at once."""
    return await as_http(
        run_seer(seer.bulk_availability, body.domains, body.concurrency),
        "Bulk availability check failed",
    )


# --- info ----------------------------------------------------------------

info_router = APIRouter()


@info_router.get("/{domain}")
@limiter.limit("60/minute")
async def info(request: Request, domain: Domain):
    """Merged RDAP + WHOIS domain info as flat fields."""
    return await as_http(run_seer(seer.info, domain), "Info lookup failed")


@info_router.post("/bulk")
@limiter.limit(BULK_LIMIT)
async def bulk_info(request: Request, body: BulkRequest):
    """Merged domain info for multiple domains at once."""
    return await as_http(
        run_seer(seer.bulk_info, body.domains, body.concurrency),
        "Bulk info lookup failed",
    )


# --- subdomains ----------------------------------------------------------

subdomains_router = APIRouter()


@subdomains_router.get("/{domain}")
@limiter.limit("20/minute")
async def subdomains(
    request: Request,
    domain: Domain,
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
    call = (
        run_seer(seer.subdomains_classify, domain, concurrency)
        if resolve
        else run_seer(seer.subdomains, domain)
    )
    return await as_http(call, "Subdomain enumeration failed")


# --- dnssec --------------------------------------------------------------

dnssec_router = APIRouter()


@dnssec_router.get("/{domain}")
@limiter.limit("60/minute")
async def dnssec(request: Request, domain: Domain):
    """DNSSEC validation report (DS/DNSKEY digest consistency)."""
    return await as_http(run_seer(seer.dnssec, domain), "DNSSEC check failed")


# --- delegation ------------------------------------------------------------

delegation_router = APIRouter()


@delegation_router.get("/{domain}")
# 30/minute (matching /posture, not /dnssec's 60): each check fans out to
# parent-zone NS queries plus a lameness probe per delegated nameserver.
@limiter.limit("30/minute")
async def delegation(request: Request, domain: Domain):
    """NS delegation health: parent delegation vs zone NS RRset, plus a
    lameness probe of each delegated nameserver."""
    return await as_http(run_seer(seer.delegation, domain), "Delegation check failed")


# --- diff ----------------------------------------------------------------

diff_router = APIRouter()


@diff_router.get("/{domain_a}/{domain_b}")
@limiter.limit("30/minute")
async def diff(
    request: Request,
    domain_a: Domain,
    domain_b: Domain,
):
    """Compare two domains side-by-side (registration, DNS, SSL)."""
    return await as_http(run_seer(seer.diff, domain_a, domain_b), "Domain diff failed")


# --- caa -----------------------------------------------------------------

caa_router = APIRouter()


@caa_router.get("/{domain}")
@limiter.limit("60/minute")
async def caa(request: Request, domain: Domain):
    """CAA (Certification Authority Authorization) policy, incl. iodef and
    wildcard-vs-base consistency analysis."""
    return await as_http(run_seer(seer.caa, domain), "CAA lookup failed")


# --- posture -------------------------------------------------------------

posture_router = APIRouter()


@posture_router.get("/{domain}")
@limiter.limit("30/minute")
async def posture(request: Request, domain: Domain):
    """Email/DNS security posture (SPF, DMARC, MTA-STS, BIMI, DANE)."""
    return await as_http(run_seer(seer.posture, domain), "Posture check failed")


# --- headers -------------------------------------------------------------

headers_router = APIRouter()


@headers_router.get("/{domain}")
@limiter.limit("20/minute")
async def headers(request: Request, domain: Domain):
    """Audit HTTP security headers, cookie flags, and version disclosure.

    Unlike its sibling routes, this one *connects* to the queried domain over
    HTTPS. No API-layer SSRF guard is applied here for the same reason it is
    not applied to ``ssl``: seer-core resolves and vets the target itself
    (refusing reserved/private addresses and pinning the validated addresses
    per redirect hop), so duplicating the check here would only add a second
    resolution with its own TOCTOU window.
    """
    return await as_http(run_seer(seer.headers, domain), "Header audit failed")


# --- takeover ------------------------------------------------------------

takeover_router = APIRouter()


@takeover_router.get("/{domain}")
@limiter.limit(HEAVY_LIMIT)
async def takeover(
    request: Request,
    domain: Domain,
    concurrency: int = Query(10, ge=1, le=MAX_CONCURRENCY),
):
    """Scan a domain's subdomains for takeover exposure.

    Enumerates via Certificate Transparency logs, then checks each host whose
    CNAME points at a takeover-prone provider. A host serving that provider's
    unclaimed-resource page is reported as vulnerable with the matched
    fingerprint as evidence; a dangling CNAME that does not resolve is
    reported as potential. Rate-limited like ``confusables`` because it fans
    out across the whole enumerated zone.
    """
    return await as_http(run_seer(seer.takeover, domain, concurrency), "Takeover scan failed")


# --- confusables ---------------------------------------------------------

confusables_router = APIRouter()


@confusables_router.get("/{domain}")
@limiter.limit(HEAVY_LIMIT)
async def confusables(
    request: Request,
    domain: Domain,
    concurrency: int = Query(10, ge=1, le=MAX_CONCURRENCY),
):
    """Find registered typosquat / look-alike domains for a domain."""
    return await as_http(run_seer(seer.confusables, domain, concurrency), "Confusables scan failed")
