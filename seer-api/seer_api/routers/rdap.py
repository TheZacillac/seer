"""RDAP API endpoints."""

from fastapi import APIRouter, Path, Request

import seer
from seer_api._run import run_seer
from seer_api.errors import http_error
from seer_api.limiting import limiter
from seer_api.ssrf import guard_async as ssrf_guard_async

router = APIRouter()


@router.get("/domain/{domain}")
@limiter.limit("30/minute")
async def rdap_domain_lookup(
    request: Request,
    domain: str = Path(..., min_length=1, max_length=253),
):
    """
    Look up RDAP information for a domain.

    Args:
        domain: Domain name to look up

    Returns:
        RDAP response with registration information
    """
    try:
        return await run_seer(seer.rdap_domain, domain)
    except Exception as e:
        raise http_error(e, "RDAP domain lookup failed")


@router.get("/ip/{ip}")
@limiter.limit("30/minute")
async def rdap_ip_lookup(
    request: Request,
    ip: str = Path(..., min_length=1, max_length=45),
):
    """
    Look up RDAP information for an IP address.

    Args:
        ip: IP address (IPv4 or IPv6) to look up

    Returns:
        RDAP response with network registration information
    """
    await ssrf_guard_async(ip, 443)
    try:
        return await run_seer(seer.rdap_ip, ip)
    except Exception as e:
        raise http_error(e, "RDAP IP lookup failed")


@router.get("/asn/{asn}")
@limiter.limit("30/minute")
async def rdap_asn_lookup(
    request: Request,
    asn: int = Path(..., ge=0, le=4_294_967_295),
):
    """
    Look up RDAP information for an Autonomous System Number.

    Args:
        asn: AS number (e.g., 15169 for Google)

    Returns:
        RDAP response with ASN registration information
    """
    try:
        return await run_seer(seer.rdap_asn, asn)
    except Exception as e:
        raise http_error(e, "RDAP ASN lookup failed")
