"""RDAP API endpoints."""

from fastapi import APIRouter, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

import seer

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


@router.get("/domain/{domain}")
@limiter.limit("30/minute")
async def rdap_domain_lookup(request: Request, domain: str):
    """
    Look up RDAP information for a domain.

    Args:
        domain: Domain name to look up

    Returns:
        RDAP response with registration information
    """
    try:
        result = seer.rdap_domain(domain)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/ip/{ip}")
@limiter.limit("30/minute")
async def rdap_ip_lookup(request: Request, ip: str):
    """
    Look up RDAP information for an IP address.

    Args:
        ip: IP address (IPv4 or IPv6) to look up

    Returns:
        RDAP response with network registration information
    """
    try:
        result = seer.rdap_ip(ip)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/asn/{asn}")
@limiter.limit("30/minute")
async def rdap_asn_lookup(request: Request, asn: int):
    """
    Look up RDAP information for an Autonomous System Number.

    Args:
        asn: AS number (e.g., 15169 for Google)

    Returns:
        RDAP response with ASN registration information
    """
    try:
        result = seer.rdap_asn(asn)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
