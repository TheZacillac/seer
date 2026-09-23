"""TLD information endpoints.

``GET /tld/{tld}`` resolves the WHOIS server, RDAP endpoint, registry URL,
and classification for a top-level domain; ``GET /tld/`` returns the full
catalog of TLDs seer knows about (embedded data, no network).

The TLD is a map/bootstrap *key*, never a connect target or URL component,
so there is no SSRF surface — validation here only rejects junk tokens with
a clear 400 instead of returning an all-``None`` payload.
"""

from fastapi import APIRouter, HTTPException, Path, Request

import seer
from seer_api._contract import TLD_TOKEN_RE
from seer_api._run import run_seer
from seer_api.errors import http_error
from seer_api.limiting import limiter

router = APIRouter()


@router.get("/")
@limiter.limit("30/minute")
async def tld_list(request: Request):
    """List every TLD seer knows about (sorted, deduplicated)."""
    try:
        return await run_seer(seer.all_tlds)
    except Exception as e:
        raise http_error(e, "TLD list failed") from e


@router.get("/{tld}")
@limiter.limit("60/minute")
async def tld_info(
    request: Request,
    tld: str = Path(..., min_length=1, max_length=64),
):
    """Look up WHOIS server, RDAP endpoint, registry URL, and type for a TLD."""
    if not TLD_TOKEN_RE.fullmatch(tld):
        raise HTTPException(
            status_code=400,
            detail="Invalid TLD: expected ASCII letters/digits/hyphens "
            "(punycode allowed), optionally with a leading dot",
        )
    try:
        return await run_seer(seer.tld_info, tld)
    except Exception as e:
        raise http_error(e, "TLD lookup failed") from e
