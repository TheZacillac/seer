"""TLD information endpoints.

``GET /tld/{tld}`` resolves the WHOIS server, RDAP endpoint, registry URL,
and classification for a top-level domain; ``GET /tld/`` returns the full
catalog of TLDs seer knows about (embedded data, no network).

The TLD is a map/bootstrap *key*, never a connect target or URL component,
so there is no SSRF surface — validation here only rejects junk tokens with
a clear 400 instead of returning an all-``None`` payload.
"""

import re

from fastapi import APIRouter, HTTPException, Path, Request

import seer
from seer_api._run import run_seer
from seer_api.errors import http_error
from seer_api.limiting import limiter

router = APIRouter()

# Plausible TLD token: optional leading dot, then 1-63 ASCII
# letters/digits/hyphens without a leading or trailing hyphen (covers
# punycode A-labels like "xn--p1ai"). Deliberately looser than full IDNA —
# unknown-but-plausible TLDs return a payload with null fields, not a 400.
# Keep in sync with the copy in seer_api/mcp/server.py.
_TLD_TOKEN_RE = re.compile(r"^\.?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


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
    if not _TLD_TOKEN_RE.fullmatch(tld):
        raise HTTPException(
            status_code=400,
            detail="Invalid TLD: expected ASCII letters/digits/hyphens "
            "(punycode allowed), optionally with a leading dot",
        )
    try:
        return await run_seer(seer.tld_info, tld)
    except Exception as e:
        raise http_error(e, "TLD lookup failed") from e
