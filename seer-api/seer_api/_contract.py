"""Input contract shared by the REST routers and the MCP server.

Bulk limits, request models, token validators and the rate limits of the
fan-out operations are defined once here, so both surfaces enforce the same
contract by construction rather than through hand-synced copies.
"""

from __future__ import annotations

import re
from typing import Annotated

from fastapi import Path
from pydantic import BaseModel, Field

MAX_BULK_DOMAINS = 100
MAX_CONCURRENCY = 50

# Limits for the expensive fan-out operations, applied per REST route and per
# MCP tool alike so neither surface can outrun the other.
BULK_LIMIT = "10/minute"
# Bulk SSL/status/propagation, confusables and takeover fan out hardest.
HEAVY_LIMIT = "5/minute"

# DNS record-type token accepted at the edge; the core parses the name itself.
RECORD_TYPE_PATTERN = r"^[A-Z0-9]+$"
RECORD_TYPE_MAX_LENGTH = 10

# Plausible TLD token: optional leading dot, then 1-63 ASCII
# letters/digits/hyphens without a leading or trailing hyphen (covers
# punycode A-labels like "xn--p1ai"). Deliberately looser than full IDNA —
# unknown-but-plausible TLDs return a payload with null fields; this only
# rejects junk with a clear error. Never a URL/connect target.
TLD_TOKEN_RE = re.compile(r"^\.?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)

# A domain path parameter.
Domain = Annotated[str, Path(min_length=1, max_length=253)]

_DomainList = Annotated[
    list[Annotated[str, Field(max_length=253)]],
    Field(min_length=1, max_length=MAX_BULK_DOMAINS),
]
_Concurrency = Annotated[int, Field(ge=1, le=MAX_CONCURRENCY)]
_RecordType = Annotated[
    str, Field(max_length=RECORD_TYPE_MAX_LENGTH, pattern=RECORD_TYPE_PATTERN)
]


class BulkRequest(BaseModel):
    """Request body for the bulk endpoints: domains plus optional concurrency."""

    domains: _DomainList
    concurrency: _Concurrency = 10


class BulkRecordRequest(BaseModel):
    """Request body for bulk DNS queries: domains, record type, concurrency."""

    domains: _DomainList
    record_type: _RecordType = "A"
    concurrency: _Concurrency = 10


class BulkPropagationRequest(BulkRecordRequest):
    """Bulk propagation: each domain fans out to every resolver, so it
    defaults to a lower concurrency."""

    concurrency: _Concurrency = 5
