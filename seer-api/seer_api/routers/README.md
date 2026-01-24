# Routers Module

FastAPI route handlers for the Seer REST API.

## Overview

This module contains all API endpoint implementations organized by feature area.

## Files

| File | Description |
|------|-------------|
| `__init__.py` | Router imports and exports |
| `lookup.py` | Smart lookup endpoints |
| `whois.py` | WHOIS lookup endpoints |
| `rdap.py` | RDAP lookup endpoints |
| `dns.py` | DNS query endpoints |
| `propagation.py` | DNS propagation endpoints |
| `status.py` | Domain status endpoints |

## Endpoints by Router

### lookup.py

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/lookup/{domain}` | GET | Smart lookup for a domain |
| `/lookup/bulk` | POST | Bulk smart lookups |

```python
# GET /lookup/example.com
# Response: LookupResult

# POST /lookup/bulk
# Body: {"domains": ["a.com", "b.com"], "concurrency": 10}
# Response: [BulkResult, ...]
```

### whois.py

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/whois/{domain}` | GET | WHOIS lookup for a domain |

```python
# GET /whois/example.com
# Response: WhoisResponse
```

### rdap.py

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/rdap/domain/{domain}` | GET | RDAP domain lookup |
| `/rdap/ip/{ip}` | GET | RDAP IP lookup |
| `/rdap/asn/{asn}` | GET | RDAP ASN lookup |

```python
# GET /rdap/domain/example.com
# GET /rdap/ip/8.8.8.8
# GET /rdap/asn/15169
# Response: RdapResponse
```

### dns.py

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/dns/{domain}/{record_type}` | GET | DNS query |

```python
# GET /dns/example.com/A
# GET /dns/example.com/MX
# Query param: ?nameserver=8.8.8.8
# Response: [DnsRecord, ...]
```

### propagation.py

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/propagation/{domain}/{record_type}` | GET | DNS propagation check |

```python
# GET /propagation/example.com/A
# Response: PropagationResult
```

### status.py

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/status/{domain}` | GET | Domain status check |
| `/status/bulk` | POST | Bulk status checks |

```python
# GET /status/example.com
# Response: StatusResponse

# POST /status/bulk
# Body: {"domains": ["a.com", "b.com"], "concurrency": 10}
# Response: [BulkResult, ...]
```

## Request/Response Models

### BulkRequest

```python
class BulkRequest(BaseModel):
    domains: list[str]           # List of domains to process
    concurrency: int = 10        # Concurrent operations (max 50)
```

### BulkResult

```python
{
    "operation": {"type": "lookup", "domain": "example.com"},
    "success": true,
    "data": {...},
    "error": null,
    "duration_ms": 523
}
```

## Error Handling

All routers use consistent error handling:

```python
from fastapi import HTTPException

try:
    result = seer.lookup(domain)
    return result
except Exception as e:
    raise HTTPException(status_code=400, detail=str(e))
```

HTTP status codes:
- `200` - Success
- `400` - Invalid request (bad domain, invalid record type, etc.)
- `500` - Internal server error

## Adding a New Router

1. Create `seer_api/routers/newfeature.py`:

```python
from fastapi import APIRouter, HTTPException
import seer

router = APIRouter(prefix="/newfeature", tags=["newfeature"])

@router.get("/{domain}")
async def newfeature(domain: str):
    try:
        result = seer.newfeature(domain)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
```

2. Register in `seer_api/main.py`:

```python
from .routers import newfeature

app.include_router(newfeature.router)
```
