# seer-api

FastAPI REST server and MCP (Model Context Protocol) server for Seer.

## Overview

`seer-api` provides two server interfaces for Seer:
- **REST API**: FastAPI-based web service with OpenAPI documentation
- **MCP Server**: Model Context Protocol server for AI assistant integration

## Installation

### Prerequisites

The `seer` Python package must be installed first:

```bash
cd seer-py
maturin develop --release
cd ..
```

### Install seer-api

```bash
cd seer-api
pip install -e .
```

## Entry Points

| Command | Description |
|---------|-------------|
| `seer-api` | Start REST API server |
| `seer-mcp` | Start MCP server |

## Modules

| Directory | Description |
|-----------|-------------|
| [`seer_api/main.py`](seer_api/main.py) | FastAPI application setup |
| [`seer_api/routers/`](seer_api/routers/) | API endpoint implementations |
| [`seer_api/mcp/`](seer_api/mcp/) | MCP server implementation |

## REST API

### Starting the Server

```bash
seer-api
```

Server runs on `http://127.0.0.1:8000` (loopback-only by default).

### Breaking change: deployment defaults

- **Default bind is `127.0.0.1`** (was `0.0.0.0`). To bind publicly,
  set both `SEER_HOST=0.0.0.0` **and** `SEER_API_KEY=<token>`. The
  server refuses to start on a non-loopback host without an auth key.
- **API documentation endpoints are off by default.** Set
  `SEER_DOCS_ENABLED=true` to re-enable `/docs`, `/redoc`, and
  `/openapi.json`.
- **Multi-worker deployments require a shared rate-limit store.**
  With `WEB_CONCURRENCY>1`, set `SEER_RATE_LIMIT_STORAGE=redis://...`
  or the server will refuse to start.

### API Documentation

Available only when `SEER_DOCS_ENABLED=true`:

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | List available endpoints |
| `/health` | GET | Health check |
| `/metrics` | GET | Operational metrics (loopback always; non-loopback gated by `SEER_METRICS_ENABLED`) |
| `/lookup/{domain}` | GET | Smart lookup (RDAP → WHOIS fallback) |
| `/whois/{domain}` | GET | WHOIS lookup |
| `/rdap/domain/{domain}` | GET | RDAP domain lookup |
| `/rdap/ip/{ip}` | GET | RDAP IP lookup |
| `/rdap/asn/{asn}` | GET | RDAP ASN lookup |
| `/dns/{domain}/{record_type}` | GET | DNS query |
| `/dns/compare/{domain}` | GET | Compare records across nameservers |
| `/propagation/{domain}/{record_type}` | GET | DNS propagation check |
| `/status/{domain}` | GET | Domain status check |
| `/ssl/{domain}` | GET | SSL certificate chain inspection |
| `/availability/{domain}` | GET | Domain availability check |
| `/info/{domain}` | GET | Merged RDAP + WHOIS domain info |
| `/subdomains/{domain}` | GET | Subdomain enumeration (CT logs) |
| `/dnssec/{domain}` | GET | DNSSEC validation |
| `/delegation/{domain}` | GET | NS delegation health |
| `/diff/{domain_a}/{domain_b}` | GET | Side-by-side domain comparison |
| `/caa/{domain}` | GET | CAA policy lookup |
| `/posture/{domain}` | GET | Email/DNS security posture |
| `/headers/{domain}` | GET | HTTP security header + cookie audit |
| `/takeover/{domain}` | GET | Subdomain takeover exposure scan |
| `/confusables/{domain}` | GET | Look-alike (typosquat) generation |
| `/tld/{tld}` | GET | TLD info (WHOIS server, RDAP endpoint) |
| `/tld/` | GET | Full TLD catalog |
| `/mcp` | GET/POST | MCP Streamable HTTP transport (see [MCP Server](#mcp-server)) |

Bulk variants: `lookup`, `whois`, `dns`, `propagation`, `status`, and `ssl`
accept `POST /<prefix>/bulk` plus an SSE-streaming `POST /<prefix>/bulk/stream`;
`availability` and `info` accept `POST /<prefix>/bulk`.

### Usage Examples

```bash
# Smart lookup
curl http://localhost:8000/lookup/example.com

# WHOIS lookup
curl http://localhost:8000/whois/example.com

# DNS query
curl http://localhost:8000/dns/example.com/MX

# Domain status
curl http://localhost:8000/status/example.com

# Bulk lookup
curl -X POST http://localhost:8000/lookup/bulk \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com", "google.com"]}'

# Bulk status
curl -X POST http://localhost:8000/status/bulk \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com", "google.com"], "concurrency": 5}'
```

### Configuration

#### CORS

Set allowed origins via environment variable:

```bash
export SEER_CORS_ORIGINS="https://example.com,https://app.example.com"
seer-api
```

Default: `*` (all origins)

#### Rate Limiting

Set the rate limit via environment variable, in the `<count>/<period>`
format the `limits` library parses (a bare number like `60` is rejected
and breaks every rate-limited request):

```bash
export SEER_RATE_LIMIT="60/minute"
seer-api
```

Default: `30/minute`

## MCP Server

Two transports expose the same tool registry:

- **stdio** (`seer-mcp`) — local subprocess, used by Claude Desktop and other
  desktop AI clients.
- **Streamable HTTP** (`POST /mcp` on the `seer-api` process) — for remote
  AI clients and web hosts. Mounted on the existing FastAPI app, so it
  inherits `SEER_API_KEY` auth, body-size cap, request logging, and CORS.

### Starting the stdio server

```bash
seer-mcp
```

### Streamable HTTP transport

Start the API server as usual; the MCP endpoint is at `POST /mcp`. Mint a
fresh bearer token with the `seer` CLI:

```bash
eval "$(seer generate-key --export)"   # exports SEER_API_KEY
seer-api

curl -N -X POST http://127.0.0.1:8000/mcp \
  -H "Authorization: Bearer $SEER_API_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

The transport runs in **stateless mode** — each POST is a fresh session,
so the server scales across `WEB_CONCURRENCY` workers without a shared
session store. Responses are SSE-framed so `tools/call` can stream long
bulk operations back to the client.

Optional env vars:

| Variable | Description |
|----------|-------------|
| `SEER_MCP_ALLOWED_HOSTS` | Comma-separated `Host:` values to allow. Enabling this turns on DNS-rebinding protection. |
| `SEER_MCP_ALLOWED_ORIGINS` | Comma-separated `Origin:` values to allow (browser hosts). |

### Available Tools

All 30 tools, on both transports:

| Tool | Description |
|------|-------------|
| `seer_lookup` | Smart domain lookup (RDAP → WHOIS fallback) |
| `seer_whois` | WHOIS lookup |
| `seer_rdap_domain` | RDAP domain lookup |
| `seer_rdap_ip` | RDAP IP lookup |
| `seer_rdap_asn` | RDAP ASN lookup |
| `seer_dig` | DNS query |
| `seer_dns_compare` | Compare records across nameservers |
| `seer_propagation` | DNS propagation check |
| `seer_status` | Domain status check |
| `seer_ssl` | SSL certificate chain inspection |
| `seer_availability` | Domain availability check |
| `seer_info` | Merged RDAP + WHOIS domain info |
| `seer_subdomains` | Subdomain enumeration (CT logs) |
| `seer_dnssec` | DNSSEC validation |
| `seer_delegation` | NS delegation health |
| `seer_diff` | Side-by-side domain comparison |
| `seer_caa` | CAA policy lookup |
| `seer_posture` | Email/DNS security posture |
| `seer_headers` | HTTP security header + cookie audit (graded A+–F) |
| `seer_takeover` | Subdomain takeover scan (HTTP-confirmed) |
| `seer_confusables` | Look-alike (typosquat) generation |
| `seer_tld_info` | TLD info (WHOIS server, RDAP endpoint) |
| `seer_bulk_lookup` | Bulk smart lookups |
| `seer_bulk_whois` | Bulk WHOIS lookups |
| `seer_bulk_dig` | Bulk DNS queries |
| `seer_bulk_propagation` | Bulk propagation checks |
| `seer_bulk_status` | Bulk status checks |
| `seer_bulk_ssl` | Bulk SSL inspections |
| `seer_bulk_info` | Bulk domain info |
| `seer_bulk_availability` | Bulk availability checks |

### Tool Schemas

#### seer_lookup

```json
{
  "name": "seer_lookup",
  "inputSchema": {
    "type": "object",
    "properties": {
      "domain": {"type": "string"}
    },
    "required": ["domain"]
  }
}
```

#### seer_dig

```json
{
  "name": "seer_dig",
  "inputSchema": {
    "type": "object",
    "properties": {
      "domain": {"type": "string"},
      "record_type": {"type": "string", "default": "A"},
      "nameserver": {"type": "string"}
    },
    "required": ["domain"]
  }
}
```

#### seer_bulk_lookup

```json
{
  "name": "seer_bulk_lookup",
  "inputSchema": {
    "type": "object",
    "properties": {
      "domains": {"type": "array", "items": {"type": "string"}},
      "concurrency": {"type": "integer", "default": 10}
    },
    "required": ["domains"]
  }
}
```

### Claude Desktop Integration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "seer": {
      "command": "seer-mcp"
    }
  }
}
```

## Development

### Running in Development

```bash
# REST API with auto-reload (loopback only)
uvicorn seer_api.main:app --reload --host 127.0.0.1 --port 8000

# MCP server
python -m seer_api.mcp.server
```

### Project Structure

```
seer-api/
├── pyproject.toml          # Package configuration
└── seer_api/
    ├── __init__.py         # Package init
    ├── main.py             # FastAPI app, middleware, lifespan checks
    ├── _env.py             # strict integer env-var parsing
    ├── _run.py             # bounded dispatch pool + request deadlines
    ├── errors.py           # error → HTTP status mapping
    ├── limiting.py         # slowapi rate limiting
    ├── middleware.py       # auth, body-size cap, request logging
    ├── ssrf.py             # API-layer SSRF guards
    ├── streaming.py        # SSE bulk-stream plumbing
    ├── routers/            # API endpoints
    │   ├── __init__.py
    │   ├── lookup.py
    │   ├── whois.py
    │   ├── rdap.py
    │   ├── dns.py
    │   ├── propagation.py
    │   ├── status.py
    │   ├── ssl.py
    │   ├── intel.py        # availability/info/subdomains/dnssec/delegation/diff/caa/posture/headers/takeover/confusables
    │   └── tld.py
    └── mcp/                # MCP server (stdio + Streamable HTTP)
        ├── __init__.py
        └── server.py
```

## Dependencies

- **seer** - Python bindings for seer-core
- **fastapi** - Web framework
- **uvicorn** - ASGI server
- **pydantic** - Data validation
- **mcp** - Model Context Protocol

## Bulk Operation Limits

| Limit | Value |
|-------|-------|
| Max domains per request | 100 |
| Max concurrency | 50 |
| Default concurrency | 10 |
