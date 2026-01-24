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

Server runs on `http://localhost:8000` with auto-reload enabled.

### API Documentation

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | List available endpoints |
| `/health` | GET | Health check |
| `/lookup/{domain}` | GET | Smart lookup |
| `/lookup/bulk` | POST | Bulk smart lookups |
| `/whois/{domain}` | GET | WHOIS lookup |
| `/rdap/domain/{domain}` | GET | RDAP domain lookup |
| `/rdap/ip/{ip}` | GET | RDAP IP lookup |
| `/rdap/asn/{asn}` | GET | RDAP ASN lookup |
| `/dns/{domain}/{record_type}` | GET | DNS query |
| `/propagation/{domain}/{record_type}` | GET | DNS propagation check |
| `/status/{domain}` | GET | Domain status check |
| `/status/bulk` | POST | Bulk status checks |

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

Set rate limit via environment variable:

```bash
export SEER_RATE_LIMIT=60  # requests per minute
seer-api
```

Default: 30 requests/minute

## MCP Server

### Starting the Server

```bash
seer-mcp
```

The MCP server uses stdio transport for communication with AI assistants.

### Available Tools

| Tool | Description |
|------|-------------|
| `seer_lookup` | Smart domain lookup (RDAP/WHOIS) |
| `seer_whois` | WHOIS lookup |
| `seer_rdap_domain` | RDAP domain lookup |
| `seer_rdap_ip` | RDAP IP lookup |
| `seer_rdap_asn` | RDAP ASN lookup |
| `seer_dig` | DNS query |
| `seer_propagation` | DNS propagation check |
| `seer_bulk_lookup` | Bulk smart lookups |
| `seer_bulk_whois` | Bulk WHOIS lookups |
| `seer_bulk_dig` | Bulk DNS queries |

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
# REST API with auto-reload
uvicorn seer_api.main:app --reload --host 0.0.0.0 --port 8000

# MCP server
python -m seer_api.mcp.server
```

### Project Structure

```
seer-api/
├── pyproject.toml          # Package configuration
└── seer_api/
    ├── __init__.py         # Package init
    ├── main.py             # FastAPI app
    ├── routers/            # API endpoints
    │   ├── __init__.py
    │   ├── lookup.py
    │   ├── whois.py
    │   ├── rdap.py
    │   ├── dns.py
    │   ├── propagation.py
    │   └── status.py
    └── mcp/                # MCP server
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
