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

## REST API

### Starting the Server

```bash
seer-api
```

Server runs on `http://127.0.0.1:8000` (loopback-only by default).

### Deployment defaults

- **Loopback-only bind.** The default host is `127.0.0.1`. To bind
  publicly, set both `SEER_HOST=0.0.0.0` **and** `SEER_API_KEY=<token>`;
  the server refuses to start on a non-loopback host without an auth key.
  A server started some other way (`uvicorn seer_api.main:app --host
  0.0.0.0`) is covered too: without `SEER_API_KEY`, every request that
  arrives on a non-loopback interface gets a 503 telling the operator to
  set the key.
- **No cross-origin browser access without a key.** With no
  `SEER_API_KEY`, a request carrying an `Origin` header is refused (403)
  unless the origin is a loopback one or listed in `SEER_CORS_ORIGINS` —
  so a web page cannot drive a local API from your browser. Clients that
  send no `Origin` (curl, SDKs) are unaffected. No CORS headers are sent
  unless `SEER_CORS_ORIGINS` is set.
- **No DNS rebinding without a key.** With no `SEER_API_KEY`, a request
  whose `Host` is not a loopback name (`localhost`, `127.0.0.0/8`, `[::1]`,
  any port) is refused with 421, `/metrics` included — a page whose domain
  was rebound to `127.0.0.1` sends its own `Host` (and, on a GET, no
  `Origin`). List other names the API may be reached by in
  `SEER_ALLOWED_HOSTS` (`host:*` matches any port), or set `SEER_API_KEY`.
  `/mcp` follows `SEER_MCP_ALLOWED_HOSTS` instead when that is set.
- **API documentation endpoints are off.** Set `SEER_DOCS_ENABLED=true`
  to serve `/docs`, `/redoc`, and `/openapi.json`.
- **Multi-worker deployments need a shared rate-limit store.** Set
  `SEER_RATE_LIMIT_STORAGE=redis://...` whenever more than one process
  serves the API: on the default in-memory store each worker keeps its own
  budget, multiplying every rate limit by the worker count. The server
  refuses to start on `memory://` when the worker count is visible to it —
  `WEB_CONCURRENCY>1` (which `seer-api`, `uvicorn` and `gunicorn` all use as
  their worker count) or `UVICORN_WORKERS>1`. **A count given any other way
  is invisible to the app and is not caught**: `uvicorn seer_api.main:app
  --workers 3`, `gunicorn -w 3 …`, `uvicorn.run(…, workers=3)`, or several
  replicas behind a load balancer. Each worker process cannot tell how many
  siblings it has, so for those deployments setting a shared store is up to
  you.

These became the defaults on 2026-04-20 (previously `0.0.0.0` with docs
on); see the CHANGELOG.

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
| `/lookup/{domain}` | GET | Smart lookup (RDAP → WHOIS fallback; WHOIS-only results add `dns_nameservers`, the live NS delegation compared with WHOIS) |
| `/whois/{domain}` | GET | WHOIS lookup |
| `/rdap/domain/{domain}` | GET | RDAP domain lookup |
| `/rdap/ip/{ip}` | GET | RDAP IP lookup |
| `/rdap/asn/{asn}` | GET | RDAP ASN lookup |
| `/dns/{domain}/{record_type}` | GET | DNS query, as `dig` reports it (status, flags, CNAME chain, wildcard probe) |
| `/dns/trace/{domain}` | GET | Delegation trace from the root servers, like `dig +trace` (`?record_type=`, default `A`) |
| `/dns/compare/{domain}` | GET | Compare records across nameservers |
| `/propagation/{domain}/{record_type}` | GET | DNS propagation check |
| `/status/{domain}` | GET | Domain status check |
| `/ssl/{domain}` | GET | SSL certificate chain inspection |
| `/availability/{domain}` | GET | Domain availability check |
| `/info/{domain}` | GET | Merged RDAP + WHOIS domain info |
| `/subdomains/{domain}` | GET | Subdomain enumeration (CT logs; `?resolve=true` also resolves and classifies each name) (`5/minute`) |
| `/dnssec/{domain}` | GET | DNSSEC validation |
| `/delegation/{domain}` | GET | NS delegation health |
| `/diff/{domain_a}/{domain_b}` | GET | Side-by-side domain comparison |
| `/caa/{domain}` | GET | CAA policy lookup |
| `/posture/{domain}` | GET | Email/DNS security posture |
| `/headers/{domain}` | GET | HTTP security header + cookie audit |
| `/audit/{domain}` | GET | Graded security assessment across email, web, TLS, DNS, takeover and registration (`5/minute`) |
| `/takeover/{domain}` | GET | Subdomain takeover exposure scan |
| `/confusables/{domain}` | GET | Look-alike (typosquat) generation |
| `/tld/{tld}` | GET | TLD info (WHOIS server, RDAP endpoint) |
| `/tld/` | GET | Full TLD catalog |
| `/mcp` | GET/POST | MCP Streamable HTTP transport (see [MCP Server](#mcp-server)) |

Bulk variants: `lookup`, `whois`, `dns`, `propagation`, `status`, and `ssl`
accept `POST /<prefix>/bulk` plus an SSE-streaming `POST /<prefix>/bulk/stream`;
`availability` and `info` accept `POST /<prefix>/bulk`. One failing domain
never fails the batch: its row carries `success: false` and the error — a
reserved (private, loopback, …) address in bulk `status`/`ssl` included,
which seer refuses to connect to.

### Errors

Failures return `{"detail": "<message>"}` with the status chosen by the
error's type: `400` invalid input (including a single-host `status`/`ssl`/
`rdap/ip` target or a nameserver that is a reserved IP address), `404` no
WHOIS server for the TLD, `429` rate limited (this API's own limit, or an
upstream registry's), `502` an upstream (WHOIS, RDAP, DNS, HTTP, TLS)
failure, `503` a deployment fault or a bulk request that found every bulk
slot busy until `SEER_REQUEST_TIMEOUT` (nothing ran; retry later), `504` a
timeout (including `SEER_REQUEST_TIMEOUT`), `500` anything else. A bulk
stream that fails or outlives `SEER_REQUEST_TIMEOUT` ends with an `error`
event.

A *hostname* that resolves to a reserved address is refused by seer-core
when it connects, and answered exactly like a hostname that does not
resolve (`ssl`: `502 SSL inspection failed`; `status`: a report whose
checks failed; a nameserver: `502 DNS resolution failed`), so the API
cannot be used to probe which internal names exist.

### Usage Examples

```bash
# Smart lookup
curl http://localhost:8000/lookup/example.com

# WHOIS lookup
curl http://localhost:8000/whois/example.com

# DNS query
curl http://localhost:8000/dns/example.com/MX

# DNS trace from the root servers down
curl "http://localhost:8000/dns/trace/www.example.com?record_type=AAAA"

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

Default: unset — no CORS headers, and (without `SEER_API_KEY`) requests
from non-loopback origins are refused. `*` is rejected at startup.

#### Rate Limiting

Every REST route has its own fixed per-client limit (e.g. `5/minute` for
`/audit`, `/subdomains`, `/takeover`, `/confusables` and `/dns/trace`),
counted per route — requests for different domains on the same route share
one budget, and an operation's `/bulk` and `/bulk/stream` routes share one
budget between them. A limit is per route, not per argument: `/subdomains`
is sized for its heavier `resolve=true` fan-out.

The expensive MCP tools carry the same limits as their REST routes
(`seer_subdomains` and `seer_audit` get `5/minute`, like `/subdomains` and
`/audit`), counted per client like REST — by client IP over HTTP; the stdio
server has one client.

`SEER_RATE_LIMIT` sets the per-client limit for the MCP endpoint
(`POST /mcp`); it does not change the REST limits. Use the
`<count>/<period>` format the `limits` library parses — several limits can
be combined with `;` (a bare number like `60` is rejected):

```bash
export SEER_RATE_LIMIT="60/minute;1000/day"
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
| `SEER_MCP_ALLOWED_HOSTS` | Comma-separated `Host:` values to allow (`host:*` matches any port). Setting this turns on the MCP SDK's DNS-rebinding protection, which then also checks `SEER_MCP_ALLOWED_ORIGINS`. |
| `SEER_MCP_ALLOWED_ORIGINS` | Comma-separated `Origin:` values to allow (browser hosts; `scheme://host:*` matches any port). Enforced even on its own and with `SEER_API_KEY` set; requests without an `Origin` (non-browser clients) are unaffected. |

### Available Tools

All 33 tools, on both transports:

| Tool | Description |
|------|-------------|
| `seer_lookup` | Smart domain lookup (RDAP → WHOIS fallback) |
| `seer_whois` | WHOIS lookup |
| `seer_rdap_domain` | RDAP domain lookup |
| `seer_rdap_ip` | RDAP IP lookup |
| `seer_rdap_asn` | RDAP ASN lookup |
| `seer_dig` | DNS query, as `dig` reports it (status, flags, CNAME chain, wildcard probe) |
| `seer_dns_trace` | Delegation trace from the root servers, like `dig +trace` |
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
| `seer_audit` | Graded security assessment across email, web, TLS, DNS, takeover and registration (`5/minute`) |
| `seer_takeover` | Subdomain takeover scan (HTTP-confirmed) |
| `seer_confusables` | Look-alike (typosquat) generation |
| `seer_tld_info` | TLD info (WHOIS server, RDAP endpoint) |
| `seer_tld_list` | Full TLD catalog |
| `seer_bulk_lookup` | Bulk smart lookups |
| `seer_bulk_whois` | Bulk WHOIS lookups |
| `seer_bulk_dig` | Bulk DNS queries |
| `seer_bulk_propagation` | Bulk propagation checks |
| `seer_bulk_status` | Bulk status checks |
| `seer_bulk_ssl` | Bulk SSL inspections |
| `seer_bulk_info` | Bulk domain info |
| `seer_bulk_availability` | Bulk availability checks |

Each tool's input schema is served by `tools/list` (defined in
`seer_api/mcp/server.py`). A failed call returns `isError: true` with the
reason and retry advice picked by the error's type: invalid input (fix the
arguments), transient (timeout, connection, rate limit: retry after a
backoff), permanent (unsupported TLD, unparseable response, TLS failure:
do not retry), or an upstream failure that may be either (retry at most
once).

Every tool is annotated read-only and non-destructive (`readOnlyHint`,
`destructiveHint: false`, `idempotentHint`), and open-world except
`seer_tld_list`, which reads embedded data only. The server also sends
`instructions` with its handshake: that results are untrusted third-party
data, and which tool fits which question.

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

The package's module layout (routers, MCP server, dispatch pool, rate
limiting, SSRF guards) is mapped in the repository's
[AGENTS.md](https://github.com/TheZacillac/seer/blob/main/AGENTS.md#seer-py-and-seer-api).

## Bulk Operation Limits

| Limit | Value |
|-------|-------|
| Max domains per request | 100 |
| Max concurrency | 50 |
| Default concurrency | 10 |
| Concurrent bulk jobs per worker (`SEER_MAX_CONCURRENT_BULK`) | 8 |

Every bulk job — a `/bulk` or `/bulk/stream` request, or an MCP
`seer_bulk_*` call — takes one of `SEER_MAX_CONCURRENT_BULK` slots for as
long as it runs, even after its client has gone (a running job cannot be
cancelled). A job that finds every slot busy waits; with
`SEER_REQUEST_TIMEOUT` set it gives up at the deadline with a `503` (MCP: a
"server busy" error to retry). The cap stays below `SEER_DISPATCH_THREADS`,
so batches can never take every thread from single-domain requests.
