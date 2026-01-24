# MCP Module

Model Context Protocol server for AI assistant integration.

## Overview

This module implements an MCP server that exposes Seer functionality as tools for AI assistants like Claude.

## Files

| File | Description |
|------|-------------|
| `__init__.py` | Module exports |
| `server.py` | MCP server implementation |

## MCP Server

### Starting the Server

```bash
seer-mcp
```

Or programmatically:

```python
from seer_api.mcp.server import run
run()
```

### Transport

Uses stdio transport for communication:
- Reads JSON-RPC requests from stdin
- Writes JSON-RPC responses to stdout

## Available Tools

### Domain Lookup Tools

| Tool | Description |
|------|-------------|
| `seer_lookup` | Smart lookup (RDAP with WHOIS fallback) |
| `seer_whois` | WHOIS lookup |
| `seer_rdap_domain` | RDAP domain lookup |
| `seer_rdap_ip` | RDAP IP lookup |
| `seer_rdap_asn` | RDAP ASN lookup |

### DNS Tools

| Tool | Description |
|------|-------------|
| `seer_dig` | DNS query |
| `seer_propagation` | DNS propagation check |

### Bulk Tools

| Tool | Description |
|------|-------------|
| `seer_bulk_lookup` | Bulk smart lookups |
| `seer_bulk_whois` | Bulk WHOIS lookups |
| `seer_bulk_dig` | Bulk DNS queries |

## Tool Definitions

### seer_lookup

```json
{
  "name": "seer_lookup",
  "description": "Smart domain lookup that tries RDAP first and falls back to WHOIS",
  "inputSchema": {
    "type": "object",
    "properties": {
      "domain": {
        "type": "string",
        "description": "Domain name to look up"
      }
    },
    "required": ["domain"]
  }
}
```

### seer_whois

```json
{
  "name": "seer_whois",
  "description": "Look up WHOIS information for a domain",
  "inputSchema": {
    "type": "object",
    "properties": {
      "domain": {
        "type": "string",
        "description": "Domain name to look up"
      }
    },
    "required": ["domain"]
  }
}
```

### seer_rdap_domain

```json
{
  "name": "seer_rdap_domain",
  "description": "Look up RDAP information for a domain",
  "inputSchema": {
    "type": "object",
    "properties": {
      "domain": {
        "type": "string",
        "description": "Domain name to look up"
      }
    },
    "required": ["domain"]
  }
}
```

### seer_rdap_ip

```json
{
  "name": "seer_rdap_ip",
  "description": "Look up RDAP information for an IP address",
  "inputSchema": {
    "type": "object",
    "properties": {
      "ip": {
        "type": "string",
        "description": "IP address to look up"
      }
    },
    "required": ["ip"]
  }
}
```

### seer_rdap_asn

```json
{
  "name": "seer_rdap_asn",
  "description": "Look up RDAP information for an ASN",
  "inputSchema": {
    "type": "object",
    "properties": {
      "asn": {
        "type": "integer",
        "description": "AS number (e.g., 15169)"
      }
    },
    "required": ["asn"]
  }
}
```

### seer_dig

```json
{
  "name": "seer_dig",
  "description": "Query DNS records for a domain",
  "inputSchema": {
    "type": "object",
    "properties": {
      "domain": {
        "type": "string",
        "description": "Domain name to query"
      },
      "record_type": {
        "type": "string",
        "description": "DNS record type",
        "default": "A"
      },
      "nameserver": {
        "type": "string",
        "description": "Optional nameserver IP"
      }
    },
    "required": ["domain"]
  }
}
```

### seer_propagation

```json
{
  "name": "seer_propagation",
  "description": "Check DNS propagation across global servers",
  "inputSchema": {
    "type": "object",
    "properties": {
      "domain": {
        "type": "string",
        "description": "Domain name to check"
      },
      "record_type": {
        "type": "string",
        "description": "DNS record type",
        "default": "A"
      }
    },
    "required": ["domain"]
  }
}
```

### seer_bulk_lookup

```json
{
  "name": "seer_bulk_lookup",
  "description": "Smart lookup for multiple domains",
  "inputSchema": {
    "type": "object",
    "properties": {
      "domains": {
        "type": "array",
        "items": {"type": "string"},
        "description": "List of domains"
      },
      "concurrency": {
        "type": "integer",
        "description": "Concurrent requests",
        "default": 10
      }
    },
    "required": ["domains"]
  }
}
```

## Integration

### Claude Desktop

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

### Custom Integration

```python
from mcp.server import Server
from mcp.server.stdio import stdio_server

# Create server
mcp = Server("seer")

# Register handlers
@mcp.list_tools()
async def list_tools():
    # Return tool definitions
    ...

@mcp.call_tool()
async def call_tool(name, arguments):
    # Execute tool
    ...

# Run server
async with stdio_server() as (read_stream, write_stream):
    await mcp.run(read_stream, write_stream, mcp.create_initialization_options())
```

## Response Format

Tool results are returned as JSON text content:

```json
{
  "type": "text",
  "text": "{\"domain\": \"example.com\", \"registrar\": \"...\"}"
}
```

Errors are also returned as text:

```json
{
  "type": "text",
  "text": "Error: Invalid domain format"
}
```
