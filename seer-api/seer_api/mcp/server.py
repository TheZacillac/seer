"""MCP server implementation for Seer domain utilities."""

import asyncio
import json
import logging
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

import seer

logger = logging.getLogger(__name__)

mcp = Server("seer")

MAX_BULK_DOMAINS = 100
MAX_CONCURRENCY = 50


def _require_str(arguments: dict[str, Any], key: str) -> str:
    """Extract and validate a required string argument."""
    value = arguments.get(key)
    if not value or not isinstance(value, str):
        raise ValueError(f"Required argument '{key}' is missing or empty")
    return value


def _require_domains(arguments: dict[str, Any]) -> list[str]:
    """Extract and validate a required domains list."""
    domains = arguments.get("domains")
    if not isinstance(domains, list) or len(domains) == 0:
        raise ValueError("'domains' must be a non-empty list")
    if len(domains) > MAX_BULK_DOMAINS:
        raise ValueError(f"'domains' list exceeds maximum of {MAX_BULK_DOMAINS}")
    for d in domains:
        if not isinstance(d, str) or not d.strip():
            raise ValueError("Each domain must be a non-empty string")
    return domains


def _get_concurrency(arguments: dict[str, Any], default: int = 10) -> int:
    """Extract and validate an optional concurrency argument."""
    concurrency = arguments.get("concurrency", default)
    if not isinstance(concurrency, int) or concurrency < 1:
        raise ValueError("'concurrency' must be a positive integer")
    return min(concurrency, MAX_CONCURRENCY)


@mcp.list_tools()
async def list_tools() -> list[Tool]:
    """List available Seer tools."""
    return [
        Tool(
            name="seer_lookup",
            description="Smart domain lookup that tries RDAP first (modern protocol with structured data) and falls back to WHOIS if RDAP is unavailable. Returns registration data with source indicator.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain name to look up (e.g., 'example.com')",
                    },
                },
                "required": ["domain"],
            },
        ),
        Tool(
            name="seer_whois",
            description="Look up WHOIS information for a domain name. Returns registrar, creation date, expiration date, nameservers, and status information.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain name to look up (e.g., 'example.com')",
                    },
                },
                "required": ["domain"],
            },
        ),
        Tool(
            name="seer_rdap_domain",
            description="Look up RDAP (Registration Data Access Protocol) information for a domain. Returns structured registration data including registrar, dates, nameservers, and DNSSEC status.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain name to look up",
                    },
                },
                "required": ["domain"],
            },
        ),
        Tool(
            name="seer_rdap_ip",
            description="Look up RDAP information for an IP address. Returns network registration information including the network range, country, and responsible organization.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IP address (IPv4 or IPv6) to look up",
                    },
                },
                "required": ["ip"],
            },
        ),
        Tool(
            name="seer_rdap_asn",
            description="Look up RDAP information for an Autonomous System Number (ASN). Returns organization and network range information.",
            inputSchema={
                "type": "object",
                "properties": {
                    "asn": {
                        "type": "integer",
                        "description": "AS number (e.g., 15169 for Google)",
                        "minimum": 0,
                        "maximum": 4294967295,
                    },
                },
                "required": ["asn"],
            },
        ),
        Tool(
            name="seer_dig",
            description="Query DNS records for a domain, similar to the 'dig' command. Supports all major record types.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain name to query",
                    },
                    "record_type": {
                        "type": "string",
                        "description": "DNS record type (A, AAAA, MX, TXT, NS, SOA, CNAME, CAA, PTR, SRV, ANY)",
                        "default": "A",
                    },
                    "nameserver": {
                        "type": "string",
                        "description": "Optional nameserver IP to query (e.g., '8.8.8.8')",
                    },
                },
                "required": ["domain"],
            },
        ),
        Tool(
            name="seer_propagation",
            description="Check DNS propagation for a domain across multiple global DNS servers. Shows which servers have the record and identifies inconsistencies.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain name to check",
                    },
                    "record_type": {
                        "type": "string",
                        "description": "DNS record type to check (default: A)",
                        "default": "A",
                    },
                },
                "required": ["domain"],
            },
        ),
        Tool(
            name="seer_status",
            description="Check the health status of a domain including HTTP accessibility, SSL certificate validity, and domain expiration.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain name to check (e.g., 'example.com')",
                    },
                },
                "required": ["domain"],
            },
        ),
        Tool(
            name="seer_bulk_lookup",
            description="Smart lookup for multiple domains at once (tries RDAP first, falls back to WHOIS). Efficient for checking many domains.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domains": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of domain names to look up",
                        "maxItems": MAX_BULK_DOMAINS,
                    },
                    "concurrency": {
                        "type": "integer",
                        "description": f"Number of concurrent requests (default: 10, max: {MAX_CONCURRENCY})",
                        "default": 10,
                        "minimum": 1,
                        "maximum": MAX_CONCURRENCY,
                    },
                },
                "required": ["domains"],
            },
        ),
        Tool(
            name="seer_bulk_whois",
            description="Look up WHOIS information for multiple domains at once. Efficient for checking many domains.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domains": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of domain names to look up",
                        "maxItems": MAX_BULK_DOMAINS,
                    },
                    "concurrency": {
                        "type": "integer",
                        "description": f"Number of concurrent requests (default: 10, max: {MAX_CONCURRENCY})",
                        "default": 10,
                        "minimum": 1,
                        "maximum": MAX_CONCURRENCY,
                    },
                },
                "required": ["domains"],
            },
        ),
        Tool(
            name="seer_bulk_dig",
            description="Query DNS records for multiple domains at once.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domains": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of domain names to query",
                        "maxItems": MAX_BULK_DOMAINS,
                    },
                    "record_type": {
                        "type": "string",
                        "description": "DNS record type (default: A)",
                        "default": "A",
                    },
                    "concurrency": {
                        "type": "integer",
                        "description": f"Number of concurrent requests (default: 10, max: {MAX_CONCURRENCY})",
                        "default": 10,
                        "minimum": 1,
                        "maximum": MAX_CONCURRENCY,
                    },
                },
                "required": ["domains"],
            },
        ),
        Tool(
            name="seer_bulk_status",
            description="Check health status for multiple domains at once. Returns HTTP, SSL, and expiration status for each domain.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domains": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of domain names to check",
                        "maxItems": MAX_BULK_DOMAINS,
                    },
                    "concurrency": {
                        "type": "integer",
                        "description": f"Number of concurrent requests (default: 10, max: {MAX_CONCURRENCY})",
                        "default": 10,
                        "minimum": 1,
                        "maximum": MAX_CONCURRENCY,
                    },
                },
                "required": ["domains"],
            },
        ),
        Tool(
            name="seer_bulk_propagation",
            description="Check DNS propagation for multiple domains at once across global DNS servers.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domains": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of domain names to check",
                        "maxItems": MAX_BULK_DOMAINS,
                    },
                    "record_type": {
                        "type": "string",
                        "description": "DNS record type to check (default: A)",
                        "default": "A",
                    },
                    "concurrency": {
                        "type": "integer",
                        "description": f"Number of concurrent requests (default: 5, max: {MAX_CONCURRENCY})",
                        "default": 5,
                        "minimum": 1,
                        "maximum": MAX_CONCURRENCY,
                    },
                },
                "required": ["domains"],
            },
        ),
    ]


@mcp.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Execute a Seer tool."""
    try:
        result = await execute_tool(name, arguments)
        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
    except ValueError as e:
        return [TextContent(type="text", text=f"Invalid input: {e}")]
    except Exception as e:
        logger.exception("Tool %s failed", name)
        return [TextContent(type="text", text="An internal error occurred while processing your request.")]


async def execute_tool(name: str, arguments: dict[str, Any]) -> Any:
    """Execute the appropriate Seer function based on tool name."""
    loop = asyncio.get_event_loop()

    match name:
        case "seer_lookup":
            domain = _require_str(arguments, "domain")
            return await loop.run_in_executor(None, seer.lookup, domain)

        case "seer_whois":
            domain = _require_str(arguments, "domain")
            return await loop.run_in_executor(None, seer.whois, domain)

        case "seer_rdap_domain":
            domain = _require_str(arguments, "domain")
            return await loop.run_in_executor(None, seer.rdap_domain, domain)

        case "seer_rdap_ip":
            ip = _require_str(arguments, "ip")
            return await loop.run_in_executor(None, seer.rdap_ip, ip)

        case "seer_rdap_asn":
            asn = arguments.get("asn")
            if not isinstance(asn, int) or asn < 0 or asn > 4294967295:
                raise ValueError(f"'asn' must be an integer between 0 and 4294967295 (got {asn!r})")
            return await loop.run_in_executor(None, seer.rdap_asn, asn)

        case "seer_dig":
            domain = _require_str(arguments, "domain")
            record_type = arguments.get("record_type", "A")
            nameserver = arguments.get("nameserver")
            return await loop.run_in_executor(
                None, seer.dig, domain, record_type, nameserver
            )

        case "seer_propagation":
            domain = _require_str(arguments, "domain")
            record_type = arguments.get("record_type", "A")
            return await loop.run_in_executor(
                None, seer.propagation, domain, record_type
            )

        case "seer_status":
            domain = _require_str(arguments, "domain")
            return await loop.run_in_executor(None, seer.status, domain)

        case "seer_bulk_lookup":
            domains = _require_domains(arguments)
            concurrency = _get_concurrency(arguments, default=10)
            return await loop.run_in_executor(
                None, seer.bulk_lookup, domains, concurrency
            )

        case "seer_bulk_whois":
            domains = _require_domains(arguments)
            concurrency = _get_concurrency(arguments, default=10)
            return await loop.run_in_executor(
                None, seer.bulk_whois, domains, concurrency
            )

        case "seer_bulk_dig":
            domains = _require_domains(arguments)
            record_type = arguments.get("record_type", "A")
            concurrency = _get_concurrency(arguments, default=10)
            return await loop.run_in_executor(
                None, seer.bulk_dig, domains, record_type, concurrency
            )

        case "seer_bulk_status":
            domains = _require_domains(arguments)
            concurrency = _get_concurrency(arguments, default=10)
            return await loop.run_in_executor(
                None, seer.bulk_status, domains, concurrency
            )

        case "seer_bulk_propagation":
            domains = _require_domains(arguments)
            record_type = arguments.get("record_type", "A")
            concurrency = _get_concurrency(arguments, default=5)
            return await loop.run_in_executor(
                None, seer.bulk_propagation, domains, record_type, concurrency
            )

        case _:
            raise ValueError(f"Unknown tool: {name}")


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await mcp.run(read_stream, write_stream, mcp.create_initialization_options())


def run():
    """Entry point for the MCP server."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
