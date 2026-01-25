"""MCP server implementation for Seer domain utilities."""

import json
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

import seer

mcp = Server("seer")


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
            name="seer_bulk_lookup",
            description="Smart lookup for multiple domains at once (tries RDAP first, falls back to WHOIS). Efficient for checking many domains.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domains": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of domain names to look up",
                    },
                    "concurrency": {
                        "type": "integer",
                        "description": "Number of concurrent requests (default: 10)",
                        "default": 10,
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
                    },
                    "concurrency": {
                        "type": "integer",
                        "description": "Number of concurrent requests (default: 10)",
                        "default": 10,
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
                    },
                    "record_type": {
                        "type": "string",
                        "description": "DNS record type (default: A)",
                        "default": "A",
                    },
                    "concurrency": {
                        "type": "integer",
                        "description": "Number of concurrent requests (default: 10)",
                        "default": 10,
                    },
                },
                "required": ["domains"],
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
            name="seer_bulk_status",
            description="Check health status for multiple domains at once. Returns HTTP, SSL, and expiration status for each domain.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domains": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of domain names to check",
                    },
                    "concurrency": {
                        "type": "integer",
                        "description": "Number of concurrent requests (default: 10)",
                        "default": 10,
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
                    },
                    "record_type": {
                        "type": "string",
                        "description": "DNS record type to check (default: A)",
                        "default": "A",
                    },
                    "concurrency": {
                        "type": "integer",
                        "description": "Number of concurrent requests (default: 5)",
                        "default": 5,
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
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]


async def execute_tool(name: str, arguments: dict[str, Any]) -> Any:
    """Execute the appropriate Seer function based on tool name."""
    match name:
        case "seer_lookup":
            return seer.lookup(arguments["domain"])

        case "seer_whois":
            return seer.whois(arguments["domain"])

        case "seer_rdap_domain":
            return seer.rdap_domain(arguments["domain"])

        case "seer_rdap_ip":
            return seer.rdap_ip(arguments["ip"])

        case "seer_rdap_asn":
            return seer.rdap_asn(arguments["asn"])

        case "seer_dig":
            return seer.dig(
                arguments["domain"],
                arguments.get("record_type", "A"),
                arguments.get("nameserver"),
            )

        case "seer_propagation":
            return seer.propagation(
                arguments["domain"],
                arguments.get("record_type", "A"),
            )

        case "seer_bulk_lookup":
            return seer.bulk_lookup(
                arguments["domains"],
                arguments.get("concurrency", 10),
            )

        case "seer_bulk_whois":
            return seer.bulk_whois(
                arguments["domains"],
                arguments.get("concurrency", 10),
            )

        case "seer_bulk_dig":
            return seer.bulk_dig(
                arguments["domains"],
                arguments.get("record_type", "A"),
                arguments.get("concurrency", 10),
            )

        case "seer_status":
            return seer.status(arguments["domain"])

        case "seer_bulk_status":
            return seer.bulk_status(
                arguments["domains"],
                arguments.get("concurrency", 10),
            )

        case "seer_bulk_propagation":
            return seer.bulk_propagation(
                arguments["domains"],
                arguments.get("record_type", "A"),
                arguments.get("concurrency", 5),
            )

        case _:
            raise ValueError(f"Unknown tool: {name}")


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await mcp.run(read_stream, write_stream, mcp.create_initialization_options())


def run():
    """Entry point for the MCP server."""
    import asyncio

    asyncio.run(main())


if __name__ == "__main__":
    run()
