"""
Seer - Domain Name Helper

A high-performance domain name utility library for WHOIS, RDAP, DNS lookups,
and DNS propagation checking.

Example usage:
    import seer

    # WHOIS lookup
    result = seer.whois("example.com")
    print(result["registrar"])

    # DNS lookup
    records = seer.dig("google.com", "MX")
    for record in records:
        print(record["data"])

    # DNS propagation check
    prop = seer.propagation("github.com", "A")
    print(f"Propagation: {prop['propagation_percentage']}%")

    # Bulk operations
    results = seer.bulk_whois(["google.com", "github.com", "cloudflare.com"])
"""

from seer._seer import (
    lookup,
    whois,
    rdap_domain,
    rdap_ip,
    rdap_asn,
    rdap_auto,
    dig,
    propagation,
    status,
    bulk_lookup,
    bulk_whois,
    bulk_dig,
    bulk_propagation,
    bulk_status,
    bulk_ssl,
    bulk_availability,
    availability,
    subdomains,
    ssl,
    dnssec,
    dns_compare,
    dns_follow,
    cancel_follow,
    diff,
    info,
    bulk_info,
    validate_public_host,
)

# Forward Rust tracing events into Python logging.
# Must be called before any seer function so that the subscriber is installed.
from seer._seer import init_rust_logging as _init_rust_logging
_init_rust_logging()

try:
    from importlib.metadata import version
    # Distribution name on PyPI (the import name stays `seer`).
    __version__ = version("domain-seer")
except Exception:
    __version__ = "unknown"
__all__ = [
    "lookup",
    "whois",
    "rdap",
    "rdap_domain",
    "rdap_ip",
    "rdap_asn",
    "rdap_auto",
    "dig",
    "propagation",
    "status",
    "bulk_lookup",
    "bulk_whois",
    "bulk_dig",
    "bulk_propagation",
    "bulk_status",
    "bulk_ssl",
    "bulk_availability",
    "availability",
    "subdomains",
    "ssl",
    "dnssec",
    "dns_compare",
    "dns_follow",
    "cancel_follow",
    "diff",
    "info",
    "bulk_info",
    "validate_public_host",
]


def rdap(query: str) -> dict:
    """
    Look up RDAP information for a domain, IP address, or ASN.

    Automatically detects the query type based on the format:
    - IP addresses (v4 or v6) -> IP lookup
    - ASN format (AS12345 or as12345, no embedded dots) -> ASN lookup
    - Everything else -> Domain lookup

    Routing is performed in Rust by ``seer_core::rdap::classify`` so that
    domains starting with ``AS`` (e.g. ``as1234.io``) are handled correctly
    instead of being misrouted to the ASN endpoint.

    Args:
        query: Domain name, IP address, or ASN (e.g., "example.com", "8.8.8.8", "AS15169")

    Returns:
        dict: RDAP response data
    """
    return rdap_auto(query)
