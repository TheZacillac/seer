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
    dig,
    propagation,
    status,
    bulk_lookup,
    bulk_whois,
    bulk_dig,
    bulk_propagation,
    bulk_status,
    bulk_availability,
    availability,
    subdomains,
    ssl,
    dnssec,
    dns_compare,
    dns_follow,
    diff,
    info,
    bulk_info,
)

# Forward Rust tracing events into Python logging.
# Must be called before any seer function so that the subscriber is installed.
from seer._seer import init_rust_logging as _init_rust_logging
_init_rust_logging()

try:
    from importlib.metadata import version
    __version__ = version("seer")
except Exception:
    __version__ = "unknown"
__all__ = [
    "lookup",
    "whois",
    "rdap_domain",
    "rdap_ip",
    "rdap_asn",
    "dig",
    "propagation",
    "status",
    "bulk_lookup",
    "bulk_whois",
    "bulk_dig",
    "bulk_propagation",
    "bulk_status",
    "bulk_availability",
    "availability",
    "subdomains",
    "ssl",
    "dnssec",
    "dns_compare",
    "dns_follow",
    "diff",
    "info",
    "bulk_info",
]


def rdap(query: str) -> dict:
    """
    Look up RDAP information for a domain, IP address, or ASN.

    Automatically detects the query type based on the format:
    - IP addresses (v4 or v6) -> IP lookup
    - ASN format (AS12345 or as12345) -> ASN lookup
    - Everything else -> Domain lookup

    Args:
        query: Domain name, IP address, or ASN (e.g., "example.com", "8.8.8.8", "AS15169")

    Returns:
        dict: RDAP response data
    """
    import ipaddress

    # Check if it's an IP address
    try:
        ipaddress.ip_address(query)
        return rdap_ip(query)
    except ValueError:
        pass

    # Check if it's an ASN
    if query.upper().startswith("AS"):
        try:
            asn = int(query[2:])
            return rdap_asn(asn)
        except ValueError:
            pass

    # Default to domain lookup
    return rdap_domain(query)
