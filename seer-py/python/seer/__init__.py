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
    whois,
    rdap_domain,
    rdap_ip,
    rdap_asn,
    dig,
    propagation,
    bulk_whois,
    bulk_dig,
    bulk_propagation,
)

try:
    from importlib.metadata import version
    __version__ = version("seer")
except Exception:
    __version__ = "unknown"
__all__ = [
    "whois",
    "rdap_domain",
    "rdap_ip",
    "rdap_asn",
    "dig",
    "propagation",
    "bulk_whois",
    "bulk_dig",
    "bulk_propagation",
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
