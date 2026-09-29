"""
Seer - Domain Name Helper

A high-performance domain name utility library for WHOIS, RDAP, DNS lookups,
and DNS propagation checking.

Example usage:
    import seer

    # WHOIS lookup
    result = seer.whois("example.com")
    print(result["registrar"])

    # DNS query, reported the way dig reports it
    result = seer.dig("google.com", "MX")
    print(result["status"])  # NOERROR, NXDOMAIN, SERVFAIL, ...
    for record in result["answers"]:
        print(record["name"], record["data"])

    # Delegation walk from the root servers down (dig +trace)
    trace = seer.dns_trace("www.example.com")
    for hop in trace["hops"]:
        print(hop["zone"], hop["server"], hop["status"])

    # DNS propagation check
    prop = seer.propagation("github.com", "A")
    print(f"Propagation: {prop['propagation_percentage']}%")

    # Bulk operations
    results = seer.bulk_whois(["google.com", "github.com", "cloudflare.com"])
"""

from seer._seer import (
    ConfigError,
    DnsError,
    LookupFailedError,
    ParseError,
    RateLimitedError,
    SeerError,
    TlsError,
    UpstreamError,
    WhoisServerNotFoundError,
    all_tlds,
    availability,
    bulk_availability,
    bulk_dig,
    bulk_info,
    bulk_lookup,
    bulk_propagation,
    bulk_ssl,
    bulk_status,
    bulk_whois,
    caa,
    cancel_follow,
    confusables,
    delegation,
    diff,
    dig,
    dns_compare,
    dns_follow,
    dns_trace,
    dnssec,
    headers,
    info,
    lookup,
    nameserver_target,
    posture,
    propagation,
    rdap_asn,
    rdap_auto,
    rdap_domain,
    rdap_ip,
    record_types,
    ssl,
    status,
    subdomains,
    subdomains_classify,
    takeover,
    tld_info,
    validate_public_host,
    whois,
)

# Errors: invalid input raises ValueError, a timeout TimeoutError, a WHOIS
# connect failure ConnectionError; every other failure raises a subclass of
# SeerError (itself a RuntimeError), e.g. RateLimitedError or DnsError.

# Importing seer._seer also installs the Rust -> Python `logging` bridge
# (see the #[pymodule_init] hook in seer-py/src/lib.rs).

# Auto-routing RDAP lookup for a domain, IP address, or ASN; routing happens
# in Rust (seer_core::rdap::classify), so `as1234.io` stays a domain lookup.
rdap = rdap_auto

try:
    from importlib.metadata import version
    # Distribution name on PyPI (the import name stays `seer`).
    __version__ = version("domain-seer")
except Exception:
    __version__ = "unknown"
__all__ = [
    "ConfigError",
    "DnsError",
    "LookupFailedError",
    "ParseError",
    "RateLimitedError",
    "SeerError",
    "TlsError",
    "UpstreamError",
    "WhoisServerNotFoundError",
    "all_tlds",
    "availability",
    "bulk_availability",
    "bulk_dig",
    "bulk_info",
    "bulk_lookup",
    "bulk_propagation",
    "bulk_ssl",
    "bulk_status",
    "bulk_whois",
    "caa",
    "cancel_follow",
    "confusables",
    "delegation",
    "diff",
    "dig",
    "dns_compare",
    "dns_follow",
    "dns_trace",
    "dnssec",
    "headers",
    "info",
    "lookup",
    "nameserver_target",
    "posture",
    "propagation",
    "rdap",
    "rdap_asn",
    "rdap_auto",
    "rdap_domain",
    "rdap_ip",
    "record_types",
    "ssl",
    "status",
    "subdomains",
    "subdomains_classify",
    "takeover",
    "tld_info",
    "validate_public_host",
    "whois",
]
