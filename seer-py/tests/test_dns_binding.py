"""Real-binding tests for seer.dig and seer.dns_trace.

Both answer from the network (a recursive resolver, or the root servers and
each zone's own nameservers), so their end-to-end tests are live-gated per
repo convention. The hermetic tests pin the binding surface: the callables
and their defaults, and that seer-core rejects invalid input with ValueError
before any network I/O and refuses a reserved nameserver before sending a
query.
"""

import inspect

import pytest

import seer

# Every key of a dig result (seer_core::dns::DnsQueryResult).
DIG_KEYS = {
    "name",
    "record_type",
    "server",
    "status",
    "flags",
    "answers",
    "authority",
    "wildcard",
    "query_time_ms",
}

# Every key of a trace (seer_core::dns::DnsTrace) and of each of its hops.
TRACE_KEYS = {"name", "record_type", "hops", "status", "answers", "error"}
HOP_KEYS = {
    "zone",
    "server",
    "address",
    "query_time_ms",
    "status",
    "authoritative",
    "referral_zone",
    "referral",
    "answers",
    "failed_servers",
}

BAD_NAMES = ["", "no-dots", "not a domain!!", "..double.dot"]


def _defaults(fn) -> dict:
    return {
        name: param.default
        for name, param in inspect.signature(fn).parameters.items()
        if param.default is not inspect.Parameter.empty
    }


@pytest.mark.parametrize("name", ["dig", "dns_trace"])
def test_is_exported(name):
    assert callable(getattr(seer, name))
    assert name in seer.__all__


def test_dig_signature_defaults():
    assert _defaults(seer.dig) == {"record_type": "A", "nameserver": None}


def test_dns_trace_signature_defaults():
    # A trace has no nameserver: it asks each zone's own servers.
    assert list(inspect.signature(seer.dns_trace).parameters) == ["domain", "record_type"]
    assert _defaults(seer.dns_trace) == {"record_type": "A"}


# --- dig ----------------------------------------------------------------------


@pytest.mark.parametrize("bad", BAD_NAMES)
def test_dig_invalid_name_raises_value_error(bad):
    with pytest.raises(ValueError):
        seer.dig(bad)


def test_dig_validates_the_name_before_the_nameserver():
    # A reserved nameserver is a RuntimeError, but the name is checked first:
    # a bad name must never cost a nameserver lookup.
    with pytest.raises(ValueError):
        seer.dig("not a domain!!", "A", "127.0.0.1")


def test_dig_unknown_record_type_raises_value_error():
    with pytest.raises(ValueError):
        seer.dig("example.com", "BOGUS")


@pytest.mark.parametrize("spec", ["127.0.0.1", "10.0.0.1:5353", "tls://169.254.169.254"])
def test_dig_reserved_nameserver_is_refused_without_leaking_it(spec):
    # SSRF guard on the query path: an IP-literal spec is vetted without any
    # DNS round-trip, so this stays hermetic. The refusal is a DnsError,
    # surfaced with its sanitized message only.
    with pytest.raises(RuntimeError) as exc:
        seer.dig("example.com", "A", spec)
    assert str(exc.value) == "DNS resolution failed"


# --- dns_trace ----------------------------------------------------------------


@pytest.mark.parametrize("bad", BAD_NAMES)
def test_dns_trace_invalid_name_raises_value_error(bad):
    with pytest.raises(ValueError):
        seer.dns_trace(bad)


def test_dns_trace_any_raises_value_error():
    # ANY is a fan-out over several queries; a trace follows one type.
    with pytest.raises(ValueError) as exc:
        seer.dns_trace("example.com", "ANY")
    assert "single record type" in str(exc.value)


def test_dns_trace_bare_srv_raises_value_error():
    with pytest.raises(ValueError) as exc:
        seer.dns_trace("example.com", "SRV")
    assert "_service._proto" in str(exc.value)


def test_dns_trace_unknown_record_type_raises_value_error():
    with pytest.raises(ValueError):
        seer.dns_trace("example.com", "BOGUS")


# --- live ---------------------------------------------------------------------


@pytest.mark.live
def test_dig_live_positive_shape():
    result = seer.dig("example.com")
    assert set(result) == DIG_KEYS
    assert result["name"] == "example.com"
    assert result["record_type"] == "A"
    assert result["server"] is None
    assert result["status"] == "NOERROR"
    assert "qr" in result["flags"]
    assert result["answers"], "example.com has A records"
    for record in result["answers"]:
        assert record["record_type"] == "A"
        assert record["name"] == "example.com"
    # example.com is its own registrable domain: no wildcard probe runs.
    assert result["wildcard"] is None
    assert isinstance(result["query_time_ms"], int)


@pytest.mark.live
def test_dig_live_nameserver_is_echoed_as_given():
    result = seer.dig("example.com", "A", "1.1.1.1")
    assert result["server"] == "1.1.1.1"
    assert result["status"] == "NOERROR"


@pytest.mark.live
def test_dig_live_probes_a_sibling_below_the_registrable_domain():
    result = seer.dig("www.example.com")
    assert result["status"] == "NOERROR"
    probe = result["wildcard"]
    assert set(probe) == {"probe_name", "present", "matches_answer"}
    assert probe["probe_name"].startswith("seer-probe-")
    assert probe["probe_name"].endswith(".example.com")


@pytest.mark.live
def test_dig_live_nxdomain_is_a_result_not_an_exception():
    # .invalid never exists (RFC 6761). Not a name under example.com: its
    # signed zone answers missing names with NODATA (minimal "black lies"
    # denial), not NXDOMAIN.
    result = seer.dig("seer-live-test.invalid")
    assert result["status"] == "NXDOMAIN"
    assert result["answers"] == []
    assert result["wildcard"] is None


@pytest.mark.live
def test_dig_live_nodata_is_noerror_without_answers():
    result = seer.dig("example.com", "NAPTR")
    assert result["status"] == "NOERROR"
    assert result["answers"] == []


@pytest.mark.live
def test_dns_trace_live_walks_from_the_root():
    # Needs direct port-53 access to the root and TLD servers: on a network
    # that intercepts DNS, the "root" answers recursively in a single hop.
    trace = seer.dns_trace("example.com")
    assert set(trace) == TRACE_KEYS
    assert trace["name"] == "example.com"
    assert trace["record_type"] == "A"
    assert trace["error"] is None
    hops = trace["hops"]
    assert [hop["zone"] for hop in hops[:2]] == [".", "com."]
    for hop in hops:
        assert set(hop) == HOP_KEYS
    assert hops[0]["referral_zone"] == "com."
    assert hops[-1]["authoritative"] is True
    assert trace["status"] == "NOERROR"
    assert trace["answers"]
