"""seer-api takes its status codes and limits from seer-core.

The tables live in seer-core (`ErrorCategory`, `contract`) and reach Python
through the bindings; seer_api/_core.py loads them once. These tests pin
that nothing here re-defines them.
"""

from __future__ import annotations

import importlib
import pathlib
import re
import sys

import pytest

import seer

ROUTERS = pathlib.Path(__file__).resolve().parent.parent / "seer_api" / "routers"


def test_every_typed_error_keeps_its_status():
    from seer_api.errors import http_status_for

    expected = {
        ValueError: 400,
        TimeoutError: 504,
        ConnectionError: 502,
        seer.RateLimitedError: 429,
        seer.WhoisServerNotFoundError: 404,
        seer.DnsError: 502,
        seer.UpstreamError: 502,
        seer.LookupFailedError: 502,
        seer.ParseError: 502,
        seer.TlsError: 502,
        seer.ConfigError: 500,
        seer.SeerError: 500,
    }
    for exc_type, status in expected.items():
        assert http_status_for(exc_type("x")) == status, exc_type.__name__


def test_seer_api_own_errors_keep_their_status():
    from seer_api.errors import ServerBusy, ServiceUnavailable, http_status_for

    assert http_status_for(ServerBusy("busy")) == 503
    assert http_status_for(ServiceUnavailable("stale")) == 503
    assert http_status_for(RuntimeError("unclassified")) == 500


def test_status_table_is_cores_table():
    from seer_api import _core
    from seer_api.errors import _STATUS_BY_TYPE

    for row in _core.ERROR_STATUS_TABLE:
        assert row in _STATUS_BY_TYPE


def test_limits_come_from_core():
    from seer_api import _contract, errors

    contract = seer.contract()
    assert contract["domain_max_length"] == _contract.DOMAIN_MAX_LENGTH
    assert contract["nameserver_max_length"] == _contract.NAMESERVER_MAX_LENGTH
    assert contract["record_type_max_length"] == _contract.RECORD_TYPE_MAX_LENGTH
    assert contract["record_type_pattern"] == _contract.RECORD_TYPE_PATTERN
    assert contract["message_max_length"] == errors._MAX_MESSAGE_LEN
    limits = contract["rate_limits"]
    assert f"{limits['light']}/minute" == _contract.LIGHT_LIMIT
    assert f"{limits['standard']}/minute" == _contract.STANDARD_LIMIT
    assert f"{limits['moderate']}/minute" == _contract.MODERATE_LIMIT
    assert f"{limits['heavy']}/minute" == _contract.HEAVY_LIMIT


def test_clean_message_is_cores():
    from seer_api.errors import clean_message

    assert clean_message("a\r\n\x1b[31mb\x00") == "a[31mb"
    assert clean_message("\x00" * 500 + "x" * 300) == "x" * 200


def test_no_router_writes_a_rate_limit_by_hand():
    # Every REST limit is a named class from _contract, so the numbers exist
    # once (in seer-core). A literal "30/minute" in a router is a fork.
    literal = re.compile(r"""["']\d+/(second|minute|hour|day)["']""")
    offenders = [
        f"{path.name}:{number}"
        for path in sorted(ROUTERS.glob("*.py"))
        for number, line in enumerate(path.read_text().splitlines(), start=1)
        if literal.search(line) and not line.lstrip().startswith("#")
    ]
    assert offenders == []


def test_stale_binding_fails_with_rebuild_message(monkeypatch):
    # A compiled extension from before `seer.contract` existed must fail the
    # import with instructions, not a bare AttributeError.
    monkeypatch.delattr(seer, "contract")
    monkeypatch.delitem(sys.modules, "seer_api._core", raising=False)
    with pytest.raises(ImportError, match="maturin develop"):
        importlib.import_module("seer_api._core")
