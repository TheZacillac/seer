"""The bulk_* bindings must cap the number of domains (issue #58).

The binding is the real trust boundary for direct seer-py and MCP callers (the
MAX_BULK_DOMAINS limit otherwise lives only in the FastAPI router). An oversized
list must be rejected with ValueError *before* any lookups run, so these tests
are hermetic (no network).
"""

import pytest

import seer

MAX_BULK_DOMAINS = 100


def _too_many():
    return [f"d{i}.example" for i in range(MAX_BULK_DOMAINS + 1)]


@pytest.mark.parametrize(
    "func, args",
    [
        (lambda d: seer.bulk_lookup(d), None),
        (lambda d: seer.bulk_whois(d), None),
        (lambda d: seer.bulk_dig(d), None),
        (lambda d: seer.bulk_status(d), None),
        (lambda d: seer.bulk_ssl(d), None),
        (lambda d: seer.bulk_propagation(d), None),
        (lambda d: seer.bulk_availability(d), None),
    ],
)
def test_bulk_rejects_too_many_domains(func, args):
    with pytest.raises(ValueError):
        func(_too_many())


def test_bulk_accepts_under_limit():
    # An under-limit list must pass the cap guard. An empty list does no network
    # work, so this stays hermetic while still exercising the guard's happy path.
    result = seer.bulk_dig([])
    assert result is not None
