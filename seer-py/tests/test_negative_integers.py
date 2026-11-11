"""Out-of-range integer arguments raise ValueError, not OverflowError.

Concurrency, ASN and iteration counts used to be unsigned PyO3 parameters, so
``-1`` failed inside PyO3's conversion with an ``OverflowError`` that no caller
expects from input validation. They are validated as signed integers now. Every
check runs before any network I/O.
"""

import pytest

import seer


@pytest.mark.parametrize(
    "call",
    [
        lambda: seer.takeover("example.com", -1),
        lambda: seer.confusables("example.com", -1),
        lambda: seer.subdomains_classify("example.com", -1),
        lambda: seer.bulk_lookup(["example.com"], -1),
        lambda: seer.bulk_dig(["example.com"], "A", -1),
        lambda: seer.bulk_propagation(["example.com"], "A", -1),
        lambda: seer.rdap_asn(-1),
        lambda: seer.rdap_asn(2**32),
        lambda: seer.dns_follow("example.com", iterations=-1),
        # Too large for a 64-bit integer: PyO3's own conversion raised
        # OverflowError before any range check ran.
        lambda: seer.rdap_asn(2**64),
        lambda: seer.rdap_asn(-(2**64)),
        lambda: seer.takeover("example.com", 2**64),
        lambda: seer.confusables("example.com", 2**64),
        lambda: seer.subdomains_classify("example.com", 2**64),
        lambda: seer.bulk_lookup(["example.com"], 2**64),
        lambda: seer.bulk_dig(["example.com"], "A", 2**64),
        lambda: seer.bulk_propagation(["example.com"], "A", 2**64),
        lambda: seer.dns_follow("example.com", iterations=2**64),
    ],
)
def test_out_of_range_integer_is_value_error(call):
    with pytest.raises(ValueError):
        call()


def test_a_non_integer_is_still_a_type_error():
    with pytest.raises(TypeError):
        seer.rdap_asn("AS15169")
