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
    ],
)
def test_out_of_range_integer_is_value_error(call):
    with pytest.raises(ValueError):
        call()
