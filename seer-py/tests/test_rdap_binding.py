"""Hermetic tests for seer.rdap / seer.rdap_auto.

``seer.rdap`` is an alias of the compiled ``rdap_auto``, so the Rust doc
comment on that binding is what ``help(seer.rdap)`` shows.
"""

import pytest

import seer


def test_rdap_is_an_alias_of_rdap_auto():
    assert seer.rdap is seer.rdap_auto
    assert {"rdap", "rdap_auto"} <= set(seer.__all__)


def test_rdap_docstring_documents_routing():
    doc = seer.rdap.__doc__
    for phrase in ("IP lookup", "ASN lookup", "domain lookup", "dict"):
        assert phrase in doc, phrase


def test_rdap_empty_query_raises_value_error():
    # seer_core::rdap::classify rejects it before any network I/O.
    with pytest.raises(ValueError):
        seer.rdap("   ")
