"""`seer.normalize_host` is seer-core's own probe-target normalization.

seer-api uses it to recognize an IP literal in any spelling core would reduce
to one, so its SSRF pre-check and core cannot disagree. Pure; no network I/O.
"""

import pytest

import seer


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("127.0.0.1.", "127.0.0.1"),
        ("127.0.0.1:443", "127.0.0.1"),
        ("x@127.0.0.1", "127.0.0.1"),
        (" 127.0.0.1", "127.0.0.1"),
        ("https://WWW.Example.com/path", "www.example.com"),
    ],
)
def test_normalizes_like_core(raw, normalized):
    assert seer.normalize_host(raw) == normalized


@pytest.mark.parametrize("raw", ["", "[::1]", "not a host", "fe80::1%eth0"])
def test_invalid_input_is_none(raw):
    assert seer.normalize_host(raw) is None
