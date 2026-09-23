"""Shared pytest config for seer-py tests.

Tests that hit real DNS/HTTP/WHOIS servers are marked ``@pytest.mark.live``
and skipped unless ``SEER_LIVE_TESTS=1``, so a plain ``pytest`` stays
hermetic.
"""

import os

import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "live: needs the live network (SEER_LIVE_TESTS=1)")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    if os.environ.get("SEER_LIVE_TESTS") == "1":
        return
    skip = pytest.mark.skip(reason="live network test; set SEER_LIVE_TESTS=1 to run")
    for item in items:
        if item.get_closest_marker("live"):
            item.add_marker(skip)
