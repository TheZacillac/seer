"""Shared pytest fixtures.

The real `seer` module is a compiled PyO3 extension that may not be
installed in minimal CI environments. Stub it with a no-op module so the
FastAPI app can be imported for unit tests that target routing, auth, and
validation behavior (none of which actually need to hit the network).
"""

from __future__ import annotations

import sys
import types


def _install_seer_stub() -> None:
    if "seer" in sys.modules:
        return
    # Prefer the real compiled module when it's importable. The streaming
    # integration test needs real bulk_* calls; other tests don't invoke
    # seer at all (they exercise validation/auth paths that short-circuit
    # before the router calls into seer).
    try:
        import seer  # noqa: F401
        return
    except ImportError:
        pass
    stub = types.ModuleType("seer")

    def _unused(*_args, **_kwargs):  # pragma: no cover - never hit in unit tests
        raise RuntimeError("seer stub should not be called in these tests")

    for name in (
        "lookup",
        "whois",
        "rdap_domain",
        "rdap_ip",
        "rdap_asn",
        "dig",
        "propagation",
        "status",
        "info",
        "bulk_lookup",
        "bulk_whois",
        "bulk_dig",
        "bulk_status",
        "bulk_propagation",
        "bulk_info",
    ):
        setattr(stub, name, _unused)
    sys.modules["seer"] = stub


_install_seer_stub()


import pytest
from fastapi.testclient import TestClient

from seer_api.main import app


@pytest.fixture
def client():
    return TestClient(app)
