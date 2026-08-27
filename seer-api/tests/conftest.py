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

    # Keep in sync with the #[pymodule] registrations in seer-py/src/lib.rs.
    # `validate_public_host` is intentionally NOT stubbed: test_hardening's
    # autouse `_real_seer_validator` fixture keys off the attribute being
    # absent to install a Python fallback validator for SSRF tests.
    for name in (
        "lookup",
        "whois",
        "rdap_domain",
        "rdap_ip",
        "rdap_asn",
        "rdap_auto",
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
        "bulk_availability",
        "availability",
        "subdomains",
        "subdomains_classify",
        "ssl",
        "dnssec",
        "delegation",
        "caa",
        "posture",
        "headers",
        "takeover",
        "confusables",
        "dns_compare",
        "dns_follow",
        "cancel_follow",
        "diff",
        "tld_info",
        "all_tlds",
    ):
        setattr(stub, name, _unused)

    # bulk_ssl needs a returning stub (parallel shape to a real bulk_*
    # result) so the validation/SSRF tests that exercise /ssl/bulk don't
    # blow up if a request makes it past the guard to the seer call.
    def _stub_bulk_ssl(domains, concurrency, progress=None):  # pragma: no cover
        results = []
        for idx, domain in enumerate(domains, start=1):
            if progress is not None:
                progress(idx, len(domains), domain)
            results.append(
                {
                    "success": True,
                    "data": {
                        "domain": domain,
                        "chain": [],
                        "san_names": [],
                        "is_valid": True,
                    },
                    "error": None,
                    "duration_ms": 0,
                    "operation": {"result_type": "ssl"},
                }
            )
        return results

    stub.bulk_ssl = _stub_bulk_ssl
    sys.modules["seer"] = stub


_install_seer_stub()


# These imports must come after _install_seer_stub(): importing seer_api.main
# pulls in the `seer` module, which must already be stubbed.
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from seer_api.main import app  # noqa: E402


@pytest.fixture
def client():
    return TestClient(app)
