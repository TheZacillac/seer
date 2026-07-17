"""Router tests for the /tld endpoints.

Same hermetic pattern as test_intel_routers: monkeypatch the underlying seer
binding function and assert the route dispatches with the expected arguments,
rejects junk tokens with 400, and maps errors via ``http_error``.
"""

from __future__ import annotations

import pytest

import seer

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw_tld",
    ["com", ".com", "xn--p1ai", "CO", "travel"],
)
def test_tld_info_dispatches_plausible_tokens(client, monkeypatch, raw_tld):
    captured = {}

    def _stub(tld):
        captured["tld"] = tld
        return {"tld": tld.lstrip("."), "whois_server": None}

    monkeypatch.setattr(seer, "tld_info", _stub, raising=False)
    resp = client.get(f"/tld/{raw_tld}")
    assert resp.status_code == 200, (raw_tld, resp.text)
    # The route passes the raw token through; normalization (dot-strip,
    # lowercase) is seer-core's job.
    assert captured["tld"] == raw_tld


def test_tld_list_dispatches(client, monkeypatch):
    monkeypatch.setattr(
        seer, "all_tlds", lambda: ["com", "net", "org"], raising=False
    )
    resp = client.get("/tld/")
    assert resp.status_code == 200, resp.text
    assert resp.json() == ["com", "net", "org"]


# ---------------------------------------------------------------------------
# Validation: junk tokens must 400 before any seer dispatch.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "junk",
    [
        "bad_tld",  # underscore
        "-com",  # leading hyphen
        "com-",  # trailing hyphen
        "..com",  # double dot
        "exa!mple",  # punctuation
        "com.net",  # embedded dot (a domain, not a TLD)
    ],
)
def test_tld_info_rejects_junk_with_400(client, monkeypatch, junk):
    def _must_not_run(_tld):
        raise AssertionError("seer.tld_info must not be reached for junk input")

    monkeypatch.setattr(seer, "tld_info", _must_not_run, raising=False)
    resp = client.get(f"/tld/{junk}")
    assert resp.status_code == 400, (junk, resp.text)
    assert "invalid tld" in resp.json()["detail"].lower()


def test_tld_info_rejects_over_length_token(client):
    # 100 chars exceeds the Path max_length=64 → FastAPI 422.
    resp = client.get("/tld/" + "a" * 100)
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Error mapping: http_error must classify by exception type.
# ---------------------------------------------------------------------------


def test_tld_info_maps_timeout_to_504(client, monkeypatch):
    def _raising(_tld):
        raise TimeoutError("upstream hung")

    monkeypatch.setattr(seer, "tld_info", _raising, raising=False)
    resp = client.get("/tld/com")
    assert resp.status_code == 504
    assert resp.json()["detail"] == "request timed out"


def test_tld_info_maps_runtime_error_to_500_with_fallback(client, monkeypatch):
    def _raising(_tld):
        raise RuntimeError("internal detail must not leak")

    monkeypatch.setattr(seer, "tld_info", _raising, raising=False)
    resp = client.get("/tld/com")
    assert resp.status_code == 500
    detail = resp.json()["detail"]
    assert detail == "TLD lookup failed"
    assert "internal detail" not in detail
