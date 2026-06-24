"""Metrics endpoint-count cardinality is bounded (issue #46).

Keying `_endpoint_counts` on the concrete request path embedded the `{domain}`
path parameter, so a persistent client hitting `/lookup/r1`, `/lookup/r2`, …
grew the dict (and the `/metrics` body) without bound. Metrics must key on the
route template and stay bounded. These tests are hermetic (no network).
"""

from __future__ import annotations

from starlette.requests import Request

from seer_api.middleware import RequestMetrics, _route_label


def _request(scope_extra: dict) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/lookup/example.com",
        "headers": [],
        "query_string": b"",
    }
    scope.update(scope_extra)
    return Request(scope)


def test_route_label_uses_route_template_not_concrete_path():
    class _Route:
        path = "/lookup/{domain}"

    label = _route_label(_request({"route": _Route()}))
    assert label == "/lookup/{domain}", "must key on the route template"


def test_route_label_buckets_unmatched_paths():
    # 404s have no route in scope; they must collapse to one fixed label so an
    # attacker can't grow the dict with arbitrary unmatched paths.
    label = _route_label(_request({}))
    assert label == "<unmatched>"


def test_record_dict_is_bounded_under_distinct_paths():
    # Defense in depth: even if a high-cardinality label slips through, the dict
    # is capped (excess buckets under "<other>").
    m = RequestMetrics()
    for i in range(5000):
        m.record(f"/lookup/d{i}.example", 200, 1.0)
    snap = m.snapshot()
    assert len(snap["endpoints"]) <= 300, (
        f"endpoint dict must stay bounded, got {len(snap['endpoints'])}"
    )
    # Every request is still counted even when its key is bucketed.
    assert snap["total_requests"] == 5000
