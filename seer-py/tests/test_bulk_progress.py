"""Integration tests for the optional progress= kwarg on bulk_* functions."""

import pytest

import seer


def test_progress_callback_invoked_once_per_item():
    """The callback should fire exactly once per completed item, 1-indexed."""
    calls = []
    domains = ["example.com", "iana.org"]

    seer.bulk_status(
        domains,
        concurrency=2,
        progress=lambda completed, total, domain: calls.append(
            (completed, total, domain)
        ),
    )

    assert len(calls) == len(domains), (
        f"expected {len(domains)} callback calls, got {len(calls)}: {calls}"
    )
    totals = {c[1] for c in calls}
    assert totals == {len(domains)}, f"total mismatch: {totals}"
    completed_values = sorted(c[0] for c in calls)
    assert completed_values == list(range(1, len(domains) + 1)), (
        f"completed values should be 1..N, got {completed_values}"
    )
    callback_domains = {c[2] for c in calls}
    assert callback_domains == set(domains), (
        f"domain set mismatch: {callback_domains} vs {set(domains)}"
    )


def test_progress_callback_exceptions_are_swallowed():
    """A raising callback must not kill the bulk run."""
    attempts = []

    def raising_cb(completed, total, domain):
        attempts.append(domain)
        raise RuntimeError("intentional test failure")

    results = seer.bulk_status(
        ["example.com", "iana.org"],
        concurrency=2,
        progress=raising_cb,
    )

    assert len(results) == 2, f"expected 2 results, got {len(results)}"
    assert len(attempts) == 2, (
        f"callback should still have been invoked twice, got {len(attempts)}"
    )


def test_progress_kwarg_is_optional():
    """Omitting progress= should preserve today's behavior."""
    results = seer.bulk_status(["example.com"], concurrency=1)
    assert len(results) == 1
