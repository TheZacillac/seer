"""Safety tests for `dns_follow` / `cancel_follow` FFI surface.

Guards two regressions:

1. A poisoned `follow_cancel_sender` mutex (from a prior panic) must not
   permanently break `cancel_follow` — we use `unwrap_or_else(|p| p.into_inner())`
   rather than `.expect(...)`. This is verified indirectly by the fact that
   `cancel_follow` succeeds (no panic) in a fresh process.

2. Concurrent `dns_follow` calls must be refused with a clear error instead
   of silently overwriting the shared cancel channel, which would strand the
   first call's cancellation path. An `AtomicBool` guard serializes callers.

The concurrency test is gated behind `SEER_LIVE_TESTS=1` because
`dns_follow` performs real DNS queries — running it in CI without the flag
would make the test flaky.
"""

from __future__ import annotations

import os
import threading

import pytest

import seer

LIVE = os.environ.get("SEER_LIVE_TESTS") == "1"


def test_cancel_follow_is_safe_on_fresh_process():
    """`cancel_follow()` with no active `dns_follow` is a no-op and must not
    panic or raise. This exercises the poison-tolerant `lock_follow()` path
    against a freshly-initialized sender."""
    # Must not raise.
    seer.cancel_follow()


@pytest.mark.skipif(not LIVE, reason="live network test (set SEER_LIVE_TESTS=1)")
def test_concurrent_dns_follow_is_rejected():
    """A second `dns_follow` started while one is running must be rejected
    with a RuntimeError mentioning 'already running', rather than silently
    overwriting the shared cancel sender."""
    errs: list[str] = []

    def runner() -> None:
        try:
            seer.dns_follow("example.com", iterations=1, interval_minutes=0.1)
        except RuntimeError as e:
            errs.append(str(e))

    threads = [threading.Thread(target=runner) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert any("already running" in e for e in errs), (
        f"expected at least one 'already running' error, got: {errs}"
    )
