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

import _thread
import threading
import time

import pytest

import seer


def test_cancel_follow_is_safe_on_fresh_process():
    """`cancel_follow()` with no active `dns_follow` is a no-op and must not
    panic or raise. This exercises the poison-tolerant `lock_follow()` path
    against a freshly-initialized sender."""
    # Must not raise.
    seer.cancel_follow()


def test_keyboard_interrupt_cancels_follow():
    """Ctrl-C must interrupt a running `dns_follow` promptly.

    The follow used to run inside one GIL-released `block_on`, so a
    KeyboardInterrupt was only raised after the whole follow (up to 60
    minutes) had finished. `interrupt_main` raises the same pending SIGINT
    state Ctrl-C does. `.invalid` is answered by the resolver itself
    (RFC 6761), so no query leaves the host; the 30s interval is what would
    keep an uninterruptible call busy.
    """
    timer = threading.Timer(0.3, _thread.interrupt_main)
    start = time.monotonic()
    timer.start()
    try:
        with pytest.raises(KeyboardInterrupt):
            seer.dns_follow("seer-follow.invalid", iterations=2, interval_minutes=0.5)
    finally:
        timer.cancel()
    assert time.monotonic() - start < 5, "the follow was not interrupted promptly"
    # The single-follow guard is released: a new follow is not refused as
    # "already running" (it fails validation instead, before any I/O).
    with pytest.raises(ValueError):
        seer.dns_follow("seer-follow.invalid", iterations=-1)


@pytest.mark.live
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
