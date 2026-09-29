"""Helpers for dispatching blocking seer calls from async handlers.

Every FastAPI route and MCP tool that calls into the PyO3 bindings uses
``run_seer`` so the call runs on the bounded dispatch pool rather than
pinning the event loop thread. A request makes ONE ``run_seer`` call: its SSRF
pre-check runs in the same dispatch (``ssrf.guarded``), so the check and the
work share one thread and one ``SEER_REQUEST_TIMEOUT`` budget. Pure-data
bindings (``all_tlds``, ``record_types``) are called directly instead.

The pool is shared by single calls and bulk streams (``streaming.py``, which
caps its own share with ``SEER_MAX_CONCURRENT_STREAMS``). There is no separate
pool per operation class: every job is a bounded core call, and the deadline
below frees the client even when a job holds its thread for its full core
timeout.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any, TypeVar

from ._env import env_int

T = TypeVar("T")

# Cap the thread pool used for PyO3 dispatch. The asyncio default executor
# is unbounded — under a burst of concurrent requests we'd spawn one thread
# per pending lookup, each holding a Tokio runtime handle, ballooning
# memory and contention. Bound it at ``SEER_DISPATCH_THREADS`` (default 50,
# matching the bulk-concurrency cap) so a malicious traffic pattern can't
# drive thread-count growth at will.
_DISPATCH_THREADS = env_int("SEER_DISPATCH_THREADS", 50, min_value=1)
_DISPATCH_EXECUTOR = ThreadPoolExecutor(
    max_workers=_DISPATCH_THREADS, thread_name_prefix="seer-dispatch"
)

# Optional per-request deadline (seconds); 0 disables it. When set, a single
# stuck upstream (WHOIS/RDAP) returns a prompt 504 to the client instead of
# tying up a bounded dispatch thread for the full core timeout. The dispatch
# thread itself cannot be cancelled — it finishes on its own — but the client
# is freed deterministically, which is what an operator SLO cares about.
_REQUEST_TIMEOUT = env_int("SEER_REQUEST_TIMEOUT", 0, min_value=0)


class Deadline:
    """One ``SEER_REQUEST_TIMEOUT`` budget, started at construction.

    Everything a request waits on — a dispatch, a bulk stream's slot and its
    job — is bounded by the same deadline, so a request that waits on several
    things cannot take a multiple of the configured timeout.
    """

    def __init__(self) -> None:
        self._end = time.monotonic() + _REQUEST_TIMEOUT if _REQUEST_TIMEOUT > 0 else None

    def remaining(self) -> float | None:
        """Seconds left (never negative), or None when no timeout is set."""
        if self._end is None:
            return None
        return max(0.0, self._end - time.monotonic())

    async def bound(self, awaitable: Awaitable[T]) -> T:
        """Await ``awaitable`` within the remaining budget.

        Raises ``TimeoutError`` (mapped to HTTP 504 by ``errors.http_error``)
        once the deadline elapses.
        """
        remaining = self.remaining()
        if remaining is None:
            return await awaitable
        try:
            return await asyncio.wait_for(awaitable, timeout=remaining)
        # asyncio.TimeoutError is its own class before Python 3.11.
        except (asyncio.TimeoutError, TimeoutError) as exc:
            raise TimeoutError("request exceeded SEER_REQUEST_TIMEOUT") from exc


async def run_seer(fn: Callable[..., Any], *args: Any) -> Any:
    """Dispatch ``fn(*args)`` on the bounded seer-dispatch thread pool.

    The PyO3 seer bindings block on a tokio runtime via ``block_on``.
    Calling them directly from an async handler would pin the event
    loop thread. ``run_in_executor`` releases the loop for other
    requests while the lookup is in flight.

    Bounded by a fresh :class:`Deadline` when ``SEER_REQUEST_TIMEOUT`` is set.
    """
    loop = asyncio.get_running_loop()
    return await Deadline().bound(loop.run_in_executor(_DISPATCH_EXECUTOR, fn, *args))
