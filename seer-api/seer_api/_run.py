"""Helpers for dispatching blocking seer calls from async handlers.

Every FastAPI route and MCP tool that calls into the PyO3 bindings uses
``run_seer`` (a bulk job: ``run_bulk``) so the call runs on the bounded
dispatch pool rather than pinning the event loop thread. A request makes ONE
dispatch: its SSRF pre-check runs in the same call (``ssrf.guarded``), so the
check and the work share one thread and one ``SEER_REQUEST_TIMEOUT`` budget.
Pure-data bindings (``all_tlds``, ``record_types``) are called directly instead.

The pool is shared by single calls and bulk jobs. A bulk job holds one
dispatch thread for its whole batch and cannot be cancelled, so every bulk
job — sync ``/bulk``, ``/bulk/stream`` (``streaming.py``) and the MCP
``seer_bulk_*`` tools — first takes a slot from one shared cap,
``SEER_MAX_CONCURRENT_BULK``, kept below the pool size: a client staying
inside its rate limits cannot pin every thread with batches and stall the
single-domain routes. There is no separate pool per operation class: every
job is a bounded core call, and the deadline below frees the client even when
a job holds its thread for its full core timeout.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import logging
import os
import time
from collections.abc import Awaitable, Callable
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, TypeVar

from ._env import env_int
from .errors import ServerBusy

T = TypeVar("T")

logger = logging.getLogger("seer_api")

# Cap the thread pool used for PyO3 dispatch. The asyncio default executor
# is unbounded — under a burst of concurrent requests we'd spawn one thread
# per pending lookup, each holding a Tokio runtime handle, ballooning
# memory and contention. Bound it at ``SEER_DISPATCH_THREADS`` (default 50,
# matching the bulk-concurrency cap) so a malicious traffic pattern can't
# drive thread-count growth at will. At least 2: one for bulk jobs, one kept
# for everything else (see `_bulk_cap`).
_DISPATCH_THREADS = env_int("SEER_DISPATCH_THREADS", 50, min_value=2)
_DISPATCH_EXECUTOR = ThreadPoolExecutor(
    max_workers=_DISPATCH_THREADS, thread_name_prefix="seer-dispatch"
)

# Optional per-request deadline (seconds); 0 disables it. When set, a single
# stuck upstream (WHOIS/RDAP) returns a prompt 504 to the client instead of
# tying up a bounded dispatch thread for the full core timeout. The dispatch
# thread itself cannot be cancelled — it finishes on its own — but the client
# is freed deterministically, which is what an operator SLO cares about.
_REQUEST_TIMEOUT = env_int("SEER_REQUEST_TIMEOUT", 0, min_value=0)


def _bulk_cap(dispatch_threads: int) -> int:
    """Concurrent bulk jobs allowed per worker process.

    ``SEER_MAX_CONCURRENT_BULK``, falling back to ``SEER_MAX_CONCURRENT_STREAMS``
    (its name from when only SSE streams were capped), default 8. Clamped to
    ``dispatch_threads - 1`` so a saturated cap always leaves the single-domain
    routes a thread.
    """
    name = (
        "SEER_MAX_CONCURRENT_BULK"
        if (os.environ.get("SEER_MAX_CONCURRENT_BULK") or "").strip()
        else "SEER_MAX_CONCURRENT_STREAMS"
    )
    configured = env_int(name, 8, min_value=1)
    cap = min(configured, dispatch_threads - 1)
    if cap < configured:
        logger.warning(
            "%s=%d leaves no dispatch thread for single-domain requests; "
            "using %d (SEER_DISPATCH_THREADS=%d minus one)",
            name,
            configured,
            cap,
            dispatch_threads,
        )
    return cap


_MAX_CONCURRENT_BULK = _bulk_cap(_DISPATCH_THREADS)
_bulk_semaphore: asyncio.Semaphore | None = None
_bulk_semaphore_loop: asyncio.AbstractEventLoop | None = None


def _bulk_slots() -> asyncio.Semaphore:
    """The per-event-loop bulk-slot semaphore, created lazily.

    Built inside the running loop (not at import) so it binds to the correct
    loop, and rebuilt if the running loop changes (e.g. across test loops).
    """
    global _bulk_semaphore, _bulk_semaphore_loop
    loop = asyncio.get_running_loop()
    if _bulk_semaphore is None or _bulk_semaphore_loop is not loop:
        _bulk_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_BULK)
        _bulk_semaphore_loop = loop
    return _bulk_semaphore


class Deadline:
    """One ``SEER_REQUEST_TIMEOUT`` budget, started at construction.

    Everything a request waits on — a dispatch, a bulk job's slot and the job
    itself — is bounded by the same deadline, so a request that waits on
    several things cannot take a multiple of the configured timeout.
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
    A bulk binding goes through :func:`run_bulk` instead.
    """
    loop = asyncio.get_running_loop()
    return await Deadline().bound(loop.run_in_executor(_DISPATCH_EXECUTOR, fn, *args))


async def dispatch_bulk(deadline: Deadline, call: Callable[[], T]) -> asyncio.Future[T]:
    """Take a bulk slot, then start ``call()`` on the dispatch pool.

    Waiting for the slot is bounded by ``deadline``; running out of it there
    raises :class:`ServerBusy` (HTTP 503) — nothing has started, so the client
    can simply retry. Without a deadline the job queues until a slot frees.
    Returns the job's future, not awaited.

    The slot is released when the job ends in its thread — not when the
    awaiting client gives up (deadline, disconnect, cancellation): a running
    job cannot be cancelled, and it holds its thread until it ends.
    """
    loop = asyncio.get_running_loop()
    slots = _bulk_slots()
    try:
        await deadline.bound(slots.acquire())
    except TimeoutError:
        raise ServerBusy(
            f"server busy: all {_MAX_CONCURRENT_BULK} bulk job slots are in use; "
            "retry later"
        ) from None

    def release(_job: Future) -> None:
        # Runs in the job's thread. A loop that has since closed has no
        # waiters left to wake.
        with contextlib.suppress(RuntimeError):
            loop.call_soon_threadsafe(slots.release)

    try:
        job = _DISPATCH_EXECUTOR.submit(call)
    except BaseException:
        slots.release()
        raise
    job.add_done_callback(release)
    return asyncio.wrap_future(job, loop=loop)


async def run_bulk(fn: Callable[..., T], *args: Any) -> T:
    """:func:`run_seer` for a bulk binding: the job takes a bulk slot first.

    One :class:`Deadline` covers the wait for a slot (:class:`ServerBusy`
    when it runs out) and the job (``TimeoutError``).
    """
    deadline = Deadline()
    job = await dispatch_bulk(deadline, functools.partial(fn, *args))
    return await deadline.bound(job)
