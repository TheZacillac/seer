"""Helpers for dispatching blocking seer calls from async handlers.

Every FastAPI route that calls into the PyO3 bindings must use
``run_seer`` so the call runs on the default executor's thread pool
rather than pinning the event loop thread.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from ._env import env_int

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


async def run_seer(fn: Callable[..., Any], *args: Any) -> Any:
    """Dispatch ``fn(*args)`` on the bounded seer-dispatch thread pool.

    The PyO3 seer bindings block on a tokio runtime via ``block_on``.
    Calling them directly from an async handler would pin the event
    loop thread. ``run_in_executor`` releases the loop for other
    requests while the lookup is in flight.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_DISPATCH_EXECUTOR, fn, *args)
