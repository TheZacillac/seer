"""Helpers for dispatching blocking seer calls from async handlers.

Every FastAPI route that calls into the PyO3 bindings must use
``run_seer`` so the call runs on the default executor's thread pool
rather than pinning the event loop thread.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable


async def run_seer(fn: Callable[..., Any], *args: Any) -> Any:
    """Dispatch ``fn(*args)`` on the default thread pool executor.

    The PyO3 seer bindings block on a tokio runtime via ``block_on``.
    Calling them directly from an async handler would pin the event
    loop thread. ``run_in_executor`` releases the loop for other
    requests while the lookup is in flight.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, fn, *args)
