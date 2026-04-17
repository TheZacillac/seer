"""Shared helpers for SSE-streaming bulk endpoints.

Every streaming endpoint has the same shape: run a blocking `seer.bulk_*`
call in a worker thread, feed progress events onto an asyncio queue via a
Python callback, then emit per-item results as SSE events, and close with
a final `done` event.

Event ordering (see spec):
    progress × N  (streamed live as items complete)
    item × N      (emitted after the bulk call returns, in completion order)
    done × 1      (final)
"""

import asyncio
import json
import time
from collections.abc import AsyncGenerator, Callable
from typing import Any

from starlette.responses import StreamingResponse


def _sse(event: str, data: dict) -> bytes:
    """Format a single Server-Sent Event."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


async def stream_bulk(
    bulk_call: Callable[..., list[dict]],
    *args: Any,
    **kwargs: Any,
) -> StreamingResponse:
    """Run `bulk_call(*args, progress=cb, **kwargs)` in a worker thread and
    return a StreamingResponse that emits SSE events as items complete.

    The callable must accept a `progress` keyword argument matching the
    shape `(completed: int, total: int, domain: str) -> None`.
    """
    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_running_loop()
    started_at = time.monotonic()

    def progress_cb(completed: int, total: int, domain: str) -> None:
        # Called from a worker thread — use call_soon_threadsafe.
        loop.call_soon_threadsafe(
            queue.put_nowait,
            ("progress", {"completed": completed, "total": total, "current_domain": domain}),
        )

    bulk_future = loop.run_in_executor(
        None, lambda: bulk_call(*args, progress=progress_cb, **kwargs)
    )

    async def event_stream() -> AsyncGenerator[bytes, None]:
        # Phase 1: stream progress events until the bulk call finishes.
        pending_results: list[dict] | None = None
        while True:
            get_task = asyncio.create_task(queue.get())
            finished, _ = await asyncio.wait(
                {get_task, bulk_future},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if get_task in finished:
                event, payload = get_task.result()
                yield _sse(event, payload)
            else:
                get_task.cancel()
            if bulk_future.done():
                # Drain any remaining progress events that arrived after the
                # future completed but before we noticed.
                while not queue.empty():
                    event, payload = queue.get_nowait()
                    yield _sse(event, payload)
                pending_results = bulk_future.result()
                break

        # Phase 2: emit one `item` event per result.
        assert pending_results is not None
        succeeded = 0
        failed = 0
        for item in pending_results:
            if item.get("success"):
                succeeded += 1
            else:
                failed += 1
            yield _sse("item", item)

        # Phase 3: emit the terminal `done` event.
        yield _sse(
            "done",
            {
                "total": len(pending_results),
                "succeeded": succeeded,
                "failed": failed,
                "duration_ms": int((time.monotonic() - started_at) * 1000),
            },
        )

    return StreamingResponse(event_stream(), media_type="text/event-stream")
