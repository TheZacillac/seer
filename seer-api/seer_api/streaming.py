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
import contextlib
import json
import logging
import time
from collections.abc import AsyncGenerator, Callable
from typing import Any

from starlette.responses import StreamingResponse

from ._run import Deadline, dispatch_bulk
from .errors import safe_error_message

logger = logging.getLogger("seer_api")


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

    # One SEER_REQUEST_TIMEOUT budget covers the wait for a slot and the job:
    # a stream that outlives it ends with an `error` event.
    deadline = Deadline()

    # Take a bulk slot (shared with the sync /bulk routes and the MCP bulk
    # tools, see _run.py) and start the job on the dispatch pool. `run_bulk`
    # can't be used here because it doesn't forward the `progress` kwarg. No
    # slot before the deadline raises ServerBusy (a 503: nothing was sent).
    # A client that disconnects mid-stream cannot stop the job; the slot is
    # held until the job itself finishes.
    bulk_future = await dispatch_bulk(
        deadline, lambda: bulk_call(*args, progress=progress_cb, **kwargs)
    )

    async def event_stream() -> AsyncGenerator[bytes, None]:
        # Phase 1: stream progress events until the bulk call finishes.
        pending_results: list[dict] | None = None
        pending_error: Exception | None = None
        while True:
            get_task = asyncio.create_task(queue.get())
            finished, _ = await asyncio.wait(
                {get_task, bulk_future},
                timeout=deadline.remaining(),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not finished:
                # Deadline passed with the job still running. The job keeps
                # its slot until it finishes (it cannot be cancelled); the
                # client is released now.
                get_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await get_task
                logger.warning("bulk stream exceeded SEER_REQUEST_TIMEOUT")
                yield _sse("error", {"message": safe_error_message(TimeoutError())})
                return
            if get_task in finished:
                event, payload = get_task.result()
                yield _sse(event, payload)
            else:
                get_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await get_task
            if bulk_future.done():
                # Drain any remaining progress events that arrived after the
                # future completed but before we noticed.
                while not queue.empty():
                    event, payload = queue.get_nowait()
                    yield _sse(event, payload)
                try:
                    pending_results = bulk_future.result()
                except Exception as e:
                    pending_error = e
                break

        # Phase 2/3: item events + done event. If bulk_future raised, emit a
        # terminal `error` event so clients can tell the stream ended abnormally.
        # The streamed message is routed through ``safe_error_message`` — the
        # SSE event arrives after response headers have been sent, so we can
        # no longer upgrade the HTTP status and must instead ensure the body
        # never leaks internal paths, Rust panic strings, or tracebacks. The
        # full exception is logged server-side for diagnosis (H13).
        # Explicit `raise` rather than `assert` — `assert` is stripped under
        # `python -O`, which would let a logic bug fall into the
        # `pending_results` for-loop below with `None` and raise TypeError
        # to the client instead of being caught here.
        if pending_results is None and pending_error is None:
            raise RuntimeError(
                "unreachable: bulk future completed with no result and no error"
            )
        if pending_error is not None:
            logger.exception(
                "streaming bulk failure",
                exc_info=(
                    type(pending_error),
                    pending_error,
                    pending_error.__traceback__,
                ),
            )
            # SECURITY (#61, related to #49): the SSE error event must NEVER
            # carry an unsanitized core error — a third-party WHOIS/RDAP server's
            # error text can contain ANSI escapes or a resolved internal IP.
            # `safe_error_message` (sanitize + 200-char cap) is load-bearing
            # here; do not replace it with `str(pending_error)`.
            yield _sse(
                "error",
                {
                    "message": safe_error_message(
                        pending_error, fallback="bulk operation failed"
                    )
                },
            )
            return

        succeeded = 0
        failed = 0
        for item in pending_results:
            if item.get("success"):
                succeeded += 1
            else:
                failed += 1
            yield _sse("item", item)

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
