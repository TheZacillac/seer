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
import logging
import time
from collections.abc import AsyncGenerator, Callable
from typing import Any

from starlette.responses import StreamingResponse

from ._env import env_int
from ._run import _DISPATCH_EXECUTOR
from .errors import safe_error_message

logger = logging.getLogger("seer_api")

# Cap concurrent in-flight bulk-stream jobs *per worker process*. A blocking
# bulk job dispatched to the executor cannot be cancelled, so a client that
# disconnects mid-stream still runs its job to completion. Without a bound, a
# flood of large requests that disconnect immediately would pin every dispatch
# thread and stall the whole API. Tunable via SEER_MAX_CONCURRENT_STREAMS.
_MAX_CONCURRENT_STREAMS = env_int("SEER_MAX_CONCURRENT_STREAMS", 8, min_value=1)
_stream_semaphore: asyncio.Semaphore | None = None
_stream_semaphore_loop: asyncio.AbstractEventLoop | None = None


def _get_stream_semaphore() -> asyncio.Semaphore:
    """Return the per-event-loop stream semaphore, creating it lazily.

    Built inside the running loop (not at import) so it binds to the correct
    loop, and rebuilt if the running loop changes (e.g. across test loops).
    """
    global _stream_semaphore, _stream_semaphore_loop
    loop = asyncio.get_running_loop()
    if _stream_semaphore is None or _stream_semaphore_loop is not loop:
        _stream_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_STREAMS)
        _stream_semaphore_loop = loop
    return _stream_semaphore


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

    # Acquire a slot before dispatching the (uncancellable) blocking job. A
    # client that disconnects mid-stream cannot stop the job, so this bound is
    # what prevents a disconnect-flood from pinning every dispatch thread.
    semaphore = _get_stream_semaphore()
    await semaphore.acquire()

    # Dispatch on the bounded seer-dispatch pool (see _run.py), not the
    # default asyncio executor. The default pool is shared with
    # ssrf.guard_async; a long bulk stream sitting on default-pool threads
    # would starve SSRF guards and stall /status, /ssl, etc. `run_seer`
    # can't be used here because it doesn't forward the `progress` kwarg.
    try:
        bulk_future = loop.run_in_executor(
            _DISPATCH_EXECUTOR, lambda: bulk_call(*args, progress=progress_cb, **kwargs)
        )
    except BaseException:
        semaphore.release()
        raise
    # Release the slot when the job actually finishes — even if the client has
    # already disconnected and the stream generator is never consumed.
    bulk_future.add_done_callback(lambda _f: semaphore.release())

    async def event_stream() -> AsyncGenerator[bytes, None]:
        # Phase 1: stream progress events until the bulk call finishes.
        pending_results: list[dict] | None = None
        pending_error: Exception | None = None
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
                try:
                    await get_task
                except asyncio.CancelledError:
                    pass
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
