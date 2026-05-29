"""Request logging, body-size, and observability middleware."""

from __future__ import annotations

import logging
import re
import time
import uuid
from collections import defaultdict

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp, Receive, Scope, Send


# Default 64KB body cap — big enough for a bulk request of 100 domains
# (each bounded at 253 chars) with a bit of headroom, small enough to
# block the DoS vector where a 10MB JSON blob blocks the event loop
# while the parser chews through it.
DEFAULT_MAX_BODY_BYTES = 64 * 1024


class MaxBodySizeMiddleware:
    """Reject any request whose body exceeds ``max_bytes`` with 413.

    Two layers of enforcement:

    1. ``Content-Length`` header — if present and over the cap, reject
       before reading the body at all. Fast-path for clients that
       advertise their size honestly.
    2. Streaming byte-count — chunked requests and clients that lie
       about Content-Length are handled by wrapping ``receive`` and
       truncating the body after ``max_bytes``.

    Implemented as a bare ASGI middleware (not
    ``BaseHTTPMiddleware``) because we need to short-circuit the
    response before the request body is buffered (M6).
    """

    def __init__(self, app: ASGIApp, max_bytes: int = DEFAULT_MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Fast path: honest Content-Length header.
        headers = dict(scope.get("headers") or [])
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > self.max_bytes:
                    await self._send_too_large(send)
                    return
            except ValueError:
                # Malformed Content-Length — let Starlette reject it.
                pass

        # Streaming path: count bytes as we read. If we blow past the
        # cap mid-stream, reply 413 immediately and stop forwarding.
        total = 0
        over_limit = False

        async def receive_wrapper() -> dict:
            nonlocal total, over_limit
            message = await receive()
            if message.get("type") == "http.request":
                body = message.get("body") or b""
                total += len(body)
                if total > self.max_bytes:
                    over_limit = True
                    # Drain the rest so we don't leave bytes in the queue.
                    return {
                        "type": "http.request",
                        "body": b"",
                        "more_body": False,
                    }
            return message

        sent_response = False

        async def send_wrapper(message: dict) -> None:
            nonlocal sent_response
            if over_limit and not sent_response:
                sent_response = True
                await self._send_too_large(send)
                return
            if sent_response:
                return
            await send(message)

        # `try/finally` so the 413 always fires when the body went over,
        # even if the downstream app raises an unhandled exception
        # (rare — FastAPI's exception handlers convert most failures into
        # responses that flow through `send_wrapper` — but a bare ASGI
        # exception would otherwise produce a 500 instead of 413).
        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        finally:
            if over_limit and not sent_response:
                sent_response = True
                try:
                    await self._send_too_large(send)
                except Exception:
                    # Best-effort: if the ASGI server has already given up,
                    # don't mask the original failure.
                    pass

    @staticmethod
    async def _send_too_large(send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b'{"detail":"request body too large"}',
            }
        )

try:
    from arcanum._logging import set_correlation_id
except ImportError:
    def set_correlation_id(cid=None):
        return cid or uuid.uuid4().hex[:16]

logger = logging.getLogger("seer_api")


class RequestMetrics:
    """Request metrics collector.

    Safe for single-threaded async use (uvicorn default). For multi-worker
    deployments each worker maintains its own counters; use an external
    metrics backend (Prometheus, StatsD) for aggregated metrics.
    """

    def __init__(self):
        self._total_requests = 0
        self._total_errors = 0
        self._status_counts: dict[int, int] = defaultdict(int)
        self._endpoint_counts: dict[str, int] = defaultdict(int)
        self._total_latency_ms = 0.0

    def record(self, path: str, status_code: int, latency_ms: float):
        self._total_requests += 1
        self._status_counts[status_code] += 1
        self._endpoint_counts[path] += 1
        self._total_latency_ms += latency_ms
        if status_code >= 400:
            self._total_errors += 1

    def snapshot(self) -> dict:
        avg_latency = (
            self._total_latency_ms / self._total_requests
            if self._total_requests > 0
            else 0
        )
        return {
            "total_requests": self._total_requests,
            "total_errors": self._total_errors,
            "avg_latency_ms": round(avg_latency, 2),
            "status_codes": dict(self._status_counts),
            "endpoints": dict(self._endpoint_counts),
        }


# Global metrics instance
metrics = RequestMetrics()


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that logs requests with timing and adds request IDs."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Sanitize X-Correlation-ID: strip non-printable/control characters
        # (prevents log injection via embedded CR/LF) and cap length.
        raw = request.headers.get("X-Correlation-ID", "")
        request_id = re.sub(r"[^\x21-\x7E]", "", raw)[:64] or uuid.uuid4().hex[:8]
        set_correlation_id(request_id)
        start_time = time.monotonic()

        # Add request ID to state for downstream use
        request.state.request_id = request_id

        try:
            response = await call_next(request)
        except Exception:
            latency_ms = (time.monotonic() - start_time) * 1000
            metrics.record(request.url.path, 500, latency_ms)
            logger.exception(
                "request_id=%s method=%s path=%s status=500 latency_ms=%.1f",
                request_id,
                request.method,
                request.url.path,
                latency_ms,
            )
            raise

        latency_ms = (time.monotonic() - start_time) * 1000
        metrics.record(request.url.path, response.status_code, latency_ms)

        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id

        # Log at appropriate level
        log_level = logging.WARNING if response.status_code >= 400 else logging.INFO
        logger.log(
            log_level,
            "request_id=%s method=%s path=%s status=%d latency_ms=%.1f",
            request_id,
            request.method,
            request.url.path,
            response.status_code,
            latency_ms,
        )

        return response
