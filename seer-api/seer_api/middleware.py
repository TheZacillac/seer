"""Request logging and observability middleware."""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

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
        request_id = str(uuid.uuid4())[:8]
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
