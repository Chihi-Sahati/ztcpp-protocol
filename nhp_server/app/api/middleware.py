"""API middleware for the NHP-Server."""

from __future__ import annotations

import logging
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that logs all requests with timing information."""

    async def dispatch(self, request: Request, call_next) -> Response:
        """Log request method, path, and duration."""
        start_time = time.time()
        request_id = request.headers.get("x-request-id", "unknown")

        logger.info(
            "Request started: method=%s path=%s request_id=%s",
            request.method,
            request.url.path,
            request_id,
        )

        response = await call_next(request)

        duration_ms = (time.time() - start_time) * 1000
        logger.info(
            "Request completed: method=%s path=%s status=%d duration=%.2fms request_id=%s",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            request_id,
        )

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time-Ms"] = f"{duration_ms:.2f}"
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiter.

    Tracks request counts per client IP within a time window.
    If the limit is exceeded, returns HTTP 429 Too Many Requests.
    """

    def __init__(self, app, max_requests: int = 100, window_seconds: int = 60) -> None:
        super().__init__(app)
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._request_counts: dict[str, list[float]] = {}

    async def dispatch(self, request: Request, call_next) -> Response:
        """Check rate limit before processing the request."""
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()

        if client_ip not in self._request_counts:
            self._request_counts[client_ip] = []

        # Clean old entries
        self._request_counts[client_ip] = [
            ts for ts in self._request_counts[client_ip]
            if (now - ts) < self._window_seconds
        ]

        if len(self._request_counts[client_ip]) >= self._max_requests:
            logger.warning(
                "Rate limit exceeded for client_ip=%s (count=%d, max=%d)",
                client_ip,
                len(self._request_counts[client_ip]),
                self._max_requests,
            )
            from starlette.responses import JSONResponse
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": f"Rate limit of {self._max_requests} requests per {self._window_seconds}s exceeded",
                },
            )

        self._request_counts[client_ip].append(now)
        return await call_next(request)


class ZtcppSbaMediationMiddleware(BaseHTTPMiddleware):
    """ZTCPP 3GPP SBA Mediation Middleware.
    
    Enforces the Authenticated-before-Connect policy on 3GPP SBI (Service-Based Interface) interactions.
    Validates the presence and structure of ZTCPP-Auth-Context and ZTCPP-Flow-Bind headers.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        """Validate ZTCPP headers on SBA paths."""
        # Only apply to SBA paths
        if not request.url.path.startswith("/api/v1/sba/"):
            return await call_next(request)

        auth_context = request.headers.get("ztcpp-auth-context")
        flow_bind = request.headers.get("ztcpp-flow-bind")

        from starlette.responses import JSONResponse

        if not auth_context:
            logger.warning("Missing ZTCPP-Auth-Context header on SBA request")
            return JSONResponse(status_code=403, content={"error": "Missing ZTCPP-Auth-Context header"})

        if not flow_bind:
            logger.warning("Missing ZTCPP-Flow-Bind header on SBA request")
            return JSONResponse(status_code=403, content={"error": "Missing ZTCPP-Flow-Bind header"})

        # Validate flow_bind format (sha256=<hex-digest>;tunnel=<micro-tunnel-id>)
        if not (flow_bind.startswith("sha256=") and ";tunnel=" in flow_bind):
            logger.warning("Invalid ZTCPP-Flow-Bind header format")
            return JSONResponse(status_code=403, content={"error": "Invalid ZTCPP-Flow-Bind header format"})

        # In a real implementation, the SAT JWT inside auth_context would be fully verified here.
        # It should match the current micro-tunnel session and intent.

        return await call_next(request)
