"""Middleware for correlation ID management."""

import uuid
from collections.abc import Awaitable, Callable
from typing import Self

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from pyrmute_registry.server.logging import get_logger

logger = get_logger(__name__)


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Extract or generate correlation IDs and bind to logging context.

    This middleware:

    1. Extracts correlation ID from X-Correlation-ID or X-Request-ID headers
    2. Generates a new UUID if no ID provided
    3. Stores ID in request.state for other middleware
    4. Binds ID to structlog context for automatic inclusion in all logs
    5. Returns ID to client in X-Correlation-ID response header
    """

    async def dispatch(
        self: Self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Process request and manage correlation ID.

        Args:
            request: Incoming request.
            call_next: Next middleware/handler in chain.

        Returns:
            Response with X-Correlation-ID header.
        """
        correlation_id = (
            request.headers.get("x-correlation-id")
            or request.headers.get("x-request-id")
            or str(uuid.uuid4())
        )

        request.state.correlation_id = correlation_id

        # Bind to structlog context
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            correlation_id=correlation_id,
        )

        response = await call_next(request)

        response.headers["X-Correlation-ID"] = correlation_id

        return response
