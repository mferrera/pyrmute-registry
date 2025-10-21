"""Middleware for extracting/generating a correlation id."""

import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import Self

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Extract or generate correlation IDs for request tracing."""

    async def dispatch(
        self: Self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Extract or generate a correlation/request id.

        Args:
            request: Incoming request.
            call_next: Next middleware/handler in chain.

        Returns:
            Response from handler.
        """
        correlation_id = (
            request.headers.get("X-Correlation-ID")
            or request.headers.get("X-Request-ID")
            or str(uuid.uuid4())
        )
        request.state.correlation_id = correlation_id

        response = await call_next(request)

        response.headers["X-Correlation-ID"] = correlation_id
        return response
