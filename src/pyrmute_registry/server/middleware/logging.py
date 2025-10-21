"""Middleware for request logging with correlation ID support."""

import logging
from collections.abc import Awaitable, Callable
from typing import Self

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log all requests and responses with correlation IDs."""

    async def dispatch(
        self: Self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Log request and response details with correlation ID.

        Args:
            request: Incoming request.
            call_next: Next middleware/handler in chain.

        Returns:
            Response from handler.
        """
        correlation_id = getattr(request.state, "correlation_id", None)

        logger.info(
            f"[{correlation_id}] {request.method} {request.url.path}",
            extra={"correlation_id": correlation_id},
        )

        try:
            response = await call_next(request)
            logger.info(
                f"[{correlation_id}] {request.method} {request.url.path} - "
                f"{response.status_code}",
                extra={"correlation_id": correlation_id},
            )
            return response
        except Exception as e:
            logger.exception(
                f"[{correlation_id}] {request.method} {request.url.path} - "
                f"Error: {e!s}",
                extra={"correlation_id": correlation_id},
            )
            raise
