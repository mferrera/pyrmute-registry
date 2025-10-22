"""Middleware for request logging with correlation ID support."""

import time
from collections.abc import Awaitable, Callable
from typing import Self

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from pyrmute_registry.server.logging import get_logger

logger = get_logger(__name__)


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
        start_time = time.time()

        logger.info(
            "request_started",
            method=request.method,
            path=request.url.path,
            query_params=str(request.query_params) if request.query_params else None,
            client_ip=request.client.host if request.client else None,
        )

        try:
            response = await call_next(request)
            duration = time.time() - start_time

            logger.info(
                "request_completed",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=round(duration * 1000, 2),
            )
            return response
        except Exception as e:
            duration = time.time() - start_time
            logger.exception(
                "request_failed",
                method=request.method,
                path=request.url.path,
                error=str(e),
                error_type=type(e).__name__,
                duration_ms=round(duration * 1000, 2),
            )
            raise
