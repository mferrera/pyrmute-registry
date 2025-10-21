"""Middleware for request logging."""

import logging
from collections.abc import Awaitable, Callable
from typing import Self

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log all requests and responses."""

    async def dispatch(
        self: Self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Log request and response details.

        Args:
            request: Incoming request.
            call_next: Next middleware/handler in chain.

        Returns:
            Response from handler.
        """
        logger.info(f"{request.method} {request.url.path}")

        try:
            response = await call_next(request)
            logger.info(f"{request.method} {request.url.path} - {response.status_code}")
            return response
        except Exception as e:
            logger.exception(
                f"{request.method} {request.url.path} - Error: {e!s}",
            )
            raise
