"""Centralized logging configuration with structlog."""

import logging
import sys
from typing import TYPE_CHECKING, Any

import structlog

from .config import Settings

if TYPE_CHECKING:
    from collections.abc import Callable


def setup_logging(settings: Settings) -> None:
    """Configure application-wide structured logging.

    Configures structlog with different output formats for development
    and production environments.

    Args:
        settings: Application settings instance.
    """
    log_level = getattr(logging, settings.log_level.upper())

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )

    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    processors: list[Callable[..., Any]] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if settings.log_format == "json" or settings.is_production:
        processors += [
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
    else:
        processors += [
            structlog.processors.ExceptionRenderer(),
            structlog.dev.ConsoleRenderer(colors=True),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a structured logger instance.

    Args:
        name: Logger name (typically __name__).

    Returns:
        Configured structlog logger.

    Example:
        ```python
        logger = get_logger(__name__)
        logger.info("user_registered", user_id=123, email="user@example.com")
        ```
    """
    return structlog.get_logger(name)  # type: ignore[no-any-return]
