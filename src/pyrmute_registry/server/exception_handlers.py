"""Exception handlers for the application."""

from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from .config import get_settings
from .logging import get_logger
from .schemas.errors import (
    DatabaseErrorResponse,
    InternalErrorResponse,
    ValidationErrorResponse,
)

logger = get_logger(__name__)


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Handle request validation errors."""
    logger.warning(
        "validation_error",
        path=request.url.path,
        errors=exc.errors(),
    )
    error_response = ValidationErrorResponse(
        detail=list(exc.errors()),
        body=exc.body,
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content=error_response.model_dump(),
    )


async def sqlalchemy_exception_handler(
    request: Request, exc: SQLAlchemyError
) -> JSONResponse:
    """Handle database errors."""
    logger.exception(
        "database_error",
        path=request.url.path,
        error=str(exc),
        error_type=type(exc).__name__,
    )
    error_response = DatabaseErrorResponse(
        detail="Database error occurred. Please try again later."
    )
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content=error_response.model_dump(),
    )


async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected errors."""
    settings = get_settings()
    logger.exception(
        "unexpected_error",
        path=request.url.path,
        error=str(exc),
        error_type=type(exc).__name__,
    )
    error_response = InternalErrorResponse(
        detail=(
            "An unexpected error occurred. Please try again later."
            if settings.is_production
            else str(exc)
        )
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_response.model_dump(),
    )
