"""Main pyremute-registry FastAPI application setup and configuration."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from .config import get_settings
from .db import init_db
from .middleware import AuditMiddleware, CorrelationIdMiddleware, LoggingMiddleware
from .routers import api_keys, health, root, schemas
from .schemas.errors import (
    DatabaseErrorResponse,
    InternalErrorResponse,
    ValidationErrorResponse,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Lifespan context manager for startup and shutdown events.

    Args:
        app: FastAPI application instance.

    Yields:
        None - control during application lifetime.
    """
    settings = get_settings()

    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    logger.info(f"Environment: {settings.environment}")
    logger.info(f"Database: {settings.database_url.split('://')[0]}")

    try:
        init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.exception(f"Failed to initialize database: {e}")
        raise

    yield

    logger.info(f"Shutting down {settings.app_name}")


def create_app() -> FastAPI:
    """Create and configure FastAPI application.

    Returns:
        Configured FastAPI application.
    """
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        description=(
            "Centralized registry for versioned Pydantic model schemas. "
            "Track schema evolution, compare versions, and ensure compatibility "
            "across services."
        ),
        version=settings.app_version,
        lifespan=lifespan,
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json",
        openapi_tags=[
            {
                "name": "api_keys",
                "description": "API key registration and management operations",
            },
            {
                "name": "schemas",
                "description": "Schema registration and management operations",
            },
            {
                "name": "health",
                "description": "Health check and monitoring endpoints",
            },
            {
                "name": "root",
                "description": "Root API information",
            },
        ],
    )

    app.add_middleware(CorrelationIdMiddleware)
    if settings.enable_auth and settings.audit_enabled:
        app.add_middleware(AuditMiddleware)

    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=settings.cors_allow_methods,
        allow_headers=settings.cors_allow_headers,
    )

    if settings.is_development or settings.is_test:
        app.add_middleware(LoggingMiddleware)

    # Exception handlers
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Handle request validation errors."""
        logger.warning(f"Validation error on {request.url.path}: {exc.errors()}")
        error_response = ValidationErrorResponse(
            detail=list(exc.errors()),
            body=exc.body,
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content=error_response.model_dump(),
        )

    @app.exception_handler(SQLAlchemyError)
    async def sqlalchemy_exception_handler(
        request: Request, exc: SQLAlchemyError
    ) -> JSONResponse:
        """Handle database errors."""
        logger.exception(f"Database error on {request.url.path}: {exc!s}")
        error_response = DatabaseErrorResponse(
            detail="Database error occurred. Please try again later."
        )
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=error_response.model_dump(),
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Handle unexpected errors."""
        logger.exception(f"Unexpected error on {request.url.path}: {exc!s}")
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

    app.include_router(root.router)
    app.include_router(health.router)
    app.include_router(schemas.router)
    app.include_router(api_keys.router)

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    log_level = settings.log_level if settings.debug else "info"

    uvicorn.run(
        "pyrmute_registry.server.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        workers=settings.workers if not settings.reload else 1,
        log_level=log_level.lower(),
        access_log=settings.is_development,
    )
