"""Main pyremute-registry FastAPI application setup and configuration."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from .config import get_settings
from .db import engine, init_db
from .exception_handlers import (
    general_exception_handler,
    sqlalchemy_exception_handler,
    validation_exception_handler,
)
from .logging import get_logger, setup_logging
from .middleware import AuditMiddleware, CorrelationIdMiddleware, LoggingMiddleware
from .routers import api_keys, health, root, schemas

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Lifespan context manager for startup and shutdown events.

    Args:
        app: FastAPI application instance.

    Yields:
        None - control during application lifetime.
    """
    settings = get_settings()
    setup_logging(settings)

    logger.info(
        "starting_application",
        app_name=settings.app_name,
        version=settings.app_version,
        environment=settings.environment,
        database_type=settings.database_url.split("://")[0],
        auth_enabled=settings.enable_auth,
        audit_enabled=settings.audit_enabled,
    )

    if settings.is_development:
        try:
            init_db()
            logger.info("database_initialized", mode="auto")
        except Exception as e:
            logger.exception("database_initialization_failed", error=str(e))
            raise
    else:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info("database_connection_verified")
        except Exception as e:
            logger.exception("database_connection_failed", error=str(e))
            raise

    yield

    logger.info("shutting_down_application", app_name=settings.app_name)


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

    if settings.should_log_requests:
        app.add_middleware(LoggingMiddleware)

    if settings.enable_auth and settings.audit_enabled:
        app.add_middleware(AuditMiddleware)

    app.add_middleware(CorrelationIdMiddleware)

    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=settings.cors_allow_methods,
        allow_headers=settings.cors_allow_headers,
    )

    # Exception handlers
    app.exception_handler(RequestValidationError)(validation_exception_handler)
    app.exception_handler(SQLAlchemyError)(sqlalchemy_exception_handler)
    app.exception_handler(Exception)(general_exception_handler)

    app.include_router(root.router)
    app.include_router(health.router)
    app.include_router(schemas.router)
    app.include_router(api_keys.router)

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    log_level = settings.log_level.lower()

    uvicorn.run(
        "pyrmute_registry.server.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        workers=settings.workers if not settings.reload else 1,
        log_level=log_level,
        access_log=settings.is_development,
    )
