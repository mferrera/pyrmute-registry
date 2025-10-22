"""Observability integration for logging, tracing, and error tracking."""

import logging
from typing import TYPE_CHECKING

import structlog
from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from .config import Settings
from .logging import get_logger, setup_logging

if TYPE_CHECKING:
    from sentry_sdk.types import Event, Hint


def enrich_sentry_event(
    event: "Event",
    hint: "Hint",
    settings: Settings,
) -> "Event | None":
    """Enrich Sentry events with additional context.

    Args:
        event: Sentry event dict.
        hint: Additional hint data.
        settings: Application settings.

    Returns:
        Enriched event dict.
    """
    event.setdefault("tags", {})
    event["tags"]["database_type"] = "sqlite" if settings.is_sqlite else "postgresql"
    event["tags"]["auth_enabled"] = str(settings.enable_auth)

    # Add correlation ID if available in request context
    try:
        context = structlog.contextvars.get_contextvars()
        if "correlation_id" in context:
            event["tags"]["correlation_id"] = context["correlation_id"]
    except Exception:
        pass  # Don't fail event sending if we can't get context

    return event


def setup_sentry(settings: Settings) -> None:
    """Configure Sentry for error tracking and performance monitoring.

    Args:
        settings: Application settings.
    """
    if not settings.sentry_dsn:
        return

    try:
        import sentry_sdk  # noqa: PLC0415
        from sentry_sdk.integrations.fastapi import FastApiIntegration  # noqa: PLC0415
        from sentry_sdk.integrations.logging import LoggingIntegration  # noqa: PLC0415
        from sentry_sdk.integrations.sqlalchemy import (  # noqa: PLC0415
            SqlalchemyIntegration,
        )

        sentry_logging = LoggingIntegration(
            level=logging.INFO,
            event_level=logging.ERROR,
        )

        sentry_sdk.init(
            dsn=settings.sentry_dsn,
            environment=settings.environment,
            release=f"{settings.app_name}@{settings.app_version}",
            traces_sample_rate=settings.sentry_traces_sample_rate,
            profiles_sample_rate=settings.sentry_profiles_sample_rate,
            integrations=[
                FastApiIntegration(),
                SqlalchemyIntegration(),
                sentry_logging,
            ],
            send_default_pii=False,
            # Tag all events
            before_send=lambda event, hint: enrich_sentry_event(event, hint, settings),
        )

        logger = get_logger(__name__)
        logger.info(
            "sentry_initialized",
            environment=settings.environment,
            traces_sample_rate=settings.sentry_traces_sample_rate,
        )
    except ImportError:
        logger = get_logger(__name__)
        logger.warning(
            "sentry_import_failed",
            message="sentry-sdk not installed, skipping Sentry setup",
        )
    except Exception as e:
        logger = get_logger(__name__)
        logger.exception("sentry_initialization_failed", error=str(e))


def setup_opentelemetry(settings: Settings, app: FastAPI | None = None) -> None:
    """Configure OpenTelemetry for distributed tracing.

    Args:
        settings: Application settings.
        app: FastAPI application instance (optional, for instrumentation).
    """
    if not settings.otel_enabled:
        return

    try:
        resource = Resource.create(
            {
                "service.name": settings.app_name,
                "service.version": settings.app_version,
                "deployment.environment": settings.environment,
            }
        )

        provider = TracerProvider(resource=resource)

        if settings.otel_exporter_otlp_endpoint:
            otlp_exporter = OTLPSpanExporter(
                endpoint=settings.otel_exporter_otlp_endpoint,
                insecure=settings.is_development,  # Use insecure in dev
            )
            provider.add_span_processor(BatchSpanProcessor(otlp_exporter))

        trace.set_tracer_provider(provider)

        if app:
            FastAPIInstrumentor.instrument_app(app)

        from .db import engine  # noqa: PLC0415

        SQLAlchemyInstrumentor().instrument(
            engine=engine,
            service=settings.app_name,
        )

        logger = get_logger(__name__)
        logger.info(
            "opentelemetry_initialized",
            endpoint=settings.otel_exporter_otlp_endpoint,
        )
    except ImportError:
        logger = get_logger(__name__)
        logger.warning(
            "opentelemetry_import_failed",
            message="opentelemetry packages not installed, skipping OTel setup",
        )
    except Exception as e:
        logger = get_logger(__name__)
        logger.exception("opentelemetry_initialization_failed", error=str(e))


def setup_observability(settings: Settings, app: FastAPI | None = None) -> None:
    """Setup all observability integrations.

    Call this during application startup. Sets up logging first, then
    initializes optional error tracking (Sentry) and distributed tracing
    (OpenTelemetry) if configured.

    Args:
        settings: Application settings.
        app: FastAPI application instance (optional, required for some integrations).

    Example:
    ```python
        @asynccontextmanager
        async def lifespan(app: FastAPI):
            settings = get_settings()
            setup_observability(settings, app)
            yield
    ```
    """
    setup_logging(settings)

    logger = get_logger(__name__)
    logger.info(
        "initializing_observability",
        sentry_enabled=bool(settings.sentry_dsn),
        otel_enabled=settings.otel_enabled,
    )

    if settings.sentry_dsn:
        setup_sentry(settings)

    if settings.otel_enabled:
        setup_opentelemetry(settings, app)

    logger.info("observability_initialized")
