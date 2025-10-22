"""Tests for observability integration."""

from collections.abc import Generator
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest
import structlog
from fastapi import FastAPI

from pyrmute_registry.server.config import Settings
from pyrmute_registry.server.observability import (
    enrich_sentry_event,
    setup_observability,
    setup_opentelemetry,
    setup_sentry,
)

if TYPE_CHECKING:
    from sentry_sdk.types import Event, Hint

# ruff: noqa: PLR2004


@pytest.fixture
def mock_sentry() -> Generator[Mock, None, None]:
    """Mock sentry_sdk for testing."""
    with patch("pyrmute_registry.server.observability.sentry_sdk") as mock:
        yield mock


@pytest.fixture
def mock_otel_trace() -> Generator[Mock, None, None]:
    """Mock OpenTelemetry trace for testing."""
    with patch("pyrmute_registry.server.observability.trace") as mock:
        yield mock


@pytest.fixture
def clean_structlog_context() -> Generator[None, None, None]:
    """Clear structlog context before and after test."""
    structlog.contextvars.clear_contextvars()
    yield
    structlog.contextvars.clear_contextvars()


def test_enrich_sentry_event_adds_context() -> None:
    """Test that Sentry events are enriched with tags and correlation ID."""
    settings = Settings(
        database_url="postgresql://localhost/test",
        enable_auth=True,
    )
    event: Event = {}
    hint: Hint = {}

    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(correlation_id="test-123")

    result = enrich_sentry_event(event, hint, settings)

    assert result is not None
    assert result["tags"]["database_type"] == "postgresql"
    assert result["tags"]["auth_enabled"] == "True"
    assert result["tags"]["correlation_id"] == "test-123"

    structlog.contextvars.clear_contextvars()


def test_setup_sentry_skips_when_no_dsn() -> None:
    """Test that Sentry setup is skipped when no DSN provided."""
    settings = Settings(sentry_dsn=None)

    # Should return early without error
    setup_sentry(settings)


def test_setup_sentry_initializes_correctly() -> None:
    """Test that Sentry is initialized with correct configuration."""
    settings = Settings(
        sentry_dsn="https://test@sentry.io/123",
        environment="production",
        app_name="Test App",
        app_version="1.0.0",
        sentry_traces_sample_rate=0.5,
    )

    with patch("sentry_sdk.init") as mock_init:
        setup_sentry(settings)

        assert mock_init.call_count == 1
        call_kwargs = mock_init.call_args.kwargs

        assert call_kwargs["dsn"] == "https://test@sentry.io/123"
        assert call_kwargs["environment"] == "production"
        assert call_kwargs["release"] == "Test App@1.0.0"
        assert call_kwargs["traces_sample_rate"] == 0.5


def test_setup_sentry_handles_errors() -> None:
    """Test that Sentry initialization errors are handled gracefully."""
    settings = Settings(sentry_dsn="https://test@sentry.io/123")

    with patch("sentry_sdk.init", side_effect=Exception("Connection failed")):
        setup_sentry(settings)  # Should not raise


def test_setup_opentelemetry_skips_when_disabled() -> None:
    """Test that OpenTelemetry setup is skipped when disabled."""
    settings = Settings(otel_enabled=False)

    # Should return early without error
    setup_opentelemetry(settings)


@patch("pyrmute_registry.server.observability.trace")
@patch("pyrmute_registry.server.observability.TracerProvider")
@patch("pyrmute_registry.server.observability.Resource")
def test_setup_opentelemetry_initializes_correctly(
    mock_resource: Mock,
    mock_provider_class: Mock,
    mock_trace: Mock,
) -> None:
    """Test that OpenTelemetry is initialized with correct configuration."""
    settings = Settings(
        otel_enabled=True,
        app_name="Test App",
        app_version="1.0.0",
        environment="production",
    )

    mock_resource_instance = Mock()
    mock_resource.create.return_value = mock_resource_instance
    mock_provider_instance = Mock()
    mock_provider_class.return_value = mock_provider_instance

    setup_opentelemetry(settings)

    resource_attrs = mock_resource.create.call_args[0][0]
    assert resource_attrs["service.name"] == "Test App"
    assert resource_attrs["service.version"] == "1.0.0"
    assert resource_attrs["deployment.environment"] == "production"

    mock_trace.set_tracer_provider.assert_called_once_with(mock_provider_instance)


@patch("pyrmute_registry.server.observability.trace")
@patch("pyrmute_registry.server.observability.TracerProvider")
@patch("pyrmute_registry.server.observability.Resource")
@patch("pyrmute_registry.server.observability.FastAPIInstrumentor")
def test_setup_opentelemetry_instruments_app(
    mock_instrumentor: Mock,
    mock_resource: Mock,
    mock_provider_class: Mock,
    mock_trace: Mock,
) -> None:
    """Test that FastAPI app is instrumented when provided."""
    settings = Settings(otel_enabled=True)
    app = FastAPI()

    mock_resource.create.return_value = Mock()
    mock_provider_class.return_value = Mock()

    setup_opentelemetry(settings, app)

    mock_instrumentor.instrument_app.assert_called_once_with(app)


@patch("pyrmute_registry.server.observability.setup_logging")
@patch("pyrmute_registry.server.observability.setup_sentry")
@patch("pyrmute_registry.server.observability.setup_opentelemetry")
def test_setup_observability_calls_all_components(
    mock_setup_otel: Mock,
    mock_setup_sentry: Mock,
    mock_setup_logging: Mock,
) -> None:
    """Test that setup_observability orchestrates all components correctly."""
    settings = Settings(
        sentry_dsn="https://test@sentry.io/123",
        otel_enabled=True,
    )
    app = FastAPI()

    call_order: list[str] = []
    mock_setup_logging.side_effect = lambda *a, **k: call_order.append("logging")
    mock_setup_sentry.side_effect = lambda *a, **k: call_order.append("sentry")
    mock_setup_otel.side_effect = lambda *a, **k: call_order.append("otel")

    setup_observability(settings, app)

    mock_setup_logging.assert_called_once_with(settings)
    mock_setup_sentry.assert_called_once_with(settings)
    mock_setup_otel.assert_called_once_with(settings, app)

    assert call_order == ["logging", "sentry", "otel"]


@patch("pyrmute_registry.server.observability.setup_logging")
@patch("pyrmute_registry.server.observability.setup_sentry")
@patch("pyrmute_registry.server.observability.setup_opentelemetry")
def test_setup_observability_skips_disabled_components(
    mock_setup_otel: Mock,
    mock_setup_sentry: Mock,
    mock_setup_logging: Mock,
) -> None:
    """Test that disabled components are not initialized."""
    settings = Settings(sentry_dsn=None, otel_enabled=False)

    setup_observability(settings)

    mock_setup_logging.assert_called_once()
    mock_setup_sentry.assert_not_called()
    mock_setup_otel.assert_not_called()


def test_observability_integration() -> None:
    """Test that full observability setup works without errors."""
    settings = Settings(
        environment="development",
        log_format="console",
        sentry_dsn=None,
        otel_enabled=False,
    )

    setup_observability(settings)
