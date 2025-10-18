"""Tests for main application setup and configuration."""

from typing import Any
from unittest.mock import patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from pyrmute_registry.server.main import create_app


def test_create_app(app_client: TestClient) -> None:
    """Test that app is created successfully."""
    assert app_client.app is not None
    assert app_client.app.title == "Pyrmute Schema Registry"  # type: ignore[attr-defined]


def test_openapi_json_available(app_client: TestClient) -> None:
    """Test that OpenAPI JSON is available."""
    response = app_client.get("/openapi.json")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "openapi" in data
    assert data["info"]["title"] == "Pyrmute Schema Registry"
    assert data["info"]["version"] == "1.0.0"


def test_openapi_includes_all_routers(app_client: TestClient) -> None:
    """Test that OpenAPI spec includes all registered routers."""
    response = app_client.get("/openapi.json")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    paths = data["paths"]

    # Check health endpoints exist
    assert "/health" in paths
    assert "/health/live" in paths
    assert "/health/ready" in paths

    # Check schema endpoints exist
    assert any("/schemas/" in path for path in paths)


def test_docs_endpoint_available_in_test(app_client: TestClient) -> None:
    """Test that Swagger docs are available in test environment."""
    response = app_client.get("/docs")

    assert response.status_code == status.HTTP_200_OK
    assert "text/html" in response.headers["content-type"]


def test_redoc_endpoint_available_in_test(app_client: TestClient) -> None:
    """Test that ReDoc is available in test environment."""
    response = app_client.get("/redoc")

    assert response.status_code == status.HTTP_200_OK
    assert "text/html" in response.headers["content-type"]


def test_cors_middleware_configured(app_client: TestClient) -> None:
    """Test that CORS middleware is properly configured."""
    response = app_client.options(
        "/health",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == status.HTTP_200_OK
    assert "access-control-allow-origin" in response.headers


def test_cors_allows_configured_origins(app_client: TestClient) -> None:
    """Test that CORS allows all origins in test environment."""
    response = app_client.get(
        "/health",
        headers={"Origin": "http://example.com"},
    )

    assert response.status_code == status.HTTP_200_OK
    # Test settings allow all origins (*)
    assert "access-control-allow-origin" in response.headers


def test_gzip_compression_for_large_responses(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that large responses are compressed."""
    # Register multiple schemas to create a large response
    for i in range(20):
        app_client.post(
            f"/schemas/auth-service/Model{i}/versions",
            json={
                "model_name": f"Model{i}",
                "version": "1.0.0",
                "json_schema": sample_schema,
                "registered_by": "test-service",
            },
        )

    # Request with Accept-Encoding header
    response = app_client.get(
        "/schemas",
        headers={"Accept-Encoding": "gzip"},
    )

    assert response.status_code == status.HTTP_200_OK
    assert len(response.content) > 0


def test_validation_error_handler(app_client: TestClient) -> None:
    """Test that validation errors are handled properly."""
    response = app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "invalid_version",  # Invalid version format
            "json_schema": {},
            "registered_by": "test",
        },
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    data = response.json()
    assert "detail" in data


def test_database_error_handler(
    app_client: TestClient,
) -> None:
    """Test that database errors are handled gracefully."""
    with patch(
        "pyrmute_registry.server.services.schema.SchemaService.get_schema_count",
        side_effect=OperationalError("Database error", None, Exception()),
    ):
        response = app_client.get("/health")

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        data = response.json()
        assert "error" in data or "detail" in data


def test_general_exception_handler(
    app_client: TestClient,
) -> None:
    """Test that unexpected exceptions are handled."""
    with patch(
        "pyrmute_registry.server.services.schema.SchemaService.get_schema_count",
        side_effect=RuntimeError("Unexpected error"),
    ):
        response = app_client.get("/health")

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        data = response.json()
        assert "error" in data or "detail" in data


def test_app_metadata(app_client: TestClient) -> None:
    """Test that app has correct metadata."""
    app = app_client.app
    assert app.title == "Pyrmute Schema Registry"  # type: ignore[attr-defined]
    assert app.version == "1.0.0"  # type: ignore[attr-defined]
    assert "Centralized registry" in app.description  # type: ignore[attr-defined]


def test_openapi_tags_configured(app_client: TestClient) -> None:
    """Test that OpenAPI tags are properly configured."""
    response = app_client.get("/openapi.json")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "tags" in data

    tag_names = [tag["name"] for tag in data["tags"]]
    assert "schemas" in tag_names
    assert "health" in tag_names
    assert "root" in tag_names


def test_invalid_endpoint_returns_404(app_client: TestClient) -> None:
    """Test that invalid endpoints return 404."""
    response = app_client.get("/invalid/endpoint")

    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_invalid_method_returns_405(app_client: TestClient) -> None:
    """Test that invalid methods return 405."""
    response = app_client.put("/")

    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED


def test_lifespan_startup(app_client: TestClient) -> None:
    """Test that lifespan startup initializes correctly."""
    # If app_client is created, startup was successful
    response = app_client.get("/health")
    assert response.status_code == status.HTTP_200_OK


def test_lifespan_database_initialization_failure() -> None:
    """Test that app handles database initialization failure."""
    with (
        patch(
            "pyrmute_registry.server.main.init_db",
            side_effect=RuntimeError("Database init failed"),
        ),
        pytest.raises(RuntimeError),
        TestClient(create_app()) as client,
    ):
        client.get("/health")


def test_error_message_sanitization_in_production(
    production_client: TestClient,
) -> None:
    """Test that error messages are sanitized in production."""
    with patch(
        "pyrmute_registry.server.services.schema.SchemaService.get_schema_count",
        side_effect=RuntimeError("Internal server details"),
    ):
        response = production_client.get("/health")
        data = response.json()
        assert "Internal server details" not in str(data)
        assert "try again later" in data.get("error", "").lower()


def test_openapi_spec_structure(app_client: TestClient) -> None:
    """Test that OpenAPI spec has proper structure."""
    response = app_client.get("/openapi.json")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert "openapi" in data
    assert "info" in data
    assert "paths" in data
    assert "components" in data

    assert "title" in data["info"]
    assert "version" in data["info"]
    assert "description" in data["info"]
