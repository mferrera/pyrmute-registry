"""Tests for health check endpoints."""

import concurrent.futures
import time
from datetime import datetime
from typing import Any
from unittest.mock import patch

from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError


def test_health_check_healthy(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test health check returns healthy status."""
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    response = app_client.get("/health")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "1.0.0"
    assert data["environment"] in ["test", "development"]
    assert data["database"]["type"] == "sqlite"
    assert data["database"]["connected"] is True
    assert data["schemas_count"] >= 1
    assert data["uptime_seconds"] >= 0
    assert "timestamp" in data


def test_health_check_returns_correct_schema_count(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that health check returns accurate schema count."""
    # Register multiple schemas
    for i in range(3):
        app_client.post(
            f"/schemas/auth-service/Model{i}/versions",
            json={
                "model_name": f"Model{i}",
                "version": "1.0.0",
                "json_schema": sample_schema,
                "registered_by": "test-service",
            },
        )

    response = app_client.get("/health")

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["schemas_count"] == 3  # noqa: PLR2004


def test_health_check_uptime_increases(
    app_client: TestClient,
) -> None:
    """Test that uptime increases between calls."""
    response1 = app_client.get("/health")
    uptime1 = response1.json()["uptime_seconds"]

    time.sleep(0.1)

    response2 = app_client.get("/health")
    uptime2 = response2.json()["uptime_seconds"]

    assert uptime2 > uptime1


def test_health_check_no_authentication_required(
    app_client: TestClient,
) -> None:
    """Test that health check does not require authentication."""
    # Even with auth disabled in test settings, verify the endpoint
    # doesn't have the AuthRequired dependency by checking it works
    response = app_client.get("/health")

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["status"] == "healthy"


def test_health_check_database_error(
    app_client: TestClient,
) -> None:
    """Test health check returns unhealthy when database fails."""
    with patch(
        "pyrmute_registry.server.services.schema.SchemaService.get_schema_count",
        side_effect=OperationalError("Connection refused", None, Exception()),
    ):
        response = app_client.get("/health")

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        data = response.json()
        assert data["status"] == "unhealthy"
        assert "Database connection failed" in data["error"]
        assert "timestamp" in data


def test_health_check_unexpected_error(
    app_client: TestClient,
) -> None:
    """Test health check handles unexpected errors gracefully."""
    with patch(
        "pyrmute_registry.server.services.schema.SchemaService.get_schema_count",
        side_effect=RuntimeError("Unexpected error"),
    ):
        response = app_client.get("/health")

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        data = response.json()
        assert data["status"] == "unhealthy"
        assert "Health check failed" in data["error"]
        assert "Unexpected error" in data["error"]


def test_health_check_database_type_detection(
    app_client: TestClient,
) -> None:
    """Test that health check correctly identifies database type."""
    response = app_client.get("/health")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    # Test database uses SQLite
    assert data["database"]["type"] == "sqlite"


def test_liveness_probe(
    app_client: TestClient,
) -> None:
    """Test liveness probe endpoint."""
    response = app_client.get("/health/live")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["alive"] is True


def test_liveness_probe_always_succeeds(
    app_client: TestClient,
) -> None:
    """Test that liveness probe succeeds even with database issues."""
    # Mock database failure
    with patch(
        "pyrmute_registry.server.services.schema.SchemaService.get_schema_count",
        side_effect=OperationalError("Connection refused", None, Exception()),
    ):
        # Liveness should still succeed
        response = app_client.get("/health/live")

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["alive"] is True


def test_readiness_probe_ready(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test readiness probe returns ready when database is connected."""
    # Ensure database is working by registering a schema
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    response = app_client.get("/health/ready")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["ready"] is True


def test_readiness_probe_not_ready(
    app_client: TestClient,
) -> None:
    """Test readiness probe returns not ready when database fails."""
    with patch(
        "pyrmute_registry.server.services.schema.SchemaService.get_schema_count",
        side_effect=OperationalError("Connection refused", None, Exception()),
    ):
        response = app_client.get("/health/ready")

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        data = response.json()
        assert data["ready"] is False


def test_readiness_probe_no_authentication_required(
    app_client: TestClient,
) -> None:
    """Test that readiness probe does not require authentication."""
    response = app_client.get("/health/ready")

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["ready"] is True


def test_liveness_probe_no_authentication_required(
    app_client: TestClient,
) -> None:
    """Test that liveness probe does not require authentication."""
    response = app_client.get("/health/live")

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["alive"] is True


def test_health_endpoints_response_format(
    app_client: TestClient,
) -> None:
    """Test that all health endpoints return valid JSON."""
    endpoints = ["/health", "/health/live", "/health/ready"]

    for endpoint in endpoints:
        response = app_client.get(endpoint)
        assert response.status_code == status.HTTP_200_OK
        # Verify it's valid JSON
        data = response.json()
        assert isinstance(data, dict)


def test_health_check_includes_all_required_fields(
    app_client: TestClient,
) -> None:
    """Test that health check response includes all required fields."""
    response = app_client.get("/health")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    required_fields = [
        "status",
        "version",
        "environment",
        "database",
        "schemas_count",
        "uptime_seconds",
        "timestamp",
    ]

    for field in required_fields:
        assert field in data, f"Missing required field: {field}"

    # Check database nested structure
    assert "type" in data["database"]
    assert "connected" in data["database"]


def test_health_check_timestamp_format(
    app_client: TestClient,
) -> None:
    """Test that health check timestamp is in ISO 8601 format."""
    response = app_client.get("/health")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    # Verify timestamp can be parsed as ISO 8601
    timestamp = data["timestamp"]
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    assert parsed is not None


def test_health_error_includes_timestamp(
    app_client: TestClient,
) -> None:
    """Test that health error response includes timestamp."""
    with patch(
        "pyrmute_registry.server.services.schema.SchemaService.get_schema_count",
        side_effect=RuntimeError("Test error"),
    ):
        response = app_client.get("/health")

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        data = response.json()
        assert "timestamp" in data


def test_multiple_concurrent_health_checks(
    app_client: TestClient,
) -> None:
    """Test that multiple concurrent health checks work correctly."""

    def check_health() -> int:
        response = app_client.get("/health")
        return response.status_code

    # Execute multiple health checks concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(check_health) for _ in range(10)]
        results = [future.result() for future in futures]

    # All should succeed
    assert all(code == status.HTTP_200_OK for code in results)


def test_health_check_with_empty_database(
    app_client: TestClient,
) -> None:
    """Test health check with no schemas registered."""
    response = app_client.get("/health")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "healthy"
    assert data["schemas_count"] == 0
