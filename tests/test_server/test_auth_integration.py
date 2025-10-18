"""Integration tests for authentication with actual endpoints."""

from typing import Any

from fastapi import status
from fastapi.testclient import TestClient


def test_endpoint_requires_auth_with_no_key(
    auth_enabled_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that endpoints require authentication when enabled."""
    response = auth_enabled_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid or missing API key" in response.json()["detail"]


def test_endpoint_works_with_header_auth(
    auth_enabled_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that endpoints work with X-API-Key header."""
    response = auth_enabled_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": "test-secret-key-12345"},
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["model_name"] == "User"


def test_endpoint_works_with_bearer_token(
    auth_enabled_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that endpoints work with Bearer token."""
    response = auth_enabled_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"Authorization": "Bearer test-secret-key-12345"},
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["model_name"] == "User"


def test_endpoint_rejects_invalid_header_key(
    auth_enabled_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that endpoints reject invalid API keys in header."""
    response = auth_enabled_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": "wrong-key"},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_endpoint_rejects_invalid_bearer_token(
    auth_enabled_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that endpoints reject invalid Bearer tokens."""
    response = auth_enabled_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"Authorization": "Bearer wrong-key"},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_get_endpoint_requires_auth(
    auth_enabled_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that GET endpoints also require authentication."""
    # First, create a schema with auth
    auth_enabled_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": "test-secret-key-12345"},
    )

    # Try to get without auth
    response = auth_enabled_client.get("/schemas/auth-service/User/versions/1.0.0")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_get_endpoint_works_with_auth(
    auth_enabled_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that GET endpoints work with authentication."""
    auth_enabled_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": "test-secret-key-12345"},
    )

    # Get with auth
    response = auth_enabled_client.get(
        "/schemas/auth-service/User/versions/1.0.0",
        headers={"X-API-Key": "test-secret-key-12345"},
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["version"] == "1.0.0"


def test_list_endpoint_requires_auth(auth_enabled_client: TestClient) -> None:
    """Test that list endpoints require authentication."""
    response = auth_enabled_client.get("/schemas")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_list_endpoint_works_with_auth(auth_enabled_client: TestClient) -> None:
    """Test that list endpoints work with authentication."""
    response = auth_enabled_client.get(
        "/schemas",
        headers={"X-API-Key": "test-secret-key-12345"},
    )

    assert response.status_code == status.HTTP_200_OK


def test_delete_endpoint_requires_auth(
    auth_enabled_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that delete endpoints require authentication."""
    auth_enabled_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": "test-secret-key-12345"},
    )

    # Try to delete without auth
    response = auth_enabled_client.delete(
        "/schemas/auth-service/User/versions/1.0.0?force=true"
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_delete_endpoint_works_with_auth(
    auth_enabled_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that delete endpoints work with authentication."""
    auth_enabled_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": "test-secret-key-12345"},
    )

    response = auth_enabled_client.delete(
        "/schemas/auth-service/User/versions/1.0.0?force=true",
        headers={"X-API-Key": "test-secret-key-12345"},
    )

    assert response.status_code == status.HTTP_200_OK


def test_health_endpoint_does_not_require_auth(
    auth_enabled_client: TestClient,
) -> None:
    """Test that health endpoints do not require authentication."""
    # Health checks should work without auth for monitoring
    response = auth_enabled_client.get("/health")

    # Health endpoint should not require auth
    assert response.status_code == status.HTTP_200_OK


def test_root_endpoint_does_not_require_auth(
    auth_enabled_client: TestClient,
) -> None:
    """Test that root endpoint does not require authentication."""
    response = auth_enabled_client.get("/")

    # Root endpoint should not require auth
    assert response.status_code == status.HTTP_200_OK


def test_multiple_requests_with_same_key(
    auth_enabled_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that the same API key works for multiple requests."""
    headers = {"X-API-Key": "test-secret-key-12345"}

    # First request
    response1 = auth_enabled_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers=headers,
    )

    # Second request
    response2 = auth_enabled_client.get(
        "/schemas/auth-service/User/versions/1.0.0",
        headers=headers,
    )

    # Third request
    response3 = auth_enabled_client.get("/schemas", headers=headers)

    assert response1.status_code == status.HTTP_201_CREATED
    assert response2.status_code == status.HTTP_200_OK
    assert response3.status_code == status.HTTP_200_OK


def test_auth_header_case_insensitive(
    auth_enabled_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that auth headers work regardless of case."""
    # HTTP headers are case-insensitive
    response = auth_enabled_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"x-api-key": "test-secret-key-12345"},  # lowercase
    )

    assert response.status_code == status.HTTP_201_CREATED


def test_bearer_token_with_wrong_scheme(
    auth_enabled_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that Bearer token must use correct scheme."""
    response = auth_enabled_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"Authorization": "Basic test-secret-key-12345"},  # Wrong scheme
    )

    # Should fail because Bearer scheme is expected
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_www_authenticate_header_in_response(
    auth_enabled_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that 401 responses include WWW-Authenticate header."""
    response = auth_enabled_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "www-authenticate" in response.headers
    # Should include both Bearer and ApiKey
    auth_header = response.headers["www-authenticate"].lower()
    assert "bearer" in auth_header or "apikey" in auth_header


def test_multiple_sequential_requests_with_auth(
    auth_enabled_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that authentication works for multiple sequential requests."""
    headers = {"X-API-Key": "test-secret-key-12345"}

    results = []
    for i in range(10):
        response = auth_enabled_client.post(
            f"/schemas/auth-service/Model{i}/versions",
            json={
                "model_name": f"Model{i}",
                "version": "1.0.0",
                "json_schema": sample_schema,
                "registered_by": "test-service",
            },
            headers=headers,
        )
        results.append(response.status_code)

    assert all(code == status.HTTP_201_CREATED for code in results)


def test_empty_api_key_header(
    auth_enabled_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that empty API key header is rejected."""
    response = auth_enabled_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": ""},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_whitespace_only_api_key(
    auth_enabled_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that whitespace-only API key is rejected."""
    response = auth_enabled_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": "   "},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_api_key_with_leading_trailing_spaces(
    auth_enabled_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that API key with spaces is rejected (exact match required)."""
    response = auth_enabled_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": " test-secret-key-12345 "},
    )

    # Should fail because of exact matching
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
