"""Tests for schema endpoints with authentication."""

from typing import Any

from fastapi import status
from fastapi.testclient import TestClient

from pyrmute_registry.server.models.api_key import ApiKey

# ruff: noqa: PLR2004


# ============================================================================
# AUTH DISABLED TESTS
# ============================================================================


def test_register_global_schema_no_auth(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test registration of a global schema with auth disabled."""
    response = app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
            "meta": {"description": "Global user schema"},
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["namespace"] is None
    assert data["model_name"] == "User"
    assert data["version"] == "1.0.0"
    assert data["registered_by"] == "test-service"
    assert data["deprecated"] is False


def test_register_namespaced_schema_no_auth(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test registration with namespace when auth is disabled."""
    response = app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
            "meta": {"description": "Auth service user schema"},
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["namespace"] == "auth-service"
    assert data["model_name"] == "User"
    assert data["version"] == "1.0.0"


# ============================================================================
# AUTH ENABLED TESTS - READ PERMISSION
# ============================================================================


def test_get_schema_with_read_permission(
    auth_enabled_client: TestClient,
    read_only_key: ApiKey,
    sample_schema: dict[str, Any],
    sample_api_key: ApiKey,
) -> None:
    """Test that read-only key can get schemas."""
    # First create a schema using write key
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

    # Now retrieve with read-only key
    response = auth_enabled_client.get(
        "/schemas/User/versions/1.0.0",
        headers={"X-API-Key": read_only_key._plaintext},  # type: ignore
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["model_name"] == "User"
    assert data["version"] == "1.0.0"


def test_get_schema_without_auth_fails(
    auth_enabled_client: TestClient,
    sample_schema: dict[str, Any],
    sample_api_key: ApiKey,
) -> None:
    """Test that getting schema without API key fails when auth is enabled."""
    # First create a schema
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

    # Try to get without auth
    response = auth_enabled_client.get("/schemas/User/versions/1.0.0")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_list_schemas_with_read_permission(
    auth_enabled_client: TestClient,
    read_only_key: ApiKey,
    sample_api_key: ApiKey,
    sample_schema: dict[str, Any],
) -> None:
    """Test that read-only key can list schemas."""
    # Create some schemas
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

    # List with read-only key
    response = auth_enabled_client.get(
        "/schemas",
        headers={"X-API-Key": read_only_key._plaintext},  # type: ignore
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] >= 1


# ============================================================================
# AUTH ENABLED TESTS - WRITE PERMISSION
# ============================================================================


def test_register_schema_with_write_permission(
    auth_enabled_client: TestClient,
    sample_api_key: ApiKey,
    sample_schema: dict[str, Any],
) -> None:
    """Test that write key can register schemas."""
    response = auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["model_name"] == "User"
    assert data["version"] == "1.0.0"


def test_register_schema_with_read_only_fails(
    auth_enabled_client: TestClient,
    read_only_key: ApiKey,
    sample_schema: dict[str, Any],
) -> None:
    """Test that read-only key cannot register schemas."""
    response = auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": read_only_key._plaintext},  # type: ignore
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_deprecate_schema_with_write_permission(
    auth_enabled_client: TestClient,
    sample_api_key: ApiKey,
    sample_schema: dict[str, Any],
) -> None:
    """Test that write key can deprecate schemas."""
    # Create schema
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

    # Deprecate it
    response = auth_enabled_client.post(
        "/schemas/User/versions/1.0.0/deprecate?message=Deprecated",
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["deprecated"] is True


def test_deprecate_schema_with_read_only_fails(
    auth_enabled_client: TestClient,
    sample_api_key: ApiKey,
    read_only_key: ApiKey,
    sample_schema: dict[str, Any],
) -> None:
    """Test that read-only key cannot deprecate schemas."""
    # Create schema with write key
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

    # Try to deprecate with read-only key
    response = auth_enabled_client.post(
        "/schemas/User/versions/1.0.0/deprecate",
        headers={"X-API-Key": read_only_key._plaintext},  # type: ignore
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


# ============================================================================
# AUTH ENABLED TESTS - DELETE PERMISSION
# ============================================================================


def test_delete_schema_with_delete_permission(
    auth_enabled_client: TestClient,
    delete_permission_key: ApiKey,
    sample_api_key: ApiKey,
    sample_schema: dict[str, Any],
) -> None:
    """Test that delete key can delete schemas."""
    # Create schema
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

    # Delete it
    response = auth_enabled_client.delete(
        "/schemas/User/versions/1.0.0?force=true",
        headers={"X-API-Key": delete_permission_key._plaintext},  # type: ignore
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["deleted"] is True


def test_delete_schema_with_write_permission_fails(
    auth_enabled_client: TestClient,
    sample_api_key: ApiKey,
    sample_schema: dict[str, Any],
) -> None:
    """Test that write key cannot delete schemas."""
    # Create schema
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

    # Try to delete with write key (insufficient permission)
    response = auth_enabled_client.delete(
        "/schemas/User/versions/1.0.0?force=true",
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_delete_schema_with_read_only_fails(
    auth_enabled_client: TestClient,
    sample_api_key: ApiKey,
    read_only_key: ApiKey,
    sample_schema: dict[str, Any],
) -> None:
    """Test that read-only key cannot delete schemas."""
    # Create schema
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

    # Try to delete with read-only key
    response = auth_enabled_client.delete(
        "/schemas/User/versions/1.0.0?force=true",
        headers={"X-API-Key": read_only_key._plaintext},  # type: ignore
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


# ============================================================================
# AUTH ENABLED TESTS - REVOKED/EXPIRED KEYS
# ============================================================================


def test_revoked_key_cannot_access(
    auth_enabled_client: TestClient,
    revoked_key: ApiKey,
    sample_api_key: ApiKey,
    sample_schema: dict[str, Any],
) -> None:
    """Test that revoked keys are rejected."""
    # Create schema first
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

    # Try to access with revoked key
    response = auth_enabled_client.get(
        "/schemas/User/versions/1.0.0",
        headers={"X-API-Key": revoked_key._plaintext},  # type: ignore
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_expired_key_cannot_access(
    auth_enabled_client: TestClient,
    expired_key: ApiKey,
    sample_api_key: ApiKey,
    sample_schema: dict[str, Any],
) -> None:
    """Test that expired keys are rejected."""
    # Create schema first
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

    # Try to access with expired key
    response = auth_enabled_client.get(
        "/schemas/User/versions/1.0.0",
        headers={"X-API-Key": expired_key._plaintext},  # type: ignore
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ============================================================================
# COMPREHENSIVE WORKFLOW TESTS (select important ones from original)
# ============================================================================


def test_register_duplicate_schema_fails(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that registering duplicate schema fails without allow_overwrite."""
    # Register first time
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    # Try to register again
    response = app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    assert response.status_code == status.HTTP_409_CONFLICT
    assert "already exists" in response.json()["detail"]


def test_register_duplicate_schema_with_overwrite(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that allow_overwrite permits duplicate registration."""
    # Register first time
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    # Register again with overwrite
    modified_schema = {**sample_schema, "description": "Modified"}
    response = app_client.post(
        "/schemas/auth-service/User/versions?allow_overwrite=true",
        json={
            "version": "1.0.0",
            "json_schema": modified_schema,
            "registered_by": "test-service-2",
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["json_schema"]["description"] == "Modified"
    assert data["registered_by"] == "test-service-2"


def test_same_model_different_namespaces(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that same model name can exist in different namespaces."""
    # Register in auth-service
    response1 = app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )

    # Register in billing-service
    response2 = app_client.post(
        "/schemas/billing-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "billing-service",
        },
    )

    assert response1.status_code == status.HTTP_201_CREATED
    assert response2.status_code == status.HTTP_201_CREATED
    assert response1.json()["namespace"] == "auth-service"
    assert response2.json()["namespace"] == "billing-service"


def test_get_latest_schema_semantic_versioning(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that latest endpoint uses semantic versioning correctly."""
    # Register in non-sequential order
    for version in ["2.0.0", "1.1.0", "1.10.0", "1.2.0"]:
        app_client.post(
            "/schemas/auth-service/User/versions",
            json={
                "version": version,
                "json_schema": sample_schema,
                "registered_by": "test-service",
            },
        )

    response = app_client.get("/schemas/auth-service/User/versions/latest")

    assert response.status_code == status.HTTP_200_OK
    # 2.0.0 should be latest, not 1.10.0
    assert response.json()["version"] == "2.0.0"


def test_list_schemas_pagination(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test listing schemas with pagination."""
    # Register multiple schemas
    for i in range(5):
        app_client.post(
            f"/schemas/auth-service/Model{i}/versions",
            json={
                "version": "1.0.0",
                "json_schema": sample_schema,
                "registered_by": "test-service",
            },
        )

    # Get first page
    response = app_client.get("/schemas?limit=2&offset=0")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 2
    assert data["limit"] == 2
    assert data["offset"] == 0
    assert data["total_count"] == 5

    # Get second page
    response = app_client.get("/schemas?limit=2&offset=2")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["offset"] == 2


def test_compare_versions_breaking_changes(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that breaking changes are detected."""
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    # V2 removes a field
    schema_v2 = {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
        },
        "required": ["id"],
    }
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "2.0.0",
            "json_schema": schema_v2,
            "registered_by": "test-service",
        },
    )

    response = app_client.get(
        "/schemas/auth-service/User/compare?from_version=1.0.0&to_version=2.0.0"
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["changes"]["compatibility"] == "breaking"
    assert len(data["changes"]["breaking_changes"]) > 0


def test_delete_schema_without_force_fails(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that deletion without force flag fails."""
    # Register schema
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    # Try to delete without force
    response = app_client.delete("/schemas/auth-service/User/versions/1.0.0")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "force=true" in response.json()["detail"]


def test_list_namespaces_for_model(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test listing all namespaces that contain a specific model."""
    # Register User in multiple namespaces
    app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "global-service",
        },
    )
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )
    app_client.post(
        "/schemas/billing-service/User/versions",
        json={
            "version": "1.5.0",
            "json_schema": sample_schema,
            "registered_by": "billing-service",
        },
    )

    # List namespaces
    response = app_client.get("/schemas/User/namespaces")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "namespaces" in data
    namespaces = data["namespaces"]

    assert "null" in namespaces  # Global
    assert "auth-service" in namespaces
    assert "billing-service" in namespaces


def test_invalid_version_format(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that invalid version format is rejected."""
    response = app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "invalid",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


def test_namespace_isolation_for_operations(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that operations in one namespace don't affect another."""
    # Register same model/version in two namespaces
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )
    app_client.post(
        "/schemas/billing-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "billing-service",
        },
    )

    # Deprecate in auth-service
    app_client.post("/schemas/auth-service/User/versions/1.0.0/deprecate")

    # Check auth-service is deprecated
    response = app_client.get("/schemas/auth-service/User/versions/1.0.0")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["deprecated"] is True

    # Check billing-service is NOT deprecated
    response = app_client.get("/schemas/billing-service/User/versions/1.0.0")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["deprecated"] is False
