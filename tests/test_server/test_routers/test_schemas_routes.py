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
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

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
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

    response = auth_enabled_client.get("/schemas/User/versions/1.0.0")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_list_schemas_with_read_permission(
    auth_enabled_client: TestClient,
    read_only_key: ApiKey,
    sample_api_key: ApiKey,
    sample_schema: dict[str, Any],
) -> None:
    """Test that read-only key can list schemas."""
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

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
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

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
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

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
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

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
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

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
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

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
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

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
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

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
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

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
    response1 = app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )

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
    for i in range(5):
        app_client.post(
            f"/schemas/auth-service/Model{i}/versions",
            json={
                "version": "1.0.0",
                "json_schema": sample_schema,
                "registered_by": "test-service",
            },
        )

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
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    response = app_client.delete("/schemas/auth-service/User/versions/1.0.0")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "force=true" in response.json()["detail"]


def test_list_namespaces_for_model(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test listing all namespaces that contain a specific model."""
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

    app_client.post("/schemas/auth-service/User/versions/1.0.0/deprecate")

    response = app_client.get("/schemas/auth-service/User/versions/1.0.0")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["deprecated"] is True

    response = app_client.get("/schemas/billing-service/User/versions/1.0.0")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["deprecated"] is False


# ============================================================================
# AVRO SCHEMA REGISTRATION TESTS
# ============================================================================


def test_register_schema_with_avro(
    app_client: TestClient,
    sample_schema: dict[str, Any],
    sample_avro_schema: dict[str, Any],
) -> None:
    """Test registering a schema with both JSON Schema and Avro schema."""
    response = app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": sample_avro_schema,
            "registered_by": "test-service",
            "meta": {"description": "User schema with Avro"},
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["model_name"] == "User"
    assert data["version"] == "1.0.0"
    assert "json_schema" in data
    assert "avro_schema" in data
    assert data["avro_schema"]["type"] == "record"
    assert data["avro_schema"]["name"] == "User"


def test_register_schema_json_only(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test registering a schema with only JSON Schema (no Avro)."""
    response = app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert "json_schema" in data
    assert data["avro_schema"] is None


def test_register_namespaced_schema_with_avro(
    app_client: TestClient,
    sample_schema: dict[str, Any],
    sample_avro_schema: dict[str, Any],
) -> None:
    """Test registering namespaced schema with Avro."""
    response = app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": sample_avro_schema,
            "registered_by": "auth-service",
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["namespace"] == "auth-service"
    assert "avro_schema" in data
    assert data["avro_schema"]["namespace"] == "com.example"


def test_register_multiple_versions_with_avro(
    app_client: TestClient,
    sample_schema: dict[str, Any],
    sample_avro_schema: dict[str, Any],
) -> None:
    """Test registering multiple versions with Avro schemas."""
    # Register version 1.0.0
    avro_v1 = {**sample_avro_schema, "name": "UserV1"}
    response1 = app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": avro_v1,
            "registered_by": "test-service",
        },
    )
    assert response1.status_code == status.HTTP_201_CREATED

    # Register version 2.0.0
    schema_v2 = {
        **sample_schema,
        "properties": {
            **sample_schema["properties"],
            "email": {"type": "string"},
        },
    }
    avro_v2 = {
        **sample_avro_schema,
        "name": "UserV2",
        "fields": [
            *sample_avro_schema["fields"],
            {"name": "email", "type": "string"},
        ],
    }
    response2 = app_client.post(
        "/schemas/User/versions",
        json={
            "version": "2.0.0",
            "json_schema": schema_v2,
            "avro_schema": avro_v2,
            "registered_by": "test-service",
        },
    )
    assert response2.status_code == status.HTTP_201_CREATED

    # Verify both versions exist with Avro
    get_v1 = app_client.get("/schemas/User/versions/1.0.0")
    assert get_v1.json()["avro_schema"]["name"] == "UserV1"

    get_v2 = app_client.get("/schemas/User/versions/2.0.0")
    assert get_v2.json()["avro_schema"]["name"] == "UserV2"


def test_register_invalid_avro_schema_fails(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that registering with invalid Avro schema fails validation."""
    invalid_avro = {
        "type": "invalid_type",
        "name": "User",
    }

    response = app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": invalid_avro,
            "registered_by": "test-service",
        },
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


def test_avro_schema_with_complex_types(
    app_client: TestClient,
) -> None:
    """Test registering Avro schema with complex types (arrays, nested records)."""
    json_schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "addresses": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "street": {"type": "string"},
                        "city": {"type": "string"},
                    },
                },
            },
        },
        "required": ["name"],
    }

    avro_schema = {
        "type": "record",
        "name": "User",
        "namespace": "com.example",
        "fields": [
            {"name": "name", "type": "string"},
            {
                "name": "addresses",
                "type": {
                    "type": "array",
                    "items": {
                        "type": "record",
                        "name": "Address",
                        "fields": [
                            {"name": "street", "type": "string"},
                            {"name": "city", "type": "string"},
                        ],
                    },
                },
            },
        ],
    }

    response = app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": json_schema,
            "avro_schema": avro_schema,
            "registered_by": "test-service",
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["avro_schema"]["fields"][1]["type"]["type"] == "array"


def test_avro_schema_with_optional_fields(
    app_client: TestClient,
) -> None:
    """Test registering Avro schema with optional fields (union types)."""
    json_schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "email": {"type": ["string", "null"]},
            "age": {"type": ["integer", "null"]},
        },
        "required": ["name"],
    }

    avro_schema = {
        "type": "record",
        "name": "User",
        "namespace": "com.example",
        "fields": [
            {"name": "name", "type": "string"},
            {"name": "email", "type": ["null", "string"], "default": None},
            {"name": "age", "type": ["null", "int"], "default": None},
        ],
    }

    response = app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": json_schema,
            "avro_schema": avro_schema,
            "registered_by": "test-service",
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    # Check that optional fields have union types
    email_field = next(f for f in data["avro_schema"]["fields"] if f["name"] == "email")
    assert "null" in email_field["type"]


# ============================================================================
# AVRO SCHEMA RETRIEVAL TESTS
# ============================================================================


def test_get_schema_returns_avro(
    app_client: TestClient,
    sample_schema: dict[str, Any],
    sample_avro_schema: dict[str, Any],
) -> None:
    """Test that getting a schema returns Avro if it was registered."""
    app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": sample_avro_schema,
            "registered_by": "test-service",
        },
    )

    response = app_client.get("/schemas/User/versions/1.0.0")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "json_schema" in data
    assert "avro_schema" in data
    assert data["avro_schema"]["type"] == "record"


def test_get_schema_without_avro(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that getting schema without Avro returns only JSON Schema."""
    app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    response = app_client.get("/schemas/User/versions/1.0.0")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "json_schema" in data
    assert data["avro_schema"] is None


def test_get_latest_schema_with_avro(
    app_client: TestClient,
    sample_schema: dict[str, Any],
    sample_avro_schema: dict[str, Any],
) -> None:
    """Test getting latest schema returns Avro."""
    # Register v1.0.0
    app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    # Register v2.0.0 with Avro
    app_client.post(
        "/schemas/User/versions",
        json={
            "version": "2.0.0",
            "json_schema": sample_schema,
            "avro_schema": sample_avro_schema,
            "registered_by": "test-service",
        },
    )

    response = app_client.get("/schemas/User/versions/latest")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["version"] == "2.0.0"
    assert "avro_schema" in data


def test_list_schemas_includes_avro_models(
    app_client: TestClient,
    sample_schema: dict[str, Any],
    sample_avro_schema: dict[str, Any],
) -> None:
    """Test that schemas with Avro can be retrieved after listing."""
    app_client.post(
        "/schemas/UserWithAvro/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": sample_avro_schema,
            "registered_by": "test-service",
        },
    )

    app_client.post(
        "/schemas/UserWithoutAvro/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    list_response = app_client.get("/schemas")
    assert list_response.status_code == status.HTTP_200_OK
    data = list_response.json()

    model_names = [s["model_name"] for s in data["schemas"]]
    assert "UserWithAvro" in model_names
    assert "UserWithoutAvro" in model_names

    with_avro_response = app_client.get("/schemas/UserWithAvro/versions/1.0.0")
    assert with_avro_response.status_code == status.HTTP_200_OK
    with_avro_data = with_avro_response.json()
    assert "avro_schema" in with_avro_data
    assert with_avro_data["avro_schema"]["type"] == "record"

    without_avro_response = app_client.get("/schemas/UserWithoutAvro/versions/1.0.0")
    assert without_avro_response.status_code == status.HTTP_200_OK
    without_avro_data = without_avro_response.json()
    assert without_avro_data["avro_schema"] is None


# ============================================================================
# AVRO SCHEMA OVERWRITE TESTS
# ============================================================================


def test_overwrite_avro_schema(
    app_client: TestClient,
    sample_schema: dict[str, Any],
    sample_avro_schema: dict[str, Any],
) -> None:
    """Test overwriting a schema updates the Avro schema."""
    # Register original
    app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": sample_avro_schema,
            "registered_by": "test-service",
        },
    )

    # Overwrite with modified Avro
    modified_avro = {
        **sample_avro_schema,
        "doc": "Updated documentation",
    }
    response = app_client.post(
        "/schemas/User/versions?allow_overwrite=true",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": modified_avro,
            "registered_by": "test-service-2",
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["avro_schema"]["doc"] == "Updated documentation"


def test_overwrite_removes_avro_schema(
    app_client: TestClient,
    sample_schema: dict[str, Any],
    sample_avro_schema: dict[str, Any],
) -> None:
    """Test overwriting with no Avro removes the Avro schema."""
    # Register with Avro
    app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": sample_avro_schema,
            "registered_by": "test-service",
        },
    )

    # Overwrite without Avro
    response = app_client.post(
        "/schemas/User/versions?allow_overwrite=true",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service-2",
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["avro_schema"] is None


def test_overwrite_adds_avro_schema(
    app_client: TestClient,
    sample_schema: dict[str, Any],
    sample_avro_schema: dict[str, Any],
) -> None:
    """Test overwriting without Avro can add Avro schema."""
    # Register without Avro
    app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    # Overwrite with Avro
    response = app_client.post(
        "/schemas/User/versions?allow_overwrite=true",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": sample_avro_schema,
            "registered_by": "test-service-2",
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert "avro_schema" in data


# ============================================================================
# AVRO NAMESPACE TESTS
# ============================================================================


def test_avro_schema_namespace_preservation(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that Avro namespace is preserved correctly."""
    avro_schema = {
        "type": "record",
        "name": "User",
        "namespace": "com.mycompany.users",
        "fields": [
            {"name": "id", "type": "string"},
            {"name": "name", "type": "string"},
        ],
    }

    response = app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": avro_schema,
            "registered_by": "test-service",
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["avro_schema"]["namespace"] == "com.mycompany.users"


def test_different_avro_namespaces_same_model(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that different registry namespaces can have different Avro namespaces."""
    avro_auth = {
        "type": "record",
        "name": "User",
        "namespace": "com.mycompany.auth",
        "fields": [{"name": "id", "type": "string"}],
    }

    avro_billing = {
        "type": "record",
        "name": "User",
        "namespace": "com.mycompany.billing",
        "fields": [{"name": "id", "type": "string"}],
    }

    # Register in auth-service namespace
    response1 = app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": avro_auth,
            "registered_by": "auth-service",
        },
    )

    # Register in billing-service namespace
    response2 = app_client.post(
        "/schemas/billing-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": avro_billing,
            "registered_by": "billing-service",
        },
    )

    assert response1.status_code == status.HTTP_201_CREATED
    assert response2.status_code == status.HTTP_201_CREATED

    # Verify different Avro namespaces
    get1 = app_client.get("/schemas/auth-service/User/versions/1.0.0")
    get2 = app_client.get("/schemas/billing-service/User/versions/1.0.0")

    assert get1.json()["avro_schema"]["namespace"] == "com.mycompany.auth"
    assert get2.json()["avro_schema"]["namespace"] == "com.mycompany.billing"


# ============================================================================
# AVRO SCHEMA WITH AUTHENTICATION TESTS
# ============================================================================


def test_register_avro_with_write_permission(
    auth_enabled_client: TestClient,
    sample_api_key: ApiKey,
    sample_schema: dict[str, Any],
    sample_avro_schema: dict[str, Any],
) -> None:
    """Test that write key can register schemas with Avro."""
    response = auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": sample_avro_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert "avro_schema" in data


def test_get_avro_with_read_permission(
    auth_enabled_client: TestClient,
    sample_api_key: ApiKey,
    read_only_key: ApiKey,
    sample_schema: dict[str, Any],
    sample_avro_schema: dict[str, Any],
) -> None:
    """Test that read-only key can retrieve Avro schemas."""
    # Register with write key
    auth_enabled_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": sample_avro_schema,
            "registered_by": "test-service",
        },
        headers={"X-API-Key": sample_api_key._plaintext},  # type: ignore
    )

    # Get with read-only key
    response = auth_enabled_client.get(
        "/schemas/User/versions/1.0.0",
        headers={"X-API-Key": read_only_key._plaintext},  # type: ignore
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "avro_schema" in data


# ============================================================================
# AVRO SCHEMA DEPRECATION TESTS
# ============================================================================


def test_deprecated_schema_keeps_avro(
    app_client: TestClient,
    sample_schema: dict[str, Any],
    sample_avro_schema: dict[str, Any],
) -> None:
    """Test that deprecating a schema doesn't remove Avro schema."""
    app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": sample_avro_schema,
            "registered_by": "test-service",
        },
    )

    app_client.post("/schemas/User/versions/1.0.0/deprecate?message=Old version")

    response = app_client.get("/schemas/User/versions/1.0.0")
    data = response.json()

    assert data["deprecated"] is True
    assert "avro_schema" in data


# ============================================================================
# AVRO SCHEMA VALIDATION TESTS
# ============================================================================


def test_avro_schema_must_be_record_type(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that Avro schema must be a record type."""
    invalid_avro = {
        "type": "string",  # Not a record
    }

    response = app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": invalid_avro,
            "registered_by": "test-service",
        },
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


def test_avro_schema_requires_name(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that Avro schema requires a name field."""
    invalid_avro = {
        "type": "record",
        "fields": [{"name": "id", "type": "string"}],
        # Missing "name" field
    }

    response = app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": invalid_avro,
            "registered_by": "test-service",
        },
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


def test_avro_schema_requires_fields(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that Avro schema requires fields array."""
    invalid_avro = {
        "type": "record",
        "name": "User",
        # Missing "fields" array
    }

    response = app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": invalid_avro,
            "registered_by": "test-service",
        },
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


# ============================================================================
# AVRO SCHEMA METADATA TESTS
# ============================================================================


def test_avro_schema_with_documentation(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that Avro schema documentation is preserved."""
    avro_schema = {
        "type": "record",
        "name": "User",
        "namespace": "com.example",
        "doc": "User record with contact information",
        "fields": [
            {
                "name": "id",
                "type": "string",
                "doc": "Unique user identifier",
            },
            {
                "name": "name",
                "type": "string",
                "doc": "Full name of the user",
            },
        ],
    }

    response = app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": avro_schema,
            "registered_by": "test-service",
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["avro_schema"]["doc"] == "User record with contact information"
    assert data["avro_schema"]["fields"][0]["doc"] == "Unique user identifier"


def test_avro_schema_with_default_values(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that Avro schema default values are preserved."""
    avro_schema = {
        "type": "record",
        "name": "User",
        "namespace": "com.example",
        "fields": [
            {"name": "id", "type": "string"},
            {"name": "status", "type": "string", "default": "active"},
            {"name": "score", "type": "int", "default": 0},
        ],
    }

    response = app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": avro_schema,
            "registered_by": "test-service",
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    status_field = next(
        f for f in data["avro_schema"]["fields"] if f["name"] == "status"
    )
    score_field = next(f for f in data["avro_schema"]["fields"] if f["name"] == "score")
    assert status_field["default"] == "active"
    assert score_field["default"] == 0


# ============================================================================
# AVRO SCHEMA EDGE CASES
# ============================================================================


def test_empty_avro_fields_array_fails(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that Avro schema with empty fields array fails."""
    invalid_avro = {
        "type": "record",
        "name": "User",
        "fields": [],  # Empty fields
    }

    response = app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": invalid_avro,
            "registered_by": "test-service",
        },
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


def test_avro_schema_with_enum_type(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test registering Avro schema with enum types."""
    avro_schema = {
        "type": "record",
        "name": "User",
        "namespace": "com.example",
        "fields": [
            {"name": "id", "type": "string"},
            {
                "name": "role",
                "type": {
                    "type": "enum",
                    "name": "Role",
                    "symbols": ["ADMIN", "USER", "GUEST"],
                },
            },
        ],
    }

    response = app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": avro_schema,
            "registered_by": "test-service",
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    role_field = next(f for f in data["avro_schema"]["fields"] if f["name"] == "role")
    assert role_field["type"]["type"] == "enum"
    assert "ADMIN" in role_field["type"]["symbols"]


def test_avro_schema_with_map_type(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test registering Avro schema with map types."""
    avro_schema = {
        "type": "record",
        "name": "User",
        "namespace": "com.example",
        "fields": [
            {"name": "id", "type": "string"},
            {
                "name": "metadata",
                "type": {"type": "map", "values": "string"},
            },
        ],
    }

    response = app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "avro_schema": avro_schema,
            "registered_by": "test-service",
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    metadata_field = next(
        f for f in data["avro_schema"]["fields"] if f["name"] == "metadata"
    )
    assert metadata_field["type"]["type"] == "map"
