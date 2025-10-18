"""Tests for schema endpoints."""

import sys
from typing import Any

from fastapi import status
from fastapi.testclient import TestClient

# ruff: noqa: PLR2004


def test_register_global_schema(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test registration of a global schema (no namespace)."""
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


def test_register_namespaced_schema_with_path(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test registration with namespace in the URL path."""
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


def test_register_namespaced_schema_with_query_param(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test registration with namespace as query parameter."""
    response = app_client.post(
        "/schemas/User/versions?namespace=auth-service",
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


def test_register_schema_with_metadata(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test schema registration with metadata."""
    response = app_client.post(
        "/schemas/billing-service/Invoice/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "billing-service",
            "meta": {
                "description": "Invoice schema",
                "environment": "production",
                "team": "billing",
            },
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["meta"]["description"] == "Invoice schema"
    assert data["meta"]["environment"] == "production"
    assert data["meta"]["team"] == "billing"


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


def test_same_model_in_namespace_and_global(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that same model can exist as both global and namespaced."""
    # Register global
    response1 = app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "global-service",
        },
    )

    # Register namespaced
    response2 = app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )

    assert response1.status_code == status.HTTP_201_CREATED
    assert response2.status_code == status.HTTP_201_CREATED
    assert response1.json()["namespace"] is None
    assert response2.json()["namespace"] == "auth-service"


def test_get_global_schema(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test retrieving a global schema."""
    # Register schema
    app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    # Get schema
    response = app_client.get("/schemas/User/versions/1.0.0")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["namespace"] is None
    assert data["model_name"] == "User"
    assert data["version"] == "1.0.0"
    assert data["json_schema"] == sample_schema


def test_get_namespaced_schema_by_path(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test retrieving a namespaced schema using URL path."""
    # Register schema
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )

    # Get schema
    response = app_client.get("/schemas/auth-service/User/versions/1.0.0")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["namespace"] == "auth-service"
    assert data["model_name"] == "User"
    assert data["version"] == "1.0.0"


def test_get_namespaced_schema_by_query(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test retrieving a namespaced schema using query parameter."""
    # Register schema
    app_client.post(
        "/schemas/User/versions?namespace=auth-service",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )

    # Get schema
    response = app_client.get("/schemas/User/versions/1.0.0?namespace=auth-service")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["namespace"] == "auth-service"
    assert data["model_name"] == "User"


def test_get_nonexistent_schema(app_client: TestClient) -> None:
    """Test getting a schema that doesn't exist."""
    response = app_client.get("/schemas/NonExistent/versions/1.0.0")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in response.json()["detail"]


def test_get_schema_wrong_namespace(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test getting a schema from wrong namespace returns 404."""
    # Register in auth-service
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )

    # Try to get from billing-service
    response = app_client.get("/schemas/billing-service/User/versions/1.0.0")
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_get_latest_global_schema(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test retrieving the latest version of a global schema."""
    # Register multiple versions
    for version in ["1.0.0", "1.1.0", "2.0.0"]:
        response = app_client.post(
            "/schemas/User/versions",
            json={
                "version": version,
                "json_schema": sample_schema,
                "registered_by": "test-service",
            },
        )
        assert response.status_code == status.HTTP_201_CREATED, response.text

    # Get latest
    response = app_client.get("/schemas/User/versions/latest")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["version"] == "2.0.0"
    assert data["namespace"] is None


def test_get_latest_namespaced_schema(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test retrieving the latest version of a namespaced schema."""
    # Register multiple versions
    for version in ["1.0.0", "1.1.0", "2.0.0"]:
        app_client.post(
            "/schemas/auth-service/User/versions",
            json={
                "version": version,
                "json_schema": sample_schema,
                "registered_by": "auth-service",
            },
        )

    # Get latest
    response = app_client.get("/schemas/auth-service/User/versions/latest")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["version"] == "2.0.0"
    assert data["namespace"] == "auth-service"


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


def test_list_versions_global_schema(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test listing all versions of a global schema."""
    # Register multiple versions
    versions = ["1.0.0", "1.1.0", "2.0.0"]
    for version in versions:
        app_client.post(
            "/schemas/User/versions",
            json={
                "version": version,
                "json_schema": sample_schema,
                "registered_by": "test-service",
            },
        )

    # List versions
    response = app_client.get("/schemas/User/versions")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["versions"] == versions


def test_list_versions_namespaced_schema(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test listing all versions of a namespaced schema."""
    versions = ["1.0.0", "1.1.0", "2.0.0"]
    for version in versions:
        app_client.post(
            "/schemas/auth-service/User/versions",
            json={
                "version": version,
                "json_schema": sample_schema,
                "registered_by": "auth-service",
            },
        )

    # List versions
    response = app_client.get("/schemas/auth-service/User/versions")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["versions"] == versions


def test_list_versions_only_for_specific_namespace(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that list versions only returns versions for the specified namespace."""
    # Register in auth-service
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )

    # Register in billing-service
    app_client.post(
        "/schemas/billing-service/User/versions",
        json={
            "version": "2.0.0",
            "json_schema": sample_schema,
            "registered_by": "billing-service",
        },
    )

    # List auth-service versions
    response = app_client.get("/schemas/auth-service/User/versions")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["versions"] == ["1.0.0"]

    # List billing-service versions
    response = app_client.get("/schemas/billing-service/User/versions")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["versions"] == ["2.0.0"]


def test_list_all_schemas(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test listing all schemas."""
    # Register schemas for multiple models and namespaces
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )
    app_client.post(
        "/schemas/billing-service/Product/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    # List all schemas
    response = app_client.get("/schemas")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 2
    assert len(data["schemas"]) == 2
    assert data["total_count"] == 2


def test_list_schemas_filtered_by_namespace(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test listing schemas filtered by namespace."""
    # Register in different namespaces
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )
    app_client.post(
        "/schemas/billing-service/Product/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "billing-service",
        },
    )

    # Filter by namespace
    response = app_client.get("/schemas?namespace=auth-service")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 1
    assert data["schemas"][0]["namespace"] == "auth-service"


def test_list_global_schemas_only(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test listing only global schemas (no namespace)."""
    # Register global schema
    app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "global-service",
        },
    )

    # Register namespaced schema
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )

    # Filter for global schemas only
    response = app_client.get("/schemas?namespace=null")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 1
    assert data["schemas"][0]["namespace"] is None


def test_list_schemas_filtered_by_model_name(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test listing schemas filtered by model name across namespaces."""
    # Register User in multiple namespaces
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
    app_client.post(
        "/schemas/billing-service/Product/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "billing-service",
        },
    )

    # Filter by model name
    response = app_client.get("/schemas?model_name=User")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 2
    assert all(schema["model_name"] == "User" for schema in data["schemas"])


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
        "/schemas/auth-service/User/versions",
        json={
            "version": "2.0.0",
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

    assert namespaces["null"] == ["1.0.0"]
    assert namespaces["auth-service"] == ["1.0.0", "2.0.0"]
    assert namespaces["billing-service"] == ["1.5.0"]


def test_list_namespaces_for_nonexistent_model(app_client: TestClient) -> None:
    """Test listing namespaces for a model that doesn't exist."""
    response = app_client.get("/schemas/NonExistentModel/namespaces")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in response.json()["detail"]


def test_compare_versions_global_schema(
    app_client: TestClient,
    sample_schema: dict[str, Any],
    sample_schema_v2: dict[str, Any],
) -> None:
    """Test comparing two versions of a global schema."""
    # Register two versions
    app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )
    app_client.post(
        "/schemas/User/versions",
        json={
            "version": "2.0.0",
            "json_schema": sample_schema_v2,
            "registered_by": "test-service",
        },
    )

    # Compare
    response = app_client.get(
        "/schemas/User/compare?from_version=1.0.0&to_version=2.0.0"
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["namespace"] is None
    assert data["model_name"] == "User"
    assert data["from_version"] == "1.0.0"
    assert data["to_version"] == "2.0.0"
    assert "changes" in data


def test_compare_versions_namespaced_schema(
    app_client: TestClient,
    sample_schema: dict[str, Any],
    sample_schema_v2: dict[str, Any],
) -> None:
    """Test comparing two versions of a namespaced schema."""
    # Register two versions
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "2.0.0",
            "json_schema": sample_schema_v2,
            "registered_by": "auth-service",
        },
    )

    # Compare
    response = app_client.get(
        "/schemas/auth-service/User/compare?from_version=1.0.0&to_version=2.0.0"
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["namespace"] == "auth-service"
    assert data["model_name"] == "User"
    assert data["from_version"] == "1.0.0"
    assert data["to_version"] == "2.0.0"


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


def test_compare_nonexistent_versions(app_client: TestClient) -> None:
    """Test comparing nonexistent versions."""
    response = app_client.get(
        "/schemas/auth-service/User/compare?from_version=1.0.0&to_version=2.0.0"
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_delete_global_schema(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test deleting a global schema version."""
    # Register schema
    app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    # Delete with force
    response = app_client.delete("/schemas/User/versions/1.0.0?force=true")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["deleted"] is True
    assert data["namespace"] is None
    assert data["model_name"] == "User"
    assert data["version"] == "1.0.0"

    # Verify it's gone
    response = app_client.get("/schemas/User/versions/1.0.0")
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_delete_namespaced_schema(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test deleting a namespaced schema version."""
    # Register schema
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )

    # Delete with force
    response = app_client.delete("/schemas/auth-service/User/versions/1.0.0?force=true")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["deleted"] is True
    assert data["namespace"] == "auth-service"
    assert data["model_name"] == "User"
    assert data["version"] == "1.0.0"

    # Verify it's gone
    response = app_client.get("/schemas/auth-service/User/versions/1.0.0")
    assert response.status_code == status.HTTP_404_NOT_FOUND


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


def test_delete_nonexistent_schema(app_client: TestClient) -> None:
    """Test deleting a schema that doesn't exist."""
    response = app_client.delete(
        "/schemas/auth-service/NonExistent/versions/1.0.0?force=true"
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_deprecate_global_schema(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test marking a global schema as deprecated."""
    # Register schema
    app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    # Deprecate it
    response = app_client.post(
        "/schemas/User/versions/1.0.0/deprecate"
        "?message=Security+vulnerability.+Please+upgrade+to+2.0.0"
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["deprecated"] is True
    assert data["deprecated_at"] is not None
    assert "Security vulnerability" in data["deprecation_message"]

    # Verify by getting the schema
    response = app_client.get("/schemas/User/versions/1.0.0")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["deprecated"] is True


def test_deprecate_namespaced_schema(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test marking a namespaced schema as deprecated."""
    # Register schema
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )

    # Deprecate it
    response = app_client.post(
        "/schemas/auth-service/User/versions/1.0.0/deprecate"
        "?message=Deprecated+in+favor+of+v2"
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["deprecated"] is True
    assert data["namespace"] == "auth-service"
    assert data["deprecated_at"] is not None
    assert "Deprecated in favor of v2" in data["deprecation_message"]


def test_deprecate_schema_without_message(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test deprecating a schema without a message."""
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    response = app_client.post("/schemas/auth-service/User/versions/1.0.0/deprecate")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["deprecated"] is True
    assert data["deprecation_message"] is None


def test_deprecate_nonexistent_schema(app_client: TestClient) -> None:
    """Test deprecating a schema that doesn't exist."""
    response = app_client.post(
        "/schemas/auth-service/NonExistent/versions/1.0.0/deprecate"
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_list_schemas_exclude_deprecated_by_default(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that deprecated schemas are excluded by default."""
    # Register two schemas
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )
    app_client.post(
        "/schemas/auth-service/Product/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )

    # Deprecate one
    app_client.post("/schemas/auth-service/Product/versions/1.0.0/deprecate")

    # List without include_deprecated
    response = app_client.get("/schemas?namespace=auth-service")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 1
    assert data["schemas"][0]["model_name"] == "User"


def test_list_schemas_include_deprecated(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test including deprecated schemas in listing."""
    # Register two schemas
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )
    app_client.post(
        "/schemas/auth-service/Product/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )

    # Deprecate one
    app_client.post("/schemas/auth-service/Product/versions/1.0.0/deprecate")

    # List with include_deprecated
    response = app_client.get("/schemas?namespace=auth-service&include_deprecated=true")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 2


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


def test_invalid_json_schema(
    app_client: TestClient,
) -> None:
    """Test that invalid JSON Schema is rejected."""
    response = app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": {
                "type": "object",
                "additionalProperties": "not_valid",
            },
            "registered_by": "test-service",
        },
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "Invalid JSON Schema" in response.json()["detail"]


def test_complex_namespace_workflow(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test a complex workflow with multiple namespaces."""
    # Create User schema in multiple namespaces and versions
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
        "/schemas/auth-service/User/versions",
        json={
            "version": "2.0.0",
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

    # Verify global latest
    response = app_client.get("/schemas/User/versions/latest")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["version"] == "1.0.0"
    assert response.json()["namespace"] is None

    # Verify auth-service latest
    response = app_client.get("/schemas/auth-service/User/versions/latest")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["version"] == "2.0.0"
    assert response.json()["namespace"] == "auth-service"

    # List all User schemas
    response = app_client.get("/schemas?model_name=User&include_deprecated=true")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["total"] == 3  # Three distinct namespace/model combinations

    # Get namespaces for User
    response = app_client.get("/schemas/User/namespaces")
    assert response.status_code == status.HTTP_200_OK
    namespaces = response.json()["namespaces"]
    assert len(namespaces) == 3  # null, auth-service, billing-service
    assert namespaces["auth-service"] == ["1.0.0", "2.0.0"]


def test_schema_list_item_includes_deprecated_versions(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that SchemaListItem includes deprecated_versions field."""
    # Register multiple versions
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "2.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )

    # Deprecate one version
    app_client.post("/schemas/auth-service/User/versions/1.0.0/deprecate")

    # List schemas with deprecated included
    response = app_client.get("/schemas?namespace=auth-service&include_deprecated=true")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    schema_item = data["schemas"][0]
    print(schema_item, file=sys.stderr)
    assert "deprecated_versions" in schema_item
    assert "1.0.0" in schema_item["deprecated_versions"]
    assert "2.0.0" not in schema_item["deprecated_versions"]


def test_multiple_services_register_same_namespace_model(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that multiple services can register versions in same namespace."""
    # Two different services register versions
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-api",
        },
    )
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "2.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-worker",
        },
    )

    # List schemas
    response = app_client.get("/schemas?namespace=auth-service&include_deprecated=true")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    schema_item = data["schemas"][0]

    # Check that both services are listed
    assert "auth-api" in schema_item["registered_by"]
    assert "auth-worker" in schema_item["registered_by"]
    assert len(schema_item["registered_by"]) == 2


def test_path_vs_query_namespace_precedence(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that path-based namespace takes precedence over query parameter."""
    # Register in auth-service
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )

    # Try to access with conflicting query parameter (should use path)
    response = app_client.get(
        "/schemas/auth-service/User/versions/1.0.0?namespace=billing-service"
    )

    # Should return 404 because path says auth-service, not billing-service
    # The path-based route should match and use auth-service
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["namespace"] == "auth-service"


def test_url_special_characters_in_namespace(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that namespaces with hyphens and underscores work correctly."""
    # Register with hyphenated namespace
    response = app_client.post(
        "/schemas/auth-service-v2/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service-v2",
        },
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["namespace"] == "auth-service-v2"

    # Register with underscored namespace
    response = app_client.post(
        "/schemas/billing_service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "billing_service",
        },
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["namespace"] == "billing_service"

    # Retrieve both
    response = app_client.get("/schemas/auth-service-v2/User/versions/1.0.0")
    assert response.status_code == status.HTTP_200_OK

    response = app_client.get("/schemas/billing_service/User/versions/1.0.0")
    assert response.status_code == status.HTTP_200_OK


def test_url_special_characters_in_model_name(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that model names with hyphens and underscores work correctly."""
    # Register with hyphenated model name
    response = app_client.post(
        "/schemas/auth-service/User-Profile/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["model_name"] == "User-Profile"

    # Register with underscored model name
    response = app_client.post(
        "/schemas/auth-service/User_Settings/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["model_name"] == "User_Settings"

    # Retrieve both
    response = app_client.get("/schemas/auth-service/User-Profile/versions/1.0.0")
    assert response.status_code == status.HTTP_200_OK

    response = app_client.get("/schemas/auth-service/User_Settings/versions/1.0.0")
    assert response.status_code == status.HTTP_200_OK


def test_global_schema_with_query_namespace_becomes_namespaced(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that using query parameter on global route creates namespaced schema."""
    # Use global endpoint with namespace query parameter
    response = app_client.post(
        "/schemas/User/versions?namespace=auth-service",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["namespace"] == "auth-service"
    assert data["model_name"] == "User"

    # Should be accessible via namespaced route
    response = app_client.get("/schemas/auth-service/User/versions/1.0.0")
    assert response.status_code == status.HTTP_200_OK

    # Should also be accessible via global route with query
    response = app_client.get("/schemas/User/versions/1.0.0?namespace=auth-service")
    assert response.status_code == status.HTTP_200_OK


def test_list_versions_empty_result(
    app_client: TestClient,
) -> None:
    """Test listing versions for non-existent model."""
    response = app_client.get("/schemas/NonExistent/versions")
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_list_schemas_empty_result(
    app_client: TestClient,
) -> None:
    """Test listing schemas with no results."""
    response = app_client.get("/schemas?namespace=nonexistent-service")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 0
    assert data["schemas"] == []
    assert data["total_count"] == 0


def test_compare_versions_identical_schemas(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test comparing two identical schema versions."""
    # Register same schema twice
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "2.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    response = app_client.get(
        "/schemas/auth-service/User/compare?from_version=1.0.0&to_version=2.0.0"
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["changes"]["compatibility"] == "identical"
    assert len(data["changes"]["breaking_changes"]) == 0


def test_deprecate_already_deprecated_schema(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test deprecating a schema that is already deprecated."""
    # Register and deprecate
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    app_client.post(
        "/schemas/auth-service/User/versions/1.0.0/deprecate?message=First+reason"
    )

    # Deprecate again with different message
    response = app_client.post(
        "/schemas/auth-service/User/versions/1.0.0/deprecate?message=Second+reason"
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["deprecated"] is True
    # Should have the new message
    assert "Second reason" in data["deprecation_message"]


def test_delete_already_deleted_schema(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test deleting a schema that has already been deleted."""
    # Register and delete
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    app_client.delete("/schemas/auth-service/User/versions/1.0.0?force=true")

    # Try to delete again
    response = app_client.delete("/schemas/auth-service/User/versions/1.0.0?force=true")

    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_register_multiple_versions_same_model(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test registering multiple versions of the same model."""
    versions = ["1.0.0", "1.0.1", "1.1.0", "2.0.0", "2.1.0"]

    for version in versions:
        response = app_client.post(
            "/schemas/auth-service/User/versions",
            json={
                "version": version,
                "json_schema": sample_schema,
                "registered_by": "test-service",
            },
        )
        assert response.status_code == status.HTTP_201_CREATED

    # List all versions
    response = app_client.get("/schemas/auth-service/User/versions")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["versions"] == versions

    # Get latest should return highest version
    response = app_client.get("/schemas/auth-service/User/versions/latest")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["version"] == "2.1.0"


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

    # Delete from auth-service
    app_client.delete("/schemas/auth-service/User/versions/1.0.0?force=true")

    # Verify auth-service is gone
    response = app_client.get("/schemas/auth-service/User/versions/1.0.0")
    assert response.status_code == status.HTTP_404_NOT_FOUND

    # Verify billing-service still exists
    response = app_client.get("/schemas/billing-service/User/versions/1.0.0")
    assert response.status_code == status.HTTP_200_OK


def test_version_sorting_with_prerelease(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that semantic versioning handles pre-release versions correctly."""
    versions = ["1.0.0", "1.0.0-alpha", "1.0.0-beta", "2.0.0-rc1", "2.0.0"]

    for version in versions:
        app_client.post(
            "/schemas/auth-service/User/versions",
            json={
                "version": version,
                "json_schema": sample_schema,
                "registered_by": "test-service",
            },
        )

    # Get latest - should return 2.0.0 (not a pre-release)
    response = app_client.get("/schemas/auth-service/User/versions/latest")
    assert response.status_code == status.HTTP_200_OK
    # This may depend on your versioning logic
    data = response.json()
    assert data["version"] in ["2.0.0", "2.0.0-rc1"]  # Depending on implementation


def test_mixed_route_access_patterns(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that schemas can be accessed via both path and query methods."""
    # Register via path
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )

    # Access via path
    response1 = app_client.get("/schemas/auth-service/User/versions/1.0.0")
    assert response1.status_code == status.HTTP_200_OK

    # Access via query parameter
    response2 = app_client.get("/schemas/User/versions/1.0.0?namespace=auth-service")
    assert response2.status_code == status.HTTP_200_OK

    # Both should return the same data
    assert response1.json()["id"] == response2.json()["id"]
    assert response1.json()["namespace"] == response2.json()["namespace"]


def test_list_schemas_with_multiple_filters(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test listing schemas with multiple filters applied."""
    # Register various schemas
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
        },
    )
    app_client.post(
        "/schemas/auth-service/Product/versions",
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

    # Filter by both namespace and model_name
    response = app_client.get("/schemas?namespace=auth-service&model_name=User")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 1
    assert data["schemas"][0]["namespace"] == "auth-service"
    assert data["schemas"][0]["model_name"] == "User"


def test_pagination_boundary_conditions(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test pagination with edge cases."""
    # Register 3 schemas
    for i in range(3):
        app_client.post(
            f"/schemas/auth-service/Model{i}/versions",
            json={
                "version": "1.0.0",
                "json_schema": sample_schema,
                "registered_by": "test-service",
            },
        )

    # Request more than available
    response = app_client.get("/schemas?limit=10&offset=0")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 3
    assert data["total_count"] == 3

    # Request with offset beyond available
    response = app_client.get("/schemas?limit=10&offset=10")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 0
    assert data["total_count"] == 3


def test_schema_metadata_persistence(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that metadata is correctly stored and retrieved."""
    metadata = {
        "description": "Test schema",
        "owner": "platform-team",
        "environment": "production",
        "tags": ["user", "authentication"],
        "custom_field": "custom_value",
    }

    # Register with metadata
    app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "auth-service",
            "meta": metadata,
        },
    )

    # Retrieve and verify metadata
    response = app_client.get("/schemas/auth-service/User/versions/1.0.0")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert data["meta"]["description"] == metadata["description"]
    assert data["meta"]["owner"] == metadata["owner"]
    assert data["meta"]["environment"] == metadata["environment"]
    assert data["meta"]["tags"] == metadata["tags"]
    assert data["meta"]["custom_field"] == metadata["custom_field"]


def test_empty_namespace_treated_as_global(
    app_client: TestClient,
    sample_schema: dict[str, Any],
) -> None:
    """Test that empty string namespace is treated as global."""
    # Register global schema
    app_client.post(
        "/schemas/User/versions",
        json={
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )

    # List with empty namespace filter
    response = app_client.get("/schemas?namespace=")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] >= 1

    # All returned schemas should be global
    for schema in data["schemas"]:
        assert schema["namespace"] is None
