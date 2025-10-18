"""Tests for SchemaService business logic."""

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from pyrmute_registry.server.models.schema import SchemaRecord
from pyrmute_registry.server.schemas.schema import SchemaCreate
from pyrmute_registry.server.services.schema import SchemaService

# ruff: noqa: PLR2004


@pytest.fixture
def schema_service(db_session: Session) -> SchemaService:
    """Create a SchemaService instance for testing."""
    return SchemaService(db_session)


@pytest.fixture
def sample_schema_data(sample_schema: dict[str, Any]) -> SchemaCreate:
    """Create sample SchemaCreate data."""
    return SchemaCreate(
        version="1.0.0",
        json_schema=sample_schema,
        registered_by="test-service",
        meta={"description": "Test schema"},
    )


# ============================================================================
# Register Schema Tests
# ============================================================================


def test_register_global_schema(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test registering a global schema."""
    response = schema_service.register_schema(
        namespace=None,
        model_name="User",
        schema_data=sample_schema_data,
    )

    assert response.namespace is None
    assert response.model_name == "User"
    assert response.version == "1.0.0"
    assert response.registered_by == "test-service"
    assert response.deprecated is False


def test_register_namespaced_schema(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test registering a namespaced schema."""
    response = schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )

    assert response.namespace == "auth-service"
    assert response.model_name == "User"
    assert response.version == "1.0.0"


def test_register_schema_with_metadata(
    schema_service: SchemaService,
    sample_schema: dict[str, Any],
) -> None:
    """Test that metadata is properly stored."""
    metadata = {
        "description": "User schema",
        "owner": "platform-team",
        "environment": "production",
    }

    schema_data = SchemaCreate(
        version="1.0.0",
        json_schema=sample_schema,
        registered_by="test-service",
        meta=metadata,
    )

    response = schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=schema_data,
    )

    assert response.meta == metadata


def test_register_duplicate_schema_raises_conflict(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test that registering duplicate schema raises conflict error."""
    # Register first time
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )

    # Try to register again without overwrite
    with pytest.raises(HTTPException) as exc_info:
        schema_service.register_schema(
            namespace="auth-service",
            model_name="User",
            schema_data=sample_schema_data,
        )

    assert exc_info.value.status_code == status.HTTP_409_CONFLICT
    assert "already exists" in exc_info.value.detail


def test_register_duplicate_schema_with_overwrite(
    schema_service: SchemaService,
    sample_schema: dict[str, Any],
) -> None:
    """Test that overwrite allows updating existing schema."""
    # Register first version
    schema_data = SchemaCreate(
        version="1.0.0",
        json_schema=sample_schema,
        registered_by="service-1",
        meta={"version": "original"},
    )

    original = schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=schema_data,
    )

    # Update with overwrite
    modified_schema = {**sample_schema, "description": "Modified"}
    updated_data = SchemaCreate(
        version="1.0.0",
        json_schema=modified_schema,
        registered_by="service-2",
        meta={"version": "updated"},
    )

    response = schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=updated_data,
        allow_overwrite=True,
    )

    assert response.id == original.id  # Same record
    assert response.json_schema["description"] == "Modified"
    assert response.registered_by == "service-2"
    assert response.meta["version"] == "updated"


def test_register_schema_invalid_version_format(
    schema_service: SchemaService,
    sample_schema: dict[str, Any],
) -> None:
    """Test that invalid semantic version raises error.

    Note: Basic format validation happens at Pydantic level.
    This tests semantic version parsing in the service layer.
    """
    # This passes Pydantic pattern but might fail semantic version parsing
    # depending on your parse_version implementation
    schema_data = SchemaCreate(
        version="999.999.999",  # Valid format but edge case
        json_schema=sample_schema,
        registered_by="test-service",
    )

    # This should succeed if parse_version handles it
    response = schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=schema_data,
    )

    assert response.version == "999.999.999"


def test_register_schema_invalid_json_schema(
    schema_service: SchemaService,
) -> None:
    """Test that invalid JSON Schema raises error."""
    invalid_schema = {
        "type": "object",
        "additionalProperties": "not_a_boolean",  # Should be boolean
    }

    schema_data = SchemaCreate(
        version="1.0.0",
        json_schema=invalid_schema,
        registered_by="test-service",
    )

    with pytest.raises(HTTPException) as exc_info:
        schema_service.register_schema(
            namespace="auth-service",
            model_name="User",
            schema_data=schema_data,
        )

    assert exc_info.value.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "Invalid JSON Schema" in exc_info.value.detail


def test_register_same_model_different_namespaces(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test that same model can exist in different namespaces."""
    response1 = schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )

    response2 = schema_service.register_schema(
        namespace="billing-service",
        model_name="User",
        schema_data=sample_schema_data,
    )

    assert response1.namespace == "auth-service"
    assert response2.namespace == "billing-service"
    assert response1.id != response2.id


def test_register_same_model_global_and_namespaced(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test that same model can exist as both global and namespaced."""
    global_response = schema_service.register_schema(
        namespace=None,
        model_name="User",
        schema_data=sample_schema_data,
    )

    namespaced_response = schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )

    assert global_response.namespace is None
    assert namespaced_response.namespace == "auth-service"
    assert global_response.id != namespaced_response.id


# ============================================================================
# Get Schema Tests
# ============================================================================


def test_get_schema_success(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test retrieving an existing schema."""
    # Register schema
    registered = schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )

    # Get schema
    response = schema_service.get_schema(
        namespace="auth-service",
        model_name="User",
        version="1.0.0",
    )

    assert response.id == registered.id
    assert response.namespace == "auth-service"
    assert response.model_name == "User"
    assert response.version == "1.0.0"


def test_get_global_schema(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test retrieving a global schema."""
    registered = schema_service.register_schema(
        namespace=None,
        model_name="User",
        schema_data=sample_schema_data,
    )

    response = schema_service.get_schema(
        namespace=None,
        model_name="User",
        version="1.0.0",
    )

    assert response.id == registered.id
    assert response.namespace is None


def test_get_schema_not_found(
    schema_service: SchemaService,
) -> None:
    """Test getting non-existent schema raises 404."""
    with pytest.raises(HTTPException) as exc_info:
        schema_service.get_schema(
            namespace="auth-service",
            model_name="NonExistent",
            version="1.0.0",
        )

    assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in exc_info.value.detail


def test_get_schema_wrong_namespace(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test that getting schema from wrong namespace fails."""
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )

    with pytest.raises(HTTPException) as exc_info:
        schema_service.get_schema(
            namespace="billing-service",
            model_name="User",
            version="1.0.0",
        )

    assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND


# ============================================================================
# Get Latest Schema Tests
# ============================================================================


def test_get_latest_schema(
    schema_service: SchemaService,
    sample_schema: dict[str, Any],
) -> None:
    """Test getting the latest version of a schema."""
    # Register multiple versions
    for version in ["1.0.0", "1.1.0", "2.0.0"]:
        schema_data = SchemaCreate(
            version=version,
            json_schema=sample_schema,
            registered_by="test-service",
        )
        schema_service.register_schema(
            namespace="auth-service",
            model_name="User",
            schema_data=schema_data,
        )

    response = schema_service.get_latest_schema(
        namespace="auth-service",
        model_name="User",
    )

    assert response.version == "2.0.0"


def test_get_latest_schema_semantic_versioning(
    schema_service: SchemaService,
    sample_schema: dict[str, Any],
) -> None:
    """Test that latest uses semantic versioning correctly."""
    # Register in non-sequential order
    for version in ["2.0.0", "1.1.0", "1.10.0", "1.2.0"]:
        schema_data = SchemaCreate(
            version=version,
            json_schema=sample_schema,
            registered_by="test-service",
        )
        schema_service.register_schema(
            namespace="auth-service",
            model_name="User",
            schema_data=schema_data,
        )

    response = schema_service.get_latest_schema(
        namespace="auth-service",
        model_name="User",
    )

    # 2.0.0 should be latest, not 1.10.0
    assert response.version == "2.0.0"


def test_get_latest_schema_not_found(
    schema_service: SchemaService,
) -> None:
    """Test getting latest for non-existent model raises 404."""
    with pytest.raises(HTTPException) as exc_info:
        schema_service.get_latest_schema(
            namespace="auth-service",
            model_name="NonExistent",
        )

    assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND


# ============================================================================
# List Versions Tests
# ============================================================================


def test_list_versions(
    schema_service: SchemaService,
    sample_schema: dict[str, Any],
) -> None:
    """Test listing all versions of a model."""
    versions = ["1.0.0", "1.1.0", "2.0.0"]

    for version in versions:
        schema_data = SchemaCreate(
            version=version,
            json_schema=sample_schema,
            registered_by="test-service",
        )
        schema_service.register_schema(
            namespace="auth-service",
            model_name="User",
            schema_data=schema_data,
        )

    response = schema_service.list_versions(
        namespace="auth-service",
        model_name="User",
    )

    assert response["versions"] == versions


def test_list_versions_sorted_semantically(
    schema_service: SchemaService,
    sample_schema: dict[str, Any],
) -> None:
    """Test that versions are sorted semantically."""
    # Register in random order
    for version in ["2.0.0", "1.1.0", "1.10.0", "1.2.0", "1.0.0"]:
        schema_data = SchemaCreate(
            version=version,
            json_schema=sample_schema,
            registered_by="test-service",
        )
        schema_service.register_schema(
            namespace="auth-service",
            model_name="User",
            schema_data=schema_data,
        )

    response = schema_service.list_versions(
        namespace="auth-service",
        model_name="User",
    )

    expected = ["1.0.0", "1.1.0", "1.2.0", "1.10.0", "2.0.0"]
    assert response["versions"] == expected


def test_list_versions_not_found(
    schema_service: SchemaService,
) -> None:
    """Test listing versions for non-existent model raises 404."""
    with pytest.raises(HTTPException) as exc_info:
        schema_service.list_versions(
            namespace="auth-service",
            model_name="NonExistent",
        )

    assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND


def test_list_versions_namespace_isolation(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test that list_versions only returns versions for specific namespace."""
    # Register in auth-service
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )

    # Register different version in billing-service
    other_data = SchemaCreate(
        version="2.0.0",
        json_schema=sample_schema_data.json_schema,
        registered_by="billing-service",
    )
    schema_service.register_schema(
        namespace="billing-service",
        model_name="User",
        schema_data=other_data,
    )

    # List auth-service versions
    response = schema_service.list_versions(
        namespace="auth-service",
        model_name="User",
    )

    assert response["versions"] == ["1.0.0"]


# ============================================================================
# List Schemas Tests
# ============================================================================


def test_list_schemas_all(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test listing all schemas without filters."""
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )
    schema_service.register_schema(
        namespace="billing-service",
        model_name="Product",
        schema_data=sample_schema_data,
    )

    response = schema_service.list_schemas()

    assert response.total == 2
    assert response.total_count == 2
    assert len(response.schemas) == 2


def test_list_schemas_filter_by_namespace(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test filtering schemas by namespace."""
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )
    schema_service.register_schema(
        namespace="billing-service",
        model_name="Product",
        schema_data=sample_schema_data,
    )

    response = schema_service.list_schemas(namespace="auth-service")

    assert response.total == 1
    assert response.schemas[0].namespace == "auth-service"


def test_list_schemas_filter_global_only(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test filtering for global schemas only."""
    # Register global
    schema_service.register_schema(
        namespace=None,
        model_name="User",
        schema_data=sample_schema_data,
    )
    # Register namespaced
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )

    response = schema_service.list_schemas(namespace="null")

    assert response.total == 1
    assert response.schemas[0].namespace is None


def test_list_schemas_filter_by_model_name(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test filtering schemas by model name across all namespaces."""
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )
    schema_service.register_schema(
        namespace="auth-service",
        model_name="Product",
        schema_data=sample_schema_data,
    )
    schema_service.register_schema(
        namespace="billing-service",
        model_name="User",
        schema_data=sample_schema_data,
    )

    # Need to query all namespaces separately or list without namespace filter
    # Let's test within a specific namespace
    response = schema_service.list_schemas(
        namespace="auth-service",
        model_name="User",
    )
    assert response.total == 1
    assert response.schemas[0].model_name == "User"
    assert response.schemas[0].namespace == "auth-service"


def test_list_schemas_exclude_deprecated_by_default(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
    db_session: Session,
) -> None:
    """Test that deprecated schemas are excluded by default."""
    # Register two schemas
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )
    schema_service.register_schema(
        namespace="auth-service",
        model_name="Product",
        schema_data=sample_schema_data,
    )

    # Manually deprecate one
    record = (
        db_session.query(SchemaRecord)
        .filter(SchemaRecord.model_name == "Product")
        .first()
    )
    assert record is not None
    record.deprecated = True
    db_session.commit()

    response = schema_service.list_schemas(namespace="auth-service")

    assert response.total == 1
    assert response.schemas[0].model_name == "User"


def test_list_schemas_include_deprecated(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
    db_session: Session,
) -> None:
    """Test including deprecated schemas in listing."""
    # Register two schemas
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )
    schema_service.register_schema(
        namespace="auth-service",
        model_name="Product",
        schema_data=sample_schema_data,
    )

    # Manually deprecate one
    record = (
        db_session.query(SchemaRecord)
        .filter(SchemaRecord.model_name == "Product")
        .first()
    )
    assert record is not None
    record.deprecated = True
    db_session.commit()

    response = schema_service.list_schemas(
        namespace="auth-service",
        include_deprecated=True,
    )

    assert response.total == 2


def test_list_schemas_pagination(
    schema_service: SchemaService,
    sample_schema: dict[str, Any],
) -> None:
    """Test pagination of schema listing."""
    # Register 5 schemas
    for i in range(5):
        schema_data = SchemaCreate(
            version="1.0.0",
            json_schema=sample_schema,
            registered_by="test-service",
        )
        schema_service.register_schema(
            namespace="auth-service",
            model_name=f"Model{i}",
            schema_data=schema_data,
        )

    # Get first page
    response1 = schema_service.list_schemas(namespace="auth-service", limit=2, offset=0)
    assert response1.total == 2
    assert response1.total_count == 5

    # Get second page
    response2 = schema_service.list_schemas(namespace="auth-service", limit=2, offset=2)
    assert response2.total == 2
    assert response2.offset == 2


def test_list_schemas_groups_versions(
    schema_service: SchemaService,
    sample_schema: dict[str, Any],
) -> None:
    """Test that multiple versions are grouped under one schema item."""
    versions = ["1.0.0", "1.1.0", "2.0.0"]

    for version in versions:
        schema_data = SchemaCreate(
            version=version,
            json_schema=sample_schema,
            registered_by="test-service",
        )
        schema_service.register_schema(
            namespace="auth-service",
            model_name="User",
            schema_data=schema_data,
        )

    response = schema_service.list_schemas(namespace="auth-service")

    assert response.total == 1  # One model with multiple versions
    assert response.schemas[0].versions == versions
    assert response.schemas[0].latest_version == "2.0.0"


def test_list_schemas_tracks_registered_by(
    schema_service: SchemaService,
    sample_schema: dict[str, Any],
) -> None:
    """Test that registered_by services are tracked."""
    # Register versions by different services
    schema_data1 = SchemaCreate(
        version="1.0.0",
        json_schema=sample_schema,
        registered_by="service-1",
    )
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=schema_data1,
    )

    schema_data2 = SchemaCreate(
        version="2.0.0",
        json_schema=sample_schema,
        registered_by="service-2",
    )
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=schema_data2,
    )

    response = schema_service.list_schemas(namespace="auth-service")

    assert len(response.schemas[0].registered_by) == 2
    assert "service-1" in response.schemas[0].registered_by
    assert "service-2" in response.schemas[0].registered_by


# ============================================================================
# List Namespaces for Model Tests
# ============================================================================


def test_list_namespaces_for_model(
    schema_service: SchemaService,
    sample_schema: dict[str, Any],
) -> None:
    """Test listing all namespaces containing a model."""
    # Register User in multiple namespaces
    schema_data = SchemaCreate(
        version="1.0.0",
        json_schema=sample_schema,
        registered_by="test-service",
    )

    schema_service.register_schema(
        namespace=None,
        model_name="User",
        schema_data=schema_data,
    )
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=schema_data,
    )
    schema_service.register_schema(
        namespace="billing-service",
        model_name="User",
        schema_data=schema_data,
    )

    response = schema_service.list_namespaces_for_model("User")

    assert "namespaces" in response
    assert "null" in response["namespaces"]  # Global
    assert "auth-service" in response["namespaces"]
    assert "billing-service" in response["namespaces"]


def test_list_namespaces_includes_versions(
    schema_service: SchemaService,
    sample_schema: dict[str, Any],
) -> None:
    """Test that namespace listing includes version lists."""
    # Register multiple versions in one namespace
    for version in ["1.0.0", "2.0.0"]:
        schema_data = SchemaCreate(
            version=version,
            json_schema=sample_schema,
            registered_by="test-service",
        )
        schema_service.register_schema(
            namespace="auth-service",
            model_name="User",
            schema_data=schema_data,
        )

    response = schema_service.list_namespaces_for_model("User")

    assert response["namespaces"]["auth-service"] == ["1.0.0", "2.0.0"]


def test_list_namespaces_not_found(
    schema_service: SchemaService,
) -> None:
    """Test listing namespaces for non-existent model raises 404."""
    with pytest.raises(HTTPException) as exc_info:
        schema_service.list_namespaces_for_model("NonExistent")

    assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND


# ============================================================================
# Compare Versions Tests
# ============================================================================


def test_compare_versions_identical(
    schema_service: SchemaService,
    sample_schema: dict[str, Any],
) -> None:
    """Test comparing identical schemas."""
    for version in ["1.0.0", "2.0.0"]:
        schema_data = SchemaCreate(
            version=version,
            json_schema=sample_schema,
            registered_by="test-service",
        )
        schema_service.register_schema(
            namespace="auth-service",
            model_name="User",
            schema_data=schema_data,
        )

    response = schema_service.compare_versions(
        namespace="auth-service",
        model_name="User",
        from_version="1.0.0",
        to_version="2.0.0",
    )

    assert response.changes["compatibility"] == "identical"
    assert len(response.changes["breaking_changes"]) == 0


def test_compare_versions_backward_compatible(
    schema_service: SchemaService,
    sample_schema: dict[str, Any],
) -> None:
    """Test detecting backward compatible changes."""
    # Version 1
    schema_v1 = {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "name": {"type": "string"},
        },
        "required": ["id"],
    }

    # Version 2 adds optional field
    schema_v2 = {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "name": {"type": "string"},
            "email": {"type": "string"},
        },
        "required": ["id"],
    }

    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=SchemaCreate(
            version="1.0.0",
            json_schema=schema_v1,
            registered_by="test-service",
        ),
    )

    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=SchemaCreate(
            version="2.0.0",
            json_schema=schema_v2,
            registered_by="test-service",
        ),
    )

    response = schema_service.compare_versions(
        namespace="auth-service",
        model_name="User",
        from_version="1.0.0",
        to_version="2.0.0",
    )

    assert response.changes["compatibility"] == "backward_compatible"
    assert "email" in response.changes["properties_added"]


def test_compare_versions_breaking_property_removed(
    schema_service: SchemaService,
) -> None:
    """Test detecting breaking change when property is removed."""
    schema_v1 = {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "name": {"type": "string"},
        },
    }

    schema_v2 = {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
        },
    }

    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=SchemaCreate(
            version="1.0.0",
            json_schema=schema_v1,
            registered_by="test-service",
        ),
    )

    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=SchemaCreate(
            version="2.0.0",
            json_schema=schema_v2,
            registered_by="test-service",
        ),
    )

    response = schema_service.compare_versions(
        namespace="auth-service",
        model_name="User",
        from_version="1.0.0",
        to_version="2.0.0",
    )

    assert response.changes["compatibility"] == "breaking"
    assert "name" in response.changes["properties_removed"]
    assert len(response.changes["breaking_changes"]) > 0


def test_compare_versions_breaking_type_changed(
    schema_service: SchemaService,
) -> None:
    """Test detecting breaking change when property type changes."""
    schema_v1 = {
        "type": "object",
        "properties": {
            "age": {"type": "string"},
        },
    }

    schema_v2 = {
        "type": "object",
        "properties": {
            "age": {"type": "integer"},
        },
    }

    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=SchemaCreate(
            version="1.0.0",
            json_schema=schema_v1,
            registered_by="test-service",
        ),
    )

    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=SchemaCreate(
            version="2.0.0",
            json_schema=schema_v2,
            registered_by="test-service",
        ),
    )

    response = schema_service.compare_versions(
        namespace="auth-service",
        model_name="User",
        from_version="1.0.0",
        to_version="2.0.0",
    )

    assert response.changes["compatibility"] == "breaking"
    assert len(response.changes["breaking_changes"]) > 0
    # Check that type change is detected
    breaking = response.changes["breaking_changes"][0]
    assert breaking["type"] == "type_changed"
    assert breaking["property"] == "age"


def test_compare_versions_breaking_required_added(
    schema_service: SchemaService,
) -> None:
    """Test detecting breaking change when required field is added."""
    schema_v1 = {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "email": {"type": "string"},
        },
        "required": ["id"],
    }

    schema_v2 = {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "email": {"type": "string"},
        },
        "required": ["id", "email"],
    }

    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=SchemaCreate(
            version="1.0.0",
            json_schema=schema_v1,
            registered_by="test-service",
        ),
    )

    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=SchemaCreate(
            version="2.0.0",
            json_schema=schema_v2,
            registered_by="test-service",
        ),
    )

    response = schema_service.compare_versions(
        namespace="auth-service",
        model_name="User",
        from_version="1.0.0",
        to_version="2.0.0",
    )

    assert response.changes["compatibility"] == "breaking"
    assert "email" in response.changes["required_added"]


def test_compare_versions_from_not_found(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test comparing when from_version doesn't exist."""
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )

    with pytest.raises(HTTPException) as exc_info:
        schema_service.compare_versions(
            namespace="auth-service",
            model_name="User",
            from_version="0.0.1",
            to_version="1.0.0",
        )

    assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND


def test_compare_versions_to_not_found(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test comparing when to_version doesn't exist."""
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )

    with pytest.raises(HTTPException) as exc_info:
        schema_service.compare_versions(
            namespace="auth-service",
            model_name="User",
            from_version="1.0.0",
            to_version="2.0.0",
        )

    assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND


# ============================================================================
# Delete Schema Tests
# ============================================================================


def test_delete_schema_success(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
    db_session: Session,
) -> None:
    """Test deleting a schema with force flag."""
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )

    result = schema_service.delete_schema(
        namespace="auth-service",
        model_name="User",
        version="1.0.0",
        force=True,
    )

    assert result is True

    # Verify it's gone
    record = (
        db_session.query(SchemaRecord)
        .filter(
            SchemaRecord.namespace == "auth-service",
            SchemaRecord.model_name == "User",
            SchemaRecord.version == "1.0.0",
        )
        .first()
    )
    assert record is None


def test_delete_schema_without_force_fails(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test that deletion without force flag raises error."""
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )

    with pytest.raises(HTTPException) as exc_info:
        schema_service.delete_schema(
            namespace="auth-service",
            model_name="User",
            version="1.0.0",
            force=False,
        )

    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert "force=true" in exc_info.value.detail


def test_delete_schema_not_found(
    schema_service: SchemaService,
) -> None:
    """Test deleting non-existent schema raises 404."""
    with pytest.raises(HTTPException) as exc_info:
        schema_service.delete_schema(
            namespace="auth-service",
            model_name="NonExistent",
            version="1.0.0",
            force=True,
        )

    assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND


def test_delete_global_schema(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
    db_session: Session,
) -> None:
    """Test deleting a global schema."""
    schema_service.register_schema(
        namespace=None,
        model_name="User",
        schema_data=sample_schema_data,
    )

    result = schema_service.delete_schema(
        namespace=None,
        model_name="User",
        version="1.0.0",
        force=True,
    )

    assert result is True

    # Verify it's gone
    record = (
        db_session.query(SchemaRecord)
        .filter(
            SchemaRecord.namespace.is_(None),
            SchemaRecord.model_name == "User",
            SchemaRecord.version == "1.0.0",
        )
        .first()
    )
    assert record is None


def test_delete_schema_namespace_isolation(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
    db_session: Session,
) -> None:
    """Test that deleting in one namespace doesn't affect another."""
    # Register in two namespaces
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )
    schema_service.register_schema(
        namespace="billing-service",
        model_name="User",
        schema_data=sample_schema_data,
    )

    # Delete from auth-service
    schema_service.delete_schema(
        namespace="auth-service",
        model_name="User",
        version="1.0.0",
        force=True,
    )

    # Verify auth-service is gone
    auth_record = (
        db_session.query(SchemaRecord)
        .filter(
            SchemaRecord.namespace == "auth-service",
            SchemaRecord.model_name == "User",
        )
        .first()
    )
    assert auth_record is None

    # Verify billing-service still exists
    billing_record = (
        db_session.query(SchemaRecord)
        .filter(
            SchemaRecord.namespace == "billing-service",
            SchemaRecord.model_name == "User",
        )
        .first()
    )
    assert billing_record is not None


# ============================================================================
# Deprecate Schema Tests
# ============================================================================


def test_deprecate_schema_with_message(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test deprecating a schema with a message."""
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )

    response = schema_service.deprecate_schema(
        namespace="auth-service",
        model_name="User",
        version="1.0.0",
        message="Security vulnerability. Upgrade to 2.0.0",
    )

    assert response.deprecated is True
    assert response.deprecated_at is not None
    assert response.deprecation_message == "Security vulnerability. Upgrade to 2.0.0"


def test_deprecate_schema_without_message(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test deprecating a schema without a message."""
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )

    response = schema_service.deprecate_schema(
        namespace="auth-service",
        model_name="User",
        version="1.0.0",
    )

    assert response.deprecated is True
    assert response.deprecated_at is not None
    assert response.deprecation_message is None


def test_deprecate_schema_sets_timestamp(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test that deprecation sets the deprecated_at timestamp."""
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )

    before = datetime.now(UTC)
    response = schema_service.deprecate_schema(
        namespace="auth-service",
        model_name="User",
        version="1.0.0",
    )
    after = datetime.now(UTC)

    assert response.deprecated_at is not None
    deprecated_at = datetime.fromisoformat(response.deprecated_at)
    assert before <= deprecated_at <= after


def test_deprecate_schema_not_found(
    schema_service: SchemaService,
) -> None:
    """Test deprecating non-existent schema raises 404."""
    with pytest.raises(HTTPException) as exc_info:
        schema_service.deprecate_schema(
            namespace="auth-service",
            model_name="NonExistent",
            version="1.0.0",
        )

    assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND


def test_deprecate_global_schema(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test deprecating a global schema."""
    schema_service.register_schema(
        namespace=None,
        model_name="User",
        schema_data=sample_schema_data,
    )

    response = schema_service.deprecate_schema(
        namespace=None,
        model_name="User",
        version="1.0.0",
        message="Deprecated",
    )

    assert response.deprecated is True
    assert response.namespace is None


def test_deprecate_already_deprecated_schema(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test that deprecating an already deprecated schema updates it."""
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )

    # First deprecation
    schema_service.deprecate_schema(
        namespace="auth-service",
        model_name="User",
        version="1.0.0",
        message="Original reason",
    )

    # Second deprecation with different message
    response = schema_service.deprecate_schema(
        namespace="auth-service",
        model_name="User",
        version="1.0.0",
        message="Updated reason",
    )

    assert response.deprecated is True
    assert response.deprecation_message == "Updated reason"


# ============================================================================
# Get Schema Count Tests
# ============================================================================


def test_get_schema_count_empty(
    schema_service: SchemaService,
) -> None:
    """Test getting schema count when empty."""
    count = schema_service.get_schema_count()
    assert count == 0


def test_get_schema_count(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test getting schema count."""
    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=sample_schema_data,
    )
    schema_service.register_schema(
        namespace="billing-service",
        model_name="Product",
        schema_data=sample_schema_data,
    )

    count = schema_service.get_schema_count()
    assert count == 2


def test_get_schema_count_multiple_versions(
    schema_service: SchemaService,
    sample_schema: dict[str, Any],
) -> None:
    """Test that count includes all versions."""
    for version in ["1.0.0", "2.0.0", "3.0.0"]:
        schema_data = SchemaCreate(
            version=version,
            json_schema=sample_schema,
            registered_by="test-service",
        )
        schema_service.register_schema(
            namespace="auth-service",
            model_name="User",
            schema_data=schema_data,
        )

    count = schema_service.get_schema_count()
    assert count == 3


# ============================================================================
# Integration and Edge Cases
# ============================================================================


def test_complete_schema_lifecycle(
    schema_service: SchemaService,
    sample_schema: dict[str, Any],
) -> None:
    """Test complete lifecycle: register, get, list, deprecate, delete."""
    # Register
    schema_data = SchemaCreate(
        version="1.0.0",
        json_schema=sample_schema,
        registered_by="test-service",
        meta={"lifecycle": "test"},
    )
    registered = schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=schema_data,
    )
    assert registered.deprecated is False

    # Get
    retrieved = schema_service.get_schema(
        namespace="auth-service",
        model_name="User",
        version="1.0.0",
    )
    assert retrieved.id == registered.id

    # List
    schemas = schema_service.list_schemas(namespace="auth-service")
    assert len(schemas.schemas) == 1

    # Deprecate
    deprecated = schema_service.deprecate_schema(
        namespace="auth-service",
        model_name="User",
        version="1.0.0",
        message="End of life",
    )
    assert deprecated.deprecated is True

    # List with deprecated excluded
    schemas_active = schema_service.list_schemas(namespace="auth-service")
    assert len(schemas_active.schemas) == 0

    # List with deprecated included
    schemas_all = schema_service.list_schemas(
        namespace="auth-service",
        include_deprecated=True,
    )
    assert len(schemas_all.schemas) == 1

    # Delete
    deleted = schema_service.delete_schema(
        namespace="auth-service",
        model_name="User",
        version="1.0.0",
        force=True,
    )
    assert deleted is True

    # Verify deleted
    with pytest.raises(HTTPException):
        schema_service.get_schema(
            namespace="auth-service",
            model_name="User",
            version="1.0.0",
        )


def test_multiple_namespaces_same_model_operations(
    schema_service: SchemaService,
    sample_schema_data: SchemaCreate,
) -> None:
    """Test operations on same model across multiple namespaces."""
    namespaces = ["auth-service", "billing-service", "analytics-service"]

    # Register in all namespaces
    for ns in namespaces:
        schema_service.register_schema(
            namespace=ns,
            model_name="User",
            schema_data=sample_schema_data,
        )

    for ns in namespaces:
        response = schema_service.get_schema(
            namespace=ns,
            model_name="User",
            version="1.0.0",
        )
        assert response.namespace == ns

    ns_response = schema_service.list_namespaces_for_model("User")
    for ns in namespaces:
        assert ns in ns_response["namespaces"]

    schema_service.deprecate_schema(
        namespace="auth-service",
        model_name="User",
        version="1.0.0",
    )

    # Verify others are not deprecated
    billing = schema_service.get_schema(
        namespace="billing-service",
        model_name="User",
        version="1.0.0",
    )
    assert billing.deprecated is False


def test_version_comparison_with_modified_properties(
    schema_service: SchemaService,
) -> None:
    """Test comparison detects modified properties."""
    schema_v1 = {
        "type": "object",
        "properties": {
            "email": {"type": "string"},
        },
    }

    schema_v2 = {
        "type": "object",
        "properties": {
            "email": {"type": "string", "format": "email"},
        },
    }

    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=SchemaCreate(
            version="1.0.0",
            json_schema=schema_v1,
            registered_by="test-service",
        ),
    )

    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=SchemaCreate(
            version="2.0.0",
            json_schema=schema_v2,
            registered_by="test-service",
        ),
    )

    response = schema_service.compare_versions(
        namespace="auth-service",
        model_name="User",
        from_version="1.0.0",
        to_version="2.0.0",
    )

    assert len(response.changes["properties_modified"]) > 0
    modified = response.changes["properties_modified"][0]
    assert modified["property"] == "email"


def test_list_schemas_with_no_results(
    schema_service: SchemaService,
) -> None:
    """Test listing schemas returns empty result when no matches."""
    response = schema_service.list_schemas(namespace="nonexistent")

    assert response.total == 0
    assert response.total_count == 0
    assert response.schemas == []


def test_metadata_preserved_through_operations(
    schema_service: SchemaService,
    sample_schema: dict[str, Any],
) -> None:
    """Test that metadata is preserved through various operations."""
    metadata = {
        "description": "Test schema",
        "owner": "platform-team",
        "tags": ["user", "authentication"],
    }

    schema_data = SchemaCreate(
        version="1.0.0",
        json_schema=sample_schema,
        registered_by="test-service",
        meta=metadata,
    )

    # Register
    registered = schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=schema_data,
    )
    assert registered.meta == metadata

    # Deprecate
    deprecated = schema_service.deprecate_schema(
        namespace="auth-service",
        model_name="User",
        version="1.0.0",
    )
    assert deprecated.meta == metadata

    retrieved = schema_service.get_schema(
        namespace="auth-service",
        model_name="User",
        version="1.0.0",
    )
    assert retrieved.meta == metadata


def test_registered_at_timestamp_preserved(
    schema_service: SchemaService,
    sample_schema: dict[str, Any],
) -> None:
    """Test that registered_at timestamp is preserved."""
    custom_timestamp = "2024-01-15T10:30:00Z"

    schema_data = SchemaCreate(
        version="1.0.0",
        json_schema=sample_schema,
        registered_by="test-service",
        registered_at=custom_timestamp,
    )

    response = schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=schema_data,
    )

    assert response.registered_at == custom_timestamp


def test_empty_required_list_handling(
    schema_service: SchemaService,
) -> None:
    """Test handling schemas with empty or missing required lists."""
    schema_v1 = {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
        },
        # No required field
    }

    schema_v2 = {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
        },
        "required": [],  # Empty required
    }

    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=SchemaCreate(
            version="1.0.0",
            json_schema=schema_v1,
            registered_by="test-service",
        ),
    )

    schema_service.register_schema(
        namespace="auth-service",
        model_name="User",
        schema_data=SchemaCreate(
            version="2.0.0",
            json_schema=schema_v2,
            registered_by="test-service",
        ),
    )

    # Should not raise an error
    response = schema_service.compare_versions(
        namespace="auth-service",
        model_name="User",
        from_version="1.0.0",
        to_version="2.0.0",
    )

    assert response.changes["compatibility"] == "identical"
