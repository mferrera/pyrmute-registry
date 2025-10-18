"""Pydantic schemas for API request/response models."""

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class SchemaCreate(BaseModel):
    """Request model for creating a schema."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "version": "1.0.0",
                "json_schema": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "email": {"type": "string", "format": "email"},
                    },
                    "required": ["id", "email"],
                },
                "registered_by": "auth-service",
                "meta": {"environment": "production", "team": "platform"},
            }
        }
    )

    version: str = Field(
        ...,
        description="Semantic version string (e.g., '1.0.0')",
        pattern=r"^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?$",
    )
    json_schema: dict[str, Any] = Field(
        ...,
        description="JSON Schema definition (must be valid Draft 7 JSON Schema)",
    )
    registered_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="ISO 8601 timestamp of registration",
    )
    registered_by: str = Field(
        ...,
        description="Name of service or user registering schema",
        min_length=1,
        max_length=255,
    )
    meta: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata (e.g., environment, tags, description, team)",
    )


class SchemaResponse(BaseModel):
    """Response model for schema data."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": 42,
                "namespace": "auth-service",
                "model_name": "User",
                "version": "1.0.0",
                "json_schema": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "email": {"type": "string", "format": "email"},
                    },
                    "required": ["id", "email"],
                },
                "registered_at": "2025-01-15T10:30:00Z",
                "registered_by": "auth-service",
                "meta": {"environment": "production"},
                "deprecated": False,
                "deprecated_at": None,
                "deprecation_message": None,
            }
        },
    )

    id: int = Field(..., description="Internal database ID")
    namespace: str | None = Field(
        None, description="Optional namespace for scoping (null for global schemas)"
    )
    model_name: str = Field(..., description="Model name")
    version: str = Field(..., description="Schema version")
    json_schema: dict[str, Any] = Field(..., description="JSON Schema definition")
    registered_at: str = Field(..., description="Registration timestamp (ISO 8601)")
    registered_by: str = Field(..., description="Registering service or user name")
    meta: dict[str, Any] = Field(default_factory=dict, description="Metadata")
    deprecated: bool = Field(
        default=False, description="Whether this schema version is deprecated"
    )
    deprecated_at: str | None = Field(
        default=None, description="Deprecation timestamp (ISO 8601)"
    )
    deprecation_message: str | None = Field(
        default=None, description="Reason for deprecation"
    )


class SchemaListItem(BaseModel):
    """Summary of a schema without full schema data."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "namespace": "auth-service",
                "model_name": "User",
                "versions": ["1.0.0", "1.1.0", "2.0.0"],
                "latest_version": "2.0.0",
                "registered_by": ["auth-service", "user-api"],
                "deprecated_versions": ["1.0.0"],
            }
        }
    )

    namespace: str | None = Field(
        None, description="Optional namespace (null for global schemas)"
    )
    model_name: str = Field(..., description="Model name")
    versions: list[str] = Field(..., description="All available versions")
    latest_version: str | None = Field(
        None, description="Latest version by semantic versioning"
    )
    registered_by: set[str] = Field(
        default_factory=set, description="Services/users that registered versions"
    )
    deprecated_versions: list[str] = Field(
        default_factory=list, description="List of deprecated versions"
    )


class SchemaListResponse(BaseModel):
    """Response for listing schemas with pagination."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "schemas": [
                    {
                        "namespace": None,
                        "model_name": "User",
                        "versions": ["1.0.0", "2.0.0"],
                        "latest_version": "2.0.0",
                        "registered_by": ["auth-service"],
                        "deprecated_versions": [],
                    },
                    {
                        "namespace": "analytics",
                        "model_name": "Event",
                        "versions": ["1.0.0"],
                        "latest_version": "1.0.0",
                        "registered_by": ["analytics-service"],
                        "deprecated_versions": [],
                    },
                ],
                "total": 2,
                "limit": 100,
                "offset": 0,
                "total_count": 2,
            }
        }
    )

    schemas: list[SchemaListItem] = Field(..., description="List of schema summaries")
    total: int = Field(..., description="Number of schemas in this response")
    limit: int = Field(..., description="Maximum number of results requested")
    offset: int = Field(..., description="Number of results skipped")
    total_count: int = Field(
        ..., description="Total number of schemas matching filters"
    )


class BreakingChange(BaseModel):
    """Details of a breaking change between schema versions."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "type": "type_changed",
                "property": "age",
                "from": "string",
                "to": "integer",
                "description": "Property 'age' type changed from string to integer",
            }
        },
        populate_by_name=True,
    )

    type: Literal[
        "properties_removed",
        "type_changed",
        "required_fields_added",
    ] = Field(..., description="Type of breaking change")
    property: str | None = Field(
        default=None, description="Property name (if applicable)"
    )
    details: list[str] | None = Field(
        default=None, description="List of affected items"
    )
    from_value: Any = Field(default=None, alias="from", description="Original value")
    to_value: Any = Field(default=None, alias="to", description="New value")
    description: str = Field(
        ..., description="Human-readable description of the change"
    )


class PropertyModification(BaseModel):
    """Details of a modified property."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "property": "email",
                "from": {"type": "string"},
                "to": {"type": "string", "format": "email"},
            }
        },
        populate_by_name=True,
    )

    property: str = Field(..., description="Property name")
    from_value: dict[str, Any] = Field(
        alias="from", description="Original property definition"
    )
    to_value: dict[str, Any] = Field(alias="to", description="New property definition")


class SchemaChanges(BaseModel):
    """Detailed changes between two schema versions."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "properties_added": ["phone"],
                "properties_removed": ["fax"],
                "properties_modified": [
                    {
                        "property": "email",
                        "from": {"type": "string"},
                        "to": {"type": "string", "format": "email"},
                    }
                ],
                "required_added": ["email"],
                "required_removed": ["fax"],
                "breaking_changes": [
                    {
                        "type": "properties_removed",
                        "details": ["fax"],
                        "description": (
                            "Removing properties can break consumers "
                            "expecting these fields"
                        ),
                    }
                ],
                "compatibility": "breaking",
            }
        }
    )

    properties_added: list[str] = Field(
        default_factory=list, description="Properties added in new version"
    )
    properties_removed: list[str] = Field(
        default_factory=list, description="Properties removed in new version"
    )
    properties_modified: list[PropertyModification] = Field(
        default_factory=list, description="Properties with modified definitions"
    )
    required_added: list[str] = Field(
        default_factory=list, description="Fields made required in new version"
    )
    required_removed: list[str] = Field(
        default_factory=list, description="Fields no longer required in new version"
    )
    breaking_changes: list[BreakingChange] = Field(
        default_factory=list,
        description="List of changes that break backward compatibility",
    )
    compatibility: Literal["identical", "backward_compatible", "breaking"] = Field(
        ..., description="Overall compatibility assessment"
    )


class ComparisonResponse(BaseModel):
    """Response for schema comparison between versions."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "namespace": "auth-service",
                "model_name": "User",
                "from_version": "1.0.0",
                "to_version": "2.0.0",
                "changes": {
                    "properties_added": ["phone"],
                    "properties_removed": [],
                    "properties_modified": [],
                    "required_added": [],
                    "required_removed": [],
                    "breaking_changes": [],
                    "compatibility": "backward_compatible",
                },
            }
        }
    )

    namespace: str | None = Field(
        None, description="Optional namespace (null for global schemas)"
    )
    model_name: str = Field(..., description="Model name")
    from_version: str = Field(..., description="Source version")
    to_version: str = Field(..., description="Target version")
    changes: dict[str, Any] = Field(
        ..., description="Detailed changes between versions"
    )


class DeleteResponse(BaseModel):
    """Response for schema deletion."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "deleted": True,
                "namespace": "auth-service",
                "model_name": "User",
                "version": "1.0.0",
            }
        }
    )

    deleted: bool = Field(..., description="Whether deletion was successful")
    namespace: str | None = Field(
        None, description="Optional namespace (null for global schemas)"
    )
    model_name: str = Field(..., description="Model name")
    version: str = Field(..., description="Deleted version")


class DeprecationRequest(BaseModel):
    """Request model for deprecating a schema."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": (
                    "This version has security vulnerabilities. Please "
                    "upgrade to 2.0.0."
                )
            }
        }
    )

    message: str | None = Field(
        default=None,
        description="Reason for deprecation",
        max_length=500,
    )


class HealthResponse(BaseModel):
    """Health check response."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "healthy",
                "version": "1.0.0",
                "schema_count": 42,
                "timestamp": "2025-01-15T10:30:00Z",
            }
        }
    )

    status: Literal["healthy", "degraded", "unhealthy"] = Field(
        ..., description="Service health status"
    )
    version: str = Field(..., description="API version")
    schema_count: int = Field(..., description="Total number of registered schemas")
    timestamp: str = Field(..., description="Health check timestamp (ISO 8601)")


class ErrorResponse(BaseModel):
    """Standard error response."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "detail": "Schema auth-service::User@1.0.0 not found",
                "error_code": "SCHEMA_NOT_FOUND",
                "timestamp": "2025-01-15T10:30:00Z",
            }
        }
    )

    detail: str = Field(..., description="Error message")
    error_code: str | None = Field(
        default=None, description="Machine-readable error code"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="Error timestamp (ISO 8601)",
    )
