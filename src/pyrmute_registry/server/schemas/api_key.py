"""Pydantic schemas for API key request/response models."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from pyrmute_registry.server.models.api_key import Permission


class ApiKeyCreate(BaseModel):
    """Request model for creating an API key."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "production-api",
                "permission": "write",
                "description": "API key for production service",
                "expires_in_days": 365,
            }
        }
    )

    name: str = Field(
        ...,
        min_length=3,
        max_length=255,
        description="Unique name for the API key",
        examples=["production-api", "ci-cd-pipeline", "dev-testing"],
    )
    permission: Permission = Field(
        default=Permission.READ,
        description="Permission level: read, write, delete, or admin",
    )
    description: str | None = Field(
        default=None,
        max_length=1000,
        description="Optional description of the key's purpose",
    )
    expires_in_days: int | None = Field(
        default=None,
        gt=0,
        le=3650,  # Max 10 years
        description="Number of days until expiration (omit for no expiration)",
    )


class ApiKeyResponse(BaseModel):
    """Response model for API key (without sensitive data)."""

    model_config = ConfigDict(
        from_attributes=True,  # Allows creation from SQLAlchemy model
        json_schema_extra={
            "example": {
                "id": 1,
                "name": "production-api",
                "permission": "write",
                "created_at": "2025-01-15T10:30:00Z",
                "created_by": "admin",
                "last_used_at": "2025-01-15T14:22:00Z",
                "use_count": 42,
                "expires_at": "2026-01-15T10:30:00Z",
                "revoked": False,
                "revoked_at": None,
                "revoked_by": None,
                "description": "API key for production service",
                "is_active": True,
                "is_expired": False,
            }
        },
    )

    id: int = Field(..., description="Internal database ID")
    name: str = Field(..., description="Human-readable name for the API key")
    permission: str = Field(..., description="Permission level")
    created_at: datetime = Field(..., description="When the key was created")
    created_by: str = Field(..., description="Who/what created the key")
    last_used_at: datetime | None = Field(
        None, description="Last time the key was used"
    )
    use_count: int = Field(..., description="Number of times the key has been used")
    expires_at: datetime | None = Field(None, description="Expiration date (if any)")
    revoked: bool = Field(..., description="Whether the key has been revoked")
    revoked_at: datetime | None = Field(
        None, description="When the key was revoked (if applicable)"
    )
    revoked_by: str | None = Field(
        None, description="Who revoked the key (if applicable)"
    )
    description: str | None = Field(None, description="Description of key's purpose")
    is_active: bool = Field(
        ..., description="Whether the key is currently active (not revoked/expired)"
    )
    is_expired: bool = Field(..., description="Whether the key has expired")


class ApiKeyCreateResponse(ApiKeyResponse):
    """Response model for key creation (includes plaintext key ONCE).

    This extends ApiKeyResponse to include the plaintext API key,
    which is ONLY shown once during creation.
    """

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": 1,
                "name": "production-api",
                "permission": "write",
                "created_at": "2025-01-15T10:30:00Z",
                "created_by": "admin",
                "last_used_at": None,
                "use_count": 0,
                "expires_at": "2026-01-15T10:30:00Z",
                "revoked": False,
                "revoked_at": None,
                "description": "API key for production service",
                "is_active": True,
                "is_expired": False,
                "api_key": "v7x9K8mN3pL2qR5tY8wZ1aB4cD6eF0gH9iJ2kL5mN8pQ1rS4tU7vW0xY3zA6bC9",  # noqa: E501
            }
        },
    )

    api_key: str = Field(
        ...,
        description=(
            "Plaintext API key - SAVE THIS SECURELY! It will never be shown again."
        ),
    )


class ApiKeyListResponse(BaseModel):
    """Response model for listing API keys."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "keys": [
                    {
                        "id": 1,
                        "name": "production-api",
                        "permission": "write",
                        "created_at": "2025-01-15T10:30:00Z",
                        "created_by": "admin",
                        "last_used_at": "2025-01-15T14:22:00Z",
                        "use_count": 42,
                        "expires_at": None,
                        "revoked": False,
                        "revoked_at": None,
                        "description": "Production service key",
                        "is_active": True,
                        "is_expired": False,
                    }
                ],
                "total": 1,
            }
        }
    )

    keys: list[ApiKeyResponse] = Field(..., description="List of API keys")
    total: int = Field(..., description="Total number of keys returned")


class ApiKeyRevokeRequest(BaseModel):
    """Request model for revoking an API key."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "revoked_by": "admin",
                "reason": "Key compromised, rotating to new key",
            }
        }
    )

    revoked_by: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Who is revoking the key",
        examples=["admin", "security-team", "user@example.com"],
    )
    reason: str | None = Field(
        default=None,
        max_length=500,
        description="Optional reason for revocation",
    )


class ApiKeyStatsResponse(BaseModel):
    """Response model for API key usage statistics."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "total_keys": 5,
                "active_keys": 4,
                "revoked_keys": 1,
                "expired_keys": 0,
                "by_permission": {
                    "read": 2,
                    "write": 2,
                    "delete": 0,
                    "admin": 1,
                },
            }
        }
    )

    total_keys: int = Field(..., description="Total number of API keys")
    active_keys: int = Field(..., description="Number of active (usable) keys")
    revoked_keys: int = Field(..., description="Number of revoked keys")
    expired_keys: int = Field(..., description="Number of expired keys")
    by_permission: dict[str, int] = Field(
        ..., description="Count of keys by permission level"
    )
