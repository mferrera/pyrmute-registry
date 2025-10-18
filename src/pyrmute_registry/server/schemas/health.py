"""Pydantic schemas for health check responses."""

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    """Health check response with system status.

    Provides information about the service health, version, database connectivity, and
    operational metrics.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "healthy",
                "version": "1.0.0",
                "environment": "production",
                "database": {
                    "type": "postgresql",
                    "connected": True,
                },
                "schemas_count": 42,
                "uptime_seconds": 3600.5,
                "timestamp": "2025-01-15T10:30:00Z",
            }
        }
    )

    status: Literal["healthy", "degraded", "unhealthy"] = Field(
        ..., description="Overall health status"
    )
    version: str = Field(..., description="API version")
    environment: str = Field(..., description="Current environment (dev/prod/test)")
    database: dict[str, str | bool] = Field(
        ...,
        description="Database information including type and connection status",
    )
    schemas_count: int = Field(..., description="Total number of registered schemas")
    uptime_seconds: float = Field(..., description="Server uptime in seconds")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="Health check timestamp (ISO 8601)",
    )


class HealthError(BaseModel):
    """Health check error response.

    Returned when the service is unable to determine its health status or when critical
    components are failing.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "unhealthy",
                "error": "Database connection failed",
                "timestamp": "2025-01-15T10:30:00Z",
            }
        }
    )

    status: Literal["unhealthy"] = Field(
        default="unhealthy", description="Health status"
    )
    error: str = Field(..., description="Error message describing the failure")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="Error timestamp (ISO 8601)",
    )
