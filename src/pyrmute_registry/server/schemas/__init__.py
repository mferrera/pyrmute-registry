"""Pydantic schemas for API models."""

from .api_key import (
    ApiKeyCreate,
    ApiKeyCreateResponse,
    ApiKeyListResponse,
    ApiKeyResponse,
    ApiKeyRevokeRequest,
    ApiKeyStatsResponse,
)
from .errors import (
    DatabaseErrorResponse,
    InternalErrorResponse,
    ValidationErrorResponse,
)
from .health import HealthError, HealthResponse
from .root import DocumentationResponse, EndpointsResponse, RootResponse
from .schema import (
    BreakingChange,
    ComparisonResponse,
    DeleteResponse,
    DeprecationRequest,
    PropertyModification,
    SchemaChanges,
    SchemaCreate,
    SchemaListItem,
    SchemaListResponse,
    SchemaResponse,
)

__all__ = [
    "ApiKeyCreate",
    "ApiKeyCreateResponse",
    "ApiKeyListResponse",
    "ApiKeyResponse",
    "ApiKeyRevokeRequest",
    "ApiKeyStatsResponse",
    "BreakingChange",
    "ComparisonResponse",
    "DatabaseErrorResponse",
    "DeleteResponse",
    "DeprecationRequest",
    "DocumentationResponse",
    "EndpointsResponse",
    "HealthError",
    "HealthResponse",
    "InternalErrorResponse",
    "PropertyModification",
    "RootResponse",
    "SchemaChanges",
    "SchemaCreate",
    "SchemaListItem",
    "SchemaListResponse",
    "SchemaResponse",
    "ValidationErrorResponse",
]
