"""Schema management endpoints."""

from typing import Annotated

from fastapi import APIRouter, Body, Path, Query, status

from pyrmute_registry.server.auth import AuthRequired
from pyrmute_registry.server.deps import SchemaServiceDep
from pyrmute_registry.server.schemas.schema import (
    ComparisonResponse,
    DeleteResponse,
    SchemaCreate,
    SchemaListResponse,
    SchemaResponse,
)

router = APIRouter(prefix="/schemas", tags=["schemas"])


# ============================================================================
# NAMESPACED SCHEMA ROUTES (must come before global routes to avoid conflicts)
# ============================================================================


@router.post(
    "/{namespace}/{model_name}/versions",
    response_model=SchemaResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register namespaced schema",
    description="Register a new schema version for a model within a service namespace.",
)
def register_namespaced_schema(
    namespace: Annotated[str, Path(description="Namespace")],
    model_name: Annotated[str, Path(description="Model name")],
    schema_data: Annotated[SchemaCreate, Body(description="Schema data")],
    service: SchemaServiceDep,
    _authenticated: AuthRequired,
    allow_overwrite: Annotated[
        bool, Query(description="Allow overwriting existing schema")
    ] = False,
) -> SchemaResponse:
    """Register a new namespaced schema version."""
    return service.register_schema(namespace, model_name, schema_data, allow_overwrite)


@router.get(
    "/{namespace}/{model_name}/versions/latest",
    response_model=SchemaResponse,
    summary="Get latest namespaced schema",
    description="Retrieve the latest version of a namespaced schema",
)
def get_latest_namespaced_schema(
    namespace: Annotated[str, Path(description="Namespace")],
    model_name: Annotated[str, Path(description="Model name")],
    service: SchemaServiceDep,
    _authenticated: AuthRequired,
) -> SchemaResponse:
    """Get the latest version of a namespaced schema."""
    return service.get_latest_schema(namespace, model_name)


@router.get(
    "/{namespace}/{model_name}/versions/{version}",
    response_model=SchemaResponse,
    summary="Get namespaced schema version",
    description="Retrieve a specific version of a namespaced schema",
)
def get_namespaced_schema(
    namespace: Annotated[str, Path(description="Namespace")],
    model_name: Annotated[str, Path(description="Model name")],
    version: Annotated[str, Path(description="Version string (e.g., '1.0.0')")],
    service: SchemaServiceDep,
    _authenticated: AuthRequired,
) -> SchemaResponse:
    """Get a specific namespaced schema version."""
    return service.get_schema(namespace, model_name, version)


@router.get(
    "/{namespace}/{model_name}/versions",
    response_model=dict[str, list[str]],
    summary="List namespaced versions",
    description="List all versions for a namespaced model",
)
def list_namespaced_versions(
    namespace: Annotated[str, Path(description="Namespace")],
    model_name: Annotated[str, Path(description="Model name")],
    service: SchemaServiceDep,
    _authenticated: AuthRequired,
) -> dict[str, list[str]]:
    """List all versions for a namespaced model."""
    return service.list_versions(namespace, model_name)


@router.get(
    "/{namespace}/{model_name}/compare",
    response_model=ComparisonResponse,
    summary="Compare namespaced versions",
    description="Compare two versions of a namespaced schema",
)
def compare_namespaced_versions(
    namespace: Annotated[str, Path(description="Namespace")],
    model_name: Annotated[str, Path(description="Model name")],
    service: SchemaServiceDep,
    _authenticated: AuthRequired,
    from_version: Annotated[str, Query(..., description="Source version")],
    to_version: Annotated[str, Query(..., description="Target version")],
) -> ComparisonResponse:
    """Compare two namespaced schema versions."""
    return service.compare_versions(namespace, model_name, from_version, to_version)


@router.delete(
    "/{namespace}/{model_name}/versions/{version}",
    response_model=DeleteResponse,
    summary="Delete namespaced schema",
    description="Delete a namespaced schema version",
)
def delete_namespaced_schema(
    namespace: Annotated[str, Path(description="Namespace")],
    model_name: Annotated[str, Path(description="Model name")],
    version: Annotated[str, Path(description="Version string")],
    service: SchemaServiceDep,
    _authenticated: AuthRequired,
    force: Annotated[
        bool, Query(description="Force deletion without safety check")
    ] = False,
) -> DeleteResponse:
    """Delete a namespaced schema version."""
    service.delete_schema(namespace, model_name, version, force)
    return DeleteResponse(
        deleted=True,
        namespace=namespace,
        model_name=model_name,
        version=version,
    )


@router.post(
    "/{namespace}/{model_name}/versions/{version}/deprecate",
    response_model=SchemaResponse,
    summary="Deprecate namespaced schema",
    description="Mark a namespaced schema version as deprecated",
)
def deprecate_namespaced_schema(
    namespace: Annotated[str, Path(description="Namespace")],
    model_name: Annotated[str, Path(description="Model name")],
    version: Annotated[str, Path(description="Version string")],
    service: SchemaServiceDep,
    _authenticated: AuthRequired,
    message: Annotated[str | None, Query(description="Deprecation message")] = None,
) -> SchemaResponse:
    """Mark a namespaced schema version as deprecated."""
    return service.deprecate_schema(namespace, model_name, version, message)


# ============================================================================
# GLOBAL SCHEMA ROUTES
# ============================================================================


@router.post(
    "/{model_name}/versions",
    response_model=SchemaResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register global schema",
    description="Register a new schema version for a global model (no namespace).",
)
def register_global_schema(
    model_name: Annotated[str, Path(description="Model name")],
    schema_data: Annotated[SchemaCreate, Body(description="Schema data")],
    service: SchemaServiceDep,
    _authenticated: AuthRequired,
    namespace: Annotated[
        str | None,
        Query(description="Optional namespace for scoping (overrides global behavior)"),
    ] = None,
    allow_overwrite: Annotated[
        bool, Query(description="Allow overwriting existing schema")
    ] = False,
) -> SchemaResponse:
    """Register a new global schema version.

    Can optionally provide a namespace query parameter to make it namespaced.
    """
    return service.register_schema(namespace, model_name, schema_data, allow_overwrite)


@router.get(
    "/{model_name}/versions/latest",
    response_model=SchemaResponse,
    summary="Get latest global schema",
    description="Retrieve the latest version of a global schema",
)
def get_latest_global_schema(
    model_name: Annotated[str, Path(description="Model name")],
    service: SchemaServiceDep,
    _authenticated: AuthRequired,
    namespace: Annotated[
        str | None, Query(description="Optional namespace for scoping")
    ] = None,
) -> SchemaResponse:
    """Get the latest version of a global schema.

    Can optionally provide a namespace query parameter to query a namespaced schema.
    """
    return service.get_latest_schema(namespace, model_name)


@router.get(
    "/{model_name}/versions/{version}",
    response_model=SchemaResponse,
    summary="Get global schema version",
    description="Retrieve a specific version of a global schema",
)
def get_global_schema(
    model_name: Annotated[str, Path(description="Model name")],
    version: Annotated[str, Path(description="Version string (e.g., '1.0.0')")],
    service: SchemaServiceDep,
    _authenticated: AuthRequired,
    namespace: Annotated[
        str | None, Query(description="Optional namespace for scoping")
    ] = None,
) -> SchemaResponse:
    """Get a specific global schema version.

    Can optionally provide a namespace query parameter to query a namespaced schema.
    """
    return service.get_schema(namespace, model_name, version)


@router.get(
    "/{model_name}/versions",
    response_model=dict[str, list[str]],
    summary="List global versions",
    description="List all versions for a global model",
)
def list_global_versions(
    model_name: Annotated[str, Path(description="Model name")],
    service: SchemaServiceDep,
    _authenticated: AuthRequired,
    namespace: Annotated[
        str | None, Query(description="Optional namespace for scoping")
    ] = None,
) -> dict[str, list[str]]:
    """List all versions for a global model.

    Can optionally provide a namespace query parameter to query a namespaced schema.
    """
    return service.list_versions(namespace, model_name)


@router.get(
    "/{model_name}/compare",
    response_model=ComparisonResponse,
    summary="Compare global versions",
    description="Compare two versions of a global schema",
)
def compare_global_versions(
    model_name: Annotated[str, Path(description="Model name")],
    service: SchemaServiceDep,
    _authenticated: AuthRequired,
    from_version: Annotated[str, Query(..., description="Source version")],
    to_version: Annotated[str, Query(..., description="Target version")],
    namespace: Annotated[
        str | None, Query(description="Optional namespace for scoping")
    ] = None,
) -> ComparisonResponse:
    """Compare two global schema versions.

    Can optionally provide a namespace query parameter to compare namespaced schemas.
    """
    return service.compare_versions(namespace, model_name, from_version, to_version)


@router.delete(
    "/{model_name}/versions/{version}",
    response_model=DeleteResponse,
    summary="Delete global schema",
    description="Delete a global schema version",
)
def delete_global_schema(
    model_name: Annotated[str, Path(description="Model name")],
    version: Annotated[str, Path(description="Version string")],
    service: SchemaServiceDep,
    _authenticated: AuthRequired,
    namespace: Annotated[
        str | None, Query(description="Optional namespace for scoping")
    ] = None,
    force: Annotated[
        bool, Query(description="Force deletion without safety check")
    ] = False,
) -> DeleteResponse:
    """Delete a global schema version.

    Can optionally provide a namespace query parameter to delete a namespaced schema.
    """
    service.delete_schema(namespace, model_name, version, force)
    return DeleteResponse(
        deleted=True,
        namespace=namespace,
        model_name=model_name,
        version=version,
    )


@router.post(
    "/{model_name}/versions/{version}/deprecate",
    response_model=SchemaResponse,
    summary="Deprecate global schema",
    description="Mark a global schema version as deprecated",
)
def deprecate_global_schema(
    model_name: Annotated[str, Path(description="Model name")],
    version: Annotated[str, Path(description="Version string")],
    service: SchemaServiceDep,
    _authenticated: AuthRequired,
    namespace: Annotated[
        str | None, Query(description="Optional namespace for scoping")
    ] = None,
    message: Annotated[str | None, Query(description="Deprecation message")] = None,
) -> SchemaResponse:
    """Mark a global schema version as deprecated.

    Can optionally provide a namespace query parameter to deprecate a namespaced schema.
    """
    return service.deprecate_schema(namespace, model_name, version, message)


@router.get(
    "/{model_name}/namespaces",
    response_model=dict[str, dict[str, list[str]]],
    summary="List namespaces",
    description="List all namespaces that have versions of this model",
)
def list_namespaces_for_model(
    model_name: Annotated[str, Path(description="Model name to search for")],
    service: SchemaServiceDep,
    _authenticated: AuthRequired,
) -> dict[str, dict[str, list[str]]]:
    """List all namespaces that contain versions of the specified model.

    Useful for discovering where a model is defined across different services.
    Returns a mapping of namespace to list of versions.

    Example response:
    {
        "namespaces": {
            "null": ["1.0.0", "2.0.0"],  # Global versions
            "user-service": ["1.0.0", "1.1.0"],
            "admin-service": ["2.0.0"]
        }
    }
    """
    return service.list_namespaces_for_model(model_name)


# ============================================================================
# LIST ALL SCHEMAS
# ============================================================================


@router.get(
    "",
    response_model=SchemaListResponse,
    summary="List schemas",
    description="List all registered schemas with optional filtering",
)
def list_schemas(  # noqa: PLR0913
    service: SchemaServiceDep,
    _authenticated: AuthRequired,
    namespace: Annotated[
        str | None,
        Query(
            description=(
                "Filter by namespace: omit for all namespaces, 'null' or emptystring"
                "for global schemas only, or specify a namespace name"
            )
        ),
    ] = None,
    model_name: Annotated[str | None, Query(description="Filter by model name")] = None,
    include_deprecated: Annotated[
        bool, Query(description="Include deprecated schemas in results")
    ] = False,
    limit: Annotated[
        int, Query(description="Maximum number of results", ge=1, le=1000)
    ] = 100,
    offset: Annotated[int, Query(description="Number of results to skip", ge=0)] = 0,
) -> SchemaListResponse:
    """List all registered schemas with pagination and filtering.

    Filters:
    - namespace:
        - Omit parameter: List schemas from ALL namespaces.
        - Empty string or 'null': Filter for global schemas only.
        - Specific name: Filter for that namespace.
    - model_name: Filter by model name (works across namespaces).
    - include_deprecated: Whether to include deprecated schemas.
    """
    return service.list_schemas(
        namespace=namespace,
        model_name=model_name,
        include_deprecated=include_deprecated,
        limit=limit,
        offset=offset,
    )
