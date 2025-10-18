"""Root endpoint for API information."""

from fastapi import APIRouter
from pydantic import HttpUrl

from pyrmute_registry.server.deps import SettingsDep
from pyrmute_registry.server.schemas.root import (
    DocumentationResponse,
    EndpointsResponse,
    RootResponse,
)

router = APIRouter(tags=["root"])


@router.get(
    "/",
    summary="API information",
    description="Get basic information about the registry API",
    response_model=RootResponse,
)
def root(settings: SettingsDep) -> RootResponse:
    """Root endpoint with API information.

    Provides links to documentation and key endpoints.

    Returns:
        RootResponse with API metadata and links.
    """
    return RootResponse(
        name=settings.app_name,
        version=settings.app_version,
        environment=settings.environment,
        documentation=DocumentationResponse(
            swagger="/docs" if not settings.is_production else None,
            redoc="/redoc" if not settings.is_production else None,
            openapi="/openapi.json",
        ),
        endpoints=EndpointsResponse(
            health="/health",
            schemas="/schemas",
        ),
        repository=HttpUrl("https://github.com/mferrera/pyrmute-registry"),
    )
