"""Health check endpoints."""

from datetime import UTC, datetime

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from pyrmute_registry.server.deps import SchemaServiceDep, SettingsDep
from pyrmute_registry.server.schemas.health import HealthError, HealthResponse

router = APIRouter(tags=["health"])

# Track server start time for uptime
SERVER_START_TIME = datetime.now(UTC)


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Service is healthy", "model": HealthResponse},
        503: {"description": "Service is unavailable", "model": HealthError},
    },
    summary="Health check",
    description=(
        "Check if the registry is healthy and operational. "
        "Returns system status, uptime, and database connectivity."
    ),
)
def health_check(
    service: SchemaServiceDep,
    settings: SettingsDep,
) -> HealthResponse | JSONResponse:
    """Health check endpoint with system status.

    Authentication is not required for health checks.

    Returns:
        HealthResponse with status information, or 503 error if unhealthy.
    """
    try:
        schema_count = service.get_schema_count()
        db_connected = True
    except SQLAlchemyError as e:
        if settings.is_production:
            error_msg = "Database connection failed. Please try again later."
        else:
            error_msg = f"Database connection failed: {e!s}"

        error_response = HealthError(error=error_msg)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=error_response.model_dump(),
        )
    except Exception as e:
        if settings.is_production:
            error_msg = "Health check failed. Please try again later."
        else:
            error_msg = f"Health check failed: {e!s}"

        error_response = HealthError(error=error_msg)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=error_response.model_dump(),
        )

    uptime = (datetime.now(UTC) - SERVER_START_TIME).total_seconds()

    db_type = (
        settings.database_url.split("://")[0]
        if "://" in settings.database_url
        else "unknown"
    )

    return HealthResponse(
        status="healthy",
        version=settings.app_version,
        environment=settings.environment,
        database={
            "type": db_type,
            "connected": db_connected,
        },
        schemas_count=schema_count,
        uptime_seconds=uptime,
    )


@router.get(
    "/health/live",
    status_code=status.HTTP_200_OK,
    summary="Liveness probe",
    description="Kubernetes liveness probe endpoint. Returns 200 if server is running.",
    response_model=dict[str, bool],
)
def liveness_probe() -> dict[str, bool]:
    """Liveness probe for Kubernetes.

    This is a lightweight endpoint that only checks if the
    server process is running. It does not check database
    connectivity or other dependencies.

    Returns:
        Simple status indicating the server is alive
    """
    return {"alive": True}


@router.get(
    "/health/ready",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Service is ready to accept requests"},
        503: {"description": "Service is not ready"},
    },
    summary="Readiness probe",
    description=(
        "Kubernetes readiness probe endpoint. "
        "Returns 200 if service is ready to accept traffic."
    ),
    response_model=dict[str, bool],
)
def readiness_probe(
    service: SchemaServiceDep,
) -> dict[str, bool] | JSONResponse:
    """Readiness probe for Kubernetes.

    This endpoint checks if the service is ready to accept traffic
    by verifying database connectivity.

    Returns:
        Status indicating if the service is ready, or 503 if not ready
    """
    try:
        service.get_schema_count()
        return {"ready": True}
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"ready": False},
        )
