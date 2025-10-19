"""API key management endpoints."""

from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Path, Query, status

from pyrmute_registry.server.auth import AuthAdmin
from pyrmute_registry.server.deps import ApiKeyServiceDep, SettingsDep
from pyrmute_registry.server.models.api_key import Permission
from pyrmute_registry.server.schemas.api_key import (
    ApiKeyCreate,
    ApiKeyCreateResponse,
    ApiKeyListResponse,
    ApiKeyResponse,
    ApiKeyRevokeRequest,
    ApiKeyRotateRequest,
    ApiKeyRotateResponse,
    ApiKeyStatsResponse,
)

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


@router.post(
    "",
    response_model=ApiKeyCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create API key",
    description=(
        "Create a new API key with specified permissions. "
        "**Important**: The plaintext key is only shown once in this response!"
    ),
)
def create_api_key(
    key_data: Annotated[ApiKeyCreate, Body(...)],
    service: ApiKeyServiceDep,
    settings: SettingsDep,
    _auth: AuthAdmin,
) -> ApiKeyCreateResponse:
    """Create a new API key.

    **IMPORTANT**: The plaintext API key is only returned once in this response.
    Store it securely - it cannot be retrieved later.

    Requires: ADMIN permission
    """
    if not settings.enable_auth:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authentication is disabled. Enable it to manage API keys.",
        )

    created_by = _auth.name if _auth else "system"
    return service.create_api_key(key_data, created_by=created_by)


@router.get(
    "",
    response_model=ApiKeyListResponse,
    summary="List API keys",
    description="List all API keys with optional filtering",
)
def list_api_keys(
    service: ApiKeyServiceDep,
    _auth: AuthAdmin,
    include_revoked: Annotated[bool, Query(description="Include revoked keys")] = False,
    permission: Annotated[
        Permission | None, Query(description="Filter by permission level")
    ] = None,
) -> ApiKeyListResponse:
    """List all API keys.

    Requires: ADMIN permission
    """
    return service.list_api_keys(
        include_revoked=include_revoked,
        permission=permission,
    )


@router.get(
    "/stats",
    response_model=ApiKeyStatsResponse,
    summary="Get API key statistics",
    description="Get aggregate statistics about API keys",
)
def get_api_key_stats(
    service: ApiKeyServiceDep,
    _auth: AuthAdmin,
) -> ApiKeyStatsResponse:
    """Get statistics about API keys.

    Requires: ADMIN permission
    """
    return service.get_api_key_stats()


@router.get(
    "/{key_id}",
    response_model=ApiKeyResponse,
    summary="Get API key details",
    description="Get details about a specific API key",
)
def get_api_key(
    key_id: Annotated[int, Path(description="API key ID")],
    service: ApiKeyServiceDep,
    _auth: AuthAdmin,
) -> ApiKeyResponse:
    """Get details about a specific API key.

    Requires: ADMIN permission
    """
    return service.get_api_key(key_id)


@router.post(
    "/{key_id}/revoke",
    response_model=ApiKeyResponse,
    summary="Revoke API key",
    description="Revoke an API key to prevent further use",
)
def revoke_api_key(
    key_id: Annotated[int, Path(description="API key ID")],
    revoke_data: Annotated[ApiKeyRevokeRequest, Body(...)],
    service: ApiKeyServiceDep,
    _auth: AuthAdmin,
) -> ApiKeyResponse:
    """Revoke an API key.

    Once revoked, the key cannot be used for authentication.
    This action cannot be undone.

    Requires: ADMIN permission
    """
    return service.revoke_api_key(key_id, revoke_data)


@router.delete(
    "/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete API key",
    description="Permanently delete an API key from the database",
)
def delete_api_key(
    key_id: Annotated[int, Path(description="API key ID")],
    service: ApiKeyServiceDep,
    _auth: AuthAdmin,
) -> None:
    """Permanently delete an API key.

    **WARNING**: This action cannot be undone and removes all audit trail.  Consider
    revoking instead to maintain history.

    Requires: ADMIN permission
    """
    service.delete_api_key(key_id)


@router.post(
    "/{key_id}/rotate",
    response_model=ApiKeyRotateResponse,
    summary="Rotate API key",
    description=(
        "Generate a new API key to replace an existing one. "
        "The old key can remain active for a grace period to allow a transition. "
        "**Important**: The new plaintext key is only shown once in this response!"
    ),
)
def rotate_api_key(
    key_id: Annotated[int, Path(description="API key ID to rotate")],
    rotation_data: Annotated[ApiKeyRotateRequest, Body(...)],
    service: ApiKeyServiceDep,
    settings: SettingsDep,
    _auth: AuthAdmin,
) -> ApiKeyRotateResponse:
    """Rotate an API key, generating a new one with the same permissions.

    The old key can remain active during a grace period for zero-downtime rotation.
    After the grace period, the old key should be manually revoked or use a background
    job to auto-revoke expired rotation grace periods.

    **IMPORTANT**: The plaintext API key for the new key is only returned once. Store
    it securely. It cannot be retrieved later.

    Requires: ADMIN permission
    """
    if not settings.enable_auth:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authentication is disabled. Enable it to manage API keys.",
        )

    rotated_by = _auth.name if _auth else "system"
    return service.rotate_api_key(key_id, rotation_data, rotated_by=rotated_by)
