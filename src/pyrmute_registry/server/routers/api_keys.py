"""API key management endpoints."""

import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Path, Query, status

from pyrmute_registry.server.auth import AuthAdmin, hash_api_key
from pyrmute_registry.server.deps import DbDep, SettingsDep
from pyrmute_registry.server.models.api_key import ApiKey, Permission
from pyrmute_registry.server.schemas.api_key import (
    ApiKeyCreate,
    ApiKeyCreateResponse,
    ApiKeyListResponse,
    ApiKeyResponse,
    ApiKeyRevokeRequest,
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
    db: DbDep,
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

    existing = db.query(ApiKey).filter(ApiKey.name == key_data.name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"API key with name '{key_data.name}' already exists",
        )

    plaintext_key = secrets.token_urlsafe(32)
    key_hash = hash_api_key(plaintext_key)

    expires_at = None
    if key_data.expires_in_days:
        expires_at = datetime.now(UTC) + timedelta(days=key_data.expires_in_days)

    api_key = ApiKey(
        name=key_data.name,
        key_hash=key_hash,
        permission=key_data.permission.value,
        created_by=_auth.name if _auth else "system",
        description=key_data.description,
        expires_at=expires_at,
    )

    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    response_dict = {
        **ApiKeyResponse.model_validate(api_key, from_attributes=True).model_dump(),
        "api_key": plaintext_key,
    }
    return ApiKeyCreateResponse(**response_dict)


@router.get(
    "",
    response_model=ApiKeyListResponse,
    summary="List API keys",
    description="List all API keys with optional filtering",
)
def list_api_keys(
    db: DbDep,
    _auth: AuthAdmin,
    include_revoked: Annotated[bool, Query(description="Include revoked keys")] = False,
    permission: Annotated[
        Permission | None, Query(description="Filter by permission level")
    ] = None,
) -> ApiKeyListResponse:
    """List all API keys.

    Requires: ADMIN permission
    """
    query = db.query(ApiKey)

    if not include_revoked:
        query = query.filter(ApiKey.revoked == False)  # noqa: E712

    if permission:
        query = query.filter(ApiKey.permission == permission.value)

    keys = query.order_by(ApiKey.created_at.desc()).all()

    return ApiKeyListResponse(
        keys=[ApiKeyResponse.model_validate(key) for key in keys],
        total=len(keys),
    )


@router.get(
    "/stats",
    response_model=ApiKeyStatsResponse,
    summary="Get API key statistics",
    description="Get aggregate statistics about API keys",
)
def get_api_key_stats(
    db: DbDep,
    _auth: AuthAdmin,
) -> ApiKeyStatsResponse:
    """Get statistics about API keys.

    Requires: ADMIN permission
    """
    all_keys = db.query(ApiKey).all()

    total = len(all_keys)
    active = sum(1 for k in all_keys if k.is_active)
    revoked = sum(1 for k in all_keys if k.revoked)
    expired = sum(1 for k in all_keys if k.is_expired and not k.revoked)

    # Count by permission
    by_permission: dict[str, int] = {
        Permission.READ.value: 0,
        Permission.WRITE.value: 0,
        Permission.DELETE.value: 0,
        Permission.ADMIN.value: 0,
    }
    for key in all_keys:
        if key.permission in by_permission:
            by_permission[key.permission] += 1

    return ApiKeyStatsResponse(
        total_keys=total,
        active_keys=active,
        revoked_keys=revoked,
        expired_keys=expired,
        by_permission=by_permission,
    )


@router.get(
    "/{key_id}",
    response_model=ApiKeyResponse,
    summary="Get API key details",
    description="Get details about a specific API key",
)
def get_api_key(
    key_id: Annotated[int, Path(description="API key ID")],
    db: DbDep,
    _auth: AuthAdmin,
) -> ApiKeyResponse:
    """Get details about a specific API key.

    Requires: ADMIN permission
    """
    key = db.query(ApiKey).filter(ApiKey.id == key_id).first()

    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key with ID {key_id} not found",
        )

    return ApiKeyResponse.model_validate(key)


@router.post(
    "/{key_id}/revoke",
    response_model=ApiKeyResponse,
    summary="Revoke API key",
    description="Revoke an API key to prevent further use",
)
def revoke_api_key(
    key_id: Annotated[int, Path(description="API key ID")],
    revoke_data: Annotated[ApiKeyRevokeRequest, Body(...)],
    db: DbDep,
    _auth: AuthAdmin,
) -> ApiKeyResponse:
    """Revoke an API key.

    Once revoked, the key cannot be used for authentication.
    This action cannot be undone.

    Requires: ADMIN permission
    """
    key = db.query(ApiKey).filter(ApiKey.id == key_id).first()

    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key with ID {key_id} not found",
        )

    if key.revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"API key '{key.name}' is already revoked",
        )

    key.revoked = True
    key.revoked_at = datetime.now(UTC)
    key.revoked_by = revoke_data.revoked_by

    if revoke_data.reason:
        if key.description:
            key.description += f"\n\nRevocation reason: {revoke_data.reason}"
        else:
            key.description = f"Revocation reason: {revoke_data.reason}"

    db.commit()
    db.refresh(key)

    return ApiKeyResponse.model_validate(key)


@router.delete(
    "/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete API key",
    description="Permanently delete an API key from the database",
)
def delete_api_key(
    key_id: Annotated[int, Path(description="API key ID")],
    db: DbDep,
    _auth: AuthAdmin,
) -> None:
    """Permanently delete an API key.

    **WARNING**: This action cannot be undone and removes all audit trail.
    Consider revoking instead to maintain history.

    Requires: ADMIN permission
    """
    key = db.query(ApiKey).filter(ApiKey.id == key_id).first()

    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key with ID {key_id} not found",
        )

    db.delete(key)
    db.commit()
