"""Business logic for API key operations."""

import secrets
from datetime import UTC, datetime, timedelta
from typing import Self

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from pyrmute_registry.server.auth import hash_api_key
from pyrmute_registry.server.models.api_key import ApiKey, Permission
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


class ApiKeyService:
    """Service layer for API key operations."""

    def __init__(self: Self, db: Session) -> None:
        """Initialize service with database session.

        Args:
            db: SQLAlchemy database session.
        """
        self.db = db

    def create_api_key(
        self: Self,
        key_data: ApiKeyCreate,
        created_by: str = "system",
    ) -> ApiKeyCreateResponse:
        """Create a new API key.

        Args:
            key_data: API key creation data.
            created_by: Who created the key (from auth context).

        Returns:
            Created API key with plaintext key (only shown once).

        Raises:
            HTTPException: If key name already exists.
        """
        existing = self.db.query(ApiKey).filter(ApiKey.name == key_data.name).first()
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
            created_by=created_by,
            description=key_data.description,
            expires_at=expires_at,
        )

        self.db.add(api_key)
        self.db.commit()
        self.db.refresh(api_key)

        response_dict = {
            **ApiKeyResponse.model_validate(api_key, from_attributes=True).model_dump(),
            "api_key": plaintext_key,
        }
        return ApiKeyCreateResponse.model_validate(response_dict)

    def list_api_keys(
        self: Self,
        include_revoked: bool = False,
        permission: Permission | None = None,
    ) -> ApiKeyListResponse:
        """List all API keys with optional filtering.

        Args:
            include_revoked: Whether to include revoked keys.
            permission: Optional filter by permission level.

        Returns:
            List of API keys with metadata.
        """
        query = self.db.query(ApiKey)

        if not include_revoked:
            query = query.filter(ApiKey.revoked == False)  # noqa: E712

        if permission:
            query = query.filter(ApiKey.permission == permission.value)

        keys = query.order_by(ApiKey.created_at.desc()).all()

        return ApiKeyListResponse(
            keys=[ApiKeyResponse.model_validate(key) for key in keys],
            total=len(keys),
        )

    def get_api_key_stats(self: Self) -> ApiKeyStatsResponse:
        """Get aggregate statistics about API keys.

        Returns:
            Statistics about all API keys.
        """
        all_keys = self.db.query(ApiKey).all()

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

    def get_api_key(self: Self, key_id: int) -> ApiKeyResponse:
        """Get details about a specific API key.

        Args:
            key_id: ID of the API key.

        Returns:
            API key details.

        Raises:
            HTTPException: If key not found.
        """
        key = self.db.query(ApiKey).filter(ApiKey.id == key_id).first()

        if not key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"API key with ID {key_id} not found",
            )

        return ApiKeyResponse.model_validate(key)

    def revoke_api_key(
        self: Self,
        key_id: int,
        revoke_data: ApiKeyRevokeRequest,
    ) -> ApiKeyResponse:
        """Revoke an API key.

        Args:
            key_id: ID of the API key to revoke.
            revoke_data: Revocation details (who, why).

        Returns:
            Updated API key details.

        Raises:
            HTTPException: If key not found or already revoked.
        """
        key = self.db.query(ApiKey).filter(ApiKey.id == key_id).first()

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

        self.db.commit()
        self.db.refresh(key)

        return ApiKeyResponse.model_validate(key)

    def delete_api_key(self: Self, key_id: int) -> bool:
        """Permanently delete an API key.

        Args:
            key_id: ID of the API key to delete.

        Returns:
            True if deleted successfully.

        Raises:
            HTTPException: If key not found.
        """
        key = self.db.query(ApiKey).filter(ApiKey.id == key_id).first()

        if not key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"API key with ID {key_id} not found",
            )

        self.db.delete(key)
        self.db.commit()

        return True

    # Add this method to the ApiKeyService class:

    def rotate_api_key(
        self: Self,
        key_id: int,
        rotation_data: ApiKeyRotateRequest,
        rotated_by: str = "system",
    ) -> ApiKeyRotateResponse:
        """Rotate an API key, generating a new one with the same permissions.

        Args:
            key_id: ID of the API key to rotate.
            rotation_data: Rotation configuration (grace period, reason).
            rotated_by: Who initiated the rotation (from auth context).

        Returns:
            Response containing both old and new keys.

        Raises:
            HTTPException: If key not found or already revoked.
        """
        # Get existing key
        old_key = self.db.query(ApiKey).filter(ApiKey.id == key_id).first()
        if not old_key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"API key with ID {key_id} not found",
            )

        if old_key.revoked:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot rotate revoked key '{old_key.name}'",
            )

        # Generate new key
        plaintext_key = secrets.token_urlsafe(32)
        key_hash = hash_api_key(plaintext_key)

        # Create new key with same permissions
        timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        new_key = ApiKey(
            name=f"{old_key.name}-rotated-{timestamp}",
            key_hash=key_hash,
            permission=old_key.permission,
            created_by=rotated_by,
            description=(
                f"Rotated from key ID {old_key.id}. {rotation_data.reason or ''}"
            ).strip(),
            expires_at=old_key.expires_at,  # Preserve original expiration
            rotated_from_id=old_key.id,
        )

        self.db.add(new_key)
        self.db.flush()  # Get new_key.id

        # Handle old key based on grace period
        grace_period_ends_at = None
        if rotation_data.grace_period_hours > 0:
            # Keep old key active with scheduled revocation
            grace_period_ends_at = datetime.now(UTC) + timedelta(
                hours=rotation_data.grace_period_hours
            )
            old_key.rotation_scheduled_at = grace_period_ends_at
            old_key.rotated_to_id = new_key.id

            if rotation_data.reason:
                old_key.description = (
                    f"{old_key.description or ''}\n\n"
                    f"Rotation scheduled: {rotation_data.reason}"
                ).strip()

            message = (
                f"New key created. Old key will remain active until "
                f"{grace_period_ends_at.isoformat()}"
            )
        else:
            # Immediate revocation
            old_key.revoked = True
            old_key.revoked_at = datetime.now(UTC)
            old_key.revoked_by = rotated_by
            old_key.rotated_to_id = new_key.id

            if rotation_data.reason:
                old_key.description = (
                    f"{old_key.description or ''}\n\n"
                    f"Revoked (rotated): {rotation_data.reason}"
                ).strip()

            message = "New key created. Old key immediately revoked."

        self.db.commit()
        self.db.refresh(old_key)
        self.db.refresh(new_key)

        return ApiKeyRotateResponse(
            old_key=ApiKeyResponse.model_validate(old_key),
            new_key=ApiKeyCreateResponse(
                **ApiKeyResponse.model_validate(new_key).model_dump(),
                api_key=plaintext_key,
            ),
            grace_period_ends_at=grace_period_ends_at,
            message=message,
        )
