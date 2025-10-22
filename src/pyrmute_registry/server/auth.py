"""Authentication and authorization with database-backed API keys."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated

import bcrypt
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from pyrmute_registry.server.logging import get_logger

from .config import Settings, get_settings
from .db import get_db
from .models.api_key import ApiKey, Permission

logger = get_logger(__name__)

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


def hash_api_key(api_key: str) -> str:
    """Hash an API key using bcrypt.

    Args:
        api_key: Plain text API key.

    Returns:
        Bcrypt hash of the key.
    """
    return bcrypt.hashpw(api_key.encode(), bcrypt.gensalt()).decode()


def verify_api_key_hash(api_key: str, key_hash: str) -> bool:
    """Verify an API key against its hash.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        api_key: Plain text API key to verify.
        key_hash: Bcrypt hash to compare against.

    Returns:
        True if key matches hash.
    """
    try:
        return bcrypt.checkpw(api_key.encode(), key_hash.encode())
    except Exception as e:
        logger.warning(
            "api_key_verification_failed",
            error=str(e),
            error_type=type(e).__name__,
        )
        return False


def authenticate_api_key(
    api_key: str,
    db: Session,
) -> ApiKey | None:
    """Authenticate an API key and return the key record if valid.

    Args:
        api_key: Plain text API key to authenticate.
        db: Database session.

    Returns:
        ApiKey record if authenticated, None otherwise.
    """
    # Query only active (non-revoked, non-expired) keys
    active_keys = (
        db.query(ApiKey)
        .filter(ApiKey.revoked == False)  # noqa: E712
        .all()
    )

    for key_record in active_keys:
        if verify_api_key_hash(api_key, key_record.key_hash):
            # Check expiration
            if not key_record.is_active:
                logger.warning(
                    "inactive_key_attempt",
                    key_name=key_record.name,
                    key_id=key_record.id,
                    revoked=key_record.revoked,
                    expired=key_record.is_expired,
                )
                continue

            # Update last used timestamp
            key_record.last_used_at = datetime.now(UTC)
            key_record.use_count += 1
            db.commit()

            logger.info(
                "authentication_successful",
                key_name=key_record.name,
                key_id=key_record.id,
                permission=key_record.permission,
            )
            return key_record

    return None


def get_current_api_key(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    db: Annotated[Session, Depends(get_db)],
    header_key: Annotated[str | None, Security(api_key_header)] = None,
    bearer_creds: Annotated[
        HTTPAuthorizationCredentials | None, Security(bearer_scheme)
    ] = None,
) -> ApiKey | None:
    """Extract and authenticate API key from request.

    Tries both X-API-Key header and Bearer token.

    Args:
        request: The incoming request.
        settings: Application settings.
        db: Database session.
        header_key: API key from X-API-Key header.
        bearer_creds: Bearer credentials from Authorization header.

    Returns:
        Authenticated ApiKey record.

    Raises:
        HTTPException: If authentication is enabled and key is invalid.
    """
    if not settings.enable_auth:
        logger.debug("authentication_disabled")
        return None

    # Extract key from either header or bearer token
    api_key = None
    auth_method = None
    if header_key:
        api_key = header_key
        auth_method = "x-api-key"
    elif bearer_creds:
        api_key = bearer_creds.credentials
        auth_method = "bearer"

    if not api_key:
        logger.warning("authentication_failed", reason="no_key_provided")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required. Provide via X-API-Key header or Bearer token.",
            headers={"WWW-Authenticate": 'Bearer, ApiKey realm="Registry"'},
        )

    key_record = authenticate_api_key(api_key, db)
    if not key_record:
        logger.warning(
            "authentication_failed",
            reason="invalid_key",
            auth_method=auth_method,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": 'Bearer, ApiKey realm="Registry"'},
        )

    # Attach api key to request state for middleware access
    request.state.api_key = key_record

    return key_record


PermissionChecker = Callable[..., ApiKey | None]


def require_permission(permission: Permission) -> PermissionChecker:
    """Dependency to require specific permission level.

    Args:
        permission: Required permission level.

    Returns:
        Dependency function that checks permissions.

    Examples:
    ```python
        @router.delete("/schemas/{id}")
        def delete_schema(
            _auth: Annotated[ApiKey, Depends(require_permission(Permission.DELETE))]
        ):
            ...
    ```
    """

    def permission_checker(
        api_key: Annotated[ApiKey | None, Depends(get_current_api_key)],
        settings: Annotated[Settings, Depends(get_settings)],
    ) -> ApiKey | None:
        """Check if the authenticated key has required permission.

        Args:
            api_key: Authenticated API key.
            settings: Application settings.

        Returns:
            ApiKey if permission granted.

        Raises:
            HTTPException: If permission denied.
        """
        if not settings.enable_auth:
            return None

        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )

        if not api_key.has_permission(permission):
            logger.warning(
                "permission_denied",
                key_name=api_key.name,
                key_id=api_key.id,
                has_permission=api_key.permission,
                required_permission=permission.value,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {permission.value}",
            )

        return api_key

    return permission_checker


AuthOptional = Annotated[ApiKey | None, Depends(get_current_api_key)]
AuthRead = Annotated[ApiKey | None, Depends(require_permission(Permission.READ))]
AuthWrite = Annotated[ApiKey | None, Depends(require_permission(Permission.WRITE))]
AuthDelete = Annotated[ApiKey | None, Depends(require_permission(Permission.DELETE))]
AuthAdmin = Annotated[ApiKey | None, Depends(require_permission(Permission.ADMIN))]
