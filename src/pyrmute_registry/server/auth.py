"""Authentication and authorization utilities."""

import hashlib
import secrets
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from .config import Settings, get_settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


def verify_api_key(
    api_key: str | None,
    settings: Settings,
) -> bool:
    """Verify that the provided API key is valid.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        api_key: The API key to verify.
        settings: Application settings.

    Returns:
        True if valid, False otherwise
    """
    if not settings.enable_auth:
        return True

    if not settings.api_key:
        return False

    if not api_key:
        return False

    return secrets.compare_digest(api_key, settings.api_key)


def get_api_key(
    settings: Annotated[Settings, Depends(get_settings)],
    header_key: Annotated[str | None, Security(api_key_header)] = None,
    bearer_creds: Annotated[
        HTTPAuthorizationCredentials | None, Security(bearer_scheme)
    ] = None,
) -> str | None:
    """Extract and validate API key from either X-API-Key header or Bearer token.

    Tries both authentication methods. X-API-Key header takes precedence.

    Args:
        header_key: API key from X-API-Key header.
        bearer_creds: Bearer credentials from Authorization header.
        settings: Application settings.

    Returns:
        Validated API key.

    Raises:
        HTTPException: If authentication is enabled and both methods fail.
    """
    if not settings.enable_auth:
        return None

    if header_key and verify_api_key(header_key, settings):
        return header_key

    bearer_key = bearer_creds.credentials if bearer_creds else None
    if bearer_key and verify_api_key(bearer_key, settings):
        return bearer_key

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=(
            "Invalid or missing API key. Provide via X-API-Key header "
            "or Authorization: Bearer token."
        ),
        headers={"WWW-Authenticate": 'Bearer, ApiKey realm="Registry"'},
    )


AuthRequired = Annotated[str | None, Depends(get_api_key)]


def generate_api_key(length: int = 32) -> str:
    """Generate a secure random API key.

    Args:
        length: Length of the key in bytes (will be hex-encoded, so actual string is
        2x).

    Returns:
        Hex-encoded random API key.

    Examples:
        ```python
        key = generate_api_key()
        len(key)
        # 64
        key = generate_api_key(length=16)
        len(key)
        # 32
        ```
    """
    return secrets.token_hex(length)


def hash_api_key(api_key: str) -> str:
    """Hash an API key for secure storage.

    Uses SHA-256 for hashing.

    Args:
        api_key: Plain text API key.

    Returns:
        Hex-encoded hash of the key.

    Examples:
        ```python
        key = "my-secret-key"
        hashed = hash_api_key(key)
        len(hashed)
        # 64
        ```
    """
    return hashlib.sha256(api_key.encode()).hexdigest()


class Permission:
    """Permission definitions for role-based access control."""

    READ_SCHEMAS = "read:schemas"
    WRITE_SCHEMAS = "write:schemas"
    DELETE_SCHEMAS = "delete:schemas"
    ADMIN = "admin"


def require_permission(permission: str) -> Callable[..., str | None]:
    """Decorator to require specific permission.

    This is a placeholder for future RBAC implementation. Currently, any valid API key
    grants all permissions.

    Args:
        permission: Required permission.

    Returns:
        Dependency function.

    Examples:
        ```python
        @router.delete("/schemas/{id}")
        def delete_schema(
            _auth: Annotated[
                str, Depends(require_permission(Permission.DELETE_SCHEMAS))
            ]
        ):
            ...
        ```
    """

    def permission_checker(
        api_key: AuthRequired,
        settings: Annotated[Settings, Depends(get_settings)],
    ) -> str | None:
        """Check if the authenticated user has the required permission.

        Args:
            api_key: Authenticated API key.
            settings: Application settings.

        Returns:
            API key if permission granted.

        Raises:
            HTTPException: If permission denied.
        """
        # For now, any valid API key has all permissions
        if not settings.enable_auth:
            return None

        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission} required",
            )

        return api_key

    return permission_checker
