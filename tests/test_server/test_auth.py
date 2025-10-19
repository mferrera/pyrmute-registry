"""Tests for authentication system."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from pyrmute_registry.server.auth import (
    authenticate_api_key,
    get_current_api_key,
    hash_api_key,
    require_permission,
    verify_api_key_hash,
)
from pyrmute_registry.server.config import Settings
from pyrmute_registry.server.models.api_key import ApiKey, Permission

# =============================================================================
# Hash and Verification Tests
# =============================================================================


def test_hash_api_key() -> None:
    """Test hashing an API key using bcrypt."""
    key = "my-secret-key"
    hashed = hash_api_key(key)

    # Bcrypt hashes are 60 characters
    assert len(hashed) == 60  # noqa: PLR2004
    assert hashed.startswith("$2b$")  # Bcrypt identifier


def test_hash_api_key_different_each_time() -> None:
    """Test that hashing produces different hashes due to salt."""
    key = "my-secret-key"
    hash1 = hash_api_key(key)
    hash2 = hash_api_key(key)

    # Hashes should be different (different salt)
    assert hash1 != hash2


def test_verify_api_key_hash_valid() -> None:
    """Test verifying a valid API key hash."""
    key = "my-secret-key"
    key_hash = hash_api_key(key)

    assert verify_api_key_hash(key, key_hash) is True


def test_verify_api_key_hash_invalid() -> None:
    """Test verifying an invalid API key hash."""
    key = "my-secret-key"
    wrong_key = "wrong-key"
    key_hash = hash_api_key(key)

    assert verify_api_key_hash(wrong_key, key_hash) is False


def test_verify_api_key_hash_uses_bcrypt() -> None:
    """Test that API key verification uses bcrypt.

    Bcrypt's checkpw is inherently timing-safe, so we just verify we're using
    bcrypt correctly rather than attempting timing-based tests which are flaky.
    """
    key = "my-secret-key"
    key_hash = hash_api_key(key)

    # Verify bcrypt hash format (ensures we're using bcrypt)
    assert key_hash.startswith("$2b$"), "Hash should use bcrypt format"
    assert len(key_hash) == 60, "Bcrypt hashes are 60 characters"  # noqa: PLR2004

    # Verify correct key validates
    assert verify_api_key_hash(key, key_hash) is True

    # Verify wrong key fails
    assert verify_api_key_hash("wrong-key", key_hash) is False
    assert verify_api_key_hash("another-wrong-key", key_hash) is False


# =============================================================================
# Authentication Tests
# =============================================================================


def test_authenticate_api_key_valid(
    db_session: Session, sample_api_key: ApiKey
) -> None:
    """Test authenticating with a valid API key."""
    result = authenticate_api_key(sample_api_key._plaintext, db_session)  # type: ignore[attr-defined]

    assert result is not None
    assert result.id == sample_api_key.id
    assert result.name == "test-key"
    assert result.permission == Permission.WRITE.value


def test_authenticate_api_key_invalid(db_session: Session) -> None:
    """Test authenticating with an invalid API key."""
    result = authenticate_api_key("invalid-key", db_session)
    assert result is None


def test_authenticate_api_key_revoked(db_session: Session, revoked_key: ApiKey) -> None:
    """Test that revoked keys cannot authenticate."""
    result = authenticate_api_key(revoked_key._plaintext, db_session)  # type: ignore[attr-defined]
    assert result is None


def test_authenticate_api_key_expired(db_session: Session, expired_key: ApiKey) -> None:
    """Test that expired keys cannot authenticate."""
    result = authenticate_api_key(expired_key._plaintext, db_session)  # type: ignore[attr-defined]
    assert result is None


def test_authenticate_api_key_updates_last_used(
    db_session: Session, sample_api_key: ApiKey
) -> None:
    """Test that authentication updates last_used_at timestamp."""
    # Get initial timestamp
    initial_last_used = sample_api_key.last_used_at
    initial_use_count = sample_api_key.use_count

    # Authenticate
    result = authenticate_api_key(sample_api_key._plaintext, db_session)  # type: ignore[attr-defined]

    assert result is not None
    assert result.last_used_at is not None
    assert result.last_used_at != initial_last_used
    assert result.use_count == initial_use_count + 1


# =============================================================================
# get_current_api_key Tests
# =============================================================================


def test_get_current_api_key_header(
    db_session: Session, auth_enabled_settings: Settings, sample_api_key: ApiKey
) -> None:
    """Test getting API key from X-API-Key header."""
    result = get_current_api_key(
        settings=auth_enabled_settings,
        db=db_session,
        header_key=sample_api_key._plaintext,  # type: ignore[attr-defined]
        bearer_creds=None,
    )

    assert result is not None
    assert result.id == sample_api_key.id


def test_get_current_api_key_bearer(
    db_session: Session, auth_enabled_settings: Settings, sample_api_key: ApiKey
) -> None:
    """Test getting API key from Bearer token."""
    bearer_creds = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials=sample_api_key._plaintext,  # type: ignore[attr-defined]
    )
    result = get_current_api_key(
        settings=auth_enabled_settings,
        db=db_session,
        header_key=None,
        bearer_creds=bearer_creds,
    )

    assert result is not None
    assert result.id == sample_api_key.id


def test_get_current_api_key_header_precedence(
    db_session: Session,
    auth_enabled_settings: Settings,
    sample_api_key: ApiKey,
    admin_api_key: ApiKey,
) -> None:
    """Test that X-API-Key header takes precedence over Bearer."""
    bearer_creds = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials=admin_api_key._plaintext,  # type: ignore[attr-defined]
    )
    result = get_current_api_key(
        settings=auth_enabled_settings,
        db=db_session,
        header_key=sample_api_key._plaintext,  # type: ignore[attr-defined]
        bearer_creds=bearer_creds,
    )

    assert result is not None
    assert result.id == sample_api_key.id  # Header key was used


def test_get_current_api_key_missing_when_auth_enabled(
    db_session: Session, auth_enabled_settings: Settings
) -> None:
    """Test that missing API key raises 401 when auth is enabled."""
    with pytest.raises(HTTPException) as exc_info:
        get_current_api_key(
            settings=auth_enabled_settings,
            db=db_session,
            header_key=None,
            bearer_creds=None,
        )

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "API key required" in exc_info.value.detail


def test_get_current_api_key_invalid_when_auth_enabled(
    db_session: Session, auth_enabled_settings: Settings
) -> None:
    """Test that invalid API key raises 401 when auth is enabled."""
    with pytest.raises(HTTPException) as exc_info:
        get_current_api_key(
            settings=auth_enabled_settings,
            db=db_session,
            header_key="invalid-key",
            bearer_creds=None,
        )

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid API key" in exc_info.value.detail


def test_get_current_api_key_auth_disabled(
    db_session: Session, auth_disabled_settings: Settings
) -> None:
    """Test that get_current_api_key returns None when auth is disabled."""
    result = get_current_api_key(
        settings=auth_disabled_settings,
        db=db_session,
        header_key=None,
        bearer_creds=None,
    )
    assert result is None


# =============================================================================
# Permission Tests
# =============================================================================


def test_api_key_has_permission_exact_match(db_session: Session) -> None:
    """Test permission check with exact match."""
    key = ApiKey(
        name="test",
        key_hash="hash",
        permission=Permission.WRITE.value,
        created_by="test",
    )
    db_session.add(key)
    db_session.commit()

    assert key.has_permission(Permission.WRITE) is True


def test_api_key_has_permission_hierarchy(db_session: Session) -> None:
    """Test permission hierarchy (higher permissions include lower)."""
    key = ApiKey(
        name="test",
        key_hash="hash",
        permission=Permission.DELETE.value,
        created_by="test",
    )
    db_session.add(key)
    db_session.commit()

    # DELETE includes WRITE, which includes READ
    assert key.has_permission(Permission.READ) is True
    assert key.has_permission(Permission.WRITE) is True
    assert key.has_permission(Permission.DELETE) is True


def test_api_key_has_permission_admin_has_all(db_session: Session) -> None:
    """Test that admin permission grants all permissions."""
    key = ApiKey(
        name="test",
        key_hash="hash",
        permission=Permission.ADMIN.value,
        created_by="test",
    )
    db_session.add(key)
    db_session.commit()

    assert key.has_permission(Permission.READ) is True
    assert key.has_permission(Permission.WRITE) is True
    assert key.has_permission(Permission.DELETE) is True
    assert key.has_permission(Permission.ADMIN) is True


def test_api_key_has_permission_insufficient(db_session: Session) -> None:
    """Test permission check with insufficient permissions."""
    key = ApiKey(
        name="test",
        key_hash="hash",
        permission=Permission.READ.value,
        created_by="test",
    )
    db_session.add(key)
    db_session.commit()

    assert key.has_permission(Permission.READ) is True
    assert key.has_permission(Permission.WRITE) is False
    assert key.has_permission(Permission.DELETE) is False
    assert key.has_permission(Permission.ADMIN) is False


def test_api_key_has_permission_revoked(
    db_session: Session, revoked_key: ApiKey
) -> None:
    """Test that revoked keys have no permissions."""
    assert revoked_key.has_permission(Permission.READ) is False
    assert revoked_key.has_permission(Permission.WRITE) is False


def test_api_key_has_permission_expired(
    db_session: Session, expired_key: ApiKey
) -> None:
    """Test that expired keys have no permissions."""
    assert expired_key.has_permission(Permission.READ) is False
    assert expired_key.has_permission(Permission.WRITE) is False


# =============================================================================
# require_permission Tests
# =============================================================================


def test_require_permission_valid_key(
    auth_enabled_settings: Settings, sample_api_key: ApiKey
) -> None:
    """Test permission requirement with valid key."""
    checker = require_permission(Permission.WRITE)
    result = checker(sample_api_key, auth_enabled_settings)

    assert result is not None
    assert result.id == sample_api_key.id


def test_require_permission_insufficient_permissions(
    auth_enabled_settings: Settings, read_only_key: ApiKey
) -> None:
    """Test permission requirement with insufficient permissions."""
    checker = require_permission(Permission.WRITE)

    with pytest.raises(HTTPException) as exc_info:
        checker(read_only_key, auth_enabled_settings)

    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert "Insufficient permissions" in exc_info.value.detail


def test_require_permission_no_api_key(auth_enabled_settings: Settings) -> None:
    """Test permission requirement with no API key."""
    checker = require_permission(Permission.WRITE)

    with pytest.raises(HTTPException) as exc_info:
        checker(None, auth_enabled_settings)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Authentication required" in exc_info.value.detail


def test_require_permission_auth_disabled(auth_disabled_settings: Settings) -> None:
    """Test permission requirement when auth is disabled."""
    checker = require_permission(Permission.WRITE)
    result = checker(None, auth_disabled_settings)

    assert result is None


def test_require_permission_admin_can_do_anything(
    auth_enabled_settings: Settings, admin_api_key: ApiKey
) -> None:
    """Test that admin permission grants all access."""
    # Test all permission levels
    for perm in [
        Permission.READ,
        Permission.WRITE,
        Permission.DELETE,
        Permission.ADMIN,
    ]:
        checker = require_permission(perm)
        result = checker(admin_api_key, auth_enabled_settings)
        assert result is not None


# =============================================================================
# ApiKey Model Tests
# =============================================================================


def test_api_key_is_active_normal(db_session: Session, sample_api_key: ApiKey) -> None:
    """Test that a normal key is active."""
    assert sample_api_key.is_active is True


def test_api_key_is_active_revoked(db_session: Session, revoked_key: ApiKey) -> None:
    """Test that a revoked key is not active."""
    assert revoked_key.is_active is False


def test_api_key_is_active_expired(db_session: Session, expired_key: ApiKey) -> None:
    """Test that an expired key is not active."""
    assert expired_key.is_active is False


def test_api_key_is_expired_normal(db_session: Session, sample_api_key: ApiKey) -> None:
    """Test that a normal key is not expired."""
    assert sample_api_key.is_expired is False


def test_api_key_is_expired_with_expiration(
    db_session: Session, expired_key: ApiKey
) -> None:
    """Test that an expired key is marked as expired."""
    assert expired_key.is_expired is True


def test_api_key_is_expired_future_expiration(db_session: Session) -> None:
    """Test that a key with future expiration is not expired."""
    key = ApiKey(
        name="future-key",
        key_hash="hash",
        permission=Permission.READ.value,
        created_by="test",
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )
    db_session.add(key)
    db_session.commit()

    assert key.is_expired is False
    assert key.is_active is True


def test_api_key_repr(db_session: Session, sample_api_key: ApiKey) -> None:
    """Test string representation of ApiKey."""
    repr_str = repr(sample_api_key)
    assert "ApiKey" in repr_str
    assert "test-key" in repr_str
    assert "write" in repr_str
    assert "ACTIVE" in repr_str


def test_api_key_repr_revoked(db_session: Session, revoked_key: ApiKey) -> None:
    """Test string representation of revoked ApiKey."""
    repr_str = repr(revoked_key)
    assert "REVOKED" in repr_str


# =============================================================================
# Permission Enum Tests
# =============================================================================


def test_permission_enum_values() -> None:
    """Test that permission enum values are correct."""
    assert Permission.READ.value == "read"
    assert Permission.WRITE.value == "write"
    assert Permission.DELETE.value == "delete"
    assert Permission.ADMIN.value == "admin"


def test_permission_enum_from_string() -> None:
    """Test creating Permission from string."""
    assert Permission("read") == Permission.READ
    assert Permission("write") == Permission.WRITE
    assert Permission("delete") == Permission.DELETE
    assert Permission("admin") == Permission.ADMIN


# =============================================================================
# Integration Tests
# =============================================================================


def test_full_auth_flow_read_operation(
    db_session: Session,
    auth_enabled_settings: Settings,
    read_only_key: ApiKey,
) -> None:
    """Test full authentication flow for read operation."""
    # Simulate incoming request with API key
    api_key_obj = get_current_api_key(
        settings=auth_enabled_settings,
        db=db_session,
        header_key=read_only_key._plaintext,  # type: ignore[attr-defined]
        bearer_creds=None,
    )

    # Check read permission (should pass)
    checker = require_permission(Permission.READ)
    result = checker(api_key_obj, auth_enabled_settings)
    assert result is not None


def test_full_auth_flow_write_operation_denied(
    db_session: Session,
    auth_enabled_settings: Settings,
    read_only_key: ApiKey,
) -> None:
    """Test full authentication flow for write operation with read-only key."""
    # Simulate incoming request with API key
    api_key_obj = get_current_api_key(
        settings=auth_enabled_settings,
        db=db_session,
        header_key=read_only_key._plaintext,  # type: ignore[attr-defined]
        bearer_creds=None,
    )

    # Check write permission (should fail)
    checker = require_permission(Permission.WRITE)
    with pytest.raises(HTTPException) as exc_info:
        checker(api_key_obj, auth_enabled_settings)

    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN


def test_full_auth_flow_admin_operation(
    db_session: Session,
    auth_enabled_settings: Settings,
    admin_api_key: ApiKey,
) -> None:
    """Test full authentication flow for admin operation."""
    # Simulate incoming request with API key
    api_key_obj = get_current_api_key(
        settings=auth_enabled_settings,
        db=db_session,
        header_key=admin_api_key._plaintext,  # type: ignore[attr-defined]
        bearer_creds=None,
    )

    # Check admin permission (should pass)
    checker = require_permission(Permission.ADMIN)
    result = checker(api_key_obj, auth_enabled_settings)
    assert result is not None


def test_auth_disabled_bypasses_all_checks(
    db_session: Session, auth_disabled_settings: Settings
) -> None:
    """Test that disabling auth bypasses all security checks."""
    # No API key provided
    api_key_obj = get_current_api_key(
        settings=auth_disabled_settings,
        db=db_session,
        header_key=None,
        bearer_creds=None,
    )
    assert api_key_obj is None

    # Permission checks should pass
    for perm in [
        Permission.READ,
        Permission.WRITE,
        Permission.DELETE,
        Permission.ADMIN,
    ]:
        checker = require_permission(perm)
        result = checker(None, auth_disabled_settings)
        assert result is None  # None is OK when auth is disabled


def test_delete_permission_includes_write_and_read(
    db_session: Session,
    auth_enabled_settings: Settings,
    delete_permission_key: ApiKey,
) -> None:
    """Test that DELETE permission includes WRITE and READ."""
    # Authenticate with delete key
    api_key_obj = get_current_api_key(
        settings=auth_enabled_settings,
        db=db_session,
        header_key=delete_permission_key._plaintext,  # type: ignore[attr-defined]
        bearer_creds=None,
    )

    # Should pass READ, WRITE, and DELETE checks
    for perm in [Permission.READ, Permission.WRITE, Permission.DELETE]:
        checker = require_permission(perm)
        result = checker(api_key_obj, auth_enabled_settings)
        assert result is not None

    # Should fail ADMIN check
    admin_checker = require_permission(Permission.ADMIN)
    with pytest.raises(HTTPException) as exc_info:
        admin_checker(api_key_obj, auth_enabled_settings)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
