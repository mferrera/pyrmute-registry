"""Tests for API key service layer."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from pyrmute_registry.server.auth import hash_api_key
from pyrmute_registry.server.models.api_key import ApiKey, Permission
from pyrmute_registry.server.schemas.api_key import (
    ApiKeyCreate,
    ApiKeyRevokeRequest,
    ApiKeyRotateRequest,
)
from pyrmute_registry.server.services.api_key import ApiKeyService

# ruff: noqa: PLR2004

# =============================================================================
# Create API Key Tests
# =============================================================================


def test_create_api_key_success(db_session: Session) -> None:
    """Test creating an API key successfully."""
    service = ApiKeyService(db_session)

    key_data = ApiKeyCreate(
        name="test-key",
        permission=Permission.WRITE,
        description="Test key",
    )

    result = service.create_api_key(key_data, created_by="test-user")

    assert result.name == "test-key"
    assert result.permission == Permission.WRITE.value
    assert result.description == "Test key"
    assert result.api_key  # Plaintext key returned
    assert len(result.api_key) > 40  # Check it's a real token
    assert result.is_active is True
    assert result.revoked is False

    db_key = db_session.query(ApiKey).filter(ApiKey.name == "test-key").first()
    assert db_key is not None
    assert db_key.created_by == "test-user"


def test_create_api_key_with_expiration(db_session: Session) -> None:
    """Test creating an API key with expiration."""
    service = ApiKeyService(db_session)

    key_data = ApiKeyCreate(
        name="expiring-key",
        permission=Permission.READ,
        expires_in_days=90,
    )

    result = service.create_api_key(key_data)

    assert result.expires_at is not None

    db_key = db_session.query(ApiKey).filter(ApiKey.name == "expiring-key").first()
    assert db_key is not None
    assert db_key.expires_at is not None

    expected_expiry = datetime.now(UTC) + timedelta(days=90)
    actual_expiry = db_key.expires_at
    if actual_expiry.tzinfo is None:
        actual_expiry = actual_expiry.replace(tzinfo=UTC)
    assert abs((actual_expiry - expected_expiry).total_seconds()) < 60


def test_create_api_key_all_permissions(db_session: Session) -> None:
    """Test creating API keys with all permission levels."""
    service = ApiKeyService(db_session)

    for perm in [
        Permission.READ,
        Permission.WRITE,
        Permission.DELETE,
        Permission.ADMIN,
    ]:
        key_data = ApiKeyCreate(
            name=f"{perm.value}-key",
            permission=perm,
        )

        result = service.create_api_key(key_data)
        assert result.permission == perm.value


def test_create_api_key_duplicate_name(db_session: Session) -> None:
    """Test that duplicate names raise an error."""
    service = ApiKeyService(db_session)

    key_data = ApiKeyCreate(name="duplicate", permission=Permission.READ)
    service.create_api_key(key_data)

    # Try to create duplicate
    with pytest.raises(HTTPException) as exc:
        service.create_api_key(key_data)

    assert exc.value.status_code == 409
    assert "already exists" in exc.value.detail


def test_create_api_key_without_description(db_session: Session) -> None:
    """Test creating an API key without description."""
    service = ApiKeyService(db_session)

    key_data = ApiKeyCreate(
        name="no-description",
        permission=Permission.READ,
    )

    result = service.create_api_key(key_data)
    assert result.description is None


def test_create_api_key_without_expiration(db_session: Session) -> None:
    """Test creating an API key without expiration."""
    service = ApiKeyService(db_session)

    key_data = ApiKeyCreate(
        name="no-expiration",
        permission=Permission.READ,
    )

    result = service.create_api_key(key_data)
    assert result.expires_at is None


# =============================================================================
# List API Keys Tests
# =============================================================================


def test_list_api_keys_success(db_session: Session) -> None:
    """Test listing API keys."""
    service = ApiKeyService(db_session)

    for i in range(3):
        key_data = ApiKeyCreate(
            name=f"list-test-{i}",
            permission=Permission.READ,
        )
        service.create_api_key(key_data)

    result = service.list_api_keys()

    assert result.total >= 3
    assert len(result.keys) >= 3


def test_list_api_keys_excludes_revoked_by_default(db_session: Session) -> None:
    """Test that revoked keys are excluded by default."""
    service = ApiKeyService(db_session)

    key_data = ApiKeyCreate(name="to-revoke", permission=Permission.READ)
    created = service.create_api_key(key_data)

    revoke_data = ApiKeyRevokeRequest(revoked_by="admin")
    service.revoke_api_key(created.id, revoke_data)

    result = service.list_api_keys(include_revoked=False)

    key_names = [key.name for key in result.keys]
    assert "to-revoke" not in key_names


def test_list_api_keys_includes_revoked_when_requested(db_session: Session) -> None:
    """Test including revoked keys when requested."""
    service = ApiKeyService(db_session)

    key_data = ApiKeyCreate(name="revoked-include", permission=Permission.READ)
    created = service.create_api_key(key_data)

    revoke_data = ApiKeyRevokeRequest(revoked_by="admin")
    service.revoke_api_key(created.id, revoke_data)

    result = service.list_api_keys(include_revoked=True)

    key_names = [key.name for key in result.keys]
    assert "revoked-include" in key_names


def test_list_api_keys_filter_by_permission(db_session: Session) -> None:
    """Test filtering API keys by permission level."""
    service = ApiKeyService(db_session)

    service.create_api_key(ApiKeyCreate(name="read-1", permission=Permission.READ))
    service.create_api_key(ApiKeyCreate(name="write-1", permission=Permission.WRITE))
    service.create_api_key(ApiKeyCreate(name="admin-1", permission=Permission.ADMIN))

    result = service.list_api_keys(permission=Permission.ADMIN)

    for key in result.keys:
        assert key.permission == Permission.ADMIN.value


def test_list_api_keys_empty(db_session: Session) -> None:
    """Test listing when no active keys exist."""
    service = ApiKeyService(db_session)

    result = service.list_api_keys()

    assert result.total == 0
    assert len(result.keys) == 0


# =============================================================================
# Get API Key Statistics Tests
# =============================================================================


def test_get_api_key_stats(db_session: Session) -> None:
    """Test getting API key statistics."""
    service = ApiKeyService(db_session)

    service.create_api_key(ApiKeyCreate(name="active", permission=Permission.READ))
    revoked_key = service.create_api_key(
        ApiKeyCreate(name="revoked", permission=Permission.WRITE)
    )
    service.revoke_api_key(revoked_key.id, ApiKeyRevokeRequest(revoked_by="admin"))

    stats = service.get_api_key_stats()

    assert stats.total_keys >= 2
    assert stats.active_keys >= 1
    assert stats.revoked_keys >= 1
    assert Permission.READ.value in stats.by_permission
    assert Permission.WRITE.value in stats.by_permission


def test_get_api_key_stats_empty(db_session: Session) -> None:
    """Test stats when no keys exist."""
    service = ApiKeyService(db_session)

    stats = service.get_api_key_stats()

    assert stats.total_keys == 0
    assert stats.active_keys == 0
    assert stats.revoked_keys == 0
    assert stats.expired_keys == 0


def test_get_api_key_stats_counts_expired(db_session: Session) -> None:
    """Test that expired keys are counted correctly."""
    service = ApiKeyService(db_session)

    # Create an expired key
    expired = ApiKey(
        name="expired",
        key_hash=hash_api_key("test"),
        permission=Permission.READ.value,
        created_by="test",
        expires_at=datetime.now(UTC) - timedelta(days=1),  # Expired yesterday
    )
    db_session.add(expired)
    db_session.commit()

    stats = service.get_api_key_stats()

    assert stats.expired_keys >= 1


# =============================================================================
# Get Single API Key Tests
# =============================================================================


def test_get_api_key_by_id(db_session: Session) -> None:
    """Test getting a specific API key by ID."""
    service = ApiKeyService(db_session)

    created = service.create_api_key(
        ApiKeyCreate(name="get-test", permission=Permission.WRITE)
    )

    result = service.get_api_key(created.id)

    assert result.id == created.id
    assert result.name == "get-test"
    assert result.permission == Permission.WRITE.value


def test_get_api_key_not_found(db_session: Session) -> None:
    """Test getting a non-existent API key."""
    service = ApiKeyService(db_session)

    with pytest.raises(HTTPException) as exc:
        service.get_api_key(99999)

    assert exc.value.status_code == 404


# =============================================================================
# Revoke API Key Tests
# =============================================================================


def test_revoke_api_key_success(db_session: Session) -> None:
    """Test revoking an API key."""
    service = ApiKeyService(db_session)

    created = service.create_api_key(
        ApiKeyCreate(name="revoke-test", permission=Permission.READ)
    )

    revoke_data = ApiKeyRevokeRequest(
        revoked_by="admin",
        reason="No longer needed",
    )

    result = service.revoke_api_key(created.id, revoke_data)

    assert result.revoked is True
    assert result.revoked_by == "admin"
    assert result.revoked_at is not None
    assert "No longer needed" in (result.description or "")

    db_key = db_session.query(ApiKey).filter(ApiKey.id == created.id).first()
    assert db_key is not None
    assert db_key.revoked is True
    assert db_key.is_active is False


def test_revoke_api_key_without_reason(db_session: Session) -> None:
    """Test revoking an API key without providing a reason."""
    service = ApiKeyService(db_session)

    created = service.create_api_key(
        ApiKeyCreate(name="revoke-no-reason", permission=Permission.READ)
    )

    revoke_data = ApiKeyRevokeRequest(revoked_by="admin")
    result = service.revoke_api_key(created.id, revoke_data)

    assert result.revoked is True


def test_revoke_api_key_already_revoked(db_session: Session) -> None:
    """Test revoking an already revoked key fails."""
    service = ApiKeyService(db_session)

    created = service.create_api_key(
        ApiKeyCreate(name="already-revoked", permission=Permission.READ)
    )

    service.revoke_api_key(created.id, ApiKeyRevokeRequest(revoked_by="admin"))

    with pytest.raises(HTTPException) as exc:
        service.revoke_api_key(created.id, ApiKeyRevokeRequest(revoked_by="admin"))

    assert exc.value.status_code == 400
    assert "already revoked" in exc.value.detail


def test_revoke_api_key_not_found(db_session: Session) -> None:
    """Test revoking a non-existent API key."""
    service = ApiKeyService(db_session)

    with pytest.raises(HTTPException) as exc:
        service.revoke_api_key(99999, ApiKeyRevokeRequest(revoked_by="admin"))

    assert exc.value.status_code == 404


# =============================================================================
# Delete API Key Tests
# =============================================================================


def test_delete_api_key_success(db_session: Session) -> None:
    """Test deleting an API key."""
    service = ApiKeyService(db_session)

    created = service.create_api_key(
        ApiKeyCreate(name="delete-test", permission=Permission.READ)
    )

    result = service.delete_api_key(created.id)

    assert result is True

    deleted = db_session.query(ApiKey).filter(ApiKey.id == created.id).first()
    assert deleted is None


def test_delete_api_key_not_found(db_session: Session) -> None:
    """Test deleting a non-existent API key."""
    service = ApiKeyService(db_session)

    with pytest.raises(HTTPException) as exc:
        service.delete_api_key(99999)

    assert exc.value.status_code == 404


# =============================================================================
# Rotate API Key Tests
# =============================================================================


def test_rotate_api_key_with_grace_period(db_session: Session) -> None:
    """Test key rotation with grace period."""
    service = ApiKeyService(db_session)

    original = service.create_api_key(
        ApiKeyCreate(name="rotate-test", permission=Permission.WRITE)
    )

    # Rotate with 24 hour grace period
    rotation_data = ApiKeyRotateRequest(
        grace_period_hours=24, reason="Testing rotation"
    )
    result = service.rotate_api_key(original.id, rotation_data, rotated_by="admin")

    # Verify old key still active but scheduled for rotation
    assert result.old_key.id == original.id
    assert result.old_key.is_active is True
    assert result.old_key.revoked is False
    assert result.old_key.rotation_scheduled_at is not None
    assert result.old_key.rotated_to_id == result.new_key.id

    assert result.new_key.is_active is True
    assert result.new_key.rotated_from_id == original.id
    assert result.new_key.permission == original.permission
    assert result.new_key.api_key  # Plaintext key included
    assert len(result.new_key.api_key) > 40

    assert "will remain active" in result.message
    assert result.grace_period_ends_at is not None

    expected_end = datetime.now(UTC) + timedelta(hours=24)
    assert abs((result.grace_period_ends_at - expected_end).total_seconds()) < 60

    db_old = db_session.query(ApiKey).filter(ApiKey.id == original.id).first()
    assert db_old is not None
    assert db_old.rotation_scheduled_at is not None
    assert db_old.rotated_to_id is not None


def test_rotate_api_key_immediate(db_session: Session) -> None:
    """Test immediate key rotation without grace period."""
    service = ApiKeyService(db_session)

    original = service.create_api_key(
        ApiKeyCreate(name="immediate-rotate", permission=Permission.DELETE)
    )

    rotation_data = ApiKeyRotateRequest(
        grace_period_hours=0, reason="Security incident"
    )
    result = service.rotate_api_key(original.id, rotation_data, rotated_by="security")

    assert result.old_key.revoked is True
    assert result.old_key.revoked_at is not None
    assert result.old_key.revoked_by == "security"
    assert result.old_key.rotation_scheduled_at is None
    assert result.old_key.is_active is False

    assert result.new_key.is_active is True
    assert result.new_key.api_key

    assert result.grace_period_ends_at is None
    assert "immediately revoked" in result.message

    db_old = db_session.query(ApiKey).filter(ApiKey.id == original.id).first()
    assert db_old is not None
    assert db_old.revoked is True
    assert "Security incident" in (db_old.description or "")


def test_rotate_api_key_preserves_permissions(db_session: Session) -> None:
    """Test that rotation preserves the original key's permissions."""
    service = ApiKeyService(db_session)

    for perm in [
        Permission.READ,
        Permission.WRITE,
        Permission.DELETE,
        Permission.ADMIN,
    ]:
        original = service.create_api_key(
            ApiKeyCreate(name=f"rotate-{perm.value}", permission=perm)
        )

        rotation_data = ApiKeyRotateRequest(grace_period_hours=1)
        result = service.rotate_api_key(original.id, rotation_data)

        assert result.new_key.permission == perm.value


def test_rotate_api_key_preserves_expiration(db_session: Session) -> None:
    """Test that rotation preserves the original key's expiration."""
    service = ApiKeyService(db_session)

    original = service.create_api_key(
        ApiKeyCreate(
            name="rotate-with-expiry", permission=Permission.READ, expires_in_days=90
        )
    )

    rotation_data = ApiKeyRotateRequest(grace_period_hours=24)
    result = service.rotate_api_key(original.id, rotation_data)

    assert result.new_key.expires_at is not None
    assert result.new_key.expires_at == result.old_key.expires_at


def test_rotate_revoked_key_fails(db_session: Session) -> None:
    """Test that rotating a revoked key raises an error."""
    service = ApiKeyService(db_session)

    key = service.create_api_key(ApiKeyCreate(name="revoked-key"))
    service.revoke_api_key(key.id, ApiKeyRevokeRequest(revoked_by="admin"))

    with pytest.raises(HTTPException) as exc:
        service.rotate_api_key(
            key.id, ApiKeyRotateRequest(grace_period_hours=24), rotated_by="admin"
        )

    assert exc.value.status_code == 400
    assert "revoked" in exc.value.detail.lower()


def test_rotate_api_key_not_found(db_session: Session) -> None:
    """Test rotating a non-existent key."""
    service = ApiKeyService(db_session)

    with pytest.raises(HTTPException) as exc:
        service.rotate_api_key(
            99999,
            ApiKeyRotateRequest(grace_period_hours=24),
        )

    assert exc.value.status_code == 404


def test_rotate_api_key_new_name_format(db_session: Session) -> None:
    """Test that rotated key has proper name format."""
    service = ApiKeyService(db_session)

    original = service.create_api_key(
        ApiKeyCreate(name="my-service", permission=Permission.WRITE)
    )

    rotation_data = ApiKeyRotateRequest(grace_period_hours=24)
    result = service.rotate_api_key(original.id, rotation_data)

    assert "my-service-rotated-" in result.new_key.name
    assert result.new_key.name != original.name


def test_rotate_api_key_links_old_to_new(db_session: Session) -> None:
    """Test that rotation creates proper linkage between old and new keys."""
    service = ApiKeyService(db_session)

    original = service.create_api_key(
        ApiKeyCreate(name="link-test", permission=Permission.WRITE)
    )

    rotation_data = ApiKeyRotateRequest(grace_period_hours=24)
    result = service.rotate_api_key(original.id, rotation_data)

    assert result.old_key.rotated_to_id == result.new_key.id
    assert result.new_key.rotated_from_id == result.old_key.id

    db_old = db_session.query(ApiKey).filter(ApiKey.id == original.id).first()
    db_new = db_session.query(ApiKey).filter(ApiKey.id == result.new_key.id).first()

    assert db_old is not None
    assert db_new is not None
    assert db_old.rotated_to_id == db_new.id
    assert db_new.rotated_from_id == db_old.id


def test_rotate_api_key_max_grace_period(db_session: Session) -> None:
    """Test rotation with maximum grace period (1 week)."""
    service = ApiKeyService(db_session)

    original = service.create_api_key(
        ApiKeyCreate(name="max-grace", permission=Permission.READ)
    )

    rotation_data = ApiKeyRotateRequest(grace_period_hours=168)  # 7 days
    result = service.rotate_api_key(original.id, rotation_data)

    assert result.grace_period_ends_at is not None
    expected_end = datetime.now(UTC) + timedelta(hours=168)
    assert abs((result.grace_period_ends_at - expected_end).total_seconds()) < 60


def test_rotate_api_key_reason_appended_to_description(db_session: Session) -> None:
    """Test that rotation reason is appended to key descriptions."""
    service = ApiKeyService(db_session)

    original = service.create_api_key(
        ApiKeyCreate(
            name="reason-test",
            permission=Permission.READ,
            description="Original description",
        )
    )

    rotation_data = ApiKeyRotateRequest(
        grace_period_hours=24, reason="Quarterly security rotation"
    )
    result = service.rotate_api_key(original.id, rotation_data)

    assert "Quarterly security rotation" in (result.old_key.description or "")
    assert "Original description" in (result.old_key.description or "")

    assert f"Rotated from key ID {original.id}" in (result.new_key.description or "")
    assert "Quarterly security rotation" in (result.new_key.description or "")


def test_rotate_api_key_is_rotation_due_property(db_session: Session) -> None:
    """Test that is_rotation_due property works correctly."""
    service = ApiKeyService(db_session)

    original = service.create_api_key(
        ApiKeyCreate(name="rotation-due-test", permission=Permission.READ)
    )

    rotation_data = ApiKeyRotateRequest(
        grace_period_hours=0
    )  # Will be scheduled but in past
    result = service.rotate_api_key(original.id, rotation_data)

    assert result.old_key.revoked is True
    assert result.old_key.is_rotation_due is False  # Because it's already revoked


# =============================================================================
# Integration Tests
# =============================================================================


def test_full_key_lifecycle(db_session: Session) -> None:
    """Test complete key lifecycle: create → use → rotate → revoke → delete."""
    service = ApiKeyService(db_session)

    created = service.create_api_key(
        ApiKeyCreate(name="lifecycle-test", permission=Permission.WRITE)
    )
    assert created.is_active is True

    rotation = service.rotate_api_key(
        created.id, ApiKeyRotateRequest(grace_period_hours=1)
    )
    assert rotation.old_key.is_active is True  # Still active during grace period
    assert rotation.new_key.is_active is True

    revoked = service.revoke_api_key(
        created.id, ApiKeyRevokeRequest(revoked_by="admin")
    )
    assert revoked.is_active is False

    deleted = service.delete_api_key(created.id)
    assert deleted is True

    # New key should still exist
    new_key = service.get_api_key(rotation.new_key.id)
    assert new_key.is_active is True


def test_multiple_rotations_chain(db_session: Session) -> None:
    """Test multiple sequential rotations create proper chain."""
    service = ApiKeyService(db_session)

    v1 = service.create_api_key(
        ApiKeyCreate(name="chain-v1", permission=Permission.WRITE)
    )

    rotation1 = service.rotate_api_key(v1.id, ApiKeyRotateRequest(grace_period_hours=0))
    v2_id = rotation1.new_key.id

    rotation2 = service.rotate_api_key(v2_id, ApiKeyRotateRequest(grace_period_hours=0))

    assert rotation1.old_key.rotated_to_id == v2_id
    assert rotation2.old_key.rotated_from_id == v1.id
    assert rotation2.new_key.rotated_from_id == v2_id
