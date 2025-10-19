"""Tests for API key management endpoints."""

import secrets

from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from pyrmute_registry.server.auth import hash_api_key
from pyrmute_registry.server.models.api_key import ApiKey, Permission

# ruff: noqa: PLR2004


# =============================================================================
# Create API Key Tests
# =============================================================================


def test_create_api_key_success(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    db_session: Session,
) -> None:
    """Test creating an API key via POST /api-keys."""
    payload = {
        "name": "new-test-key",
        "permission": "write",
        "description": "A test API key",
    }

    response = auth_enabled_client.post(
        "/api-keys", json=payload, headers=admin_key_header
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["name"] == "new-test-key"
    assert data["permission"] == "write"
    assert data["description"] == "A test API key"
    assert "api_key" in data  # Plaintext key only shown once
    assert len(data["api_key"]) > 40  # Should be a long random key
    assert data["is_active"] is True
    assert data["revoked"] is False

    # Verify key was saved
    key = db_session.query(ApiKey).filter(ApiKey.name == "new-test-key").first()
    assert key is not None
    assert key.permission == "write"


def test_create_api_key_with_expiration(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
) -> None:
    """Test creating an API key with expiration via HTTP."""
    payload = {
        "name": "expiring-key",
        "permission": "read",
        "expires_in_days": 90,
    }

    response = auth_enabled_client.post(
        "/api-keys", json=payload, headers=admin_key_header
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["expires_at"] is not None


def test_create_api_key_all_permissions(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
) -> None:
    """Test creating API keys with all permission levels via HTTP."""
    permissions = ["read", "write", "delete", "admin"]

    for perm in permissions:
        payload = {
            "name": f"{perm}-key-route",
            "permission": perm,
        }

        response = auth_enabled_client.post(
            "/api-keys", json=payload, headers=admin_key_header
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["permission"] == perm


def test_create_api_key_duplicate_name(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    sample_api_key: ApiKey,
) -> None:
    """Test creating an API key with duplicate name returns 409."""
    payload = {
        "name": sample_api_key.name,
        "permission": "read",
    }

    response = auth_enabled_client.post(
        "/api-keys", json=payload, headers=admin_key_header
    )

    assert response.status_code == status.HTTP_409_CONFLICT
    assert "already exists" in response.json()["detail"]


def test_create_api_key_requires_admin(
    auth_enabled_client: TestClient,
    write_key_header: dict[str, str],
) -> None:
    """Test creating an API key requires admin permission."""
    payload = {
        "name": "unauthorized-key",
        "permission": "read",
    }

    response = auth_enabled_client.post(
        "/api-keys", json=payload, headers=write_key_header
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_create_api_key_without_auth(
    auth_enabled_client: TestClient,
) -> None:
    """Test creating an API key without authentication returns 401."""
    payload = {
        "name": "unauthenticated-key",
        "permission": "read",
    }

    response = auth_enabled_client.post("/api-keys", json=payload)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_create_api_key_when_auth_disabled(
    app_client: TestClient,
) -> None:
    """Test creating an API key fails when auth is disabled."""
    payload = {
        "name": "test-key",
        "permission": "read",
    }

    response = app_client.post("/api-keys", json=payload)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Authentication is disabled" in response.json()["detail"]


def test_create_api_key_invalid_permission(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
) -> None:
    """Test creating an API key with invalid permission returns 422."""
    payload = {
        "name": "invalid-key",
        "permission": "invalid",
    }

    response = auth_enabled_client.post(
        "/api-keys", json=payload, headers=admin_key_header
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_create_api_key_name_too_short(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
) -> None:
    """Test API key name validation (minimum length)."""
    payload = {
        "name": "ab",  # Less than 3 characters
        "permission": "read",
    }

    response = auth_enabled_client.post(
        "/api-keys", json=payload, headers=admin_key_header
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_create_api_key_invalid_expiration(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
) -> None:
    """Test creating an API key with invalid expiration returns 422."""
    payload = {
        "name": "invalid-expiration-key",
        "permission": "read",
        "expires_in_days": 0,  # Invalid - must be > 0
    }

    response = auth_enabled_client.post(
        "/api-keys", json=payload, headers=admin_key_header
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# =============================================================================
# List API Keys Tests
# =============================================================================


def test_list_api_keys_success(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    sample_api_key: ApiKey,
    admin_api_key: ApiKey,
    read_only_key: ApiKey,
) -> None:
    """Test listing API keys via GET /api-keys."""
    response = auth_enabled_client.get("/api-keys", headers=admin_key_header)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "keys" in data
    assert "total" in data
    assert data["total"] >= 3  # At least the 3 fixture keys

    key_names = [key["name"] for key in data["keys"]]
    assert sample_api_key.name in key_names
    assert admin_api_key.name in key_names
    assert read_only_key.name in key_names


def test_list_api_keys_excludes_revoked_by_default(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    revoked_key: ApiKey,
) -> None:
    """Test that revoked keys are excluded by default."""
    response = auth_enabled_client.get("/api-keys", headers=admin_key_header)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    key_names = [key["name"] for key in data["keys"]]
    assert revoked_key.name not in key_names


def test_list_api_keys_includes_revoked_when_requested(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    revoked_key: ApiKey,
) -> None:
    """Test including revoked keys when requested via query param."""
    response = auth_enabled_client.get(
        "/api-keys?include_revoked=true", headers=admin_key_header
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    key_names = [key["name"] for key in data["keys"]]
    assert revoked_key.name in key_names


def test_list_api_keys_filter_by_permission(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    admin_api_key: ApiKey,
) -> None:
    """Test filtering API keys by permission level via query param."""
    response = auth_enabled_client.get(
        "/api-keys?permission=admin", headers=admin_key_header
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    # Should only include admin keys
    for key in data["keys"]:
        assert key["permission"] == "admin"


def test_list_api_keys_requires_admin(
    auth_enabled_client: TestClient,
    write_key_header: dict[str, str],
) -> None:
    """Test listing API keys requires admin permission."""
    response = auth_enabled_client.get("/api-keys", headers=write_key_header)

    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_list_api_keys_without_auth(
    auth_enabled_client: TestClient,
) -> None:
    """Test listing API keys without authentication returns 401."""
    response = auth_enabled_client.get("/api-keys")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# =============================================================================
# Get API Key Statistics Tests
# =============================================================================


def test_get_api_key_stats(  # noqa: PLR0913
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    sample_api_key: ApiKey,
    admin_api_key: ApiKey,
    read_only_key: ApiKey,
    revoked_key: ApiKey,
) -> None:
    """Test getting API key statistics via GET /api-keys/stats."""
    response = auth_enabled_client.get("/api-keys/stats", headers=admin_key_header)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert "total_keys" in data
    assert "active_keys" in data
    assert "revoked_keys" in data
    assert "expired_keys" in data
    assert "by_permission" in data

    assert data["total_keys"] >= 4
    assert data["revoked_keys"] >= 1  # At least the revoked fixture
    assert "read" in data["by_permission"]
    assert "write" in data["by_permission"]
    assert "delete" in data["by_permission"]
    assert "admin" in data["by_permission"]


def test_get_api_key_stats_requires_admin(
    auth_enabled_client: TestClient,
    read_key_header: dict[str, str],
) -> None:
    """Test getting stats requires admin permission."""
    response = auth_enabled_client.get("/api-keys/stats", headers=read_key_header)

    assert response.status_code == status.HTTP_403_FORBIDDEN


# =============================================================================
# Get Single API Key Tests
# =============================================================================


def test_get_api_key_by_id(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    sample_api_key: ApiKey,
) -> None:
    """Test getting a specific API key by ID via GET /api-keys/{id}."""
    response = auth_enabled_client.get(
        f"/api-keys/{sample_api_key.id}", headers=admin_key_header
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["id"] == sample_api_key.id
    assert data["name"] == sample_api_key.name
    assert data["permission"] == sample_api_key.permission
    assert "api_key" not in data  # Plaintext should never be returned


def test_get_api_key_not_found(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
) -> None:
    """Test getting a non-existent API key returns 404."""
    response = auth_enabled_client.get("/api-keys/99999", headers=admin_key_header)

    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_get_api_key_requires_admin(
    auth_enabled_client: TestClient,
    write_key_header: dict[str, str],
    sample_api_key: ApiKey,
) -> None:
    """Test getting an API key requires admin permission."""
    response = auth_enabled_client.get(
        f"/api-keys/{sample_api_key.id}", headers=write_key_header
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


# =============================================================================
# Revoke API Key Tests
# =============================================================================


def test_revoke_api_key_success(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    db_session: Session,
) -> None:
    """Test revoking an API key via POST /api-keys/{id}/revoke."""
    key = ApiKey(
        name="key-to-revoke",
        key_hash=hash_api_key("test"),
        permission=Permission.READ.value,
        created_by="test",
    )
    db_session.add(key)
    db_session.commit()
    db_session.refresh(key)

    revoke_payload = {
        "revoked_by": "admin",
        "reason": "No longer needed",
    }

    response = auth_enabled_client.post(
        f"/api-keys/{key.id}/revoke",
        json=revoke_payload,
        headers=admin_key_header,
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["revoked"] is True
    assert data["revoked_by"] == "admin"
    assert data["revoked_at"] is not None

    db_session.refresh(key)
    assert key.revoked is True
    assert key.revoked_by == "admin"
    assert key.description is not None
    assert "No longer needed" in key.description


def test_revoke_api_key_already_revoked(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    revoked_key: ApiKey,
) -> None:
    """Test revoking an already revoked key returns 400."""
    revoke_payload = {
        "revoked_by": "admin",
    }

    response = auth_enabled_client.post(
        f"/api-keys/{revoked_key.id}/revoke",
        json=revoke_payload,
        headers=admin_key_header,
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "already revoked" in response.json()["detail"]


def test_revoke_api_key_not_found(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
) -> None:
    """Test revoking a non-existent API key returns 404."""
    revoke_payload = {
        "revoked_by": "admin",
    }

    response = auth_enabled_client.post(
        "/api-keys/99999/revoke",
        json=revoke_payload,
        headers=admin_key_header,
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_revoke_api_key_requires_admin(
    auth_enabled_client: TestClient,
    write_key_header: dict[str, str],
    sample_api_key: ApiKey,
) -> None:
    """Test revoking an API key requires admin permission."""
    revoke_payload = {
        "revoked_by": "unauthorized-user",
    }

    response = auth_enabled_client.post(
        f"/api-keys/{sample_api_key.id}/revoke",
        json=revoke_payload,
        headers=write_key_header,
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_revoke_api_key_without_reason(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    db_session: Session,
) -> None:
    """Test revoking an API key without providing a reason."""
    key = ApiKey(
        name="key-to-revoke-no-reason",
        key_hash=hash_api_key("test"),
        permission=Permission.READ.value,
        created_by="test",
    )
    db_session.add(key)
    db_session.commit()
    db_session.refresh(key)

    revoke_payload = {
        "revoked_by": "admin",
        # No reason provided
    }

    response = auth_enabled_client.post(
        f"/api-keys/{key.id}/revoke",
        json=revoke_payload,
        headers=admin_key_header,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["revoked"] is True


# =============================================================================
# Delete API Key Tests
# =============================================================================


def test_delete_api_key_success(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    db_session: Session,
) -> None:
    """Test deleting an API key via DELETE /api-keys/{id}."""
    key = ApiKey(
        name="key-to-delete",
        key_hash=hash_api_key("test"),
        permission=Permission.READ.value,
        created_by="test",
    )
    db_session.add(key)
    db_session.commit()
    db_session.refresh(key)
    key_id = key.id

    response = auth_enabled_client.delete(
        f"/api-keys/{key_id}", headers=admin_key_header
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT

    # Verify deleted from database
    deleted_key = db_session.query(ApiKey).filter(ApiKey.id == key_id).first()
    assert deleted_key is None


def test_delete_api_key_not_found(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
) -> None:
    """Test deleting a non-existent API key returns 404."""
    response = auth_enabled_client.delete("/api-keys/99999", headers=admin_key_header)

    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_delete_api_key_requires_admin(
    auth_enabled_client: TestClient,
    write_key_header: dict[str, str],
    sample_api_key: ApiKey,
) -> None:
    """Test deleting an API key requires admin permission."""
    response = auth_enabled_client.delete(
        f"/api-keys/{sample_api_key.id}", headers=write_key_header
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


# =============================================================================
# Rotate API Key Tests
# =============================================================================


def test_rotate_api_key_with_grace_period(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    sample_api_key: ApiKey,
) -> None:
    """Test rotating an API key with grace period via POST /api-keys/{id}/rotate."""
    rotation_payload = {
        "grace_period_hours": 24,
        "reason": "Routine security rotation",
    }

    response = auth_enabled_client.post(
        f"/api-keys/{sample_api_key.id}/rotate",
        json=rotation_payload,
        headers=admin_key_header,
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert "old_key" in data
    assert "new_key" in data
    assert "grace_period_ends_at" in data
    assert "message" in data

    assert data["old_key"]["id"] == sample_api_key.id
    assert data["old_key"]["is_active"] is True
    assert data["old_key"]["revoked"] is False
    assert data["old_key"]["rotation_scheduled_at"] is not None
    assert data["old_key"]["rotated_to_id"] == data["new_key"]["id"]

    assert data["new_key"]["is_active"] is True
    assert data["new_key"]["rotated_from_id"] == sample_api_key.id
    assert "api_key" in data["new_key"]
    assert len(data["new_key"]["api_key"]) > 40

    assert data["grace_period_ends_at"] is not None
    assert "will remain active" in data["message"]


def test_rotate_api_key_immediate(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    db_session: Session,
) -> None:
    """Test immediate key rotation without grace period."""
    key = ApiKey(
        name="immediate-rotate-key",
        key_hash=hash_api_key("test"),
        permission=Permission.WRITE.value,
        created_by="test",
    )
    db_session.add(key)
    db_session.commit()
    db_session.refresh(key)

    rotation_payload = {
        "grace_period_hours": 0,
        "reason": "Security incident",
    }

    response = auth_enabled_client.post(
        f"/api-keys/{key.id}/rotate",
        json=rotation_payload,
        headers=admin_key_header,
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert data["old_key"]["revoked"] is True
    assert data["old_key"]["revoked_at"] is not None
    assert data["old_key"]["is_active"] is False
    assert data["old_key"]["rotation_scheduled_at"] is None

    assert data["new_key"]["is_active"] is True

    assert data["grace_period_ends_at"] is None
    assert "immediately revoked" in data["message"]


def test_rotate_api_key_not_found(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
) -> None:
    """Test rotating a non-existent key returns 404."""
    rotation_payload = {
        "grace_period_hours": 24,
    }

    response = auth_enabled_client.post(
        "/api-keys/99999/rotate",
        json=rotation_payload,
        headers=admin_key_header,
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_rotate_api_key_revoked_key_fails(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    revoked_key: ApiKey,
) -> None:
    """Test rotating a revoked key returns 400."""
    rotation_payload = {
        "grace_period_hours": 24,
    }

    response = auth_enabled_client.post(
        f"/api-keys/{revoked_key.id}/rotate",
        json=rotation_payload,
        headers=admin_key_header,
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "revoked" in response.json()["detail"].lower()


def test_rotate_api_key_requires_admin(
    auth_enabled_client: TestClient,
    write_key_header: dict[str, str],
    sample_api_key: ApiKey,
) -> None:
    """Test rotating an API key requires admin permission."""
    rotation_payload = {
        "grace_period_hours": 24,
    }

    response = auth_enabled_client.post(
        f"/api-keys/{sample_api_key.id}/rotate",
        json=rotation_payload,
        headers=write_key_header,
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_rotate_api_key_without_auth(
    auth_enabled_client: TestClient,
    sample_api_key: ApiKey,
) -> None:
    """Test rotating without authentication returns 401."""
    rotation_payload = {
        "grace_period_hours": 24,
    }

    response = auth_enabled_client.post(
        f"/api-keys/{sample_api_key.id}/rotate",
        json=rotation_payload,
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_rotate_api_key_validation_grace_period_too_long(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    sample_api_key: ApiKey,
) -> None:
    """Test that grace period over 168 hours (1 week) returns 422."""
    rotation_payload = {
        "grace_period_hours": 200,  # Max is 168
    }

    response = auth_enabled_client.post(
        f"/api-keys/{sample_api_key.id}/rotate",
        json=rotation_payload,
        headers=admin_key_header,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_rotate_api_key_validation_negative_grace_period(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    sample_api_key: ApiKey,
) -> None:
    """Test that negative grace period returns 422."""
    rotation_payload = {
        "grace_period_hours": -1,
    }

    response = auth_enabled_client.post(
        f"/api-keys/{sample_api_key.id}/rotate",
        json=rotation_payload,
        headers=admin_key_header,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_rotate_api_key_when_auth_disabled(
    app_client: TestClient,
    sample_api_key: ApiKey,
) -> None:
    """Test rotating a key fails when auth is disabled."""
    rotation_payload = {
        "grace_period_hours": 24,
    }

    response = app_client.post(
        f"/api-keys/{sample_api_key.id}/rotate",
        json=rotation_payload,
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Authentication is disabled" in response.json()["detail"]


def test_rotate_api_key_preserves_permission(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    db_session: Session,
) -> None:
    """Test that rotation preserves the original key's permission."""
    key = ApiKey(
        name="permission-test-key",
        key_hash=hash_api_key("test"),
        permission=Permission.DELETE.value,
        created_by="test",
    )
    db_session.add(key)
    db_session.commit()
    db_session.refresh(key)

    rotation_payload = {
        "grace_period_hours": 1,
    }

    response = auth_enabled_client.post(
        f"/api-keys/{key.id}/rotate",
        json=rotation_payload,
        headers=admin_key_header,
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    # New key should have same permission
    assert data["new_key"]["permission"] == Permission.DELETE.value
    assert data["old_key"]["permission"] == Permission.DELETE.value


# =============================================================================
# Integration Tests
# =============================================================================


def test_create_and_use_api_key(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
) -> None:
    """Test creating an API key and using it for authentication."""
    payload = {
        "name": "integration-test-key",
        "permission": "admin",
    }

    create_response = auth_enabled_client.post(
        "/api-keys", json=payload, headers=admin_key_header
    )

    assert create_response.status_code == status.HTTP_201_CREATED
    new_key = create_response.json()["api_key"]

    # Use the new key to list keys
    new_key_header = {"X-API-Key": new_key}
    list_response = auth_enabled_client.get("/api-keys", headers=new_key_header)

    assert list_response.status_code == status.HTTP_200_OK


def test_create_revoke_and_verify_unusable(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
) -> None:
    """Test that a revoked key cannot be used."""
    payload = {
        "name": "key-to-revoke-test",
        "permission": "admin",
    }

    create_response = auth_enabled_client.post(
        "/api-keys", json=payload, headers=admin_key_header
    )

    assert create_response.status_code == status.HTTP_201_CREATED
    data = create_response.json()
    new_key = data["api_key"]
    key_id = data["id"]

    revoke_payload = {"revoked_by": "admin"}
    revoke_response = auth_enabled_client.post(
        f"/api-keys/{key_id}/revoke",
        json=revoke_payload,
        headers=admin_key_header,
    )

    assert revoke_response.status_code == status.HTTP_200_OK

    # Try to use the revoked key
    revoked_key_header = {"X-API-Key": new_key}
    list_response = auth_enabled_client.get("/api-keys", headers=revoked_key_header)

    assert list_response.status_code == status.HTTP_401_UNAUTHORIZED


def test_rotate_and_use_new_key(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    db_session: Session,
) -> None:
    """Test rotating a key and using the new key for authentication."""
    key = ApiKey(
        name="rotate-use-test",
        key_hash=hash_api_key("test"),
        permission=Permission.ADMIN.value,
        created_by="test",
    )
    db_session.add(key)
    db_session.commit()
    db_session.refresh(key)

    rotation_payload = {
        "grace_period_hours": 1,
        "reason": "Testing rotation",
    }

    rotate_response = auth_enabled_client.post(
        f"/api-keys/{key.id}/rotate",
        json=rotation_payload,
        headers=admin_key_header,
    )

    assert rotate_response.status_code == status.HTTP_200_OK
    rotation_data = rotate_response.json()
    new_key = rotation_data["new_key"]["api_key"]

    # Use the new key to make an authenticated request
    new_key_header = {"X-API-Key": new_key}
    list_response = auth_enabled_client.get("/api-keys", headers=new_key_header)

    assert list_response.status_code == status.HTTP_200_OK


def test_rotate_old_key_still_works_during_grace_period(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    db_session: Session,
) -> None:
    """Test that old key still works during grace period."""
    plaintext_key = secrets.token_urlsafe(32)
    key = ApiKey(
        name="grace-period-test",
        key_hash=hash_api_key(plaintext_key),
        permission=Permission.ADMIN.value,
        created_by="test",
    )
    db_session.add(key)
    db_session.commit()
    db_session.refresh(key)

    rotation_payload = {
        "grace_period_hours": 24,
    }

    rotate_response = auth_enabled_client.post(
        f"/api-keys/{key.id}/rotate",
        json=rotation_payload,
        headers=admin_key_header,
    )

    assert rotate_response.status_code == status.HTTP_200_OK

    old_key_header = {"X-API-Key": plaintext_key}
    list_response = auth_enabled_client.get("/api-keys", headers=old_key_header)

    assert list_response.status_code == status.HTTP_200_OK


def test_rotate_immediate_old_key_stops_working(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    db_session: Session,
) -> None:
    """Test that old key stops working immediately with 0 hour grace period."""
    plaintext_key = secrets.token_urlsafe(32)
    key = ApiKey(
        name="immediate-stop-test",
        key_hash=hash_api_key(plaintext_key),
        permission=Permission.ADMIN.value,
        created_by="test",
    )
    db_session.add(key)
    db_session.commit()
    db_session.refresh(key)

    rotation_payload = {
        "grace_period_hours": 0,
    }

    rotate_response = auth_enabled_client.post(
        f"/api-keys/{key.id}/rotate",
        json=rotation_payload,
        headers=admin_key_header,
    )

    assert rotate_response.status_code == status.HTTP_200_OK

    # Old key should NOT work anymore
    old_key_header = {"X-API-Key": plaintext_key}
    list_response = auth_enabled_client.get("/api-keys", headers=old_key_header)

    assert list_response.status_code == status.HTTP_401_UNAUTHORIZED


def test_permission_hierarchy(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
) -> None:
    """Test that permission hierarchy is enforced."""
    for perm, expected_status in [
        ("read", status.HTTP_403_FORBIDDEN),
        ("write", status.HTTP_403_FORBIDDEN),
        ("delete", status.HTTP_403_FORBIDDEN),
        ("admin", status.HTTP_200_OK),
    ]:
        payload = {"name": f"{perm}-hierarchy-test", "permission": perm}
        create_response = auth_enabled_client.post(
            "/api-keys", json=payload, headers=admin_key_header
        )
        assert create_response.status_code == status.HTTP_201_CREATED

        new_key = create_response.json()["api_key"]
        test_header = {"X-API-Key": new_key}

        # Try to list keys (requires admin)
        list_response = auth_enabled_client.get("/api-keys", headers=test_header)
        assert list_response.status_code == expected_status


def test_expired_key_cannot_authenticate(
    auth_enabled_client: TestClient,
    expired_key: ApiKey,
) -> None:
    """Test that an expired key cannot be used for authentication."""
    expired_header = {"X-API-Key": expired_key._plaintext}  # type: ignore[attr-defined]

    response = auth_enabled_client.get("/api-keys", headers=expired_header)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_full_rotation_lifecycle(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    db_session: Session,
) -> None:
    """Test complete rotation lifecycle: create → rotate → revoke old → delete old."""
    create_payload = {
        "name": "lifecycle-test",
        "permission": "write",
    }

    create_response = auth_enabled_client.post(
        "/api-keys", json=create_payload, headers=admin_key_header
    )
    assert create_response.status_code == status.HTTP_201_CREATED
    original_id = create_response.json()["id"]
    original_key = create_response.json()["api_key"]

    rotate_payload = {
        "grace_period_hours": 1,
        "reason": "Testing full lifecycle",
    }

    rotate_response = auth_enabled_client.post(
        f"/api-keys/{original_id}/rotate",
        json=rotate_payload,
        headers=admin_key_header,
    )
    assert rotate_response.status_code == status.HTTP_200_OK
    new_id = rotate_response.json()["new_key"]["id"]
    new_key = rotate_response.json()["new_key"]["api_key"]

    old_header = {"X-API-Key": original_key}
    new_header = {"X-API-Key": new_key}

    old_response = auth_enabled_client.get("/api-keys/stats", headers=old_header)
    new_response = auth_enabled_client.get("/api-keys/stats", headers=new_header)

    assert old_response.status_code == status.HTTP_403_FORBIDDEN  # write permission
    assert new_response.status_code == status.HTTP_403_FORBIDDEN  # write permission

    revoke_payload = {"revoked_by": "admin"}
    revoke_response = auth_enabled_client.post(
        f"/api-keys/{original_id}/revoke",
        json=revoke_payload,
        headers=admin_key_header,
    )
    assert revoke_response.status_code == status.HTTP_200_OK

    old_after_revoke = auth_enabled_client.get("/api-keys/stats", headers=old_header)
    assert old_after_revoke.status_code == status.HTTP_401_UNAUTHORIZED

    new_after_revoke = auth_enabled_client.get("/api-keys/stats", headers=new_header)
    assert new_after_revoke.status_code == status.HTTP_403_FORBIDDEN  # write permission

    delete_response = auth_enabled_client.delete(
        f"/api-keys/{original_id}", headers=admin_key_header
    )
    assert delete_response.status_code == status.HTTP_204_NO_CONTENT

    get_old = auth_enabled_client.get(
        f"/api-keys/{original_id}", headers=admin_key_header
    )
    assert get_old.status_code == status.HTTP_404_NOT_FOUND

    get_new = auth_enabled_client.get(f"/api-keys/{new_id}", headers=admin_key_header)
    assert get_new.status_code == status.HTTP_200_OK


def test_multiple_sequential_rotations(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
) -> None:
    """Test multiple rotations in sequence create proper chain."""
    create_payload = {
        "name": "chain-v1",
        "permission": "admin",
    }

    v1_response = auth_enabled_client.post(
        "/api-keys", json=create_payload, headers=admin_key_header
    )
    assert v1_response.status_code == status.HTTP_201_CREATED
    v1_id = v1_response.json()["id"]

    rotate1_response = auth_enabled_client.post(
        f"/api-keys/{v1_id}/rotate",
        json={"grace_period_hours": 0},
        headers=admin_key_header,
    )
    assert rotate1_response.status_code == status.HTTP_200_OK
    v2_id = rotate1_response.json()["new_key"]["id"]

    assert rotate1_response.json()["old_key"]["rotated_to_id"] == v2_id
    assert rotate1_response.json()["new_key"]["rotated_from_id"] == v1_id

    rotate2_response = auth_enabled_client.post(
        f"/api-keys/{v2_id}/rotate",
        json={"grace_period_hours": 0},
        headers=admin_key_header,
    )
    assert rotate2_response.status_code == status.HTTP_200_OK
    v3_id = rotate2_response.json()["new_key"]["id"]

    assert rotate2_response.json()["old_key"]["rotated_to_id"] == v3_id
    assert rotate2_response.json()["new_key"]["rotated_from_id"] == v2_id

    v2_get = auth_enabled_client.get(f"/api-keys/{v2_id}", headers=admin_key_header)
    assert v2_get.status_code == status.HTTP_200_OK
    v2_data = v2_get.json()
    assert v2_data["rotated_from_id"] == v1_id
    assert v2_data["rotated_to_id"] == v3_id


def test_rotate_response_includes_rotation_fields(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    sample_api_key: ApiKey,
) -> None:
    """Test that rotation response includes all expected rotation fields."""
    rotation_payload = {
        "grace_period_hours": 24,
        "reason": "Test rotation fields",
    }

    response = auth_enabled_client.post(
        f"/api-keys/{sample_api_key.id}/rotate",
        json=rotation_payload,
        headers=admin_key_header,
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    old_key = data["old_key"]
    assert "rotation_scheduled_at" in old_key
    assert "rotated_to_id" in old_key
    assert "is_rotation_due" in old_key
    assert old_key["rotation_scheduled_at"] is not None
    assert old_key["rotated_to_id"] is not None

    new_key = data["new_key"]
    assert "rotated_from_id" in new_key
    assert "rotation_scheduled_at" in new_key
    assert "is_rotation_due" in new_key
    assert new_key["rotated_from_id"] is not None
    assert new_key["rotation_scheduled_at"] is None  # New key not scheduled


def test_list_includes_rotation_fields(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    db_session: Session,
) -> None:
    """Test that listing keys includes rotation fields."""
    key = ApiKey(
        name="list-rotation-fields",
        key_hash=hash_api_key("test"),
        permission=Permission.READ.value,
        created_by="test",
    )
    db_session.add(key)
    db_session.commit()
    db_session.refresh(key)

    rotation_payload = {"grace_period_hours": 24}
    auth_enabled_client.post(
        f"/api-keys/{key.id}/rotate",
        json=rotation_payload,
        headers=admin_key_header,
    )

    list_response = auth_enabled_client.get(
        "/api-keys?include_revoked=true", headers=admin_key_header
    )

    assert list_response.status_code == status.HTTP_200_OK
    keys = list_response.json()["keys"]

    rotated_key = next((k for k in keys if k["name"] == "list-rotation-fields"), None)
    assert rotated_key is not None

    assert "rotation_scheduled_at" in rotated_key
    assert "rotated_to_id" in rotated_key
    assert "rotated_from_id" in rotated_key
    assert "is_rotation_due" in rotated_key


def test_get_single_key_includes_rotation_fields(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    db_session: Session,
) -> None:
    """Test that getting a single key includes rotation fields."""
    key = ApiKey(
        name="get-rotation-fields",
        key_hash=hash_api_key("test"),
        permission=Permission.READ.value,
        created_by="test",
    )
    db_session.add(key)
    db_session.commit()
    db_session.refresh(key)

    rotation_payload = {"grace_period_hours": 24}
    rotate_response = auth_enabled_client.post(
        f"/api-keys/{key.id}/rotate",
        json=rotation_payload,
        headers=admin_key_header,
    )
    new_id = rotate_response.json()["new_key"]["id"]

    old_response = auth_enabled_client.get(
        f"/api-keys/{key.id}", headers=admin_key_header
    )

    assert old_response.status_code == status.HTTP_200_OK
    old_data = old_response.json()
    assert old_data["rotation_scheduled_at"] is not None
    assert old_data["rotated_to_id"] == new_id
    assert old_data["rotated_from_id"] is None

    new_response = auth_enabled_client.get(
        f"/api-keys/{new_id}", headers=admin_key_header
    )

    assert new_response.status_code == status.HTTP_200_OK
    new_data = new_response.json()
    assert new_data["rotated_from_id"] == key.id
    assert new_data["rotated_to_id"] is None
    assert new_data["rotation_scheduled_at"] is None


# =============================================================================
# Edge Case Tests
# =============================================================================


def test_create_api_key_with_max_expiration(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
) -> None:
    """Test creating an API key with maximum expiration (10 years)."""
    payload = {
        "name": "max-expiration-key",
        "permission": "read",
        "expires_in_days": 3650,  # 10 years
    }

    response = auth_enabled_client.post(
        "/api-keys", json=payload, headers=admin_key_header
    )

    assert response.status_code == status.HTTP_201_CREATED


def test_rotate_without_reason(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    sample_api_key: ApiKey,
) -> None:
    """Test rotating without providing a reason."""
    rotation_payload = {
        "grace_period_hours": 24,
        # No reason provided
    }

    response = auth_enabled_client.post(
        f"/api-keys/{sample_api_key.id}/rotate",
        json=rotation_payload,
        headers=admin_key_header,
    )

    assert response.status_code == status.HTTP_200_OK


def test_rotate_with_max_grace_period(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    sample_api_key: ApiKey,
) -> None:
    """Test rotation with maximum grace period (1 week = 168 hours)."""
    rotation_payload = {
        "grace_period_hours": 168,
    }

    response = auth_enabled_client.post(
        f"/api-keys/{sample_api_key.id}/rotate",
        json=rotation_payload,
        headers=admin_key_header,
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["grace_period_ends_at"] is not None
