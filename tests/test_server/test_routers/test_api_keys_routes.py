"""Tests for API key management endpoints."""

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
    """Test creating an API key successfully."""
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

    # Verify key was saved to database
    key = db_session.query(ApiKey).filter(ApiKey.name == "new-test-key").first()
    assert key is not None
    assert key.permission == "write"


def test_create_api_key_with_expiration(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    db_session: Session,
) -> None:
    """Test creating an API key with expiration."""
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

    # Verify expiration is approximately 90 days from now
    key = db_session.query(ApiKey).filter(ApiKey.name == "expiring-key").first()
    assert key is not None
    assert key.expires_at is not None


def test_create_api_key_all_permissions(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
) -> None:
    """Test creating API keys with all permission levels."""
    permissions = ["read", "write", "delete", "admin"]

    for perm in permissions:
        payload = {
            "name": f"{perm}-key",
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
    """Test creating an API key with duplicate name fails."""
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
    """Test creating an API key without authentication fails."""
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
    """Test creating an API key with invalid permission fails validation."""
    payload = {
        "name": "invalid-key",
        "permission": "invalid",
    }

    response = auth_enabled_client.post(
        "/api-keys", json=payload, headers=admin_key_header
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


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
    """Test listing API keys."""
    response = auth_enabled_client.get("/api-keys", headers=admin_key_header)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "keys" in data
    assert "total" in data
    assert data["total"] >= 3  # At least the 3 fixture keys

    # Verify keys are present
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
    """Test including revoked keys when requested."""
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
    sample_api_key: ApiKey,
    admin_api_key: ApiKey,
) -> None:
    """Test filtering API keys by permission level."""
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
    """Test listing API keys without authentication fails."""
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
    """Test getting API key statistics."""
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
    """Test getting a specific API key by ID."""
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
    """Test getting a non-existent API key."""
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
    """Test revoking an API key."""
    # Create a key to revoke
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

    # Verify in database
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
    """Test revoking an already revoked key fails."""
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
    """Test revoking a non-existent API key."""
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
    """Test deleting an API key."""
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
    """Test deleting a non-existent API key."""
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
# Integration Tests
# =============================================================================


def test_create_and_use_api_key(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
) -> None:
    """Test creating an API key and using it for authentication."""
    # Create a new key
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
    # Create a key
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

    # Revoke the key
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


def test_permission_hierarchy(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    db_session: Session,
) -> None:
    """Test that permission hierarchy is enforced."""
    # Create keys with different permission levels
    for perm, expected_status in [
        ("read", status.HTTP_403_FORBIDDEN),
        ("write", status.HTTP_403_FORBIDDEN),
        ("delete", status.HTTP_403_FORBIDDEN),
        ("admin", status.HTTP_200_OK),
    ]:
        # Create a key with the permission level
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
    admin_key_header: dict[str, str],
    expired_key: ApiKey,
) -> None:
    """Test that an expired key cannot be used for authentication."""
    expired_header = {"X-API-Key": expired_key._plaintext}  # type: ignore[attr-defined]

    response = auth_enabled_client.get("/api-keys", headers=expired_header)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# =============================================================================
# Edge Case Tests
# =============================================================================


def test_create_api_key_with_max_expiration(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
) -> None:
    """Test creating an API key with maximum expiration."""
    payload = {
        "name": "max-expiration-key",
        "permission": "read",
        "expires_in_days": 3650,  # 10 years
    }

    response = auth_enabled_client.post(
        "/api-keys", json=payload, headers=admin_key_header
    )

    assert response.status_code == status.HTTP_201_CREATED


def test_create_api_key_with_invalid_expiration(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
) -> None:
    """Test creating an API key with invalid expiration fails."""
    payload = {
        "name": "invalid-expiration-key",
        "permission": "read",
        "expires_in_days": 0,  # Invalid
    }

    response = auth_enabled_client.post(
        "/api-keys", json=payload, headers=admin_key_header
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


def test_list_api_keys_empty(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
    db_session: Session,
) -> None:
    """Test listing API keys when all are revoked."""
    # Revoke all existing keys except the admin key
    all_keys = db_session.query(ApiKey).all()
    admin_key_id = None

    # Find the admin key ID from the header
    for key in all_keys:
        if key.permission == Permission.ADMIN.value and not key.revoked:
            admin_key_id = key.id
            break

    # Revoke all except the one we're using
    for key in all_keys:
        if key.id != admin_key_id:
            key.revoked = True

    db_session.commit()

    # List should still show the admin key
    response = auth_enabled_client.get("/api-keys", headers=admin_key_header)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] >= 1  # At least the admin key


def test_api_key_name_validation(
    auth_enabled_client: TestClient,
    admin_key_header: dict[str, str],
) -> None:
    """Test API key name validation."""
    payload = {
        "name": "ab",
        "permission": "read",
    }

    response = auth_enabled_client.post(
        "/api-keys", json=payload, headers=admin_key_header
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
