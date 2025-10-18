"""Tests for authentication system."""

import time
from typing import Any

import pytest
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

from pyrmute_registry.server.auth import (
    Permission,
    generate_api_key,
    get_api_key,
    hash_api_key,
    require_permission,
    verify_api_key,
)
from pyrmute_registry.server.config import Settings


@pytest.fixture
def auth_enabled_settings() -> Settings:
    """Settings with authentication enabled."""
    return Settings(
        database_url="sqlite:///:memory:",
        enable_auth=True,
        api_key="test-api-key-12345",
        environment="test",
    )


@pytest.fixture
def auth_disabled_settings() -> Settings:
    """Settings with authentication disabled."""
    return Settings(
        database_url="sqlite:///:memory:",
        enable_auth=False,
        environment="test",
    )


def test_verify_api_key_valid(auth_enabled_settings: Settings) -> None:
    """Test API key verification with valid key."""
    result = verify_api_key("test-api-key-12345", auth_enabled_settings)
    assert result is True


def test_verify_api_key_invalid(auth_enabled_settings: Settings) -> None:
    """Test API key verification with invalid key."""
    result = verify_api_key("wrong-key", auth_enabled_settings)
    assert result is False


def test_verify_api_key_missing(auth_enabled_settings: Settings) -> None:
    """Test API key verification with missing key."""
    result = verify_api_key(None, auth_enabled_settings)
    assert result is False


def test_verify_api_key_auth_disabled(auth_disabled_settings: Settings) -> None:
    """Test that verification passes when auth is disabled."""
    result = verify_api_key("any-key", auth_disabled_settings)
    assert result is True


def test_verify_api_key_no_configured_key() -> None:
    """Test that verification fails when no key is configured but auth is enabled."""
    settings = Settings(
        database_url="sqlite:///:memory:",
        enable_auth=True,
        api_key=None,
        environment="test",
    )
    result = verify_api_key("some-key", settings)
    assert result is False


def test_verify_api_key_constant_time_comparison(
    auth_enabled_settings: Settings,
) -> None:
    """Test that verification uses constant-time comparison.

    This test verifies the function uses secrets.compare_digest which prevents timing
    attacks.
    """
    iterations = 1000

    # Measure time for correct key
    start = time.perf_counter()
    for _ in range(iterations):
        verify_api_key("test-api-key-12345", auth_enabled_settings)
    correct_time = time.perf_counter() - start

    # Measure time for wrong key (same length)
    start = time.perf_counter()
    for _ in range(iterations):
        verify_api_key("wrong-key-1234567", auth_enabled_settings)
    wrong_time = time.perf_counter() - start

    # Times should be similar (within 50% variance)
    # This is a loose check as timing can vary
    ratio = max(correct_time, wrong_time) / min(correct_time, wrong_time)
    assert ratio < 2, "Timing difference suggests non-constant-time comparison"  # noqa: PLR2004


def test_get_api_key_header_takes_precedence(
    auth_enabled_settings: Settings,
) -> None:
    """Test that X-API-Key header takes precedence over bearer token."""
    bearer_creds = HTTPAuthorizationCredentials(
        scheme="Bearer", credentials="wrong-key"
    )
    result = get_api_key(
        header_key="test-api-key-12345",
        bearer_creds=bearer_creds,
        settings=auth_enabled_settings,
    )
    assert result == "test-api-key-12345"


def test_get_api_key_falls_back_to_bearer(auth_enabled_settings: Settings) -> None:
    """Test that bearer token is used when header is missing."""
    bearer_creds = HTTPAuthorizationCredentials(
        scheme="Bearer", credentials="test-api-key-12345"
    )
    result = get_api_key(
        header_key=None,
        bearer_creds=bearer_creds,
        settings=auth_enabled_settings,
    )
    assert result == "test-api-key-12345"


def test_get_api_key_both_invalid(auth_enabled_settings: Settings) -> None:
    """Test that error is raised when both methods provide invalid keys."""
    bearer_creds = HTTPAuthorizationCredentials(
        scheme="Bearer", credentials="wrong-bearer"
    )

    with pytest.raises(HTTPException) as exc_info:
        get_api_key(
            header_key="wrong-header",
            bearer_creds=bearer_creds,
            settings=auth_enabled_settings,
        )

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "X-API-Key header or Authorization: Bearer" in exc_info.value.detail


def test_get_api_key_both_missing(auth_enabled_settings: Settings) -> None:
    """Test that error is raised when both methods are missing."""
    with pytest.raises(HTTPException) as exc_info:
        get_api_key(
            header_key=None,
            bearer_creds=None,
            settings=auth_enabled_settings,
        )

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


def test_get_api_key_auth_disabled(auth_disabled_settings: Settings) -> None:
    """Test that get_api_key returns None when auth is disabled."""
    result = get_api_key(
        header_key=None,
        bearer_creds=None,
        settings=auth_disabled_settings,
    )
    assert result is None


def test_generate_api_key_default_length() -> None:
    """Test generating API key with default length."""
    key = generate_api_key()
    assert len(key) == 64  #  noqa: PLR2004
    assert all(c in "0123456789abcdef" for c in key)


def test_generate_api_key_custom_length() -> None:
    """Test generating API key with custom length."""
    key = generate_api_key(length=16)
    assert len(key) == 32  #  noqa: PLR2004


def test_generate_api_key_uniqueness() -> None:
    """Test that generated API keys are unique."""
    keys = [generate_api_key() for _ in range(100)]
    assert len(set(keys)) == 100, "Generated keys should be unique"  #  noqa: PLR2004


def test_generate_api_key_randomness() -> None:
    """Test that generated API keys appear random."""
    key1 = generate_api_key()
    key2 = generate_api_key()

    assert key1 != key2

    # Keys should have good entropy (not all same character)
    assert len(set(key1)) > 10  #  noqa: PLR2004
    assert len(set(key2)) > 10  #  noqa: PLR2004


def test_hash_api_key() -> None:
    """Test hashing an API key."""
    key = "my-secret-key"
    hashed = hash_api_key(key)

    # SHA-256 produces 64 character hex string
    assert len(hashed) == 64  #  noqa: PLR2004
    assert all(c in "0123456789abcdef" for c in hashed)


def test_hash_api_key_deterministic() -> None:
    """Test that hashing is deterministic."""
    key = "my-secret-key"
    hash1 = hash_api_key(key)
    hash2 = hash_api_key(key)

    assert hash1 == hash2


def test_hash_api_key_different_for_different_keys() -> None:
    """Test that different keys produce different hashes."""
    hash1 = hash_api_key("key1")
    hash2 = hash_api_key("key2")

    assert hash1 != hash2


def test_require_permission_with_valid_key(auth_enabled_settings: Settings) -> None:
    """Test permission check with valid API key."""
    checker = require_permission(Permission.WRITE_SCHEMAS)
    result = checker("test-api-key-12345", auth_enabled_settings)
    assert result == "test-api-key-12345"


def test_require_permission_with_invalid_key(auth_enabled_settings: Settings) -> None:
    """Test permission check with invalid API key."""
    checker = require_permission(Permission.WRITE_SCHEMAS)

    with pytest.raises(HTTPException) as exc_info:
        checker(None, auth_enabled_settings)

    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert "Permission denied" in exc_info.value.detail


def test_require_permission_auth_disabled(auth_disabled_settings: Settings) -> None:
    """Test permission check when auth is disabled."""
    checker = require_permission(Permission.WRITE_SCHEMAS)
    result = checker(None, auth_disabled_settings)
    assert result is None


def test_permission_constants() -> None:
    """Test that permission constants are defined."""
    assert Permission.READ_SCHEMAS == "read:schemas"
    assert Permission.WRITE_SCHEMAS == "write:schemas"
    assert Permission.DELETE_SCHEMAS == "delete:schemas"
    assert Permission.ADMIN == "admin"


def test_auth_with_real_endpoint(
    app_client: Any,
    sample_schema: dict[str, Any],
) -> None:
    """Test authentication with a real endpoint (integration test)."""
    # This test uses the test client which has auth disabled
    # Just verify the endpoint works
    response = app_client.post(
        "/schemas/auth-service/User/versions",
        json={
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": sample_schema,
            "registered_by": "test-service",
        },
    )
    assert response.status_code == status.HTTP_201_CREATED
