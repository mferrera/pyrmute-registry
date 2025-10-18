"""Tests for the RegistryClient."""

from typing import Any
from unittest.mock import Mock, patch

import httpx
import pytest
from httpx import codes

from pyrmute_registry.client import RegistryClient
from pyrmute_registry.exceptions import (
    RegistryConnectionError,
    RegistryError,
    SchemaConflictError,
    SchemaNotFoundError,
)

# ruff: noqa: PLR2004


@pytest.fixture
def sample_schema() -> dict[str, Any]:
    """Sample JSON schema for testing."""
    return {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "name": {"type": "string"},
            "email": {"type": "string", "format": "email"},
        },
        "required": ["id", "name"],
    }


@pytest.fixture
def mock_response() -> Mock:
    """Create a mock httpx Response."""
    response = Mock(spec=httpx.Response)
    response.status_code = codes.OK
    response.json.return_value = {}
    return response


# ============================================================================
# CLIENT INITIALIZATION
# ============================================================================


def test_client_initialization() -> None:
    """Test basic client initialization."""
    client = RegistryClient("http://localhost:8000")

    assert client.base_url == "http://localhost:8000"
    assert client.max_retries == 3
    assert not client._closed


def test_client_initialization_strips_trailing_slash() -> None:
    """Test that trailing slash is removed from base URL."""
    client = RegistryClient("http://localhost:8000/")

    assert client.base_url == "http://localhost:8000"


def test_client_initialization_with_api_key() -> None:
    """Test client initialization with API key."""
    client = RegistryClient("http://localhost:8000", api_key="test-key")

    assert "X-API-Key" in client.client.headers
    assert client.client.headers["X-API-Key"] == "test-key"


def test_client_initialization_with_custom_timeout() -> None:
    """Test client initialization with custom timeout."""
    client = RegistryClient("http://localhost:8000", timeout=30.0)

    assert client.client.timeout.read == 30.0


# ============================================================================
# REGISTER SCHEMA
# ============================================================================


def test_register_schema_global(sample_schema: dict[str, Any]) -> None:
    """Test registering a global schema."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = Mock(
            status_code=codes.CREATED,
            json=lambda: {
                "id": 1,
                "namespace": None,
                "model_name": "User",
                "version": "1.0.0",
                "json_schema": sample_schema,
            },
        )

        client = RegistryClient("http://localhost:8000")
        result = client.register_schema("User", "1.0.0", sample_schema, "test-service")

        assert result["model_name"] == "User"
        assert result["version"] == "1.0.0"
        assert mock_post.call_count == 1

        # Verify URL
        call_args = mock_post.call_args
        assert call_args[0][0] == "http://localhost:8000/schemas/User/versions"


def test_register_schema_namespaced(sample_schema: dict[str, Any]) -> None:
    """Test registering a namespaced schema."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = Mock(
            status_code=codes.CREATED,
            json=lambda: {
                "id": 1,
                "namespace": "auth-service",
                "model_name": "User",
                "version": "1.0.0",
                "json_schema": sample_schema,
            },
        )

        client = RegistryClient("http://localhost:8000")
        result = client.register_schema(
            "User",
            "1.0.0",
            sample_schema,
            "test-service",
            namespace="auth-service",
        )

        assert result["namespace"] == "auth-service"

        # Verify URL
        call_args = mock_post.call_args
        assert (
            call_args[0][0]
            == "http://localhost:8000/schemas/auth-service/User/versions"
        )


def test_register_schema_with_metadata(sample_schema: dict[str, Any]) -> None:
    """Test registering schema with metadata."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = Mock(
            status_code=codes.CREATED,
            json=lambda: {"id": 1, "model_name": "User"},
        )

        client = RegistryClient("http://localhost:8000")
        metadata = {"environment": "production", "team": "platform"}

        client.register_schema(
            "User",
            "1.0.0",
            sample_schema,
            "test-service",
            metadata=metadata,
        )

        # Verify payload includes metadata
        call_args = mock_post.call_args
        payload = call_args.kwargs["json"]
        assert payload["meta"] == metadata


def test_register_schema_with_overwrite(sample_schema: dict[str, Any]) -> None:
    """Test registering schema with allow_overwrite."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = Mock(
            status_code=codes.CREATED,
            json=lambda: {"id": 1, "model_name": "User"},
        )

        client = RegistryClient("http://localhost:8000")
        client.register_schema(
            "User",
            "1.0.0",
            sample_schema,
            "test-service",
            allow_overwrite=True,
        )

        # Verify query parameter
        call_args = mock_post.call_args
        assert "allow_overwrite=true" in call_args[0][0]


def test_register_schema_conflict(sample_schema: dict[str, Any]) -> None:
    """Test schema conflict error."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = Mock(
            status_code=codes.CONFLICT,
        )
        mock_post.return_value.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Conflict",
            request=Mock(),
            response=mock_post.return_value,
        )

        client = RegistryClient("http://localhost:8000")

        with pytest.raises(SchemaConflictError) as exc_info:
            client.register_schema("User", "1.0.0", sample_schema, "test-service")

        assert "already exists" in str(exc_info.value)


def test_register_schema_validation_error(sample_schema: dict[str, Any]) -> None:
    """Test validation error on registration."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = Mock(
            status_code=codes.UNPROCESSABLE_ENTITY,
            text="Invalid schema",
        )
        mock_post.return_value.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Unprocessable",
            request=Mock(),
            response=mock_post.return_value,
        )

        client = RegistryClient("http://localhost:8000")

        with pytest.raises(RegistryError) as exc_info:
            client.register_schema("User", "1.0.0", sample_schema, "test-service")

        assert "Invalid schema data" in str(exc_info.value)


def test_register_schema_connection_error(sample_schema: dict[str, Any]) -> None:
    """Test connection error on registration."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.side_effect = httpx.ConnectError("Connection failed")

        client = RegistryClient("http://localhost:8000", max_retries=1)

        with pytest.raises(RegistryConnectionError) as exc_info:
            client.register_schema("User", "1.0.0", sample_schema, "test-service")

        assert "Unable to connect" in str(exc_info.value)


def test_register_schema_timeout_error(sample_schema: dict[str, Any]) -> None:
    """Test timeout error on registration."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.side_effect = httpx.TimeoutException("Timeout")

        client = RegistryClient("http://localhost:8000", max_retries=1)

        with pytest.raises(RegistryConnectionError) as exc_info:
            client.register_schema("User", "1.0.0", sample_schema, "test-service")

        assert "timeout" in str(exc_info.value).lower()


# ============================================================================
# GET SCHEMA
# ============================================================================


def test_get_schema_global(sample_schema: dict[str, Any]) -> None:
    """Test getting a global schema."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {
                "id": 1,
                "namespace": None,
                "model_name": "User",
                "version": "1.0.0",
                "json_schema": sample_schema,
            },
        )

        client = RegistryClient("http://localhost:8000")
        result = client.get_schema("User", "1.0.0")

        assert result["model_name"] == "User"
        assert result["version"] == "1.0.0"

        # Verify URL
        call_args = mock_get.call_args
        assert call_args[0][0] == "http://localhost:8000/schemas/User/versions/1.0.0"


def test_get_schema_namespaced(sample_schema: dict[str, Any]) -> None:
    """Test getting a namespaced schema."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {
                "id": 1,
                "namespace": "auth-service",
                "model_name": "User",
                "version": "1.0.0",
                "json_schema": sample_schema,
            },
        )

        client = RegistryClient("http://localhost:8000")
        result = client.get_schema("User", "1.0.0", namespace="auth-service")

        assert result["namespace"] == "auth-service"

        # Verify URL
        call_args = mock_get.call_args
        assert (
            call_args[0][0]
            == "http://localhost:8000/schemas/auth-service/User/versions/1.0.0"
        )


def test_get_schema_not_found() -> None:
    """Test schema not found error."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(status_code=codes.NOT_FOUND)
        mock_get.return_value.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Not Found",
            request=Mock(),
            response=mock_get.return_value,
        )

        client = RegistryClient("http://localhost:8000")

        with pytest.raises(SchemaNotFoundError) as exc_info:
            client.get_schema("User", "1.0.0")

        assert "not found" in str(exc_info.value)


def test_get_schema_connection_error() -> None:
    """Test connection error when getting schema."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.side_effect = httpx.ConnectError("Connection failed")

        client = RegistryClient("http://localhost:8000", max_retries=1)

        with pytest.raises(RegistryConnectionError):
            client.get_schema("User", "1.0.0")


# ============================================================================
# GET LATEST SCHEMA
# ============================================================================


def test_get_latest_schema_global(sample_schema: dict[str, Any]) -> None:
    """Test getting latest global schema."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {
                "id": 2,
                "namespace": None,
                "model_name": "User",
                "version": "2.0.0",
                "json_schema": sample_schema,
            },
        )

        client = RegistryClient("http://localhost:8000")
        result = client.get_latest_schema("User")

        assert result["version"] == "2.0.0"

        # Verify URL
        call_args = mock_get.call_args
        assert call_args[0][0] == "http://localhost:8000/schemas/User/versions/latest"


def test_get_latest_schema_namespaced(sample_schema: dict[str, Any]) -> None:
    """Test getting latest namespaced schema."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {
                "id": 2,
                "namespace": "auth-service",
                "model_name": "User",
                "version": "2.0.0",
                "json_schema": sample_schema,
            },
        )

        client = RegistryClient("http://localhost:8000")
        result = client.get_latest_schema("User", namespace="auth-service")

        assert result["namespace"] == "auth-service"

        # Verify URL
        call_args = mock_get.call_args
        assert (
            call_args[0][0]
            == "http://localhost:8000/schemas/auth-service/User/versions/latest"
        )


def test_get_latest_schema_not_found() -> None:
    """Test model not found when getting latest."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(status_code=codes.NOT_FOUND)
        mock_get.return_value.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Not Found",
            request=Mock(),
            response=mock_get.return_value,
        )

        client = RegistryClient("http://localhost:8000")

        with pytest.raises(SchemaNotFoundError) as exc_info:
            client.get_latest_schema("User")

        assert "not found" in str(exc_info.value)


# ============================================================================
# LIST SCHEMAS
# ============================================================================


def test_list_schemas_all() -> None:
    """Test listing all schemas."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {
                "schemas": [
                    {
                        "namespace": None,
                        "model_name": "User",
                        "versions": ["1.0.0", "2.0.0"],
                    },
                    {
                        "namespace": "auth-service",
                        "model_name": "Session",
                        "versions": ["1.0.0"],
                    },
                ],
                "total": 2,
            },
        )

        client = RegistryClient("http://localhost:8000")
        result = client.list_schemas()

        assert len(result["schemas"]) == 2
        assert result["total"] == 2


def test_list_schemas_with_filters() -> None:
    """Test listing schemas with filters."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {"schemas": [], "total": 0},
        )

        client = RegistryClient("http://localhost:8000")
        client.list_schemas(
            namespace="auth-service",
            model_name="User",
            include_deprecated=True,
            limit=50,
            offset=10,
        )

        # Verify query parameters
        call_args = mock_get.call_args
        params = call_args.kwargs["params"]
        assert params["namespace"] == "auth-service"
        assert params["model_name"] == "User"
        assert params["include_deprecated"] is True
        assert params["limit"] == 50
        assert params["offset"] == 10


def test_list_schemas_connection_error() -> None:
    """Test connection error when listing schemas."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.side_effect = httpx.ConnectError("Connection failed")

        client = RegistryClient("http://localhost:8000", max_retries=1)

        with pytest.raises(RegistryConnectionError):
            client.list_schemas()


# ============================================================================
# LIST VERSIONS
# ============================================================================


def test_list_versions_global() -> None:
    """Test listing versions for global model."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {"versions": ["1.0.0", "1.1.0", "2.0.0"]},
        )

        client = RegistryClient("http://localhost:8000")
        versions = client.list_versions("User")

        assert versions == ["1.0.0", "1.1.0", "2.0.0"]

        # Verify URL
        call_args = mock_get.call_args
        assert call_args[0][0] == "http://localhost:8000/schemas/User/versions"


def test_list_versions_namespaced() -> None:
    """Test listing versions for namespaced model."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {"versions": ["1.0.0", "2.0.0"]},
        )

        client = RegistryClient("http://localhost:8000")
        versions = client.list_versions("User", namespace="auth-service")

        assert len(versions) == 2

        # Verify URL
        call_args = mock_get.call_args
        assert (
            call_args[0][0]
            == "http://localhost:8000/schemas/auth-service/User/versions"
        )


def test_list_versions_not_found() -> None:
    """Test model not found when listing versions."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(status_code=codes.NOT_FOUND)
        mock_get.return_value.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Not Found",
            request=Mock(),
            response=mock_get.return_value,
        )

        client = RegistryClient("http://localhost:8000")

        with pytest.raises(SchemaNotFoundError):
            client.list_versions("User")


# ============================================================================
# HEALTH CHECK
# ============================================================================


def test_health_check_simple() -> None:
    """Test simple health check."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(status_code=codes.OK)

        client = RegistryClient("http://localhost:8000")
        result = client.health_check()

        assert result is True


def test_health_check_detailed() -> None:
    """Test detailed health check."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {
                "status": "healthy",
                "version": "1.0.0",
                "schemas_count": 42,
            },
        )

        client = RegistryClient("http://localhost:8000")
        result = client.health_check(detailed=True)

        assert isinstance(result, dict)
        assert result["status"] == "healthy"
        assert result["schemas_count"] == 42


def test_health_check_unhealthy() -> None:
    """Test health check with unhealthy status."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(status_code=codes.SERVICE_UNAVAILABLE)

        client = RegistryClient("http://localhost:8000")
        result = client.health_check()

        assert result is False


def test_health_check_connection_error() -> None:
    """Test health check with connection error."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.side_effect = httpx.ConnectError("Connection failed")

        client = RegistryClient("http://localhost:8000")
        result = client.health_check()

        assert result is False


def test_health_check_detailed_connection_error() -> None:
    """Test detailed health check with connection error."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.side_effect = httpx.ConnectError("Connection failed")

        client = RegistryClient("http://localhost:8000")
        result = client.health_check(detailed=True)

        assert isinstance(result, dict)
        assert result["healthy"] is False
        assert "error" in result


# ============================================================================
# COMPARE SCHEMAS
# ============================================================================


def test_compare_schemas_global() -> None:
    """Test comparing global schema versions."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {
                "namespace": None,
                "model_name": "User",
                "from_version": "1.0.0",
                "to_version": "2.0.0",
                "changes": {
                    "properties_added": ["age"],
                    "breaking_changes": [],
                    "compatibility": "backward_compatible",
                },
            },
        )

        client = RegistryClient("http://localhost:8000")
        result = client.compare_schemas("User", "1.0.0", "2.0.0")

        assert result["from_version"] == "1.0.0"
        assert result["to_version"] == "2.0.0"
        assert "age" in result["changes"]["properties_added"]


def test_compare_schemas_namespaced() -> None:
    """Test comparing namespaced schema versions."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {
                "namespace": "auth-service",
                "model_name": "User",
                "from_version": "1.0.0",
                "to_version": "2.0.0",
                "changes": {},
            },
        )

        client = RegistryClient("http://localhost:8000")
        result = client.compare_schemas(
            "User", "1.0.0", "2.0.0", namespace="auth-service"
        )

        assert result["namespace"] == "auth-service"

        # Verify URL
        call_args = mock_get.call_args
        assert (
            call_args[0][0] == "http://localhost:8000/schemas/auth-service/User/compare"
        )


def test_compare_schemas_not_found() -> None:
    """Test comparison with version not found."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(status_code=codes.NOT_FOUND)
        mock_get.return_value.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Not Found",
            request=Mock(),
            response=mock_get.return_value,
        )

        client = RegistryClient("http://localhost:8000")

        with pytest.raises(SchemaNotFoundError) as exc_info:
            client.compare_schemas("User", "1.0.0", "99.0.0")

        assert "not found" in str(exc_info.value)


# ============================================================================
# DELETE SCHEMA
# ============================================================================


def test_delete_schema_global() -> None:
    """Test deleting a global schema."""
    with patch("httpx.Client.delete") as mock_delete:
        mock_delete.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {
                "deleted": True,
                "namespace": None,
                "model_name": "User",
                "version": "1.0.0",
            },
        )

        client = RegistryClient("http://localhost:8000")
        result = client.delete_schema("User", "1.0.0", force=True)

        assert result["deleted"] is True

        # Verify URL includes force parameter
        call_args = mock_delete.call_args
        assert "force=true" in call_args[0][0]


def test_delete_schema_namespaced() -> None:
    """Test deleting a namespaced schema."""
    with patch("httpx.Client.delete") as mock_delete:
        mock_delete.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {
                "deleted": True,
                "namespace": "auth-service",
                "model_name": "User",
                "version": "1.0.0",
            },
        )

        client = RegistryClient("http://localhost:8000")
        result = client.delete_schema(
            "User", "1.0.0", namespace="auth-service", force=True
        )

        assert result["namespace"] == "auth-service"

        # Verify URL
        call_args = mock_delete.call_args
        assert (
            call_args[0][0]
            == "http://localhost:8000/schemas/auth-service/User/versions/1.0.0?force=true"
        )


def test_delete_schema_not_found() -> None:
    """Test deleting non-existent schema."""
    with patch("httpx.Client.delete") as mock_delete:
        mock_delete.return_value = Mock(status_code=codes.NOT_FOUND)
        mock_delete.return_value.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Not Found",
            request=Mock(),
            response=mock_delete.return_value,
        )

        client = RegistryClient("http://localhost:8000")

        with pytest.raises(SchemaNotFoundError):
            client.delete_schema("User", "1.0.0", force=True)


# ============================================================================
# DEPRECATE SCHEMA
# ============================================================================


def test_deprecate_schema_global() -> None:
    """Test deprecating a global schema."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {
                "id": 1,
                "namespace": None,
                "model_name": "User",
                "version": "1.0.0",
                "deprecated": True,
                "deprecation_message": "Use v2.0.0 instead",
            },
        )

        client = RegistryClient("http://localhost:8000")
        result = client.deprecate_schema("User", "1.0.0", message="Use v2.0.0 instead")

        assert result["deprecated"] is True
        assert result["deprecation_message"] == "Use v2.0.0 instead"


def test_deprecate_schema_namespaced() -> None:
    """Test deprecating a namespaced schema."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {
                "id": 1,
                "namespace": "auth-service",
                "model_name": "User",
                "version": "1.0.0",
                "deprecated": True,
            },
        )

        client = RegistryClient("http://localhost:8000")
        result = client.deprecate_schema("User", "1.0.0", namespace="auth-service")

        assert result["namespace"] == "auth-service"

        # Verify URL
        call_args = mock_post.call_args
        assert (
            call_args[0][0]
            == "http://localhost:8000/schemas/auth-service/User/versions/1.0.0/deprecate"
        )


def test_deprecate_schema_not_found() -> None:
    """Test deprecating non-existent schema."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = Mock(status_code=codes.NOT_FOUND)
        mock_post.return_value.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Not Found",
            request=Mock(),
            response=mock_post.return_value,
        )

        client = RegistryClient("http://localhost:8000")

        with pytest.raises(SchemaNotFoundError):
            client.deprecate_schema("User", "99.0.0")


# ============================================================================
# CLIENT LIFECYCLE
# ============================================================================


def test_client_close() -> None:
    """Test client cleanup."""
    client = RegistryClient("http://localhost:8000")
    client.close()

    assert client._closed is True


def test_client_ensure_open_after_close() -> None:
    """Test that operations fail after client is closed."""
    client = RegistryClient("http://localhost:8000")
    client.close()

    with pytest.raises(RegistryError) as exc_info:
        client.health_check()

    assert "closed" in str(exc_info.value).lower()


def test_client_context_manager(sample_schema: dict[str, Any]) -> None:
    """Test client as context manager."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = Mock(
            status_code=codes.CREATED,
            json=lambda: {"id": 1, "model_name": "User"},
        )

        with RegistryClient("http://localhost:8000") as client:
            assert not client._closed
            client.register_schema("User", "1.0.0", sample_schema, "test-service")

        # Client should be closed after context exit
        assert client._closed


def test_client_context_manager_with_exception(
    sample_schema: dict[str, Any],
) -> None:
    """Test client cleanup even when exception occurs."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.side_effect = httpx.ConnectError("Connection failed")

        try:
            with RegistryClient("http://localhost:8000", max_retries=1) as client:
                client.register_schema("User", "1.0.0", sample_schema, "test-service")
        except Exception:
            pass

        # Client should still be closed after exception
        assert client._closed


def test_client_del_closes_client() -> None:
    """Test that __del__ closes the client."""
    client = RegistryClient("http://localhost:8000")
    assert not client._closed

    # Trigger __del__
    client.__del__()

    assert client._closed


# ============================================================================
# RETRY BEHAVIOR
# ============================================================================


def test_register_schema_retries_on_connection_error(
    sample_schema: dict[str, Any],
) -> None:
    """Test that registration retries on connection errors."""
    call_count = 0

    def side_effect(*args: Any, **kwargs: Any) -> Mock:
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise httpx.ConnectError("Connection failed")
        return Mock(
            status_code=codes.CREATED,
            json=lambda: {"id": 1, "model_name": "User"},
        )

    with patch("httpx.Client.post", side_effect=side_effect):
        client = RegistryClient("http://localhost:8000", max_retries=3)
        result = client.register_schema("User", "1.0.0", sample_schema, "test-service")

        # Should have retried and eventually succeeded
        assert call_count == 3
        assert result["model_name"] == "User"


def test_register_schema_retries_on_timeout(sample_schema: dict[str, Any]) -> None:
    """Test that registration retries on timeout."""
    call_count = 0

    def side_effect(*args: Any, **kwargs: Any) -> Mock:
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise httpx.TimeoutException("Timeout")
        return Mock(
            status_code=codes.CREATED,
            json=lambda: {"id": 1, "model_name": "User"},
        )

    with patch("httpx.Client.post", side_effect=side_effect):
        client = RegistryClient("http://localhost:8000", max_retries=3)
        result = client.register_schema("User", "1.0.0", sample_schema, "test-service")

        assert call_count == 2
        assert result["model_name"] == "User"


def test_register_schema_does_not_retry_on_http_error(
    sample_schema: dict[str, Any],
) -> None:
    """Test that registration does not retry on HTTP errors like 409."""
    call_count = 0

    def side_effect(*args: Any, **kwargs: Any) -> Mock:
        nonlocal call_count
        call_count += 1
        response = Mock(status_code=codes.CONFLICT)
        response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Conflict",
            request=Mock(),
            response=response,
        )
        return response

    with patch("httpx.Client.post", side_effect=side_effect):
        client = RegistryClient("http://localhost:8000", max_retries=3)

        with pytest.raises(SchemaConflictError):
            client.register_schema("User", "1.0.0", sample_schema, "test-service")

        # Should not retry on HTTP errors
        assert call_count == 1


# ============================================================================
# EDGE CASES
# ============================================================================


def test_register_schema_empty_metadata(sample_schema: dict[str, Any]) -> None:
    """Test registering schema with empty metadata dict."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = Mock(
            status_code=codes.CREATED,
            json=lambda: {"id": 1, "model_name": "User"},
        )

        client = RegistryClient("http://localhost:8000")
        client.register_schema(
            "User",
            "1.0.0",
            sample_schema,
            "test-service",
            metadata={},
        )

        # Verify payload has empty meta
        call_args = mock_post.call_args
        payload = call_args.kwargs["json"]
        assert payload["meta"] == {}


def test_register_schema_without_metadata(sample_schema: dict[str, Any]) -> None:
    """Test registering schema without metadata parameter."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = Mock(
            status_code=codes.CREATED,
            json=lambda: {"id": 1, "model_name": "User"},
        )

        client = RegistryClient("http://localhost:8000")
        client.register_schema(
            "User",
            "1.0.0",
            sample_schema,
            "test-service",
        )

        # Verify payload has empty meta
        call_args = mock_post.call_args
        payload = call_args.kwargs["json"]
        assert payload["meta"] == {}


def test_list_schemas_no_filters() -> None:
    """Test listing schemas without any filters."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {"schemas": [], "total": 0},
        )

        client = RegistryClient("http://localhost:8000")
        client.list_schemas()

        # Verify parameters
        call_args = mock_get.call_args
        params = call_args.kwargs["params"]
        assert "namespace" not in params
        assert "model_name" not in params
        assert params["include_deprecated"] is False
        assert params["limit"] == 100
        assert params["offset"] == 0


def test_list_schemas_global_only() -> None:
    """Test listing only global schemas."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {"schemas": [], "total": 0},
        )

        client = RegistryClient("http://localhost:8000")
        client.list_schemas(namespace="")

        # Verify namespace parameter is empty string for global
        call_args = mock_get.call_args
        params = call_args.kwargs["params"]
        assert params["namespace"] == ""


def test_compare_schemas_with_query_params() -> None:
    """Test that compare_schemas properly encodes query parameters."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {
                "from_version": "1.0.0",
                "to_version": "2.0.0",
                "changes": {},
            },
        )

        client = RegistryClient("http://localhost:8000")
        client.compare_schemas("User", "1.0.0", "2.0.0")

        # Verify query parameters
        call_args = mock_get.call_args
        params = call_args.kwargs["params"]
        assert params["from_version"] == "1.0.0"
        assert params["to_version"] == "2.0.0"


def test_delete_schema_without_force() -> None:
    """Test delete without force parameter."""
    with patch("httpx.Client.delete") as mock_delete:
        mock_delete.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {"deleted": True},
        )

        client = RegistryClient("http://localhost:8000")
        client.delete_schema("User", "1.0.0", force=False)

        # Verify URL does not include force parameter
        call_args = mock_delete.call_args
        assert "force=true" not in call_args[0][0]


def test_deprecate_schema_without_message() -> None:
    """Test deprecating schema without message."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {"deprecated": True},
        )

        client = RegistryClient("http://localhost:8000")
        client.deprecate_schema("User", "1.0.0")

        # Verify params
        call_args = mock_post.call_args
        params = call_args.kwargs.get("params", {})
        assert "message" not in params or params.get("message") is None


def test_deprecate_schema_with_message() -> None:
    """Test deprecating schema with message."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {"deprecated": True},
        )

        client = RegistryClient("http://localhost:8000")
        client.deprecate_schema("User", "1.0.0", message="Deprecated")

        # Verify message in params
        call_args = mock_post.call_args
        params = call_args.kwargs["params"]
        assert params["message"] == "Deprecated"


# ============================================================================
# SPECIAL CHARACTERS AND ENCODING
# ============================================================================


def test_register_schema_with_special_characters_in_name(
    sample_schema: dict[str, Any],
) -> None:
    """Test registering schema with special characters in model name."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = Mock(
            status_code=codes.CREATED,
            json=lambda: {"id": 1, "model_name": "User-Model_V2"},
        )

        client = RegistryClient("http://localhost:8000")
        result = client.register_schema(
            "User-Model_V2",
            "1.0.0",
            sample_schema,
            "test-service",
        )

        assert result["model_name"] == "User-Model_V2"


def test_namespace_with_special_characters(sample_schema: dict[str, Any]) -> None:
    """Test namespaced operations with special characters."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = Mock(
            status_code=codes.CREATED,
            json=lambda: {"id": 1, "namespace": "auth-service-v2"},
        )

        client = RegistryClient("http://localhost:8000")
        result = client.register_schema(
            "User",
            "1.0.0",
            sample_schema,
            "test-service",
            namespace="auth-service-v2",
        )

        assert result["namespace"] == "auth-service-v2"


# ============================================================================
# ERROR MESSAGE CONTENT
# ============================================================================


def test_schema_conflict_error_message_includes_suggestion(
    sample_schema: dict[str, Any],
) -> None:
    """Test that conflict error includes helpful suggestion."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = Mock(status_code=codes.CONFLICT)
        mock_post.return_value.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Conflict",
            request=Mock(),
            response=mock_post.return_value,
        )

        client = RegistryClient("http://localhost:8000")

        with pytest.raises(Exception) as exc_info:
            client.register_schema("User", "1.0.0", sample_schema, "test-service")

        error_msg = str(exc_info.value)
        assert "already exists" in error_msg
        assert "allow_overwrite=True" in error_msg


def test_connection_error_message_includes_url() -> None:
    """Test that connection error includes registry URL."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.side_effect = httpx.ConnectError("Connection failed")

        client = RegistryClient("http://localhost:8000", max_retries=1)

        with pytest.raises(Exception) as exc_info:
            client.get_schema("User", "1.0.0")

        error_msg = str(exc_info.value)
        assert "http://localhost:8000" in error_msg


# ============================================================================
# PAYLOAD VALIDATION
# ============================================================================


def test_register_schema_payload_structure(sample_schema: dict[str, Any]) -> None:
    """Test that registration payload has correct structure."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = Mock(
            status_code=codes.CREATED,
            json=lambda: {"id": 1},
        )

        client = RegistryClient("http://localhost:8000")
        client.register_schema(
            "User",
            "1.0.0",
            sample_schema,
            "test-service",
            metadata={"env": "prod"},
        )

        # Verify payload structure
        call_args = mock_post.call_args
        payload = call_args.kwargs["json"]

        assert "version" in payload
        assert "json_schema" in payload
        assert "registered_at" in payload
        assert "registered_by" in payload
        assert "meta" in payload

        assert payload["version"] == "1.0.0"
        assert payload["json_schema"] == sample_schema
        assert payload["registered_by"] == "test-service"
        assert payload["meta"] == {"env": "prod"}


def test_register_schema_timestamp_format(sample_schema: dict[str, Any]) -> None:
    """Test that registered_at timestamp is in ISO format."""
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = Mock(
            status_code=codes.CREATED,
            json=lambda: {"id": 1},
        )

        client = RegistryClient("http://localhost:8000")
        client.register_schema(
            "User",
            "1.0.0",
            sample_schema,
            "test-service",
        )

        # Verify timestamp format
        call_args = mock_post.call_args
        payload = call_args.kwargs["json"]

        # Should be ISO format with timezone
        assert "T" in payload["registered_at"]
        assert payload["registered_at"].endswith("Z") or "+" in payload["registered_at"]


# ============================================================================
# HTTP CLIENT CONFIGURATION
# ============================================================================


def test_client_follows_redirects() -> None:
    """Test that client is configured to follow redirects."""
    client = RegistryClient("http://localhost:8000")

    assert client.client.follow_redirects is True


def test_client_has_correct_headers() -> None:
    """Test that client has correct default headers."""
    client = RegistryClient("http://localhost:8000")

    assert "Content-Type" in client.client.headers
    assert client.client.headers["Content-Type"] == "application/json"


def test_client_with_api_key_has_correct_header() -> None:
    """Test that API key is set in correct header."""
    client = RegistryClient("http://localhost:8000", api_key="secret-key")

    assert "X-API-Key" in client.client.headers
    assert client.client.headers["X-API-Key"] == "secret-key"
    # Should not set Authorization header
    assert "Authorization" not in client.client.headers


# ============================================================================
# INTEGRATION-STYLE TESTS
# ============================================================================


def test_full_schema_lifecycle(sample_schema: dict[str, Any]) -> None:
    """Test complete schema lifecycle: register, get, compare, deprecate, delete."""
    with (
        patch("httpx.Client.post") as mock_post,
        patch("httpx.Client.get") as mock_get,
        patch("httpx.Client.delete") as mock_delete,
    ):
        # Setup mocks
        mock_post.return_value = Mock(
            status_code=codes.CREATED,
            json=lambda: {
                "id": 1,
                "model_name": "User",
                "version": "1.0.0",
                "deprecated": False,
            },
        )
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {
                "id": 1,
                "model_name": "User",
                "version": "1.0.0",
                "json_schema": sample_schema,
            },
        )
        mock_delete.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {"deleted": True},
        )

        with RegistryClient("http://localhost:8000") as client:
            # Register
            result = client.register_schema(
                "User", "1.0.0", sample_schema, "test-service"
            )
            assert result["model_name"] == "User"

            # Get
            schema = client.get_schema("User", "1.0.0")
            assert schema["json_schema"] == sample_schema

            # Deprecate
            mock_post.return_value.json = lambda: {
                "id": 1,
                "deprecated": True,
            }
            deprecated = client.deprecate_schema("User", "1.0.0")
            assert deprecated["deprecated"] is True

            # Delete
            deleted = client.delete_schema("User", "1.0.0", force=True)
            assert deleted["deleted"] is True
