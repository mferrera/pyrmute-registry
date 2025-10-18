"""Tests for the RegistryPlugin."""

from typing import Any
from unittest.mock import Mock, patch

import pytest
from pydantic import BaseModel
from pyrmute import ModelManager, ModelVersion

from pyrmute_registry.exceptions import (
    RegistryConnectionError,
    RegistryError,
    RegistryPluginError,
    SchemaConflictError,
)
from pyrmute_registry.plugin import (
    RegistryPlugin,
    RegistryPluginConfig,
    create_plugin,
)

# ruff: noqa: PLR2004


@pytest.fixture
def model_manager() -> ModelManager:
    """Create a fresh ModelManager for testing."""
    return ModelManager()


@pytest.fixture
def sample_schema() -> dict[str, Any]:
    """Sample JSON schema for testing."""
    return {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "name": {"type": "string"},
        },
        "required": ["id"],
    }


@pytest.fixture
def mock_registry_client() -> Mock:
    """Create a mock RegistryClient."""
    client = Mock()
    client.health_check.return_value = True
    client.register_schema.return_value = {"id": 1, "model_name": "User"}
    client.get_schema.return_value = {"json_schema": {}}
    client.list_schemas.return_value = {"schemas": [], "total": 0}
    client.close.return_value = None
    return client


# ============================================================================
# PLUGIN INITIALIZATION
# ============================================================================


def test_plugin_initialization_with_kwargs(model_manager: ModelManager) -> None:
    """Test plugin initialization with keyword arguments."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_client.return_value.health_check.return_value = True

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            namespace="test-service",
            auto_register=True,
        )

        assert plugin.registry_url == "http://localhost:8000"
        assert plugin.namespace == "test-service"
        assert plugin.auto_register is True
        assert plugin.fail_on_error is False


def test_plugin_initialization_with_config(model_manager: ModelManager) -> None:
    """Test plugin initialization with config object."""
    config = RegistryPluginConfig(
        registry_url="http://localhost:8000",
        namespace="test-service",
        auto_register=False,
    )

    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_client.return_value.health_check.return_value = True

        plugin = RegistryPlugin(model_manager, config=config)

        assert plugin.registry_url == "http://localhost:8000"
        assert plugin.namespace == "test-service"
        assert plugin.auto_register is False


def test_plugin_initialization_with_config_and_kwargs_raises_error(
    model_manager: ModelManager,
) -> None:
    """Test that providing both config and kwargs raises ValueError."""
    config = RegistryPluginConfig(registry_url="http://localhost:8000")

    with pytest.raises(ValueError) as exc_info:
        RegistryPlugin(
            model_manager,
            config=config,
            namespace="test-service",  # type: ignore[call-overload]
        )

    assert "both 'config' and keyword arguments" in str(exc_info.value)


def test_plugin_initialization_invalid_kwarg(model_manager: ModelManager) -> None:
    """Test that invalid kwargs raise TypeError."""
    with pytest.raises(TypeError) as exc_info:
        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            invalid_param="value",  # type: ignore[call-overload]
        )

    assert "unexpected keyword argument" in str(exc_info.value)
    assert "invalid_param" in str(exc_info.value)


def test_plugin_initialization_without_registry_url(
    model_manager: ModelManager,
) -> None:
    """Test that missing registry URL raises error."""
    with patch.dict("os.environ", {}, clear=True):
        with pytest.raises(RegistryPluginError) as exc_info:
            RegistryPlugin(model_manager)

        assert "Registry URL must be provided" in str(exc_info.value)


def test_plugin_initialization_from_env(model_manager: ModelManager) -> None:
    """Test plugin initialization from environment variables."""
    with (
        patch.dict(
            "os.environ",
            {
                "PYRMUTE_REGISTRY_URL": "http://registry:8000",
                "PYRMUTE_REGISTRY_NAMESPACE": "env-service",
                "PYRMUTE_REGISTRY_API_KEY": "env-key",
            },
        ),
        patch("pyrmute_registry.plugin.RegistryClient") as mock_client,
    ):
        mock_client.return_value.health_check.return_value = True

        plugin = RegistryPlugin(model_manager)

        assert plugin.registry_url == "http://registry:8000"
        assert plugin.namespace == "env-service"

        # Verify API key was passed to client
        call_kwargs = mock_client.call_args.kwargs
        assert call_kwargs["api_key"] == "env-key"


def test_plugin_initialization_global_namespace(model_manager: ModelManager) -> None:
    """Test plugin initialization with None namespace (global)."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_client.return_value.health_check.return_value = True

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            namespace=None,
        )

        assert plugin.namespace is None


def test_plugin_initialization_patches_manager_when_auto_register(
    model_manager: ModelManager,
) -> None:
    """Test that manager is patched when auto_register is True."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_client.return_value.health_check.return_value = True

        original_method = model_manager.model

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
        )

        # Manager should be patched
        assert model_manager.model != original_method
        assert plugin._original_model_method == original_method


def test_plugin_initialization_no_patch_when_auto_register_false(
    model_manager: ModelManager,
) -> None:
    """Test that manager is not patched when auto_register is False."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_client.return_value.health_check.return_value = True

        original_method = model_manager.model

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=False,
        )

        # Manager should not be patched
        assert model_manager.model == original_method
        assert plugin._original_model_method is None


# ============================================================================
# CONNECTIVITY CHECK
# ============================================================================


def test_plugin_initialization_checks_connectivity(
    model_manager: ModelManager,
) -> None:
    """Test that plugin checks registry connectivity on init."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {"healthy": True, "status": "ok"}

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
        )

        # Should call health check
        mock_instance.health_check.assert_called_once_with(detailed=True)


def test_plugin_initialization_warns_on_unhealthy_registry(
    model_manager: ModelManager,
) -> None:
    """Test warning when registry is unhealthy."""
    with (
        patch("pyrmute_registry.plugin.RegistryClient") as mock_client,
        pytest.warns(UserWarning, match="unhealthy"),
    ):
        mock_client.return_value.health_check.return_value = {
            "healthy": False,
            "error": "Database down",
        }

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            fail_on_error=False,
        )


def test_plugin_initialization_raises_on_unhealthy_with_fail_on_error(
    model_manager: ModelManager,
) -> None:
    """Test error when registry unhealthy and fail_on_error=True."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_client.return_value.health_check.return_value = {
            "healthy": False,
            "error": "Down",
        }

        with pytest.raises(RegistryConnectionError):
            RegistryPlugin(
                model_manager,
                registry_url="http://localhost:8000",
                fail_on_error=True,
            )


def test_plugin_initialization_warns_on_connection_error(
    model_manager: ModelManager,
) -> None:
    """Test warning when registry is unavailable."""
    with (
        patch("pyrmute_registry.plugin.RegistryClient") as mock_client,
        pytest.warns(UserWarning, match="unavailable"),
    ):
        mock_client.return_value.health_check.side_effect = RegistryConnectionError(
            "Connection refused"
        )

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            fail_on_error=False,
        )


# ============================================================================
# AUTO-REGISTRATION
# ============================================================================


def test_auto_registration_registers_schema(model_manager: ModelManager) -> None:
    """Test that auto-registration registers schemas when models are defined."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.register_schema.return_value = {"id": 1}

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            namespace="test-service",
            auto_register=True,
        )

        # Define a model
        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str

        # Should have registered the schema
        mock_instance.register_schema.assert_called_once()
        call_args = mock_instance.register_schema.call_args
        assert call_args.kwargs["model_name"] == "User"
        assert call_args.kwargs["version"] == "1.0.0"
        assert call_args.kwargs["namespace"] == "test-service"


def test_auto_registration_skips_duplicate(model_manager: ModelManager) -> None:
    """Test that auto-registration skips already registered models."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.register_schema.return_value = {"id": 1}

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
        )

        # Register same model twice
        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str

        # Mark as registered
        plugin._registered_models.add(("User", "1.0.0"))

        # Try to register again (shouldn't call client)
        initial_call_count = mock_instance.register_schema.call_count

        # Re-register
        plugin.register_schema_safe("User", "1.0.0", {})

        # Should not call register again
        assert mock_instance.register_schema.call_count == initial_call_count


def test_auto_registration_handles_conflict_gracefully(
    model_manager: ModelManager,
) -> None:
    """Test that conflict errors are handled gracefully."""
    with (
        patch("pyrmute_registry.plugin.RegistryClient") as mock_client,
        pytest.warns(UserWarning, match="conflict"),
    ):
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.register_schema.side_effect = SchemaConflictError(
            "Already exists"
        )

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
            fail_on_error=False,
        )

        # Should warn but not raise
        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str


def test_auto_registration_raises_on_conflict_with_fail_on_error(
    model_manager: ModelManager,
) -> None:
    """Test that conflict raises when fail_on_error=True."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.register_schema.side_effect = SchemaConflictError(
            "Already exists"
        )

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
            fail_on_error=True,
        )

        with pytest.raises(RegistryPluginError):

            @model_manager.model("User", "1.0.0")
            class User(BaseModel):
                name: str


def test_auto_registration_includes_metadata(model_manager: ModelManager) -> None:
    """Test that auto-registration includes model metadata."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.register_schema.return_value = {"id": 1}

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
        )

        @model_manager.model("User", "1.0.0", enable_ref=True)
        class User(BaseModel):
            name: str

        # Should include enable_ref in metadata
        call_args = mock_instance.register_schema.call_args
        metadata = call_args.kwargs["metadata"]
        assert metadata["enable_ref"] is True


def test_auto_registration_merges_default_metadata(
    model_manager: ModelManager,
) -> None:
    """Test that default metadata is merged with model metadata."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.register_schema.return_value = {"id": 1}

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
            metadata={"environment": "test", "team": "platform"},
        )

        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str

        # Should include both default and model metadata
        call_args = mock_instance.register_schema.call_args
        metadata = call_args.kwargs["metadata"]
        assert metadata["environment"] == "test"
        assert metadata["team"] == "platform"
        assert "enable_ref" in metadata


# ============================================================================
# MANUAL REGISTRATION
# ============================================================================


def test_register_existing_models_all(model_manager: ModelManager) -> None:
    """Test registering all existing models."""

    # Define models first
    @model_manager.model("User", "1.0.0")
    class User(BaseModel):
        name: str

    @model_manager.model("User", "2.0.0")
    class UserV2(BaseModel):
        name: str
        email: str

    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.register_schema.return_value = {"id": 1}

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=False,
        )

        results = plugin.register_existing_models()

        # Should register both versions
        assert results["User@1.0.0"] is True
        assert results["User@2.0.0"] is True
        assert mock_instance.register_schema.call_count == 2


def test_register_existing_models_specific(model_manager: ModelManager) -> None:
    """Test registering specific models."""

    @model_manager.model("User", "1.0.0")
    class User(BaseModel):
        name: str

    @model_manager.model("Product", "1.0.0")
    class Product(BaseModel):
        name: str

    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.register_schema.return_value = {"id": 1}

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=False,
        )

        results = plugin.register_existing_models([("User", "1.0.0")])

        # Should only register User
        assert results["User@1.0.0"] is True
        assert "Product@1.0.0" not in results
        assert mock_instance.register_schema.call_count == 1


def test_register_existing_models_handles_errors(
    model_manager: ModelManager,
) -> None:
    """Test that registration errors are handled properly."""

    @model_manager.model("User", "1.0.0")
    class User(BaseModel):
        name: str

    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.register_schema.side_effect = Exception("Network error")

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=False,
            fail_on_error=False,
        )

        with pytest.warns(UserWarning, match="Unexpected error"):
            results = plugin.register_existing_models()

        # Should return False for failed registration
        assert results["User@1.0.0"] is False


# ============================================================================
# SYNC WITH REGISTRY
# ============================================================================


def test_sync_with_registry_in_sync(model_manager: ModelManager) -> None:
    """Test sync when local and registry match."""

    @model_manager.model("User", "1.0.0")
    class User(BaseModel):
        name: str

    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.list_schemas.return_value = {
            "schemas": [
                {
                    "model_name": "User",
                    "versions": ["1.0.0"],
                }
            ]
        }

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            namespace="test-service",
            auto_register=False,
        )

        status = plugin.sync_with_registry()

        assert status["in_sync"] is True
        assert not status["local_only"]
        assert not status["registry_only"]
        assert not status["version_mismatches"]


def test_sync_with_registry_local_only(model_manager: ModelManager) -> None:
    """Test sync with models only in local."""

    @model_manager.model("User", "1.0.0")
    class User(BaseModel):
        name: str

    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.list_schemas.return_value = {"schemas": []}

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=False,
        )

        status = plugin.sync_with_registry()

        assert status["in_sync"] is False
        assert "User" in status["local_only"]
        assert "1.0.0" in status["local_only"]["User"]


def test_sync_with_registry_registry_only(model_manager: ModelManager) -> None:
    """Test sync with models only in registry."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.list_schemas.return_value = {
            "schemas": [
                {
                    "model_name": "User",
                    "versions": ["1.0.0"],
                }
            ]
        }

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=False,
        )

        status = plugin.sync_with_registry()

        assert status["in_sync"] is False
        assert "User" in status["registry_only"]


def test_sync_with_registry_version_mismatch(model_manager: ModelManager) -> None:
    """Test sync with version mismatches."""

    @model_manager.model("User", "1.0.0")
    class UserV1(BaseModel):
        name: str

    @model_manager.model("User", "2.0.0")
    class UserV2(BaseModel):
        name: str
        email: str

    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.list_schemas.return_value = {
            "schemas": [
                {
                    "model_name": "User",
                    "versions": ["1.0.0", "3.0.0"],
                }
            ]
        }

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=False,
        )

        status = plugin.sync_with_registry()

        assert status["in_sync"] is False
        assert "User" in status["version_mismatches"]
        assert "2.0.0" in status["version_mismatches"]["User"]["local_only"]
        assert "3.0.0" in status["version_mismatches"]["User"]["registry_only"]


# ============================================================================
# COMPARE WITH REGISTRY
# ============================================================================


def test_compare_with_registry_matches(model_manager: ModelManager) -> None:
    """Test comparison when schemas match."""
    schema = {"type": "object", "properties": {"name": {"type": "string"}}}

    @model_manager.model("User", "1.0.0")
    class User(BaseModel):
        name: str

    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.get_schema.return_value = {"json_schema": schema}

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=False,
        )

        # Mock manager to return same schema
        with patch.object(model_manager, "get_schema", return_value=schema):
            result = plugin.compare_with_registry("User", "1.0.0")

        assert result["matches"] is True
        assert "differences" not in result


def test_compare_with_registry_differs(model_manager: ModelManager) -> None:
    """Test comparison when schemas differ."""
    local_schema = {
        "type": "object",
        "properties": {"name": {"type": "string"}, "age": {"type": "integer"}},
    }
    registry_schema = {
        "type": "object",
        "properties": {"name": {"type": "string"}},
    }

    @model_manager.model("User", "1.0.0")
    class User(BaseModel):
        name: str

    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.get_schema.return_value = {"json_schema": registry_schema}

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=False,
        )

        with patch.object(model_manager, "get_schema", return_value=local_schema):
            result = plugin.compare_with_registry("User", "1.0.0")

        assert result["matches"] is False
        assert "differences" in result
        assert "age" in result["differences"]["properties_added"]


# ============================================================================
# VALIDATE AGAINST REGISTRY
# ============================================================================


def test_validate_against_registry_success(model_manager: ModelManager) -> None:
    """Test successful validation."""
    schema = {"type": "object"}

    @model_manager.model("User", "1.0.0")
    class User(BaseModel):
        name: str

    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.get_schema.return_value = {"json_schema": schema}

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=False,
        )

        with patch.object(model_manager, "get_schema", return_value=schema):
            result = plugin.validate_against_registry("User", "1.0.0")

        assert result is True


def test_validate_against_registry_failure(model_manager: ModelManager) -> None:
    """Test validation failure."""

    @model_manager.model("User", "1.0.0")
    class User(BaseModel):
        name: str

    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.get_schema.return_value = {"json_schema": {"type": "object"}}

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=False,
        )

        with patch.object(model_manager, "get_schema", return_value={"type": "string"}):
            result = plugin.validate_against_registry("User", "1.0.0")

        assert result is False


def test_validate_against_registry_raises_on_mismatch(
    model_manager: ModelManager,
) -> None:
    """Test validation raises when raise_on_mismatch=True."""

    @model_manager.model("User", "1.0.0")
    class User(BaseModel):
        name: str

    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.get_schema.return_value = {"json_schema": {"type": "object"}}

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=False,
        )

        with patch.object(model_manager, "get_schema", return_value={"type": "string"}):
            with pytest.raises(RegistryPluginError) as exc_info:
                plugin.validate_against_registry(
                    "User", "1.0.0", raise_on_mismatch=True
                )

            assert "mismatch" in str(exc_info.value).lower()


# ============================================================================
# PLUGIN LIFECYCLE
# ============================================================================


def test_plugin_restore_manager(model_manager: ModelManager) -> None:
    """Test restoring original manager methods."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_client.return_value.health_check.return_value = True

        original_method = model_manager.model

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
        )

        # Manager should be patched
        assert model_manager.model != original_method

        # Restore
        plugin.restore_manager()

        # Manager should be restored
        assert model_manager.model == original_method
        assert plugin._original_model_method is None


def test_plugin_close(model_manager: ModelManager) -> None:
    """Test plugin cleanup."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True

        original_method = model_manager.model

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
        )

        plugin.close()

        # Should restore manager and close client
        assert model_manager.model == original_method
        mock_instance.close.assert_called_once()


def test_plugin_context_manager(model_manager: ModelManager) -> None:
    """Test plugin as context manager."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True

        original_method = model_manager.model

        with RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
        ):
            # Manager should be patched inside context
            assert model_manager.model != original_method

        # Manager should be restored after context
        assert model_manager.model == original_method
        mock_instance.close.assert_called_once()


def test_plugin_context_manager_with_exception(
    model_manager: ModelManager,
) -> None:
    """Test that plugin cleanup happens even with exception."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True

        original_method = model_manager.model

        try:
            with RegistryPlugin(
                model_manager,
                registry_url="http://localhost:8000",
                auto_register=True,
            ):
                raise ValueError("Test error")
        except ValueError:
            pass

        # Manager should still be restored
        assert model_manager.model == original_method
        mock_instance.close.assert_called_once()


# ============================================================================
# UTILITY METHODS
# ============================================================================


def test_get_registered_models(model_manager: ModelManager) -> None:
    """Test getting registered models."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.register_schema.return_value = {"id": 1}

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
        )

        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str

        registered = plugin.get_registered_models()

        assert ("User", "1.0.0") in registered
        assert len(registered) == 1


def test_clear_registration_cache(model_manager: ModelManager) -> None:
    """Test clearing registration cache."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=False,
        )

        # Add some registered models
        plugin._registered_models.add(("User", "1.0.0"))
        plugin._registered_models.add(("Product", "1.0.0"))

        assert len(plugin._registered_models) == 2

        plugin.clear_registration_cache()

        assert len(plugin._registered_models) == 0


def test_set_metadata(model_manager: ModelManager) -> None:
    """Test setting default metadata."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_client.return_value.health_check.return_value = True

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            metadata={"env": "dev"},
        )

        plugin.set_metadata({"team": "platform", "region": "us-west"})

        assert plugin.default_metadata["env"] == "dev"
        assert plugin.default_metadata["team"] == "platform"
        assert plugin.default_metadata["region"] == "us-west"


def test_health_check(model_manager: ModelManager) -> None:
    """Test plugin health check."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {
            "healthy": True,
            "status": "healthy",
            "schemas_count": 42,
        }

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            namespace="test-service",
            auto_register=True,
        )

        # Register a model
        plugin._registered_models.add(("User", "1.0.0"))

        health = plugin.health_check()

        assert health["plugin_active"] is True
        assert health["auto_register"] is True
        assert health["registry_url"] == "http://localhost:8000"
        assert health["namespace"] == "test-service"
        assert health["registered_models"] == 1
        assert health["registry_healthy"] is True


def test_health_check_with_unhealthy_registry(
    model_manager: ModelManager,
) -> None:
    """Test health check when registry is unhealthy."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.side_effect = [
            True,  # Initial check during init
            Exception("Connection error"),  # During health_check call
        ]

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            fail_on_error=False,
        )

        health = plugin.health_check()

        assert health["registry_healthy"] is False
        assert "registry_error" in health


def test_repr(model_manager: ModelManager) -> None:
    """Test string representation."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_client.return_value.health_check.return_value = True

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            namespace="test-service",
        )

        repr_str = repr(plugin)

        assert "namespace=test-service" in repr_str
        assert "http://localhost:8000" in repr_str
        assert "registered=0" in repr_str


def test_repr_global_namespace(model_manager: ModelManager) -> None:
    """Test string representation with global namespace."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_client.return_value.health_check.return_value = True

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            namespace=None,
        )

        repr_str = repr(plugin)

        assert "global" in repr_str


# ============================================================================
# GET REGISTRY SCHEMA
# ============================================================================


def test_get_registry_schema(model_manager: ModelManager) -> None:
    """Test getting schema from registry."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.get_schema.return_value = {
            "id": 1,
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": {"type": "object"},
        }

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            namespace="test-service",
        )

        schema = plugin.get_registry_schema("User", "1.0.0")

        assert schema["model_name"] == "User"
        mock_instance.get_schema.assert_called_once_with(
            "User", "1.0.0", namespace="test-service"
        )


def test_get_registry_schema_error(model_manager: ModelManager) -> None:
    """Test error when getting schema from registry."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.get_schema.side_effect = RegistryError("Not found")

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
        )

        with pytest.raises(Exception) as exc_info:
            plugin.get_registry_schema("User", "1.0.0")

        assert "Failed to retrieve schema" in str(exc_info.value)


# ============================================================================
# CREATE PLUGIN FACTORY
# ============================================================================


def test_create_plugin_basic(model_manager: ModelManager) -> None:
    """Test create_plugin factory function."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_client.return_value.health_check.return_value = True

        plugin = create_plugin(
            model_manager,
            registry_url="http://localhost:8000",
            namespace="test-service",
        )

        assert isinstance(plugin, RegistryPlugin)
        assert plugin.registry_url == "http://localhost:8000"
        assert plugin.namespace == "test-service"


def test_create_plugin_with_kwargs(model_manager: ModelManager) -> None:
    """Test create_plugin with additional kwargs."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_client.return_value.health_check.return_value = True

        plugin = create_plugin(
            model_manager,
            registry_url="http://localhost:8000",
            namespace="test-service",
            auto_register=False,
            fail_on_error=True,
            metadata={"env": "prod"},
        )

        assert plugin.auto_register is False
        assert plugin.fail_on_error is True
        assert plugin.default_metadata["env"] == "prod"


# ============================================================================
# CONFIGURATION OBJECT
# ============================================================================


def test_plugin_config_defaults() -> None:
    """Test RegistryPluginConfig defaults."""
    config = RegistryPluginConfig(registry_url="http://localhost:8000")

    assert config.registry_url == "http://localhost:8000"
    assert config.namespace is None
    assert config.auto_register is True
    assert config.fail_on_error is False
    assert config.verify_ssl is True
    assert config.api_key is None
    assert config.allow_overwrite is False
    assert config.metadata == {}


def test_plugin_config_custom_values() -> None:
    """Test RegistryPluginConfig with custom values."""
    config = RegistryPluginConfig(
        registry_url="http://registry:8000",
        namespace="custom-service",
        auto_register=False,
        fail_on_error=True,
        verify_ssl=False,
        api_key="secret",
        allow_overwrite=True,
        metadata={"team": "platform"},
    )

    assert config.registry_url == "http://registry:8000"
    assert config.namespace == "custom-service"
    assert config.auto_register is False
    assert config.fail_on_error is True
    assert config.verify_ssl is False
    assert config.api_key == "secret"
    assert config.allow_overwrite is True
    assert config.metadata == {"team": "platform"}


# ============================================================================
# ALLOW OVERWRITE
# ============================================================================


def test_allow_overwrite_passed_to_client(model_manager: ModelManager) -> None:
    """Test that allow_overwrite is passed to client."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.register_schema.return_value = {"id": 1}

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            allow_overwrite=True,
            auto_register=True,
        )

        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str

        # Verify allow_overwrite was passed
        call_args = mock_instance.register_schema.call_args
        assert call_args.kwargs["allow_overwrite"] is True


# ============================================================================
# NAMESPACE BEHAVIOR
# ============================================================================


def test_plugin_with_global_namespace(model_manager: ModelManager) -> None:
    """Test plugin with None namespace (global)."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.register_schema.return_value = {"id": 1}

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            namespace=None,
            auto_register=True,
        )

        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str

        # Verify namespace is None
        call_args = mock_instance.register_schema.call_args
        assert call_args.kwargs["namespace"] is None
        assert call_args.kwargs["registered_by"] == "global"


def test_plugin_with_namespaced_schema(model_manager: ModelManager) -> None:
    """Test plugin with specific namespace."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.register_schema.return_value = {"id": 1}

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            namespace="auth-service",
            auto_register=True,
        )

        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str

        # Verify namespace is set
        call_args = mock_instance.register_schema.call_args
        assert call_args.kwargs["namespace"] == "auth-service"
        assert call_args.kwargs["registered_by"] == "auth-service"


# ============================================================================
# ERROR HANDLING EDGE CASES
# ============================================================================


def test_register_schema_connection_error_warning(
    model_manager: ModelManager,
) -> None:
    """Test that connection errors produce warnings."""
    with (
        patch("pyrmute_registry.plugin.RegistryClient") as mock_client,
        pytest.warns(UserWarning, match="connection failed"),
    ):
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.register_schema.side_effect = RegistryConnectionError(
            "Connection refused"
        )

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
            fail_on_error=False,
        )

        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str


def test_register_schema_unexpected_error_warning(
    model_manager: ModelManager,
) -> None:
    """Test that unexpected errors produce warnings."""
    with (
        patch("pyrmute_registry.plugin.RegistryClient") as mock_client,
        pytest.warns(UserWarning, match="Unexpected error"),
    ):
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.register_schema.side_effect = RuntimeError("Unexpected")

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
            fail_on_error=False,
        )

        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str


def test_sync_with_registry_error(model_manager: ModelManager) -> None:
    """Test sync_with_registry handles errors."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.list_schemas.side_effect = RegistryError("Connection failed")

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            fail_on_error=False,
        )

        status = plugin.sync_with_registry()

        assert status["in_sync"] is False
        assert "error" in status


def test_sync_with_registry_error_with_fail_on_error(
    model_manager: ModelManager,
) -> None:
    """Test sync raises with fail_on_error=True."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.list_schemas.side_effect = RegistryError("Connection failed")

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            fail_on_error=True,
        )

        with pytest.raises(RegistryPluginError, match="Failed to sync"):
            plugin.sync_with_registry()


# ============================================================================
# MODEL VERSION HANDLING
# ============================================================================


def test_auto_registration_with_modelversion(model_manager: ModelManager) -> None:
    """Test auto-registration with ModelVersion objects."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.register_schema.return_value = {"id": 1}

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
        )

        version = ModelVersion(1, 0, 0)

        @model_manager.model("User", version)
        class User(BaseModel):
            name: str

        # Should convert ModelVersion to string
        call_args = mock_instance.register_schema.call_args
        assert call_args.kwargs["version"] == "1.0.0"


# ============================================================================
# INTEGRATION-STYLE TESTS
# ============================================================================


def test_full_plugin_workflow(model_manager: ModelManager) -> None:
    """Test complete plugin workflow."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.register_schema.return_value = {"id": 1}
        mock_instance.list_schemas.return_value = {
            "schemas": [{"model_name": "User", "versions": ["1.0.0"]}]
        }
        mock_instance.get_schema.return_value = {"json_schema": {"type": "object"}}

        with RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            namespace="test-service",
            auto_register=True,
        ) as plugin:
            # Define model (should auto-register)
            @model_manager.model("User", "1.0.0")
            class User(BaseModel):
                name: str

            # Check registration
            assert ("User", "1.0.0") in plugin.get_registered_models()

            status = plugin.sync_with_registry()
            assert status["in_sync"] is True

            schema = plugin.get_registry_schema("User", "1.0.0")
            assert schema is not None

            health = plugin.health_check()
            assert health["plugin_active"] is True


def test_multiple_models_registration(model_manager: ModelManager) -> None:
    """Test registering multiple models."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = True
        mock_instance.register_schema.return_value = {"id": 1}

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
        )

        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str

        @model_manager.model("Product", "1.0.0")
        class Product(BaseModel):
            name: str
            price: float

        @model_manager.model("Order", "1.0.0")
        class Order(BaseModel):
            user_id: str
            product_id: str

        # Should have registered all three models
        assert mock_instance.register_schema.call_count == 3
        assert len(plugin.get_registered_models()) == 3
