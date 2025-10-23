"""Tests for the RegistryPlugin."""

import warnings
from unittest.mock import Mock, patch

import httpx
import pytest
from httpx import codes
from pydantic import BaseModel, ValidationError
from pyrmute import ModelManager, ModelVersion
from pytest import LogCaptureFixture

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


def test_plugin_initialization_with_avro_defaults(model_manager: ModelManager) -> None:
    """Test plugin initialization with default Avro settings."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_client.return_value.health_check.return_value = {"healthy": True}

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
        )

        assert plugin.include_avro is True
        assert plugin.avro_namespace == "com.example"


def test_plugin_initialization_with_custom_avro_namespace(
    model_manager: ModelManager,
) -> None:
    """Test plugin initialization with custom Avro namespace."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_client.return_value.health_check.return_value = {"healthy": True}

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            include_avro=True,
            avro_namespace="com.mycompany.api",
        )

        assert plugin.include_avro is True
        assert plugin.avro_namespace == "com.mycompany.api"


def test_plugin_initialization_avro_disabled(model_manager: ModelManager) -> None:
    """Test plugin initialization with Avro disabled."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_client.return_value.health_check.return_value = {"healthy": True}

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            include_avro=False,
        )

        assert plugin.include_avro is False


def test_plugin_initialization_avro_config_object(
    model_manager: ModelManager,
) -> None:
    """Test plugin initialization with Avro settings in config object."""
    config = RegistryPluginConfig(
        registry_url="http://localhost:8000",
        namespace="test-service",
        include_avro=True,
        avro_namespace="com.test.service",
    )

    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_client.return_value.health_check.return_value = {"healthy": True}

        plugin = RegistryPlugin(model_manager, config=config)

        assert plugin.include_avro is True
        assert plugin.avro_namespace == "com.test.service"


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

    with pytest.raises(
        RegistryPluginError,
        match="Cannot provide both config object and keyword arguments",
    ):
        RegistryPlugin(
            model_manager,
            config=config,
            namespace="test-service",  # type: ignore[call-overload]
        )


def test_plugin_initialization_invalid_kwarg(model_manager: ModelManager) -> None:
    """Test that invalid kwargs raise TypeError."""
    with pytest.raises(ValidationError, match="should be a valid string"):
        RegistryPlugin(
            model_manager,
            registry_url=1,
            invalid_param="value",  # type: ignore[call-overload]
        )


def test_plugin_initialization_without_registry_url(
    model_manager: ModelManager,
) -> None:
    """Test that missing registry URL raises error."""
    with patch.dict("os.environ", {}, clear=True):
        with pytest.raises(RegistryPluginError) as exc_info:
            RegistryPlugin(model_manager)

        assert "registry_url must be provided" in str(exc_info.value)


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

        assert model_manager.model == original_method
        assert plugin._original_model_method is None


def test_auto_register_with_avro_enabled(model_manager: ModelManager) -> None:
    """Test auto-registration includes Avro schema when enabled."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {"healthy": True}
        mock_instance.register_schema.return_value = {"id": 1}

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
            include_avro=True,
            avro_namespace="com.test",
        )

        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str
            email: str

        assert mock_instance.register_schema.call_count == 1

        call_args = mock_instance.register_schema.call_args
        assert call_args.kwargs["avro_schema"] is not None
        avro_schema = call_args.kwargs["avro_schema"]
        assert avro_schema["type"] == "record"
        assert avro_schema["namespace"] == "com.test"


def test_auto_register_without_avro_when_disabled(model_manager: ModelManager) -> None:
    """Test auto-registration excludes Avro schema when disabled."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {"healthy": True}
        mock_instance.register_schema.return_value = {"id": 1}

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
            include_avro=False,
        )

        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str
            email: str

        assert mock_instance.register_schema.call_count == 1

        call_args = mock_instance.register_schema.call_args
        assert call_args.kwargs.get("avro_schema") is None


def test_auto_register_avro_generation_failure_does_not_block_json(
    model_manager: ModelManager, caplog: LogCaptureFixture
) -> None:
    """Test that Avro generation failure doesn't prevent JSON Schema registration."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {"healthy": True}
        mock_instance.register_schema.return_value = {"id": 1}

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
            include_avro=True,
            fail_on_error=False,
        )

        with patch.object(
            model_manager, "get_avro_schema", side_effect=Exception("Avro error")
        ):

            @model_manager.model("User", "1.0.0")
            class User(BaseModel):
                name: str

            assert mock_instance.register_schema.call_count == 1
            call_args = mock_instance.register_schema.call_args
            assert "schema" in call_args.kwargs
            assert call_args.kwargs.get("avro_schema") is None
            assert "Avro error" in caplog.text


def test_auto_register_with_namespace_and_avro(model_manager: ModelManager) -> None:
    """Test auto-registration with both namespace and Avro enabled."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {"healthy": True}
        mock_instance.register_schema.return_value = {"id": 1}

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            namespace="user-service",
            auto_register=True,
            include_avro=True,
            avro_namespace="com.myapp.users",
        )

        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str

        # Check registration call
        call_args = mock_instance.register_schema.call_args
        assert call_args.kwargs["namespace"] == "user-service"
        assert call_args.kwargs["avro_schema"] is not None
        assert call_args.kwargs["avro_schema"]["namespace"] == "com.myapp.users"


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

        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str

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

        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str

        plugin._registered_models.add(("User", "1.0.0"))
        initial_call_count = mock_instance.register_schema.call_count
        plugin.register_schema_safe("User", "1.0.0", {})

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

        assert results["User@1.0.0"] is False


def test_manual_register_model_with_avro(model_manager: ModelManager) -> None:
    """Test manually registering a model with Avro schema."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {"healthy": True}
        mock_instance.register_schema.return_value = {"id": 1}

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=False,
            include_avro=True,
            avro_namespace="com.manual",
        )

        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str
            email: str

        result = plugin.register_model("User", "1.0.0")

        assert result is True
        call_args = mock_instance.register_schema.call_args
        assert call_args.kwargs["avro_schema"] is not None
        assert call_args.kwargs["avro_schema"]["namespace"] == "com.manual"


def test_register_existing_models_with_avro(model_manager: ModelManager) -> None:
    """Test registering multiple existing models with Avro."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {"healthy": True}
        mock_instance.register_schema.return_value = {"id": 1}

        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str

        @model_manager.model("Product", "1.0.0")
        class Product(BaseModel):
            title: str

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=False,
            include_avro=True,
            avro_namespace="com.batch",
        )

        results = plugin.register_existing_models()

        assert len(results) == 2
        assert mock_instance.register_schema.call_count == 2

        for call_args in mock_instance.register_schema.call_args_list:
            assert call_args.kwargs["avro_schema"] is not None
            assert call_args.kwargs["avro_schema"]["namespace"] == "com.batch"


def test_set_avro_config_enable(model_manager: ModelManager) -> None:
    """Test enabling Avro after plugin initialization."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {"healthy": True}

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            include_avro=False,
        )

        assert plugin.include_avro is False

        plugin.set_avro_config(include_avro=True, avro_namespace="com.newns")

        assert plugin.include_avro is True
        assert plugin.avro_namespace == "com.newns"  # type: ignore[unreachable]


def test_set_avro_config_disable(model_manager: ModelManager) -> None:
    """Test disabling Avro after plugin initialization."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {"healthy": True}

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            include_avro=True,
            avro_namespace="com.test",
        )

        assert plugin.include_avro is True

        plugin.set_avro_config(include_avro=False)

        assert plugin.include_avro is False
        # Namespace unchanged
        assert plugin.avro_namespace == "com.test"  # type: ignore[unreachable]


def test_set_avro_config_change_namespace_only(model_manager: ModelManager) -> None:
    """Test changing only the Avro namespace."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {"healthy": True}

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            include_avro=True,
            avro_namespace="com.old",
        )

        plugin.set_avro_config(avro_namespace="com.new")

        assert plugin.include_avro is True
        assert plugin.avro_namespace == "com.new"


def test_set_avro_config_affects_future_registrations(
    model_manager: ModelManager,
) -> None:
    """Test that changing Avro config affects future registrations."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {"healthy": True}
        mock_instance.register_schema.return_value = {"id": 1}

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=False,
            include_avro=False,
        )

        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str

        plugin.register_model("User", "1.0.0")
        call1 = mock_instance.register_schema.call_args
        assert call1.kwargs.get("avro_schema") is None

        plugin.set_avro_config(include_avro=True, avro_namespace="com.enabled")

        @model_manager.model("Product", "1.0.0")
        class Product(BaseModel):
            title: str

        plugin.register_model("Product", "1.0.0")
        call2 = mock_instance.register_schema.call_args
        assert call2.kwargs["avro_schema"] is not None
        assert call2.kwargs["avro_schema"]["namespace"] == "com.enabled"


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

        assert model_manager.model != original_method

        plugin.restore_manager()

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
            assert model_manager.model != original_method

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


def test_get_schema_returns_full_response(model_manager: ModelManager) -> None:
    """Test that get_schema returns RegistrySchemaResponse with all fields."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {"healthy": True}
        mock_instance.get_schema.return_value = {
            "id": 1,
            "namespace": "test-service",
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
            },
            "avro_schema": {
                "type": "record",
                "name": "User",
                "namespace": "com.test",
                "fields": [{"name": "name", "type": "string"}],
            },
            "registered_at": "2025-01-01T00:00:00Z",
            "registered_by": "test-user",
            "meta": {},
            "deprecated": False,
        }

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            namespace="test-service",
        )

        response = plugin.get_registry_schema("User", "1.0.0")

        assert "json_schema" in response
        assert "avro_schema" in response
        assert "version" in response
        assert "registered_by" in response
        assert response["version"] == "1.0.0"
        assert response["avro_schema"]["type"] == "record"


def test_get_schema_without_avro(model_manager: ModelManager) -> None:
    """Test get_schema when Avro schema is not present."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {"healthy": True}
        mock_instance.get_schema.return_value = {
            "id": 1,
            "namespace": None,
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": {"type": "object"},
            "registered_at": "2025-01-01T00:00:00Z",
            "registered_by": "test-user",
            "meta": {},
            "deprecated": False,
        }

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
        )

        response = plugin.get_registry_schema("User", "1.0.0")

        assert "json_schema" in response
        assert "avro_schema" not in response
        assert response["version"] == "1.0.0"


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

            @model_manager.model("User", "1.0.0")
            class User(BaseModel):
                name: str

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

        assert mock_instance.register_schema.call_count == 3
        assert len(plugin.get_registered_models()) == 3


def test_plugin_check_connectivity_healthy(model_manager: ModelManager) -> None:
    """Test plugin connectivity check with healthy registry."""
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {
                "status": "healthy",
                "schemas_count": 10,
            },
        )

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            fail_on_error=False,
        )

        assert plugin.client is not None


def test_plugin_check_connectivity_unhealthy_no_fail() -> None:
    """Test plugin handles unhealthy registry when fail_on_error=False."""
    with (
        patch("httpx.Client.get") as mock_get,
        patch("pyrmute_registry.plugin.ModelManager") as mock_manager,
    ):
        mock_get.return_value = Mock(
            status_code=codes.SERVICE_UNAVAILABLE,
            text="Database down",
        )

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            plugin = RegistryPlugin(
                mock_manager,
                registry_url="http://localhost:8000",
                fail_on_error=False,
            )

            assert len(w) == 1
            assert "unhealthy" in str(w[0].message).lower()
            assert plugin.client is not None


def test_plugin_check_connectivity_unhealthy_with_fail() -> None:
    """Test plugin raises when registry unhealthy and fail_on_error=True."""
    with (
        patch("httpx.Client.get") as mock_get,
        patch("pyrmute_registry.plugin.ModelManager") as mock_manager,
    ):
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {
                "status": "unhealthy",
                "error": "Database connection lost",
            },
        )

        with pytest.raises(RegistryConnectionError) as exc_info:
            RegistryPlugin(
                mock_manager,
                registry_url="http://localhost:8000",
                fail_on_error=True,
            )

        assert "unhealthy" in str(exc_info.value).lower()


def test_plugin_check_connectivity_connection_error_no_fail() -> None:
    """Test plugin handles connection errors when fail_on_error=False."""
    with (
        patch("httpx.Client.get") as mock_get,
        patch("pyrmute_registry.plugin.ModelManager") as mock_manager,
    ):
        mock_get.side_effect = httpx.ConnectError("Connection refused")

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            plugin = RegistryPlugin(
                mock_manager,
                registry_url="http://localhost:8000",
                fail_on_error=False,
            )

            assert len(w) == 1
            assert "unavailable" in str(w[0].message).lower()
            assert plugin.client is not None


def test_plugin_check_connectivity_connection_error_with_fail() -> None:
    """Test plugin raises on connection errors when fail_on_error=True."""
    with (
        patch("httpx.Client.get") as mock_get,
        patch("pyrmute_registry.plugin.ModelManager") as mock_manager,
    ):
        mock_get.side_effect = httpx.ConnectError("Connection refused")

        with pytest.raises(RegistryConnectionError) as exc_info:
            RegistryPlugin(
                mock_manager,
                registry_url="http://localhost:8000",
                fail_on_error=True,
            )

        assert "unable to connect" in str(exc_info.value).lower()


def test_plugin_check_connectivity_timeout_error() -> None:
    """Test plugin handles timeout errors gracefully."""
    with (
        patch("httpx.Client.get") as mock_get,
        patch("pyrmute_registry.plugin.ModelManager") as mock_manager,
    ):
        mock_get.side_effect = httpx.TimeoutException("Request timeout")

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            RegistryPlugin(
                mock_manager,
                registry_url="http://localhost:8000",
                fail_on_error=False,
            )

            assert len(w) == 1
            assert "unavailable" in str(w[0].message).lower()


def test_plugin_check_connectivity_malformed_response() -> None:
    """Test plugin handles malformed health response."""
    with (
        patch("httpx.Client.get") as mock_get,
        patch("pyrmute_registry.plugin.ModelManager") as mock_manager,
    ):
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {"some_field": "some_value"},
        )

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            plugin = RegistryPlugin(
                mock_manager,
                registry_url="http://localhost:8000",
                fail_on_error=False,
            )

            assert len(w) == 1
            assert plugin.client is not None


def test_plugin_health_check_method() -> None:
    """Test plugin's health_check method returns correct status."""
    with (
        patch("httpx.Client.get") as mock_get,
        patch("pyrmute_registry.plugin.ModelManager") as mock_manager,
    ):
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {"status": "healthy", "schemas_count": 5},
        )

        plugin = RegistryPlugin(
            mock_manager,
            registry_url="http://localhost:8000",
            namespace="test-service",
        )

        health = plugin.health_check()

        assert health["plugin_active"] is True
        assert health["registry_healthy"] is True
        assert health["namespace"] == "test-service"
        assert "registry_details" in health


def test_plugin_health_check_unhealthy_registry() -> None:
    """Test plugin health check reports unhealthy registry."""
    with (
        patch("httpx.Client.get") as mock_get,
        patch("pyrmute_registry.plugin.ModelManager") as mock_manager,
    ):
        # Initial connectivity check - healthy
        mock_get.return_value = Mock(
            status_code=codes.OK,
            json=lambda: {"status": "healthy"},
        )

        plugin = RegistryPlugin(
            mock_manager,
            registry_url="http://localhost:8000",
            fail_on_error=False,
        )

        mock_get.return_value = Mock(
            status_code=codes.SERVICE_UNAVAILABLE,
            text="Service down",
        )

        health = plugin.health_check()

        assert health["plugin_active"] is True
        assert health["registry_healthy"] is False
        assert "registry_details" in health
        assert health["registry_details"]["healthy"] is False


def test_health_check_includes_avro_info(model_manager: ModelManager) -> None:
    """Test that health check includes Avro configuration info."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {
            "healthy": True,
            "status": "healthy",
        }

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            include_avro=True,
            avro_namespace="com.health",
        )

        health = plugin.health_check()

        assert health["plugin_active"] is True
        assert health["include_avro"] is True
        assert health["avro_namespace"] == "com.health"


def test_health_check_avro_namespace_none_when_disabled(
    model_manager: ModelManager,
) -> None:
    """Test that avro_namespace is None in health check when Avro disabled."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {
            "healthy": True,
            "status": "healthy",
        }

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            include_avro=False,
        )

        health = plugin.health_check()

        assert health["include_avro"] is False
        assert health["avro_namespace"] is None


def test_health_check_with_registry_details(model_manager: ModelManager) -> None:
    """Test health check includes detailed registry information."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        detailed_health = {
            "healthy": True,
            "status": "healthy",
            "schemas_count": 42,
            "version": "1.2.3",
        }
        mock_instance.health_check.return_value = detailed_health

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
        )

        health = plugin.health_check()

        assert health["registry_healthy"] is True
        assert health["registry_details"] == detailed_health
        assert health["registry_details"]["schemas_count"] == 42


def test_register_complex_model_with_avro(model_manager: ModelManager) -> None:
    """Test registering a complex model with nested types and Avro."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {"healthy": True}
        mock_instance.register_schema.return_value = {"id": 1}

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
            include_avro=True,
            avro_namespace="com.complex",
        )

        @model_manager.model("Address", "1.0.0")
        class Address(BaseModel):
            street: str
            city: str
            zipcode: str

        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str
            age: int
            email: str | None = None
            addresses: list[Address] = []

        assert mock_instance.register_schema.call_count == 2

        user_call = next(
            call
            for call in mock_instance.register_schema.call_args_list
            if call.kwargs["model_name"] == "User"
        )
        avro_schema = user_call.kwargs["avro_schema"]
        assert avro_schema is not None
        assert avro_schema["namespace"] == "com.complex"


def test_register_model_with_optional_fields_avro(
    model_manager: ModelManager,
) -> None:
    """Test Avro generation for models with optional fields."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {"healthy": True}
        mock_instance.register_schema.return_value = {"id": 1}

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
            include_avro=True,
        )

        @model_manager.model("OptionalUser", "1.0.0")
        class OptionalUser(BaseModel):
            name: str
            email: str | None = None
            age: int | None = None

        call_args = mock_instance.register_schema.call_args
        avro_schema = call_args.kwargs["avro_schema"]

        assert avro_schema is not None
        fields = {field["name"]: field for field in avro_schema["fields"]}

        assert "name" in fields
        assert "email" in fields
        assert "age" in fields


def test_multiple_versions_with_avro(model_manager: ModelManager) -> None:
    """Test registering multiple versions of a model with Avro."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {"healthy": True}
        mock_instance.register_schema.return_value = {"id": 1}

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
            include_avro=True,
            avro_namespace="com.versioned",
        )

        @model_manager.model("User", "1.0.0")
        class UserV1(BaseModel):
            name: str

        @model_manager.model("User", "2.0.0")
        class UserV2(BaseModel):
            name: str
            email: str

        @model_manager.model("User", "3.0.0")
        class UserV3(BaseModel):
            name: str
            email: str
            age: int

        assert mock_instance.register_schema.call_count == 3

        for call_args in mock_instance.register_schema.call_args_list:
            assert call_args.kwargs["avro_schema"] is not None
            assert call_args.kwargs["avro_schema"]["namespace"] == "com.versioned"


def test_registration_continues_on_avro_error_when_fail_on_error_false(
    model_manager: ModelManager, caplog: LogCaptureFixture
) -> None:
    """Test registration continues if Avro generation fails and fail_on_error=False."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {"healthy": True}
        mock_instance.register_schema.return_value = {"id": 1}

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
            include_avro=True,
            fail_on_error=False,
        )

        with patch.object(
            model_manager,
            "get_avro_schema",
            side_effect=Exception("Avro conversion error"),
        ):

            @model_manager.model("User", "1.0.0")
            class User(BaseModel):
                name: str

            assert mock_instance.register_schema.call_count == 1
            call_args = mock_instance.register_schema.call_args
            assert "schema" in call_args.kwargs
            assert call_args.kwargs.get("avro_schema") is None
            assert "Avro conversion error" in caplog.text


def test_registration_error_raises_when_fail_on_error_true(
    model_manager: ModelManager,
) -> None:
    """Test that actual registration errors raise when fail_on_error=True."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {"healthy": True}
        mock_instance.register_schema.side_effect = RegistryError("Connection failed")

        RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            auto_register=True,
            fail_on_error=True,
        )

        with pytest.raises(RegistryPluginError) as exc_info:

            @model_manager.model("User", "1.0.0")
            class User(BaseModel):
                name: str

        assert "connection failed" in str(exc_info.value).lower()


def test_create_plugin_with_avro_settings(model_manager: ModelManager) -> None:
    """Test create_plugin factory function with Avro settings."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_client.return_value.health_check.return_value = {"healthy": True}

        plugin = create_plugin(
            model_manager,
            registry_url="http://localhost:8000",
            namespace="factory-test",
            include_avro=True,
            avro_namespace="com.factory",
        )

        assert isinstance(plugin, RegistryPlugin)
        assert plugin.include_avro is True
        assert plugin.avro_namespace == "com.factory"


def test_create_plugin_without_avro(model_manager: ModelManager) -> None:
    """Test create_plugin factory function with Avro disabled."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_client.return_value.health_check.return_value = {"healthy": True}

        plugin = create_plugin(
            model_manager,
            registry_url="http://localhost:8000",
            include_avro=False,
        )

        assert isinstance(plugin, RegistryPlugin)
        assert plugin.include_avro is False


def test_full_workflow_with_avro(model_manager: ModelManager) -> None:
    """Test complete workflow: register, fetch, with Avro enabled."""
    with patch("pyrmute_registry.plugin.RegistryClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.health_check.return_value = {"healthy": True}
        mock_instance.register_schema.return_value = {"id": 1}
        mock_instance.get_schema.return_value = {
            "id": 1,
            "model_name": "User",
            "version": "1.0.0",
            "json_schema": {"type": "object"},
            "avro_schema": {"type": "record", "name": "User"},
            "registered_at": "2025-01-01T00:00:00Z",
            "registered_by": "workflow-test",
            "meta": {},
            "deprecated": False,
        }

        plugin = RegistryPlugin(
            model_manager,
            registry_url="http://localhost:8000",
            namespace="workflow",
            auto_register=True,
            include_avro=True,
            avro_namespace="com.workflow",
        )

        @model_manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str
            email: str

        assert len(plugin.get_registered_models()) == 1

        response = plugin.get_registry_schema("User", "1.0.0")
        assert "json_schema" in response
        assert "avro_schema" in response

        health = plugin.health_check()
        assert health["include_avro"] is True
        assert health["avro_namespace"] == "com.workflow"
