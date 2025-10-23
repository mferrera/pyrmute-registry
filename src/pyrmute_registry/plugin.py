"""Plugin to connect pyrmute ModelManager with schema registry."""

import logging
import os
import warnings
from collections.abc import Callable
from types import TracebackType
from typing import Any, Self, TypeAlias, cast, overload

from pydantic import BaseModel, Field
from pyrmute import ModelManager, ModelVersion
from pyrmute.avro_types import AvroRecordSchema
from pyrmute.types import DecoratedBaseModel

from .client import RegistryClient
from .exceptions import (
    RegistryConnectionError,
    RegistryError,
    RegistryPluginError,
    SchemaConflictError,
)
from .types import JsonSchema, RegistrySchemaResponse

logger = logging.getLogger(__name__)

ModelCallable: TypeAlias = Callable[
    [str, str | ModelVersion, bool, bool],
    Callable[[type[DecoratedBaseModel]], type[DecoratedBaseModel]],
]


class RegistryPluginConfig(BaseModel):
    """Configuration for RegistryPlugin.

    Attributes:
        registry_url: URL of the registry server (or from PYRMUTE_REGISTRY_URL env).
        namespace: Optional namespace for multi-tenant scoping. If None, schemas are
            registered as global. Examples: "auth-service", "payment-api".
        auto_register: Whether to automatically register schemas on model definition.
        fail_on_error: Whether to raise exceptions on registration errors.
        verify_ssl: Whether to verify SSL certificates.
        api_key: Optional API key for authentication (or from PYRMUTE_REGISTRY_API_KEY
            env).
        allow_overwrite: Whether to allow overwriting existing schemas.
        metadata: Default metadata to include with all registrations.
        include_avro: Whether to generate and register Avro schemas alongside JSON
            Schema.
        avro_namespace: Namespace for Avro schemas (e.g., "com.myapp"). Only used if
            include_avro is True.
    """

    registry_url: str | None = Field(
        default=None,
        description="Registry server URL (or from PYRMUTE_REGISTRY_URL env)",
    )
    namespace: str | None = Field(
        default=None,
        description="Optional namespace for scoping (None for global schemas)",
    )
    auto_register: bool = Field(
        default=True,
        description="Auto-register schemas on model definition",
    )
    fail_on_error: bool = Field(
        default=False,
        description="Raise exceptions on registration errors",
    )
    verify_ssl: bool = Field(
        default=True,
        description="Verify SSL certificates",
    )
    api_key: str | None = Field(
        default=None,
        description="API key for authentication (or from PYRMUTE_REGISTRY_API_KEY env)",
    )
    allow_overwrite: bool = Field(
        default=False,
        description="Allow overwriting existing schemas",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Default metadata for all registrations",
    )
    include_avro: bool = Field(
        default=True,
        description="Generate and register Avro schemas alongside JSON Schema",
    )
    avro_namespace: str = Field(
        default="com.example",
        description="Namespace for Avro schemas (e.g., 'com.myapp')",
    )


class RegistryPlugin:
    """Plugin for automatic schema registration with a centralized registry.

    This plugin wraps a Pyrmute ModelManager to automatically register schemas with a
    remote registry service whenever models are defined. It provides functionality for
    schema synchronization, comparison, and validation.

    The plugin supports both global and namespaced schemas, and can optionally generate
    and register Avro schemas alongside JSON Schema.

    Examples:
        Basic usage with auto-registration (namespaced):
        ```python
        from pyrmute import ModelManager
        from pyrmute_registry import RegistryPlugin

        manager = ModelManager()
        plugin = RegistryPlugin(
            manager,
            registry_url="http://localhost:8000",
            namespace="user-service",
        )

        # Schemas are automatically registered when models are defined
        @manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str
            email: str
        ```

        With Avro schema registration:
        ```python
        plugin = RegistryPlugin(
            manager,
            registry_url="http://localhost:8000",
            namespace="user-service",
            include_avro=True,
            avro_namespace="com.myapp.users",
        )
        ```

        Global schema registration:
        ```python
        plugin = RegistryPlugin(
            manager,
            registry_url="http://localhost:8000",
            namespace=None,  # Register as global schemas
        )
        ```

        Using configuration object:
        ```python
        from pyrmute_registry import RegistryPlugin, RegistryPluginConfig

        config = RegistryPluginConfig(
            registry_url="http://localhost:8000",
            namespace="user-service",
            auto_register=True,
            fail_on_error=False,
            include_avro=True,
            avro_namespace="com.myapp",
        )
        plugin = RegistryPlugin(manager, config=config)
        ```

        Manual registration without auto-registration:
        ```python
        plugin = RegistryPlugin(
            manager,
            registry_url="http://localhost:8000",
            namespace="user-service",
            auto_register=False,
        )

        # Define models first
        @manager.model("User", "1.0.0")
        class User(BaseModel):
            name: str

        # Register manually later
        results = plugin.register_existing_models()
        ```

        Using as context manager:
        ```python
        with RegistryPlugin(manager, registry_url="...") as plugin:
            # Plugin automatically cleans up on exit
            @manager.model("User", "1.0.0")
            class User(BaseModel):
                name: str
        ```
    """

    @overload
    def __init__(
        self: Self,
        manager: ModelManager,
        *,
        config: RegistryPluginConfig,
    ) -> None: ...

    @overload
    def __init__(
        self: Self,
        manager: ModelManager,
        *,
        registry_url: str | None = None,
        namespace: str | None = None,
        auto_register: bool = True,
        fail_on_error: bool = False,
        verify_ssl: bool = True,
        api_key: str | None = None,
        allow_overwrite: bool = False,
        metadata: dict[str, Any] | None = None,
        include_avro: bool = True,
        avro_namespace: str = "com.example",
    ) -> None: ...

    def __init__(
        self: Self,
        manager: ModelManager,
        config: RegistryPluginConfig | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the registry plugin.

        The plugin can be initialized in two ways:

        1. With a `RegistryPluginConfig` object (recommended)
        2. With individual keyword arguments (backwards compatible)

        Args:
            manager: Pyrmute ModelManager instance to wrap. The plugin will intercept
                model registration calls to automatically register schemas with the
                registry.
            config: Configuration object containing all plugin settings. If provided,
                all other keyword arguments must be omitted. This is the recommended
                way to configure the plugin for better maintainability and reusability.
            registry_url: URL of the registry server (e.g., `http://localhost:8000`).
                If not provided, will use `PYRMUTE_REGISTRY_URL` environment variable.
                Required if config is not provided.
            namespace: Optional namespace for multi-tenant scoping. If None, schemas
                are registered as global. If provided, schemas are scoped to this
                namespace (e.g., `user-service`, `payment-api`). Can also be set via
                `PYRMUTE_REGISTRY_NAMESPACE` environment variable.
            auto_register: Whether to automatically register schemas when models
                are defined. If `True`, schemas are registered immediately upon model
                creation. If `False`, schemas must be registered manually via
                `register_model()`. Default is `True`.
            fail_on_error: Whether to raise exceptions when registration fails.
                If `True`, registration errors will propagate and potentially crash
                the application. If `False`, errors are logged as warnings and the
                application continues. Default is `False` for non-blocking behavior.
            verify_ssl: Whether to verify SSL certificates when connecting to
                the registry. Should be `True` in production for security. Can be
                set to `False` for development with self-signed certificates.
                Default is `True`.
            api_key: Optional API key for authenticating with the registry server.
                If not provided, will use `PYRMUTE_REGISTRY_API_KEY` environment
                variable. Only required if the registry server has authentication
                enabled. Default is `None`.
            allow_overwrite: Whether to allow overwriting existing schema versions
                in the registry. If `True`, registering a schema with an existing
                model name and version will update the existing entry. If `False`,
                attempting to register a duplicate will fail. Default is `False`
                to prevent accidental overwrites.
            metadata: Default metadata dictionary to include with all schema
                registrations. This metadata will be merged with any model-specific
                metadata. Useful for tracking deployment info, team ownership, etc.
                Default is an empty dict.
            include_avro: Whether to generate and register Avro schemas alongside
                JSON Schema. If `True`, both schemas will be sent to the registry.
                Default is `True`.
            avro_namespace: Namespace for generated Avro schemas (e.g., 'com.myapp').
                Only used when `include_avro=True`. Default is 'com.example'.
            **kwargs: When config is `None`, accepts any of the individual parameters
                listed above as keyword arguments. When config is provided, no
                additional kwargs should be passed.

        Raises:
            RegistryPluginError: If configuration is invalid.
            RegistryConnectionError: If fail_on_error=True and registry is unreachable.

        Examples:
            With config object (recommended):
            ```python
            config = RegistryPluginConfig(
                registry_url="http://registry:8000",
                namespace="api-service",
                include_avro=True,
                avro_namespace="com.mycompany.api",
            )
            plugin = RegistryPlugin(manager, config=config)
            ```

            With keyword arguments:
            ```python
            plugin = RegistryPlugin(
                manager,
                registry_url="http://registry:8000",
                namespace="api-service",
                include_avro=True,
                avro_namespace="com.mycompany.api",
            )
            ```

            Without Avro:
            ```python
            plugin = RegistryPlugin(
                manager,
                registry_url="http://registry:8000",
                include_avro=False,
            )
            ```
        """
        self.manager = manager

        if config is not None:
            if kwargs:
                raise RegistryPluginError(
                    "Cannot provide both config object and keyword arguments"
                )
        else:
            config = RegistryPluginConfig.model_validate(kwargs)

        self.registry_url = config.registry_url or os.getenv("PYRMUTE_REGISTRY_URL")
        if not self.registry_url:
            raise RegistryPluginError(
                "registry_url must be provided either as argument or "
                "via PYRMUTE_REGISTRY_URL environment variable"
            )

        # Namespace is optional - None means global schemas
        self.namespace = config.namespace or os.getenv("PYRMUTE_REGISTRY_NAMESPACE")

        self.auto_register = config.auto_register
        self.fail_on_error = config.fail_on_error
        self.allow_overwrite = config.allow_overwrite
        self.default_metadata = config.metadata.copy()

        # Avro configuration
        self.include_avro = config.include_avro
        self.avro_namespace = config.avro_namespace

        api_key = config.api_key or os.getenv("PYRMUTE_REGISTRY_API_KEY")

        self.client = RegistryClient(
            self.registry_url,
            verify_ssl=config.verify_ssl,
            api_key=api_key,
        )

        self._registered_models: set[tuple[str, str]] = set()
        self._original_model_method: Callable[..., Any] | None = None
        self._original_migration_method = None

        self._check_connectivity()

        if self.auto_register:
            self._patch_manager()

        scope = f"namespace '{self.namespace}'" if self.namespace else "global scope"
        avro_status = (
            f" with Avro (namespace={self.avro_namespace})"
            if self.include_avro
            else " (JSON only)"
        )
        logger.info(
            f"RegistryPlugin initialized for {scope}{avro_status} "
            f"with registry at {self.registry_url}"
        )

    def _check_connectivity(self: Self) -> None:
        """Check if registry is reachable and healthy.

        Raises:
            RegistryConnectionError: If fail_on_error=True and registry is unreachable.

        Warns:
            UserWarning: If fail_on_error=False and registry is unhealthy or
                unreachable.
        """
        try:
            health = self.client.health_check(detailed=True)

            if isinstance(health, dict) and not health.get("healthy", False):
                msg = f"Registry server at {self.registry_url} is unhealthy: {health}"
                logger.warning(msg)
                if self.fail_on_error:
                    raise RegistryConnectionError(msg)
                warnings.warn(
                    f"Registry is unhealthy but plugin will continue. "
                    f"Schema registration may fail. Health status: {health}",
                    UserWarning,
                    stacklevel=2,
                )
        except RegistryConnectionError as e:
            msg = f"Registry server at {self.registry_url} is not available: {e}"
            logger.warning(msg)
            if self.fail_on_error:
                raise
            warnings.warn(
                f"Registry is unavailable but plugin will continue. "
                f"Schema registration will be skipped. Error: {e}",
                UserWarning,
                stacklevel=2,
            )

    def register_schema_safe(
        self: Self,
        name: str,
        version: str,
        schema: JsonSchema,
        metadata: dict[str, Any] | None = None,
        avro_schema: AvroRecordSchema | None = None,
    ) -> bool:
        """Safely register a schema with error handling.

        Args:
            name: Model name.
            version: Model version.
            schema: JSON schema.
            metadata: Optional metadata.
            avro_schema: Optional Avro schema.

        Returns:
            `True` if registration succeeded, `False` otherwise.
        """
        key = (name, version)
        if key in self._registered_models:
            logger.debug(f"Schema {name} v{version} already registered, skipping")
            return True

        try:
            full_metadata = {**self.default_metadata, **(metadata or {})}

            self.client.register_schema(
                model_name=name,
                version=version,
                schema=schema,
                registered_by=self.namespace or "global",
                namespace=self.namespace,
                avro_schema=avro_schema,
                metadata=full_metadata,
                allow_overwrite=self.allow_overwrite,
            )

            self._registered_models.add(key)
            identifier = f"{self.namespace}::{name}" if self.namespace else name
            schema_types = "JSON+Avro" if avro_schema else "JSON"
            logger.info(
                f"✓ Registered {identifier} v{version} ({schema_types}) to registry"
            )
            return True

        except SchemaConflictError as e:
            msg = f"Schema conflict for {name} v{version}: {e}"
            logger.warning(msg)
            if self.fail_on_error:
                raise RegistryPluginError(msg) from e
            warnings.warn(msg, UserWarning, stacklevel=3)
            return False

        except RegistryConnectionError as e:
            msg = f"Connection error registering {name} v{version}: {e}"
            logger.error(msg)
            if self.fail_on_error:
                raise RegistryPluginError(msg) from e
            warnings.warn(
                f"Registry connection failed. Schema registration skipped. Error: {e}",
                UserWarning,
                stacklevel=3,
            )
            return False

        except RegistryError as e:
            msg = f"Failed to register {name} v{version}: {e}"
            logger.error(msg)
            if self.fail_on_error:
                raise RegistryPluginError(msg) from e
            warnings.warn(msg, UserWarning, stacklevel=3)
            return False

        except Exception as e:
            msg = f"Unexpected error registering {name} v{version}: {e}"
            logger.exception(msg)
            if self.fail_on_error:
                raise RegistryPluginError(msg) from e
            warnings.warn(msg, UserWarning, stacklevel=3)
            return False

    def _patch_manager(self: Self) -> None:
        """Monkey-patch the manager's model decorator to auto-register schemas."""
        self._original_model_method = self.manager.model

        def model_with_registry(
            name: str,
            version: str | ModelVersion,
            enable_ref: bool = False,
            backward_compatible: bool = False,
        ) -> Callable[[type[DecoratedBaseModel]], type[DecoratedBaseModel]]:
            """Wrapper around manager.model that adds registry registration."""

            def decorator(cls: type[DecoratedBaseModel]) -> type[DecoratedBaseModel]:
                assert self._original_model_method is not None
                result = self._original_model_method(
                    name, version, enable_ref, backward_compatible
                )(cls)

                version_str = (
                    str(version) if isinstance(version, ModelVersion) else version
                )

                try:
                    schema = self.manager.get_schema(name, version_str)

                    avro_schema = None
                    if self.include_avro:
                        try:
                            avro_schema = self.manager.get_avro_schema(
                                name,
                                version_str,
                                namespace=self.avro_namespace,
                                include_docs=True,
                            )
                        except Exception as avro_error:
                            # Log but don't fail - Avro generation is optional
                            logger.warning(
                                f"Failed to generate Avro schema for {name} "
                                f"v{version_str}: {avro_error}. Continuing "
                                "with JSON Schema only."
                            )

                    metadata = {
                        "enable_ref": enable_ref,
                        "backward_compatible": backward_compatible,
                    }

                    self.register_schema_safe(
                        name, version_str, schema, metadata, avro_schema
                    )

                except Exception as e:
                    msg = (
                        f"Failed to get or register schema for {name} "
                        f"v{version_str}: {e}"
                    )
                    logger.error(msg)
                    if self.fail_on_error:
                        raise RegistryPluginError(msg) from e
                    warnings.warn(msg, UserWarning, stacklevel=2)

                return result  # type: ignore[no-any-return]

            return decorator

        self.manager.model = model_with_registry  # type: ignore[method-assign]
        logger.debug("manager.model method patched for auto-registration")

    def restore_manager(self: Self) -> None:
        """Restore the original manager methods (undo patching).

        This removes the auto-registration wrapper and returns the manager to its
        original state.
        """
        if self._original_model_method is not None:
            self.manager.model = self._original_model_method  # type: ignore[method-assign]
            self._original_model_method = None
            logger.debug("manager.model method restored to original")

    def register_existing_models(
        self: Self,
        models: list[tuple[str, str]] | None = None,
    ) -> dict[str, bool]:
        """Register existing models that were defined before plugin initialization.

        Args:
            models: Optional list of `(name, version)` tuples to register.  If `None`,
                registers all models in the manager.

        Returns:
            Dict mapping `"name@version"` to registration success status.

        Examples:
            Register all existing models:
            ```python
            # Define models before plugin
            @manager.model("User", "1.0.0")
            class UserV1(BaseModel):
                name: str

            @manager.model("User", "2.0.0")
            class UserV2(BaseModel):
                name: str
                email: str

            # Create plugin and register existing models
            plugin = RegistryPlugin(manager, auto_register=False)
            results = plugin.register_existing_models()
            # {"User@1.0.0": True, "User@2.0.0": True}
            ```

            Register specific models only:
            ```python
            results = plugin.register_existing_models([
                ("User", "1.0.0"),
                ("Product", "1.0.0"),
            ])
            ```
        """
        results: dict[str, bool] = {}

        if models is None:
            models = []
            for model_name in self.manager.list_models():
                for model_version in self.manager.list_versions(model_name):
                    models.append((model_name, str(model_version)))

        for name, version in models:
            try:
                schema = self.manager.get_schema(name, version)

                avro_schema = None
                if self.include_avro:
                    try:
                        avro_schema = self.manager.get_avro_schema(
                            name,
                            version,
                            namespace=self.avro_namespace,
                            include_docs=True,
                        )
                    except Exception as avro_error:
                        logger.warning(
                            f"Failed to generate Avro schema for {name} v{version}: "
                            f"{avro_error}. Registering JSON Schema only."
                        )

                success = self.register_schema_safe(
                    name, version, schema, None, avro_schema
                )
                results[f"{name}@{version}"] = success
            except Exception as e:
                msg = f"Failed to register {name}@{version}: {e}"
                logger.error(msg)
                if self.fail_on_error:
                    raise RegistryPluginError(msg) from e
                results[f"{name}@{version}"] = False

        return results

    def register_model(
        self: Self,
        name: str,
        version: str,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Manually register a specific model version.

        Args:
            name: Model name.
            version: Model version.
            metadata: Optional metadata to include with registration.

        Returns:
            `True` if registration succeeded, `False` otherwise.

        Examples:
            ```python
            # Register a specific model
            success = plugin.register_model("User", "1.0.0")

            # With custom metadata
            success = plugin.register_model(
                "User", "1.0.0",
                metadata={"team": "backend", "priority": "high"}
        )
        ```
        """
        try:
            schema = self.manager.get_schema(name, version)

            avro_schema = None
            if self.include_avro:
                try:
                    avro_schema = self.manager.get_avro_schema(
                        name,
                        version,
                        namespace=self.avro_namespace,
                        include_docs=True,
                    )
                except Exception as avro_error:
                    logger.warning(
                        f"Failed to generate Avro schema for {name} v{version}: "
                        f"{avro_error}. Registering JSON Schema only."
                    )

            return self.register_schema_safe(
                name, version, schema, metadata, avro_schema
            )
        except Exception as e:
            msg = f"Failed to register {name} v{version}: {e}"
            logger.error(msg)
            if self.fail_on_error:
                raise RegistryPluginError(msg) from e
            return False

    def sync_with_registry(self) -> dict[str, Any]:
        """Synchronize local models with the registry.

        Compares local models with registry and identifies:

        - Models only in local
        - Models only in registry
        - Version mismatches

        Returns:
            Dict with sync status and recommendations containing:

            - `local_only`: Models present locally but not in registry.
            - `registry_only`: Models present in registry but not locally.
            - `version_mismatches`: Models with different versions.
            - `in_sync`: Boolean indicating if everything is synchronized.

        Examples:
            Check sync status:
            ```python
            status = plugin.sync_with_registry()

            if not status["in_sync"]:
                if status["local_only"]:
                    print(f"Register these: {status['local_only']}")
                if status["registry_only"]:
                    print(f"Missing locally: {status['registry_only']}")
                if status["version_mismatches"]:
                    print(f"Version conflicts: {status['version_mismatches']}")
            ```

            Auto-sync local models to registry:
            ```python
            status = plugin.sync_with_registry()
            for model_name, versions in status["local_only"].items():
                for version in versions:
                    plugin.register_existing_models([(model_name, version)])
            ```
        """
        try:
            # Get all local models
            local_models: dict[str, Any] = {}
            for name in self.manager.list_models():
                versions = {str(v) for v in self.manager.list_versions(name)}
                local_models[name] = versions

            # Get all registry models for this namespace
            registry_data = self.client.list_schemas(namespace=self.namespace)
            registry_models: dict[str, Any] = {}
            for model_info in registry_data.get("schemas", []):
                name = model_info["model_name"]
                versions = set(model_info.get("versions", []))
                registry_models[name] = versions

            # Calculate differences
            local_names = set(local_models.keys())
            registry_names = set(registry_models.keys())

            local_only = {}
            for name in local_names - registry_names:
                local_only[name] = list(local_models[name])

            registry_only = {}
            for name in registry_names - local_names:
                registry_only[name] = list(registry_models[name])

            version_mismatches = {}
            for name in local_names & registry_names:
                local_vers = local_models[name]
                registry_vers = registry_models[name]
                if local_vers != registry_vers:
                    version_mismatches[name] = {
                        "local_only": list(local_vers - registry_vers),
                        "registry_only": list(registry_vers - local_vers),
                    }

            return {
                "local_only": local_only,
                "registry_only": registry_only,
                "version_mismatches": version_mismatches,
                "in_sync": not (local_only or registry_only or version_mismatches),
            }

        except RegistryError as e:
            msg = f"Failed to sync with registry: {e}"
            logger.error(msg)
            if self.fail_on_error:
                raise RegistryPluginError(msg) from e
            return {
                "error": str(e),
                "in_sync": False,
            }

    def get_registry_schema(
        self,
        model_name: str,
        version: str,
    ) -> RegistrySchemaResponse:
        """Retrieve a schema from the registry.

        Args:
            model_name: Name of the model.
            version: Version string.

        Returns:
            Schema data from registry including json_schema, optional avro_schema, and
            metadata.

        Raises:
            RegistryPluginError: If retrieval fails.

        Examples:
            ```python
            schema_data = plugin.get_registry_schema("User", "1.0.0")
            print(schema_data["json_schema"])  # The JSON schema
            print(schema_data.get("avro_schema"))  # The Avro schema (if available)
            print(schema_data["registered_by"])  # Service that registered it
            ```
        """
        try:
            return self.client.get_schema(model_name, version, namespace=self.namespace)
        except RegistryError as e:
            msg = f"Failed to retrieve schema {model_name} v{version}: {e}"
            logger.error(msg)
            raise RegistryPluginError(msg) from e

    def compare_with_registry(
        self,
        model_name: str,
        version: str,
    ) -> dict[str, Any]:
        """Compare local model schema with registry version.

        Args:
            model_name: Name of the model.
            version: Version string.

        Returns:
            Dict with comparison results including:

            - `matches`: Boolean indicating if schemas match.
            - `local_schema`: The local schema.
            - `registry_schema`: The registry schema.
            - `differences`: Dict of differences (if schemas don't match).

        Examples:
            Detect schema drift:
            ```python
            result = plugin.compare_with_registry("User", "1.0.0")

            if not result["matches"]:
                print(f"Schema drift detected!")
                print(f"Added: {result['differences']['properties_added']}")
                print(f"Removed: {result['differences']['properties_removed']}")
            ```

            Compare before deployment:
            ```python
            models_to_check = [("User", "1.0.0"), ("Product", "2.0.0")]

            for model, version in models_to_check:
                result = plugin.compare_with_registry(model, version)
                if not result["matches"]:
                    raise ValueError(f"Schema mismatch for {model} v{version}")
            ```
        """
        try:
            local_schema: dict[str, Any] = self.manager.get_schema(model_name, version)

            registry_data = self.client.get_schema(
                model_name, version, namespace=self.namespace
            )
            registry_schema = registry_data.get("json_schema", {})

            matches = local_schema == registry_schema

            result = {
                "model_name": model_name,
                "version": version,
                "matches": matches,
                "local_schema": local_schema,
                "registry_schema": registry_schema,
            }

            if not matches:
                local_props = set(local_schema.get("properties", {}).keys())
                registry_props = set(
                    cast("dict[str, Any]", registry_schema.get("properties", {})).keys()
                )

                result["differences"] = {
                    "properties_added": list(local_props - registry_props),
                    "properties_removed": list(registry_props - local_props),
                }

            return result

        except Exception as e:
            msg = f"Failed to compare schemas for {model_name} v{version}: {e}"
            logger.error(msg)
            if self.fail_on_error:
                raise RegistryPluginError(msg) from e
            return {
                "model_name": model_name,
                "version": version,
                "error": str(e),
                "matches": False,
            }

    def validate_against_registry(
        self,
        model_name: str,
        version: str,
        raise_on_mismatch: bool = False,
    ) -> bool:
        """Validate that local schema matches registry.

        Args:
            model_name: Name of the model.
            version: Version string.
            raise_on_mismatch: Whether to raise exception on mismatch.

        Returns:
            `True` if schemas match, `False` otherwise.

        Raises:
            RegistryPluginError: If `raise_on_mismatch=True` and schemas don't match.

        Examples:
            Validate before proceeding:
            ```python
            if not plugin.validate_against_registry("User", "1.0.0"):
                print("Warning: Schema mismatch detected")
            ```

            Strict validation (raises on mismatch):
            ```python
            try:
                plugin.validate_against_registry(
                    "User", "1.0.0",
                    raise_on_mismatch=True
                )
            except RegistryPluginError as e:
                print(f"Validation failed: {e}")
            ```
        """
        comparison = self.compare_with_registry(model_name, version)

        if not comparison.get("matches", False):
            msg = (
                f"Schema mismatch for {model_name} v{version}. "
                f"Differences: {comparison.get('differences', 'unknown')}"
            )
            logger.warning(msg)

            if raise_on_mismatch:
                raise RegistryPluginError(msg)

            return False

        return True

    def get_registered_models(self) -> set[tuple[str, str]]:
        """Get set of models registered during this session.

        Returns:
            Set of `(name, version)` tuples representing models registered by this
            plugin instance.

        Examples:
            ```python
            registered = plugin.get_registered_models()
            print(f"Registered {len(registered)} models this session")
            for name, version in registered:
                print(f"  - {name} v{version}")
            ```
        """
        return self._registered_models.copy()

    def sync_all_models(self: Self) -> dict[str, bool]:
        """Synchronize all local models with registry.

        This is a convenience method that registers all models in the manager.

        Returns:
            Dict mapping `"name@version"` to registration success status.

        Examples:
            ```python
            # Sync everything
            results = plugin.sync_all_models()

            successful = sum(1 for success in results.values() if success)
            print(f"Successfully synced {successful}/{len(results)} models")
            ```
        """
        return self.register_existing_models()

    def list_registered_models(self: Self) -> list[tuple[str, str]]:
        """Get list of models registered in this session.

        Returns:
            List of `(name, version)` tuples for registered models.

        Examples:
            ```python
            registered = plugin.list_registered_models()
            print(f"Registered {len(registered)} models this session")

            for name, version in registered:
                print(f"  - {name} v{version}")
            ```
        """
        return list(self._registered_models)

    def clear_registration_cache(self) -> None:
        """Clear the cache of registered models.

        This allows re-registration of models that were previously registered in this
        session. Useful for testing or when you need to force re-registration.

        Examples:
            ```python
            # Register models
            plugin.register_existing_models()

            # Clear cache to allow re-registration
            plugin.clear_registration_cache()

            # Can now register again
            plugin.register_existing_models()
            ```
        """
        self._registered_models.clear()
        logger.debug("Registration cache cleared")

    def set_metadata(self, metadata: dict[str, Any]) -> None:
        """Update default metadata for future registrations.

        Args:
            metadata: Metadata dict to merge with existing default metadata.

        Examples:
            Add deployment metadata:
            ```python
            plugin.set_metadata({
                "deployment": "production",
                "region": "us-west-2",
                "version": "1.2.3",
            })
            ```
        """
        self.default_metadata.update(metadata)
        logger.debug(f"Default metadata updated: {self.default_metadata}")

    def set_avro_config(
        self,
        include_avro: bool | None = None,
        avro_namespace: str | None = None,
    ) -> None:
        """Update Avro schema configuration.

        Args:
            include_avro: Whether to include Avro schemas. If None, keeps current
                setting.
            avro_namespace: New Avro namespace. If None, keeps current setting.

        Examples:
            Enable Avro with new namespace:
            ```python
            plugin.set_avro_config(
                include_avro=True,
                avro_namespace="com.mycompany.newservice"
            )
            ```

            Disable Avro:
            ```python
            plugin.set_avro_config(include_avro=False)
            ```
        """
        if include_avro is not None:
            self.include_avro = include_avro
            logger.debug(f"Avro generation {'enabled' if include_avro else 'disabled'}")

        if avro_namespace is not None:
            self.avro_namespace = avro_namespace
            logger.debug(f"Avro namespace set to: {avro_namespace}")

    def health_check(self) -> dict[str, Any]:
        """Check health of plugin and registry connection.

        Returns:
            Dict with health status information including:

            - `plugin_active`: Whether plugin is active.
            - `auto_register`: Auto-registration status.
            - `registry_url`: Registry URL.
            - `namespace`: Namespace (or None for global).
            - `registered_models`: Count of registered models.
            - `include_avro`: Whether Avro schemas are being generated.
            - `avro_namespace`: Avro namespace if applicable.
            - `registry_healthy`: Whether registry is healthy.
            - `registry_details`: Detailed registry health info.

        Examples:
            ```python
            health = plugin.health_check()

            if not health["registry_healthy"]:
                print(f"Registry unhealthy: {health.get('registry_error')}")

            print(f"Registered {health['registered_models']} models")
            print(f"Avro enabled: {health['include_avro']}")
            ```
        """
        result: dict[str, Any] = {
            "plugin_active": True,
            "auto_register": self.auto_register,
            "registry_url": self.registry_url,
            "namespace": self.namespace,
            "registered_models": len(self._registered_models),
            "include_avro": self.include_avro,
            "avro_namespace": self.avro_namespace if self.include_avro else None,
        }

        try:
            registry_health = self.client.health_check(detailed=True)
            result["registry_healthy"] = (
                registry_health.get("healthy", False)
                if isinstance(registry_health, dict)
                else registry_health
            )
            if isinstance(registry_health, dict):
                result["registry_details"] = registry_health
        except Exception as e:
            result["registry_healthy"] = False
            result["registry_error"] = str(e)

        return result

    def close(self: Self) -> None:
        """Close the registry client and clean up resources.

        This method:

        - Restores the original manager methods (removes monkey-patching)
        - Closes the HTTP client connection
        - Cleans up any resources

        Examples:
            Manual cleanup:
            ```python
            plugin = RegistryPlugin(manager, registry_url="...")
            try:
                # Use plugin
                pass
            finally:
                plugin.close()
            ```

            Or use context manager (automatic cleanup):
            ```python
            with RegistryPlugin(manager, registry_url="...") as plugin:
                # Plugin automatically closes on exit
                pass
            ```
        """
        self.restore_manager()
        self.client.close()
        logger.info("RegistryPlugin closed")

    def __enter__(self) -> Self:
        """Context manager entry.

        Returns:
            Self for use in `with` statements.
        """
        return self

    def __exit__(
        self: Self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Context manager exit.

        Args:
            exc_type: Exception type if an exception occurred.
            exc_val: Exception value if an exception occurred.
            exc_tb: Exception traceback if an exception occurred.
        """
        self.close()

    def __repr__(self) -> str:
        """String representation.

        Returns:
            Human-readable string representation of the plugin.
        """
        scope = f"namespace={self.namespace}" if self.namespace else "global"
        avro_info = f", avro={self.avro_namespace}" if self.include_avro else ""
        return (
            f"RegistryPlugin({scope}{avro_info}, "
            f"registry={self.registry_url}, "
            f"registered={len(self._registered_models)})"
        )


def create_plugin(
    manager: ModelManager,
    registry_url: str | None = None,
    namespace: str | None = None,
    **kwargs: Any,
) -> RegistryPlugin:
    """Factory function to create a RegistryPlugin.

    This is a convenience function that provides a cleaner API for plugin creation
    without needing to import the class directly.

    Args:
        manager: Pyrmute ModelManager instance.
        registry_url: URL of the registry server.
        namespace: Optional namespace for scoping (None for global schemas).
        **kwargs: Additional configuration arguments passed to `RegistryPlugin`.
            Valid arguments include:

            - `auto_register`: Whether to auto-register schemas (default: `True`).
            - `fail_on_error`: Whether to raise on errors (default: `False`).
            - `verify_ssl`: Whether to verify SSL certificates (default: `True`).
            - `api_key`: API key for authentication (default: `None`).
            - `allow_overwrite`: Allow overwriting schemas (default: `False`).
            - `metadata`: Default metadata dict (default: `{}`).
            - `include_avro`: Generate Avro schemas (default: `True`).
            - `avro_namespace`: Avro namespace (default: `"com.example"`).

    Returns:
        Initialized `RegistryPlugin` instance.

    Examples:
        Basic usage (namespaced):
        ```python
        from pyrmute import ModelManager
        from pyrmute_registry import create_plugin

        manager = ModelManager()
        plugin = create_plugin(
            manager,
            registry_url="http://registry:8000",
            namespace="api-service",
        )
        ```

        With Avro schemas:
        ```python
        plugin = create_plugin(
            manager,
            registry_url="http://registry:8000",
            namespace="api-service",
            include_avro=True,
            avro_namespace="com.mycompany.api",
        )
        ```

        Global schemas without Avro:
        ```python
        plugin = create_plugin(
            manager,
            registry_url="http://registry:8000",
            namespace=None,  # Global schemas
            include_avro=False,
        )
        ```

        With additional configuration:
        ```python
        plugin = create_plugin(
            manager,
            registry_url="http://registry:8000",
            namespace="api-service",
            fail_on_error=False,
            verify_ssl=True,
            metadata={"team": "platform", "env": "prod"},
            include_avro=True,
            avro_namespace="com.mycompany",
        )
        ```

        With environment variables:
        ```python
        # PYRMUTE_REGISTRY_URL and PYRMUTE_REGISTRY_NAMESPACE set in environment
        plugin = create_plugin(manager)
        ```
    """
    return RegistryPlugin(
        manager=manager,
        registry_url=registry_url,
        namespace=namespace,
        **kwargs,
    )
