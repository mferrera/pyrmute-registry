"""Registry client for communicating with the schema registry server."""

import logging
from datetime import UTC, datetime
from types import TracebackType
from typing import Any, Self

import httpx
from httpx import codes
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from .constants import DEFAULT_MAX_RETRIES, DEFAULT_TIMEOUT
from .exceptions import (
    RegistryConnectionError,
    RegistryError,
    SchemaConflictError,
    SchemaNotFoundError,
)
from .types import JsonSchema

logger = logging.getLogger(__name__)


class RegistryClient:
    """Client for interacting with the pyrmute schema registry.

    This client provides an interface to the schema registry with:

    - Automatic retries for transient failures
    - Error handling
    - Connection pooling
    - Request/response logging
    - Namespace support for multi-tenant deployments

    Example:
        ```python
        # Context manager (recommended)
        with RegistryClient("http://registry:8000") as client:
            # Register global schema
            client.register_schema("User", "1.0.0", schema, "api-service")

            # Register namespaced schema
            client.register_schema(
                "User", "1.0.0", schema, "api-service",
                namespace="auth-service"
            )

        # Or manual lifecycle management
        client = RegistryClient("http://registry:8000")
        try:
            client.register_schema("User", "1.0.0", schema, "api-service")
        finally:
            client.close()
        ```
    """

    def __init__(
        self: Self,
        base_url: str,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        verify_ssl: bool = True,
        api_key: str | None = None,
    ) -> None:
        """Initialize the registry client.

        Args:
            base_url: Base URL of the registry server.
            timeout: Request timeout in seconds.
            max_retries: Maximum number of retry attempts for failed requests.
            verify_ssl: Whether to verify SSL certificates.
            api_key: Optional API key for authentication.
        """
        self.base_url = base_url.rstrip("/")
        self.max_retries = max_retries
        self._closed = False

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["X-API-Key"] = api_key

        self.client = httpx.Client(
            timeout=timeout,
            verify=verify_ssl,
            headers=headers,
            follow_redirects=True,
        )

        logger.debug(f"Initialized RegistryClient with base_url={base_url}")

    def _ensure_open(self) -> None:
        """Ensure client is not closed."""
        if self._closed:
            raise RegistryError("Client has been closed")

    def register_schema(  # noqa: PLR0913
        self: Self,
        model_name: str,
        version: str,
        schema: JsonSchema,
        registered_by: str,
        namespace: str | None = None,
        metadata: dict[str, Any] | None = None,
        allow_overwrite: bool = False,
    ) -> dict[str, Any]:
        """Register a schema with the registry.

        Args:
            model_name: Name of the model.
            version: Semantic version string (e.g., '1.0.0').
            schema: JSON Schema definition.
            registered_by: Service or user registering this schema.
            namespace: Optional namespace for scoping (None for global schemas).
            metadata: Additional metadata (tags, environment, etc.).
            allow_overwrite: Whether to overwrite existing schema.

        Returns:
            Registered schema response with id, version, and metadata.

        Raises:
            SchemaConflictError: If schema exists and allow_overwrite=False.
            RegistryConnectionError: If unable to connect to registry.
            RegistryError: For other registration errors.

        Example:
            ```python
            # Register global schema
            client.register_schema(
                "User", "1.0.0", user_schema, "api-service"
            )

            # Register namespaced schema
            client.register_schema(
                "User", "1.0.0", user_schema, "api-service",
                namespace="auth-service",
                metadata={"environment": "production"}
            )
            ```
        """
        try:
            return self._register_schema_with_retry(
                model_name,
                version,
                schema,
                registered_by,
                namespace,
                metadata,
                allow_overwrite,
            )
        except httpx.ConnectError as e:
            logger.error(f"Connection failed to {self.base_url}: {e}")
            raise RegistryConnectionError(
                f"Unable to connect to registry at {self.base_url}"
            ) from e
        except httpx.TimeoutException as e:
            logger.error(f"Request timeout for {model_name} v{version}: {e}")
            raise RegistryConnectionError(
                f"Request timeout while registering {model_name} v{version}"
            ) from e

    @retry(
        retry=retry_if_exception_type((httpx.ConnectError, httpx.TimeoutException)),
        stop=stop_after_attempt(DEFAULT_MAX_RETRIES),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    def _register_schema_with_retry(  # noqa: PLR0913
        self: Self,
        model_name: str,
        version: str,
        schema: JsonSchema,
        registered_by: str,
        namespace: str | None = None,
        metadata: dict[str, Any] | None = None,
        allow_overwrite: bool = False,
    ) -> dict[str, Any]:
        """Register a schema with the registry (with retry logic)."""
        self._ensure_open()

        payload = {
            "version": version,
            "json_schema": schema,
            "registered_at": datetime.now(UTC).isoformat(),
            "registered_by": registered_by,
            "meta": metadata or {},
        }

        # Build URL based on whether namespace is provided
        if namespace:
            url = f"{self.base_url}/schemas/{namespace}/{model_name}/versions"
        else:
            url = f"{self.base_url}/schemas/{model_name}/versions"

        if allow_overwrite:
            url += "?allow_overwrite=true"

        identifier = f"{namespace}::{model_name}" if namespace else model_name
        logger.info(f"Registering schema {identifier} v{version} by {registered_by}")

        try:
            response = self.client.post(url, json=payload)
            response.raise_for_status()
            result: dict[str, Any] = response.json()
            logger.info(f"Successfully registered {identifier} v{version}")
            return result

        except httpx.HTTPStatusError as e:
            if e.response.status_code == codes.CONFLICT:
                logger.warning(f"Schema conflict for {identifier} v{version}")
                raise SchemaConflictError(
                    f"Schema {identifier} v{version} already exists. "
                    f"Use allow_overwrite=True to replace it."
                ) from e
            if e.response.status_code == codes.UNPROCESSABLE_ENTITY:
                logger.error(
                    f"Validation error for {identifier} v{version}: {e.response.text}"
                )
                raise RegistryError(f"Invalid schema data: {e.response.text}") from e
            logger.error(f"HTTP error {e.response.status_code}: {e.response.text}")
            raise RegistryError(
                f"Failed to register schema: {e.response.status_code} {e.response.text}"
            ) from e

    @retry(
        retry=retry_if_exception_type((httpx.ConnectError, httpx.TimeoutException)),
        stop=stop_after_attempt(DEFAULT_MAX_RETRIES),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    def get_schema(
        self: Self,
        model_name: str,
        version: str,
        namespace: str | None = None,
    ) -> JsonSchema:
        """Retrieve a specific schema version.

        Args:
            model_name: Name of the model.
            version: Semantic version string.
            namespace: Optional namespace for scoping.

        Returns:
            Schema data including the JSON Schema and metadata.

        Raises:
            SchemaNotFoundError: If schema not found.
            RegistryConnectionError: If unable to connect to registry.
            RegistryError: For other retrieval errors.

        Example:
            ```python
            # Get global schema
            schema = client.get_schema("User", "1.0.0")

            # Get namespaced schema
            schema = client.get_schema("User", "1.0.0", namespace="auth-service")
            ```
        """
        self._ensure_open()

        if namespace:
            url = f"{self.base_url}/schemas/{namespace}/{model_name}/versions/{version}"
        else:
            url = f"{self.base_url}/schemas/{model_name}/versions/{version}"

        identifier = f"{namespace}::{model_name}" if namespace else model_name
        logger.debug(f"Fetching schema {identifier} v{version}")

        try:
            response = self.client.get(url)
            response.raise_for_status()
            result: JsonSchema = response.json()
            logger.info(f"Successfully found schema {identifier} v{version}")
            return result

        except httpx.ConnectError as e:
            raise RegistryConnectionError(
                f"Unable to connect to registry at {self.base_url}"
            ) from e

        except httpx.HTTPStatusError as e:
            if e.response.status_code == codes.NOT_FOUND:
                raise SchemaNotFoundError(
                    f"Schema {identifier} v{version} not found"
                ) from e
            raise RegistryError(
                f"Failed to retrieve schema: {e.response.status_code}"
            ) from e

    @retry(
        retry=retry_if_exception_type((httpx.ConnectError, httpx.TimeoutException)),
        stop=stop_after_attempt(DEFAULT_MAX_RETRIES),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    def get_latest_schema(
        self: Self,
        model_name: str,
        namespace: str | None = None,
    ) -> JsonSchema:
        """Retrieve the latest version of a schema.

        Args:
            model_name: Name of the model.
            namespace: Optional namespace for scoping.

        Returns:
            Latest schema data.

        Raises:
            SchemaNotFoundError: If model not found.
            RegistryConnectionError: If unable to connect to registry.

        Example:
            ```python
            # Get latest global schema
            schema = client.get_latest_schema("User")

            # Get latest namespaced schema
            schema = client.get_latest_schema("User", namespace="auth-service")
            ```
        """
        self._ensure_open()

        if namespace:
            url = f"{self.base_url}/schemas/{namespace}/{model_name}/versions/latest"
        else:
            url = f"{self.base_url}/schemas/{model_name}/versions/latest"

        identifier = f"{namespace}::{model_name}" if namespace else model_name
        logger.debug(f"Fetching latest schema for {identifier}")

        try:
            response = self.client.get(url)
            response.raise_for_status()
            result: JsonSchema = response.json()
            logger.info(f"Successfully found latest schema for {identifier}")
            return result

        except httpx.ConnectError as e:
            raise RegistryConnectionError(
                f"Unable to connect to registry at {self.base_url}"
            ) from e

        except httpx.HTTPStatusError as e:
            if e.response.status_code == codes.NOT_FOUND:
                raise SchemaNotFoundError(f"Model {identifier} not found") from e
            raise RegistryError(
                f"Failed to retrieve latest schema: {e.response.status_code}"
            ) from e

    @retry(
        retry=retry_if_exception_type((httpx.ConnectError, httpx.TimeoutException)),
        stop=stop_after_attempt(DEFAULT_MAX_RETRIES),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    def list_schemas(
        self: Self,
        namespace: str | None = None,
        model_name: str | None = None,
        include_deprecated: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        """List all registered schemas with optional filtering.

        Args:
            namespace: Optional filter by namespace.
                - None (default): List schemas from all namespaces.
                - "" or "null": Filter for global schemas only.
                - "service-name": Filter for specific namespace.
            model_name: Optional filter by model name.
            include_deprecated: Whether to include deprecated schemas.
            limit: Maximum number of results (1-1000).
            offset: Number of results to skip for pagination.

        Returns:
            Dict containing list of schemas with pagination info.

        Example:
            ```python
            # List all schemas
            result = client.list_schemas()

            # List schemas in specific namespace
            result = client.list_schemas(namespace="auth-service")

            # List specific model across namespaces
            result = client.list_schemas(model_name="User")

            # Paginated results
            result = client.list_schemas(limit=50, offset=100)
            ```
        """
        self._ensure_open()

        params: dict[str, Any] = {
            "include_deprecated": include_deprecated,
            "limit": limit,
            "offset": offset,
        }
        if namespace is not None:
            params["namespace"] = namespace
        if model_name is not None:
            params["model_name"] = model_name

        url = f"{self.base_url}/schemas"
        logger.debug(f"Listing schemas with params: {params}")

        try:
            response = self.client.get(url, params=params)
            response.raise_for_status()
            result: dict[str, Any] = response.json()
            logger.info("Successfully listed schemas")
            return result

        except httpx.ConnectError as e:
            raise RegistryConnectionError(
                f"Unable to connect to registry at {self.base_url}"
            ) from e

        except httpx.HTTPStatusError as e:
            raise RegistryError(
                f"Failed to list schemas: {e.response.status_code}"
            ) from e

    @retry(
        retry=retry_if_exception_type((httpx.ConnectError, httpx.TimeoutException)),
        stop=stop_after_attempt(DEFAULT_MAX_RETRIES),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    def list_versions(
        self: Self,
        model_name: str,
        namespace: str | None = None,
    ) -> list[str]:
        """List all versions for a specific model.

        Args:
            model_name: Name of the model.
            namespace: Optional namespace for scoping.

        Returns:
            List of version strings sorted by semantic versioning.

        Raises:
            SchemaNotFoundError: If model not found.

        Example:
            ```python
            # List versions for global model
            versions = client.list_versions("User")

            # List versions for namespaced model
            versions = client.list_versions("User", namespace="auth-service")
            ```
        """
        self._ensure_open()

        if namespace:
            url = f"{self.base_url}/schemas/{namespace}/{model_name}/versions"
        else:
            url = f"{self.base_url}/schemas/{model_name}/versions"

        identifier = f"{namespace}::{model_name}" if namespace else model_name
        logger.debug(f"Listing versions for {identifier}")

        try:
            response = self.client.get(url)
            response.raise_for_status()
            result: dict[str, Any] = response.json()
            logger.info(f"Successfully got list of versions for {identifier}")
            versions: list[str] = result["versions"]
            return versions

        except httpx.ConnectError as e:
            raise RegistryConnectionError(
                f"Unable to connect to registry at {self.base_url}"
            ) from e

        except httpx.HTTPStatusError as e:
            if e.response.status_code == codes.NOT_FOUND:
                raise SchemaNotFoundError(f"Model {identifier} not found") from e
            raise RegistryError(
                f"Failed to list versions: {e.response.status_code}"
            ) from e

    def health_check(self: Self, detailed: bool = False) -> bool | dict[str, Any]:
        """Check if the registry server is available.

        Args:
            detailed: If True, return detailed health information.

        Returns:
            True/False if detailed=False, or dict with health details if detailed=True.

        Example:
            ```python
            # Simple health check
            if client.health_check():
                print("Registry is healthy")

            # Detailed health check
            health = client.health_check(detailed=True)
            print(f"Status: {health['status']}")
            print(f"Schemas: {health['schemas_count']}")
            ```
        """
        self._ensure_open()

        try:
            response = self.client.get(
                f"{self.base_url}/health",
                timeout=5.0,  # Shorter timeout for health checks
            )

            if not detailed:
                return response.status_code == codes.OK

            if response.status_code == codes.OK:
                result: dict[str, Any] = response.json()
                logger.info("Successful health check")
                return result

            return {
                "healthy": False,
                "status_code": response.status_code,
                "error": response.text,
            }

        except httpx.HTTPError as e:
            if detailed:
                return {
                    "healthy": False,
                    "error": str(e),
                }
            return False

    def compare_schemas(
        self: Self,
        model_name: str,
        from_version: str,
        to_version: str,
        namespace: str | None = None,
    ) -> dict[str, Any]:
        """Get a diff between two schema versions.

        Args:
            model_name: Name of the model.
            from_version: Source version.
            to_version: Target version.
            namespace: Optional namespace for scoping.

        Returns:
            Diff information showing changes between versions, including:.
            - properties_added: New properties.
            - properties_removed: Removed properties.
            - properties_modified: Modified properties.
            - breaking_changes: List of breaking changes.
            - compatibility: Overall compatibility assessment.

        Raises:
            SchemaNotFoundError: If either version not found.

        Example:
            ```python
            # Compare versions
            diff = client.compare_schemas("User", "1.0.0", "2.0.0")

            if diff["breaking_changes"]:
                print("Warning: Breaking changes detected!")
            ```
        """
        self._ensure_open()

        if namespace:
            url = f"{self.base_url}/schemas/{namespace}/{model_name}/compare"
        else:
            url = f"{self.base_url}/schemas/{model_name}/compare"

        params = {"from_version": from_version, "to_version": to_version}

        identifier = f"{namespace}::{model_name}" if namespace else model_name
        logger.debug(f"Comparing {identifier} {from_version} -> {to_version}")

        try:
            response = self.client.get(url, params=params)
            response.raise_for_status()
            logger.info(
                f"Successfully compared {identifier} v{from_version} : v{to_version}"
            )
            result: dict[str, Any] = response.json()
            return result

        except httpx.HTTPStatusError as e:
            if e.response.status_code == codes.NOT_FOUND:
                raise SchemaNotFoundError(
                    f"One or both versions not found: {from_version}, {to_version}"
                ) from e
            raise RegistryError(
                f"Failed to compare schemas: {e.response.status_code}"
            ) from e

    def delete_schema(
        self: Self,
        model_name: str,
        version: str,
        namespace: str | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        """Delete a schema version.

        Args:
            model_name: Name of the model.
            version: Version to delete.
            namespace: Optional namespace for scoping.
            force: Force deletion without safety check.

        Returns:
            Deletion confirmation.

        Raises:
            SchemaNotFoundError: If schema not found.
            RegistryError: If deletion fails.

        Example:
            ```python
            # Delete with confirmation
            client.delete_schema("User", "1.0.0", force=True)

            # Delete namespaced schema
            client.delete_schema(
                "User", "1.0.0",
                namespace="auth-service",
                force=True
            )
            ```
        """
        self._ensure_open()

        if namespace:
            url = f"{self.base_url}/schemas/{namespace}/{model_name}/versions/{version}"
        else:
            url = f"{self.base_url}/schemas/{model_name}/versions/{version}"

        if force:
            url += "?force=true"

        identifier = f"{namespace}::{model_name}" if namespace else model_name
        logger.warning(f"Deleting schema {identifier} v{version}")

        try:
            response = self.client.delete(url)
            response.raise_for_status()
            logger.info(f"Successfully deleted {identifier} v{version}")
            result: dict[str, Any] = response.json()
            return result

        except httpx.HTTPStatusError as e:
            if e.response.status_code == codes.NOT_FOUND:
                raise SchemaNotFoundError(
                    f"Schema {identifier} v{version} not found"
                ) from e
            raise RegistryError(
                f"Failed to delete schema: {e.response.status_code} {e.response.text}"
            ) from e

    def deprecate_schema(
        self: Self,
        model_name: str,
        version: str,
        namespace: str | None = None,
        message: str | None = None,
    ) -> dict[str, Any]:
        """Mark a schema version as deprecated.

        Args:
            model_name: Name of the model.
            version: Version to deprecate.
            namespace: Optional namespace for scoping.
            message: Optional deprecation message.

        Returns:
            Updated schema response.

        Raises:
            SchemaNotFoundError: If schema not found.
            RegistryError: If deprecation fails.

        Example:
            ```python
            client.deprecate_schema(
                "User", "1.0.0",
                message="Security vulnerability. Please upgrade to 2.0.0"
            )
            ```
        """
        self._ensure_open()

        if namespace:
            url = (
                f"{self.base_url}/schemas/{namespace}/{model_name}/versions/"
                f"{version}/deprecate"
            )
        else:
            url = f"{self.base_url}/schemas/{model_name}/versions/{version}/deprecate"

        params = {}
        if message:
            params["message"] = message

        identifier = f"{namespace}::{model_name}" if namespace else model_name
        logger.warning(f"Deprecating schema {identifier} v{version}")

        try:
            response = self.client.post(url, params=params)
            response.raise_for_status()
            logger.info(f"Successfully deprecated {identifier} v{version}")
            result: dict[str, Any] = response.json()
            return result

        except httpx.HTTPStatusError as e:
            if e.response.status_code == codes.NOT_FOUND:
                raise SchemaNotFoundError(
                    f"Schema {identifier} v{version} not found"
                ) from e
            raise RegistryError(
                f"Failed to deprecate schema: {e.response.status_code} "
                f"{e.response.text}"
            ) from e

    def close(self: Self) -> None:
        """Close the HTTP client and release resources."""
        if not self._closed:
            self.client.close()
            self._closed = True
            logger.debug("RegistryClient closed")

    def __enter__(self: Self) -> Self:
        """Context manager entry."""
        return self

    def __exit__(
        self: Self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Context manager exit."""
        self.close()

    def __del__(self: Self) -> None:
        """Ensure client is closed on deletion."""
        if not self._closed:
            self.close()
