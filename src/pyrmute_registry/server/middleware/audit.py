"""Middleware for automatic audit logging of authenticated actions."""

import contextlib
import logging
from collections.abc import Awaitable, Callable, Generator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Final, Self

from fastapi import Request, Response
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware

from pyrmute_registry.server.config import get_settings
from pyrmute_registry.server.db import get_db
from pyrmute_registry.server.services.audit import AuditService

if TYPE_CHECKING:
    from pyrmute_registry.server.models.api_key import ApiKey

logger = logging.getLogger(__name__)


MIN_SCHEMA_PATH_PARTS: Final[int] = 3


class AuditMiddleware(BaseHTTPMiddleware):
    """Middleware to automatically log authenticated actions.

    Captures authenticated operations based on configuration and logs them to the
    audit_logs table. Extracts context from request state and response status to create
    audit trails.

    Configuration is driven by Settings.audit_methods and Settings.audit_paths. Only
    logs operations that:

    - Use an authenticated API key (request.state.api_key exists)
    - Use methods listed in audit_methods
    - Target paths matching audit_paths patterns
    """

    @contextmanager
    def _get_db_session(self: Self, request: Request) -> Generator[Session, None, None]:
        """Get database session respecting dependency overrides.

        Args:
            request: Incoming request with app context.

        Yields:
            Database session.
        """
        db_dependency = request.app.dependency_overrides.get(get_db, get_db)
        db_gen = db_dependency()
        db = next(db_gen)

        try:
            yield db
        finally:
            with contextlib.suppress(StopIteration):
                next(db_gen)

    async def dispatch(
        self: Self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Process request and log if auditable.

        Args:
            request: Incoming request.
            call_next: Next middleware/handler in chain.

        Returns:
            Response from handler.
        """
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
        path = request.url.path

        response = await call_next(request)

        should_audit = self._should_audit(request)
        if not should_audit:
            return response

        # Audit logging happens after response, in its own transaction
        # This prevents audit failures from affecting the main operation
        try:
            with self._get_db_session(request) as db:
                audit_service = AuditService(db)

                api_key: ApiKey | None = getattr(request.state, "api_key", None)

                action = self._determine_action(request.method, path)
                resource_type = self._determine_resource_type(path)
                resource_id = self._extract_resource_id(path)

                audit_service.log_action(
                    action=action,
                    resource_type=resource_type,
                    method=request.method,
                    path=path,
                    api_key=api_key,
                    resource_id=resource_id,
                    status_code=response.status_code,
                    client_ip=client_ip,
                    user_agent=user_agent,
                )

        except Exception as e:
            logger.exception(
                f"Failed to create audit log for {request.method} {path}: {e}"
            )

        return response

    def _should_audit(self: Self, request: Request) -> bool:
        """Determine if a request should be audited.

        Args:
            request: Incoming request.

        Returns:
            True if request should be audited, False otherwise.
        """
        # Respect FastAPI's dependency override system for settings too
        settings_dependency = request.app.dependency_overrides.get(
            get_settings, get_settings
        )
        settings = settings_dependency()

        if not settings.audit_enabled:
            return False

        if request.method not in settings.audit_methods:
            return False

        path = request.url.path
        if not any(path.startswith(prefix) for prefix in settings.audit_paths):
            return False

        # Only audit authenticated requests
        # (The api_key is set by the auth dependency in request.state)
        api_key = getattr(request.state, "api_key", None)
        return api_key is not None

    def _determine_action(self: Self, method: str, path: str) -> str:
        """Determine action name from method and path.

        Extracts a simple action name based on HTTP method and resource.

        Format: {method}_{resource} (e.g., "post_schema", "delete_key")

        Args:
            method: HTTP method.
            path: Request path.

        Returns:
            Action name for audit log.
        """
        resource_type = self._determine_resource_type(path)
        return f"{method.lower()}_{resource_type}"

    def _determine_resource_type(self: Self, path: str) -> str:
        """Determine resource type from request path.

        Extracts the resource from paths in the format: /{resource}/...

        Args:
            path: Request path.

        Returns:
            Resource type for audit log.
        """
        parts = [p for p in path.split("/") if p]

        if not parts:
            return "unknown"

        resource = parts[0]

        # Normalize to singular form for consistency
        if resource == "api-keys":
            return "key"
        if resource.endswith("s") and not resource.endswith("ss"):
            return resource[:-1]

        return resource

    def _extract_resource_id(self: Self, path: str) -> str | None:
        """Extract resource identifier from path.

        Tries to extract meaningful identifiers from the URL path.

        - For schemas: namespace::model@version or model@version
        - For other resources: the ID from the path

        Args:
            path: Request path.

        Returns:
            Resource identifier if available, None otherwise.
        """
        parts = [p for p in path.split("/") if p]

        if not parts:
            return None

        resource = parts[0]

        # For schemas, build full identifier from path structure
        # Path patterns:
        # /schemas/{namespace}/{model}/versions/{version}
        # /schemas/{model}/versions/{version} (global namespace)
        if resource == "schemas" and len(parts) >= MIN_SCHEMA_PATH_PARTS:
            # Check if second part is "versions" (global namespace case)
            if parts[1] == "versions":
                return None  # /schemas/versions - no identifier yet

            namespace = parts[1] if parts[1] != "null" else None
            model_name = parts[2] if parts[2] != "versions" else None

            # Find version after "versions" keyword
            version = None
            if "versions" in parts:
                versions_index = parts.index("versions")
                if len(parts) > versions_index + 1:
                    version = parts[versions_index + 1]

            if model_name and version:
                return (
                    f"{namespace}::{model_name}@{version}"
                    if namespace
                    else f"{model_name}@{version}"
                )
            if model_name:
                return f"{namespace}::{model_name}" if namespace else model_name

        # For other resources, return the ID segment
        if len(parts) > 1 and parts[1] not in {"null", "undefined", "versions"}:
            return parts[1]

        return None
