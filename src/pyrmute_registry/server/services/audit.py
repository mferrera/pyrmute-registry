"""Business logic for audit logging operations."""

import logging
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any, Self

from sqlalchemy.orm import Session

from pyrmute_registry.server.models.api_key import ApiKey
from pyrmute_registry.server.models.audit_log import AuditLog

logger = logging.getLogger(__name__)


class AuditService:
    """Service layer for audit logging operations.

    Handles creation and querying of audit logs for tracking all authenticated actions
    performed through the API. Provides sanitization of sensitive data and structured
    logging for security and compliance purposes.
    """

    def __init__(self: Self, db: Session) -> None:
        """Initialize service with database session.

        Args:
            db: SQLAlchemy database session.
        """
        self.db = db

    @contextmanager
    def log_operation(  # noqa: PLR0913
        self: Self,
        action: str,
        resource_type: str,
        method: str,
        path: str,
        api_key: ApiKey | None = None,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> Generator[dict[str, Any], None, None]:
        """Context manager for automatic audit logging of operations.

        Usage:
            with audit.log_operation(
                "register_schema", "schema", "POST", path, api_key
            ):
                result = schema_service.register_schema(...)
                yield {"resource_id": result.full_identifier, "version": result.version}

        Or in endpoint:
            with audit.log_operation(...) as audit_context:
                result = service.do_something()
                audit_context["resource_id"] = result.id
                audit_context["status_code"] = 201

        Args:
            action: Action being performed.
            resource_type: Type of resource.
            method: HTTP method.
            path: Request path.
            api_key: Authenticated API key.
            client_ip: Client IP address.
            user_agent: Client user agent.

        Yields:
            Dictionary for storing operation context (resource_id, response_summary,
                etc.).
        """
        # Context dict for the caller to populate
        context: dict[str, Any] = {
            "resource_id": None,
            "status_code": None,
            "request_params": None,
            "response_summary": None,
            "error_message": None,
        }

        try:
            yield context

            # If we get here, operation succeeded
            if context["status_code"] is None:
                context["status_code"] = 200
        except Exception as e:
            context["error_message"] = str(e)
            if context["status_code"] is None:
                context["status_code"] = 500
            raise
        finally:
            try:
                self.log_action(
                    action=action,
                    resource_type=resource_type,
                    method=method,
                    path=path,
                    api_key=api_key,
                    resource_id=context.get("resource_id"),
                    status_code=context.get("status_code"),
                    client_ip=client_ip,
                    user_agent=user_agent,
                    request_params=context.get("request_params"),
                    response_summary=context.get("response_summary"),
                    error_message=context.get("error_message"),
                )
            except Exception as audit_error:
                logger.exception(
                    f"Failed to create audit log: {audit_error}",
                )

    def log_action(  # noqa: PLR0913
        self: Self,
        action: str,
        resource_type: str,
        method: str,
        path: str,
        api_key: ApiKey | None = None,
        resource_id: str | None = None,
        status_code: int | None = None,
        client_ip: str | None = None,
        user_agent: str | None = None,
        request_params: dict[str, Any] | None = None,
        response_summary: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> AuditLog | None:
        """Log an authenticated action.

        Creates an audit log entry for tracking API operations. Automatically sanitizes
        sensitive data from request parameters.

        Args:
            action: Action performed (e.g., 'register_schema', 'revoke_key').
            resource_type: Type of resource (e.g., 'schema', 'api_key').
            method: HTTP method (GET, POST, PUT, DELETE, etc.).
            path: Request path.
            api_key: Authenticated API key (None if auth disabled).
            resource_id: ID of affected resource (e.g., schema full_identifier).
            status_code: HTTP response status code.
            client_ip: Client IP address.
            user_agent: Client user agent string.
            request_params: Sanitized request parameters.
            response_summary: Summary of response (avoid sensitive data).
            error_message: Error message if action failed.

        Returns:
            Created audit log entry, or None if logging failed.
        """
        sanitized_params = (
            self._sanitize_params(request_params) if request_params else None
        )

        audit_entry = AuditLog(
            action=action,
            resource_type=resource_type,
            method=method,
            path=path,
            api_key_id=api_key.id if api_key else None,
            api_key_name=api_key.name if api_key else None,
            permission_level=api_key.permission if api_key else None,
            resource_id=resource_id,
            status_code=status_code,
            client_ip=client_ip,
            user_agent=user_agent,
            request_params=sanitized_params,
            response_summary=response_summary,
            error_message=error_message,
        )

        self.db.add(audit_entry)
        try:
            self.db.commit()
            self.db.refresh(audit_entry)
            logger.debug(f"Audit log created: {audit_entry}")
            return audit_entry
        except Exception as e:
            self.db.rollback()
            logger.exception(f"Failed to create audit log: {e}")
            return None

    @staticmethod
    def _sanitize_params(params: dict[str, Any]) -> dict[str, Any]:
        """Remove sensitive data from request parameters.

        Args:
            params: Raw request parameters.

        Returns:
            Sanitized parameters safe for logging.
        """
        if not params:
            return {}

        # List of parameter names that should be redacted
        sensitive_keys = {
            "api_key",
            "key",
            "token",
            "password",
            "secret",
            "authorization",
            "key_hash",
        }

        sanitized = {}
        for key, value in params.items():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = value

        return sanitized
