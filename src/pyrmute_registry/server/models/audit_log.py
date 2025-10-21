"""Database model for audit logging."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from pyrmute_registry.server.db import Base


class AuditLog(Base):
    """Database model for audit logging of authenticated actions.

    Tracks all authenticated operations performed through the API, including:

    - Schema operations (create, update, delete, deprecate)
    - API key operations (create, revoke, rotate, delete)
    - Request metadata (method, path, status, client info)
    - Authentication context (which key performed the action)

    Used for security monitoring, compliance auditing, and debugging.
    """

    __tablename__ = "audit_logs"

    # Primary identifier
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal database ID",
    )

    # Timestamp
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        index=True,
        comment="When the action was performed (UTC)",
    )

    # Authentication context
    api_key_id: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        index=True,
        comment="ID of the API key used (NULL if auth disabled)",
    )

    api_key_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
        comment="Name of the API key used for denormalized queries",
    )

    permission_level: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
        comment="Permission level of the API key (read/write/delete/admin)",
    )

    # Action details
    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Action performed (e.g., 'register_schema', 'revoke_key')",
    )

    resource_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Type of resource affected (e.g., 'schema', 'api_key')",
    )

    resource_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
        comment="Identifier of the affected resource (e.g., schema full_identifier)",
    )

    # HTTP request context
    method: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        comment="HTTP method (GET, POST, PUT, DELETE, etc.)",
    )

    path: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        comment="Request path (e.g., '/api/v1/schemas/namespace/model')",
    )

    status_code: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        index=True,
        comment="HTTP response status code (200, 404, 500, etc.)",
    )

    # Client information for security tracking
    client_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        index=True,
        comment="Client IP address (IPv4 or IPv6)",
    )

    user_agent: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Client User-Agent string",
    )

    # Additional context (sanitized - no sensitive data)
    request_params: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
        comment="Sanitized request parameters (no API keys or sensitive data)",
    )

    response_summary: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
        comment="Summary of response data (e.g., created resource ID, version)",
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Error message if the action failed",
    )

    # Table constraints and indexes
    __table_args__ = (
        # Composite index for finding actions by a specific API key
        Index("idx_api_key_timestamp", "api_key_id", "timestamp"),
        # Composite index for filtering by action type and time
        Index("idx_action_timestamp", "action", "timestamp"),
        # Composite index for resource-based queries
        Index("idx_resource_type_id", "resource_type", "resource_id"),
        # Index for security monitoring (failed requests)
        Index("idx_status_timestamp", "status_code", "timestamp"),
        # Index for IP-based security analysis
        Index("idx_client_ip_timestamp", "client_ip", "timestamp"),
        # Composite index for API key activity by action type
        Index("idx_api_key_action", "api_key_id", "action"),
        # Index for permission-level analysis
        Index("idx_permission_level", "permission_level"),
    )

    def __repr__(self) -> str:
        """String representation of audit log entry."""
        key_info = f"key={self.api_key_name}" if self.api_key_name else "no_auth"
        status_info = f"status={self.status_code}" if self.status_code else "pending"
        return (
            f"<AuditLog(id={self.id}, "
            f"action='{self.action}', "
            f"resource='{self.resource_type}', "
            f"{key_info}, {status_info})>"
        )

    def __str__(self) -> str:
        """Human-readable string representation."""
        timestamp_str = self.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        key_name = self.api_key_name or "unauthenticated"
        return (
            f"[{timestamp_str}] {key_name}: {self.action} on "
            f"{self.resource_type} ({self.method} {self.path})"
        )

    @property
    def was_successful(self) -> bool:
        """Check if the logged action was successful.

        Returns:
            True if status code indicates success (2xx), False otherwise
        """
        if self.status_code is None:
            return False
        return 200 <= self.status_code < 300  # noqa: PLR2004

    @property
    def was_client_error(self) -> bool:
        """Check if the logged action resulted in a client error.

        Returns:
            True if status code indicates client error (4xx), False otherwise
        """
        if self.status_code is None:
            return False
        return 400 <= self.status_code < 500  # noqa: PLR2004

    @property
    def was_server_error(self) -> bool:
        """Check if the logged action resulted in a server error.

        Returns:
            True if status code indicates server error (5xx), False otherwise
        """
        if self.status_code is None:
            return False
        return 500 <= self.status_code < 600  # noqa: PLR2004

    @property
    def is_authenticated(self) -> bool:
        """Check if this action was authenticated.

        Returns:
            True if performed with an API key, False otherwise
        """
        return self.api_key_id is not None
