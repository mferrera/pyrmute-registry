"""SQLAlchemy database models."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from pyrmute_registry.server.db import Base


class SchemaRecord(Base):
    """Database model for storing versioned schemas.

    Stores JSON schemas with versioning information and metadata about when and by whom
    the schema was registered. Supports optional namespace scoping (e.g.,
    service-specific schemas) and deprecation tracking.

    Schemas can be:
    - Global: model_name@version (namespace=NULL)
    - Namespaced: namespace::model_name@version (namespace='service-name')
    """

    __tablename__ = "schemas"

    # Primary identifier
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal database ID",
    )

    # Optional namespace for schema scoping
    namespace: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
        comment=(
            "Optional namespace for scoping (e.g., service name). NULL = global schema"
        ),
    )

    # Model identification
    model_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Name of the data model",
    )

    version: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Semantic version string (e.g., '1.0.0')",
    )

    # Schema content
    json_schema: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        comment="JSON Schema definition (Draft 2020-12)",
    )

    # Registration metadata
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        comment="When the schema was registered",
    )

    registered_by: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Service or user that registered this schema",
    )

    meta: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
        default=dict,
        comment="Additional metadata (tags, environment, description, etc.)",
    )

    # Deprecation tracking
    deprecated: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="Whether this schema version is deprecated",
    )

    deprecated_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
        comment="When the schema was marked as deprecated",
    )

    deprecation_message: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="Reason for deprecation or migration instructions",
    )

    # Table constraints and indexes
    __table_args__ = (
        # Ensure uniqueness of namespace + model + version combination
        # NULL namespace is treated as a distinct value (global scope)
        UniqueConstraint(
            "namespace",
            "model_name",
            "version",
            name="uix_namespace_model_version",
        ),
        # Composite index for common query pattern
        Index("idx_namespace_model_version", "namespace", "model_name", "version"),
        # Index for finding all schemas in a namespace
        Index("idx_namespace", "namespace"),
        # Index for finding schemas by model name across namespaces
        Index("idx_model_name", "model_name"),
        # Index for filtering by model within a namespace
        Index("idx_namespace_model", "namespace", "model_name"),
        # Index for filtering by registering service/user
        Index("idx_registered_by", "registered_by"),
        # Index for time-based queries
        Index("idx_registered_at", "registered_at"),
        # Index for finding deprecated schemas
        Index("idx_deprecated", "deprecated"),
        # Composite index for namespace-scoped queries with deprecation status
        Index(
            "idx_namespace_model_deprecated",
            "namespace",
            "model_name",
            "deprecated",
        ),
    )

    def __repr__(self) -> str:
        """String representation of schema record."""
        deprecated_str = " [DEPRECATED]" if self.deprecated else ""
        return (
            f"<SchemaRecord(id={self.id}, "
            f"identifier='{self.full_identifier}', "
            f"registered_by='{self.registered_by}'{deprecated_str})>"
        )

    def __str__(self) -> str:
        """Human-readable string representation."""
        return self.full_identifier

    @property
    def is_deprecated(self) -> bool:
        """Check if this schema version is deprecated.

        Returns:
            True if deprecated, False otherwise
        """
        return self.deprecated

    @property
    def full_identifier(self) -> str:
        """Get the full schema identifier for display/API responses.

        Returns:
            Full identifier in format:
            - 'model_name@version' for global schemas (namespace=NULL)
            - 'namespace::model_name@version' for namespaced schemas
        """
        if self.namespace:
            return f"{self.namespace}::{self.model_name}@{self.version}"
        return f"{self.model_name}@{self.version}"

    @property
    def is_global(self) -> bool:
        """Check if this is a global schema (no namespace).

        Returns:
            True if global, False if namespaced
        """
        return self.namespace is None

    @classmethod
    def parse_identifier(cls, identifier: str) -> tuple[str | None, str, str]:
        """Parse a full identifier into components.

        Args:
            identifier: Full identifier string, either:
                - 'model_name@version' (global)
                - 'namespace::model_name@version' (namespaced)

        Returns:
            Tuple of (namespace, model_name, version)
            namespace will be None for global schemas

        Raises:
            ValueError: If identifier format is invalid
        """
        # Check for namespace separator
        if "::" in identifier:
            namespace_part, rest = identifier.split("::", 1)
            namespace = namespace_part
        else:
            namespace = None
            rest = identifier

        # Parse model_name@version
        if "@" not in rest:
            raise ValueError(
                f"Invalid identifier format: '{identifier}'. "
                "Expected 'model@version' or 'namespace::model@version'"
            )

        model_name, version = rest.rsplit("@", 1)

        if not model_name or not version:
            raise ValueError(
                f"Invalid identifier format: '{identifier}'. "
                "Model name and version cannot be empty"
            )

        return namespace, model_name, version
