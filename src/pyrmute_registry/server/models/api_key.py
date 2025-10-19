"""Database models for API keys."""

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from pyrmute_registry.server.db import Base


class Permission(StrEnum):
    """Permission levels for API keys."""

    READ = "read"
    """Can read schemas."""

    WRITE = "write"
    """Can read and write schemas."""

    DELETE = "delete"
    """Can read, write, and delete schemas."""

    ADMIN = "admin"
    """Full access including key management."""


class ApiKey(Base):
    """Database model for API key storage.

    API keys are hashed using bcrypt before storage. The plaintext key is only
    shown once upon creation and cannot be retrieved afterwards.

    Attributes:
        id: Unique identifier.
        name: Human-readable name for the key (e.g., "production-api", "ci-cd").
        key_hash: Bcrypt hash of the API key.
        permission: Permission level (read, write, delete, admin).
        created_at: When the key was created.
        created_by: Who/what created the key.
        last_used_at: Last time the key was used for authentication.
        expires_at: Optional expiration date.
        revoked: Whether the key has been revoked.
        revoked_at: When the key was revoked.
        revoked_by: Who revoked the key.
        metadata: Additional metadata (team, purpose, etc.).
    """

    __tablename__ = "api_keys"

    # Primary identifier
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal database ID",
    )

    # Key identification
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
        comment="Human-readable name for the API key",
    )

    # Security
    key_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        comment="Bcrypt hash of the API key",
    )

    permission: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=Permission.READ.value,
        index=True,
        comment="Permission level: read, write, delete, admin",
    )

    # Creation tracking
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        index=True,
        comment="When the key was created",
    )

    created_by: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Service or user that created this key",
    )

    # Usage tracking
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last time the key was used for authentication",
    )

    use_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of times the key has been used",
    )

    # Expiration
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Optional expiration date",
    )

    # Revocation
    revoked: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="Whether the key has been revoked",
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the key was revoked",
    )

    revoked_by: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Who revoked the key",
    )

    # Additional metadata
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Optional description of the key's purpose",
    )

    # Table constraints and indexes
    __table_args__ = (
        # Index for active key lookups
        Index("idx_active_keys", "revoked", "expires_at"),
        # Index for permission-based queries
        Index("idx_permission", "permission"),
        # Index for finding keys by creator
        Index("idx_created_by", "created_by"),
    )

    def __repr__(self) -> str:
        """String representation."""
        status = "REVOKED" if self.revoked else "ACTIVE"
        return (
            f"<ApiKey(id={self.id}, name='{self.name}', "
            f"permission='{self.permission}', status={status})>"
        )

    @property
    def is_active(self) -> bool:
        """Check if the key is currently active.

        Returns:
            True if not revoked and not expired.
        """
        if self.revoked:
            return False

        if self.expires_at:
            # Ensure timezone-aware comparison
            now = datetime.now(UTC)
            expires = self.expires_at

            # If expires_at is naive (from SQLite), assume UTC
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)

            if now > expires:
                return False  # Expired

        return True

    @property
    def is_expired(self) -> bool:
        """Check if the key has expired.

        Returns:
            True if past expiration date.
        """
        if not self.expires_at:
            return False

        # Ensure timezone-aware comparison
        now = datetime.now(UTC)
        expires = self.expires_at

        # If expires_at is naive (from SQLite), assume UTC
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)

        return now > expires

    def has_permission(self, required: Permission) -> bool:
        """Check if this key has the required permission level.

        Permission hierarchy:
        - READ: Can only read
        - WRITE: Can read and write
        - DELETE: Can read, write, and delete
        - ADMIN: Full access

        Args:
            required: Required permission level.

        Returns:
            True if key has sufficient permissions.
        """
        if not self.is_active:
            return False

        hierarchy = {
            Permission.READ: 1,
            Permission.WRITE: 2,
            Permission.DELETE: 3,
            Permission.ADMIN: 4,
        }

        current_level = hierarchy.get(Permission(self.permission), 0)
        required_level = hierarchy.get(required, 0)

        return current_level >= required_level
