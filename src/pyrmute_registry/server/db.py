"""Database configuration and session management."""

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""


def get_engine() -> Engine:
    """Create and configure database engine."""
    settings = get_settings()

    connect_args: dict[str, Any] = {}
    if settings.is_sqlite:
        connect_args["check_same_thread"] = False

    return create_engine(
        settings.database_url,
        connect_args=connect_args,
        echo=settings.environment == "development",
    )


engine = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Initialize database tables."""
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Dependency for getting database sessions.

    Yields:
        Database session that is automatically closed after use.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """Context manager for database sessions.

    Yields:
        Database session with automatic commit/rollback.
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
