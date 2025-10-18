"""Test configuration and fixtures."""

from collections.abc import Generator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from sqlalchemy.pool import StaticPool

from pyrmute_registry.server.config import Settings, get_settings
from pyrmute_registry.server.db import Base, get_db
from pyrmute_registry.server.main import create_app

# Test database URL
TEST_DATABASE_URL = "sqlite:///:memory:"
TEST_API_KEY = "test-secret-key-12345"


def get_test_settings() -> Settings:
    """Override settings for testing."""
    return Settings(
        database_url=TEST_DATABASE_URL,
        enable_auth=False,
        environment="test",
        cors_origins=["*"],
    )


def get_auth_settings() -> Settings:
    """Override settings for auth testing."""
    return Settings(
        database_url=TEST_DATABASE_URL,
        enable_auth=True,
        api_key=TEST_API_KEY,
        environment="test",
        cors_origins=["*"],
    )


# Create test engine with in-memory SQLite
test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,  # Use StaticPool for in-memory database
)

TestSessionLocal = scoped_session(
    sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
)


@pytest.fixture(autouse=True)
def reset_settings_cache() -> Generator[None, None, None]:
    """Clear settings cache before each test."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(scope="function")
def db_session() -> Generator[Session, None, None]:
    """Create test database session for each test.

    This fixture creates a fresh database with all tables for each test, then tears it
    down after the test completes.

    Yields:
        Database session with clean state
    """
    Base.metadata.create_all(bind=test_engine)
    session = TestSessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
        TestSessionLocal.remove()
        Base.metadata.drop_all(bind=test_engine)


def override_get_db() -> Generator[Session, None, None]:
    """Override database dependency for testing.

    This is used by the FastAPI dependency injection system
    to provide a test database session.
    """
    session = TestSessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
        TestSessionLocal.remove()


@pytest.fixture
def app_client() -> Generator[TestClient, None, None]:
    """Create test client with overridden dependencies.

    This fixture provides a FastAPI TestClient configured for testing with
    authentication disabled and using an in-memory database.

    Yields:
        FastAPI test client
    """
    app = create_app()

    app.dependency_overrides[get_settings] = get_test_settings
    app.dependency_overrides[get_db] = override_get_db

    Base.metadata.create_all(bind=test_engine)

    try:
        with TestClient(app) as client:
            yield client
    finally:
        Base.metadata.drop_all(bind=test_engine)
        app.dependency_overrides.clear()


@pytest.fixture
def production_client() -> Generator[TestClient, None, None]:
    """Create test client with production settings."""

    def get_prod_settings() -> Settings:
        return Settings(
            database_url=TEST_DATABASE_URL,
            environment="production",
        )

    app = create_app()
    app.dependency_overrides[get_settings] = get_prod_settings
    app.dependency_overrides[get_db] = override_get_db

    Base.metadata.create_all(bind=test_engine)

    try:
        with TestClient(app) as client:
            yield client
    finally:
        Base.metadata.drop_all(bind=test_engine)
        app.dependency_overrides.clear()


@pytest.fixture
def auth_enabled_client() -> Generator[TestClient]:
    """Create test client with authentication enabled."""
    app = create_app()

    app.dependency_overrides[get_settings] = get_auth_settings
    app.dependency_overrides[get_db] = override_get_db

    Base.metadata.create_all(bind=test_engine)

    try:
        with TestClient(app) as client:
            yield client
    finally:
        Base.metadata.drop_all(bind=test_engine)
        app.dependency_overrides.clear()


@pytest.fixture
def sample_schema() -> dict[str, Any]:
    """Sample JSON schema for testing.

    Returns:
        A valid JSON Schema with basic user properties.
    """
    return {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "name": {"type": "string"},
            "email": {"type": "string", "format": "email"},
        },
        "required": ["id", "name"],
    }


@pytest.fixture
def sample_schema_v2() -> dict[str, Any]:
    """Sample JSON schema version 2 for testing.

    This version adds a new field and makes email required, useful for testing schema
    evolution and comparison.

    Returns:
        A valid JSON Schema v2 with additional properties.
    """
    return {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "name": {"type": "string"},
            "email": {"type": "string", "format": "email"},
            "age": {"type": "integer"},  # New field
        },
        "required": ["id", "name", "email"],  # Email now required
    }
