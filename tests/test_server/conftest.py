"""Test configuration and fixtures."""

from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from pyrmute_registry.server.auth import hash_api_key
from pyrmute_registry.server.config import Settings, get_settings
from pyrmute_registry.server.db import Base, get_db
from pyrmute_registry.server.main import create_app
from pyrmute_registry.server.models.api_key import ApiKey, Permission

# Test database URL
TEST_DATABASE_URL = "sqlite:///:memory:"


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
        environment="test",
        cors_origins=["*"],
    )


@pytest.fixture(autouse=True)
def reset_settings_cache() -> Generator[None, None, None]:
    """Clear settings cache before each test."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(scope="function")
def db_engine() -> Generator[Engine, None, None]:
    """Create a new database engine for each test."""
    engine = create_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture(scope="function")
def db_session(db_engine: Engine) -> Generator[Session, None, None]:
    """Create test database session for each test.

    This fixture creates a fresh database session for each test, then tears it
    down after the test completes.

    Yields:
        Database session with clean state
    """
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=db_engine)
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@pytest.fixture
def app_client(db_session: Session) -> Generator[TestClient, None, None]:
    """Create test client with overridden dependencies.

    This fixture provides a FastAPI TestClient configured for testing with
    authentication disabled and using an in-memory database.

    Yields:
        FastAPI test client.
    """
    app = create_app()

    def override_get_db() -> Generator[Session, None, None]:
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_settings] = get_test_settings
    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def production_client(db_session: Session) -> Generator[TestClient, None, None]:
    """Create test client with production settings."""

    def get_prod_settings() -> Settings:
        return Settings(
            database_url=TEST_DATABASE_URL,
            environment="production",
        )

    def override_get_db() -> Generator[Session, None, None]:
        try:
            yield db_session
        finally:
            pass

    app = create_app()
    app.dependency_overrides[get_settings] = get_prod_settings
    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def auth_enabled_client(db_session: Session) -> Generator[TestClient, None, None]:
    """Create test client with authentication enabled."""
    app = create_app()

    def override_get_db() -> Generator[Session, None, None]:
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_settings] = get_auth_settings
    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def sample_schema() -> dict[str, Any]:
    """Sample JSON schema for testing."""
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
    """Sample JSON schema version 2 for testing."""
    return {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "name": {"type": "string"},
            "email": {"type": "string", "format": "email"},
            "age": {"type": "integer"},
        },
        "required": ["id", "name", "email"],
    }


@pytest.fixture
def auth_enabled_settings() -> Settings:
    """Settings with authentication enabled."""
    return Settings(
        database_url="sqlite:///:memory:",
        enable_auth=True,
        environment="test",
    )


@pytest.fixture
def auth_disabled_settings() -> Settings:
    """Settings with authentication disabled."""
    return Settings(
        database_url="sqlite:///:memory:",
        enable_auth=False,
        environment="test",
    )


@pytest.fixture
def sample_api_key(db_session: Session) -> ApiKey:
    """Create a sample API key for testing."""
    plaintext = "test-key-secret-12345"
    key = ApiKey(
        name="test-key",
        key_hash=hash_api_key(plaintext),
        permission=Permission.WRITE.value,
        created_by="test",
        description="Test API key",
    )
    db_session.add(key)
    db_session.commit()
    db_session.refresh(key)
    key._plaintext = plaintext  # type: ignore[attr-defined]
    return key


@pytest.fixture
def admin_api_key(db_session: Session) -> ApiKey:
    """Create an admin API key for testing."""
    plaintext = "admin-key-secret-67890"
    key = ApiKey(
        name="test-admin-key",
        key_hash=hash_api_key(plaintext),
        permission=Permission.ADMIN.value,
        created_by="test",
        description="Admin API key",
    )
    db_session.add(key)
    db_session.commit()
    db_session.refresh(key)
    key._plaintext = plaintext  # type: ignore[attr-defined]
    return key


@pytest.fixture
def read_only_key(db_session: Session) -> ApiKey:
    """Create a read-only API key for testing."""
    plaintext = "readonly-key-secret-11111"
    key = ApiKey(
        name="readonly-key",
        key_hash=hash_api_key(plaintext),
        permission=Permission.READ.value,
        created_by="test",
        description="Read-only API key",
    )
    db_session.add(key)
    db_session.commit()
    db_session.refresh(key)
    key._plaintext = plaintext  # type: ignore[attr-defined]
    return key


@pytest.fixture
def delete_permission_key(db_session: Session) -> ApiKey:
    """Create an API key with delete permission for testing."""
    plaintext = "delete-key-secret-44444"
    key = ApiKey(
        name="delete-key",
        key_hash=hash_api_key(plaintext),
        permission=Permission.DELETE.value,
        created_by="test",
        description="Delete permission API key",
    )
    db_session.add(key)
    db_session.commit()
    db_session.refresh(key)
    key._plaintext = plaintext  # type: ignore[attr-defined]
    return key


@pytest.fixture
def revoked_key(db_session: Session) -> ApiKey:
    """Create a revoked API key for testing."""
    plaintext = "revoked-key-secret-22222"
    key = ApiKey(
        name="revoked-key",
        key_hash=hash_api_key(plaintext),
        permission=Permission.WRITE.value,
        created_by="test",
        description="Revoked API key",
        revoked=True,
        revoked_at=datetime.now(UTC),
        revoked_by="test",
    )
    db_session.add(key)
    db_session.commit()
    db_session.refresh(key)
    key._plaintext = plaintext  # type: ignore[attr-defined]
    return key


@pytest.fixture
def expired_key(db_session: Session) -> ApiKey:
    """Create an expired API key for testing."""
    plaintext = "expired-key-secret-33333"
    key = ApiKey(
        name="expired-key",
        key_hash=hash_api_key(plaintext),
        permission=Permission.WRITE.value,
        created_by="test",
        description="Expired API key",
        expires_at=datetime.now(UTC) - timedelta(days=1),
    )
    db_session.add(key)
    db_session.commit()
    db_session.refresh(key)
    key._plaintext = plaintext  # type: ignore[attr-defined]
    return key


@pytest.fixture
def admin_key_header(db_session: Session, admin_api_key: ApiKey) -> dict[str, str]:
    """Create authentication header with admin API key."""
    return {"X-API-Key": admin_api_key._plaintext}  # type: ignore[attr-defined]


@pytest.fixture
def write_key_header(db_session: Session, sample_api_key: ApiKey) -> dict[str, str]:
    """Create authentication header with write API key."""
    return {"X-API-Key": sample_api_key._plaintext}  # type: ignore[attr-defined]


@pytest.fixture
def read_key_header(db_session: Session, read_only_key: ApiKey) -> dict[str, str]:
    """Create authentication header with read-only API key."""
    return {"X-API-Key": read_only_key._plaintext}  # type: ignore[attr-defined]
