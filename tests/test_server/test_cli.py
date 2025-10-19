"""Tests for CLI commands."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
from pytest import MonkeyPatch
from typer.testing import CliRunner

from pyrmute_registry.server.cli import app, main

runner = CliRunner()


@pytest.fixture(autouse=True)
def set_column_width(monkeypatch: MonkeyPatch) -> None:
    """Sets a higher column width to prevent tests from failing."""
    monkeypatch.setenv("TERMINAL_WIDTH", "3000")


# =============================================================================
# Serve Command Tests
# =============================================================================


def test_serve_command_default_settings() -> None:
    """Test serve command with default settings."""
    with patch("pyrmute_registry.server.cli.uvicorn.run") as mock_run:
        result = runner.invoke(app, ["serve"])

        assert result.exit_code == 0
        assert "Starting Pyrmute Schema Registry" in result.stdout
        assert "http://0.0.0.0:8000" in result.stdout

        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["host"] == "0.0.0.0"
        assert call_kwargs["port"] == 8000  # noqa: PLR2004
        assert call_kwargs["reload"] is False
        assert call_kwargs["workers"] == 1


def test_serve_command_custom_host_port() -> None:
    """Test serve command with custom host and port."""
    with patch("pyrmute_registry.server.cli.uvicorn.run") as mock_run:
        result = runner.invoke(app, ["serve", "--host", "127.0.0.1", "--port", "8080"])

        assert result.exit_code == 0
        assert "http://127.0.0.1:8080" in result.stdout

        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["host"] == "127.0.0.1"
        assert call_kwargs["port"] == 8080  # noqa: PLR2004


def test_serve_command_with_reload() -> None:
    """Test serve command with reload enabled."""
    with patch("pyrmute_registry.server.cli.uvicorn.run") as mock_run:
        result = runner.invoke(app, ["serve", "--reload"])

        assert result.exit_code == 0
        assert "Reload: True" in result.stdout

        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["reload"] is True
        assert call_kwargs["workers"] == 1  # Should force 1 worker with reload


def test_serve_command_with_workers() -> None:
    """Test serve command with multiple workers."""
    with patch("pyrmute_registry.server.cli.uvicorn.run") as mock_run:
        result = runner.invoke(app, ["serve", "--workers", "4"])

        assert result.exit_code == 0
        assert "Workers: 4" in result.stdout

        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["workers"] == 4  # noqa: PLR2004


def test_serve_command_workers_forced_to_one_with_reload() -> None:
    """Test that workers is forced to 1 when reload is enabled."""
    with patch("pyrmute_registry.server.cli.uvicorn.run") as mock_run:
        result = runner.invoke(app, ["serve", "--reload", "--workers", "4"])

        assert result.exit_code == 0

        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["workers"] == 1  # Should force 1 with reload


def test_serve_command_with_log_level() -> None:
    """Test serve command with custom log level."""
    with patch("pyrmute_registry.server.cli.uvicorn.run") as mock_run:
        result = runner.invoke(app, ["serve", "--log-level", "debug"])

        assert result.exit_code == 0

        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["log_level"] == "debug"


def test_serve_command_with_no_access_log() -> None:
    """Test serve command with access log disabled."""
    with patch("pyrmute_registry.server.cli.uvicorn.run") as mock_run:
        result = runner.invoke(app, ["serve", "--no-access-log"])

        assert result.exit_code == 0

        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["access_log"] is False


def test_serve_command_shows_docs_in_dev() -> None:
    """Test that serve command shows docs URLs in development."""
    with patch("pyrmute_registry.server.cli.uvicorn.run"):
        result = runner.invoke(app, ["serve"])

        assert result.exit_code == 0
        # In test environment, should show docs
        assert "Docs:" in result.stdout or "Environment:" in result.stdout


def test_serve_command_keyboard_interrupt() -> None:
    """Test serve command handles keyboard interrupt gracefully."""
    with patch(
        "pyrmute_registry.server.cli.uvicorn.run",
        side_effect=KeyboardInterrupt(),
    ):
        result = runner.invoke(app, ["serve"])

        assert result.exit_code == 0
        assert "Shutting down gracefully" in result.stdout


# =============================================================================
# Database Initialization Tests
# =============================================================================


def test_init_db_command_success() -> None:
    """Test init-db command succeeds."""
    with patch("pyrmute_registry.server.cli.db_init") as mock_init:
        result = runner.invoke(app, ["init-db"])

        assert result.exit_code == 0
        assert "Database initialized successfully" in result.stdout
        mock_init.assert_called_once()


def test_init_db_command_with_custom_url() -> None:
    """Test init-db command with custom database URL."""
    with patch("pyrmute_registry.server.cli.db_init") as mock_init:
        result = runner.invoke(
            app, ["init-db", "--database-url", "postgresql://localhost/test"]
        )

        assert result.exit_code == 0
        mock_init.assert_called_once()


def test_init_db_command_failure() -> None:
    """Test init-db command handles failure."""
    with patch(
        "pyrmute_registry.server.cli.db_init",
        side_effect=RuntimeError("Connection failed"),
    ):
        result = runner.invoke(app, ["init-db"])

        assert result.exit_code == 1
        assert "Failed to initialize database" in result.stdout


# =============================================================================
# API Key Management Tests
# =============================================================================


def test_create_admin_key_command_success() -> None:
    """Test create-admin-key command creates a key successfully."""
    with (
        patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class,
        patch("pyrmute_registry.server.cli.hash_api_key") as mock_hash,
        patch("pyrmute_registry.server.cli.secrets.token_urlsafe") as mock_token,
    ):
        # Setup mocks
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_hash.return_value = "hashed_key"
        mock_token.return_value = "test-key-12345"

        # Mock query to return no existing keys
        mock_session.query.return_value.filter.return_value.first.return_value = None

        # Mock the created API key
        mock_api_key = MagicMock()
        mock_api_key.name = "test-key"
        mock_api_key.permission = "admin"
        mock_api_key.created_at = "2025-01-01T00:00:00"
        mock_api_key.expires_at = None

        result = runner.invoke(
            app,
            ["create-admin-key", "--name", "test-key", "--permission", "admin"],
        )

        assert result.exit_code == 0
        assert "API Key created successfully" in result.stdout
        assert "test-key-12345" in result.stdout
        assert "IMPORTANT" in result.stdout
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()


def test_create_admin_key_command_with_description() -> None:
    """Test create-admin-key with description."""
    with (
        patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class,
        patch("pyrmute_registry.server.cli.hash_api_key"),
        patch("pyrmute_registry.server.cli.secrets.token_urlsafe") as mock_token,
    ):
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_token.return_value = "test-key-12345"
        mock_session.query.return_value.filter.return_value.first.return_value = None

        result = runner.invoke(
            app,
            [
                "create-admin-key",
                "--name",
                "ci-key",
                "--description",
                "CI/CD pipeline key",
            ],
        )

        assert result.exit_code == 0
        assert "API Key created successfully" in result.stdout


def test_create_admin_key_command_with_expiration() -> None:
    """Test create-admin-key with expiration."""
    with (
        patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class,
        patch("pyrmute_registry.server.cli.hash_api_key"),
        patch("pyrmute_registry.server.cli.secrets.token_urlsafe") as mock_token,
    ):
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_token.return_value = "test-key-12345"
        mock_session.query.return_value.filter.return_value.first.return_value = None

        result = runner.invoke(
            app,
            [
                "create-admin-key",
                "--name",
                "temp-key",
                "--expires-in-days",
                "90",
            ],
        )

        assert result.exit_code == 0
        assert "API Key created successfully" in result.stdout


def test_create_admin_key_command_duplicate_name() -> None:
    """Test create-admin-key fails with duplicate name."""
    with (
        patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class,
    ):
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock existing key
        existing_key = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = (
            existing_key
        )

        result = runner.invoke(
            app,
            ["create-admin-key", "--name", "existing-key"],
        )

        assert result.exit_code == 1
        assert "already exists" in result.stdout


def test_create_admin_key_command_invalid_permission() -> None:
    """Test create-admin-key fails with invalid permission."""
    result = runner.invoke(
        app,
        ["create-admin-key", "--name", "test-key", "--permission", "invalid"],
    )

    assert result.exit_code == 1
    assert "Invalid permission" in result.stdout


def test_create_admin_key_command_with_read_permission() -> None:
    """Test create-admin-key with read permission."""
    with (
        patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class,
        patch("pyrmute_registry.server.cli.hash_api_key"),
        patch("pyrmute_registry.server.cli.secrets.token_urlsafe") as mock_token,
    ):
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_token.return_value = "test-key-12345"
        mock_session.query.return_value.filter.return_value.first.return_value = None

        result = runner.invoke(
            app,
            ["create-admin-key", "--name", "readonly", "--permission", "read"],
        )

        assert result.exit_code == 0
        assert "API Key created successfully" in result.stdout


def test_list_keys_command_empty() -> None:
    """Test list-keys with no keys."""
    with patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_session_filter = mock_session.query.return_value.filter
        mock_session_filter.return_value.order_by.return_value.all.return_value = []

        result = runner.invoke(app, ["list-keys"])

        assert result.exit_code == 0
        assert "No API keys found" in result.stdout


def test_list_keys_command_with_keys() -> None:
    """Test list-keys displays keys."""
    with patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Create mock API keys
        key1 = MagicMock()
        key1.name = "admin-key"
        key1.id = 1
        key1.permission = "admin"
        key1.created_at = "2025-01-01T00:00:00"
        key1.created_by = "cli"
        key1.last_used_at = None
        key1.use_count = 0
        key1.expires_at = None
        key1.is_expired = False
        key1.revoked = False
        key1.description = "Admin key"

        key2 = MagicMock()
        key2.name = "readonly-key"
        key2.id = 2
        key2.permission = "read"
        key2.created_at = "2025-01-02T00:00:00"
        key2.created_by = "cli"
        key2.last_used_at = "2025-01-03T00:00:00"
        key2.use_count = 42
        key2.expires_at = None
        key2.is_expired = False
        key2.revoked = False
        key2.description = None

        mock_session_filter = mock_session.query.return_value.filter
        mock_session_filter.return_value.order_by.return_value.all.return_value = [
            key1,
            key2,
        ]

        result = runner.invoke(app, ["list-keys"])

        assert result.exit_code == 0
        assert "Found 2 API key(s)" in result.stdout
        assert "admin-key" in result.stdout
        assert "readonly-key" in result.stdout
        assert "ACTIVE" in result.stdout


def test_list_keys_command_with_revoked() -> None:
    """Test list-keys includes revoked keys when requested."""
    with patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        key = MagicMock()
        key.name = "revoked-key"
        key.id = 1
        key.permission = "write"
        key.created_at = "2025-01-01T00:00:00"
        key.created_by = "cli"
        key.last_used_at = None
        key.use_count = 0
        key.expires_at = None
        key.revoked = True
        key.revoked_at = "2025-01-02T00:00:00"
        key.revoked_by = "admin"
        key.description = None
        key.is_expired = False

        mock_session.query.return_value.order_by.return_value.all.return_value = [key]

        result = runner.invoke(app, ["list-keys", "--include-revoked"])

        assert result.exit_code == 0
        assert "revoked-key" in result.stdout
        assert "REVOKED" in result.stdout


def test_revoke_key_command_success() -> None:
    """Test revoke-key successfully revokes a key."""
    with patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        key = MagicMock()
        key.name = "test-key"
        key.revoked = False
        key.description = None

        mock_session.query.return_value.filter.return_value.first.return_value = key

        result = runner.invoke(app, ["revoke-key", "test-key"], input="y\n")

        assert result.exit_code == 0
        assert "has been revoked" in result.stdout
        assert key.revoked is True
        mock_session.commit.assert_called_once()


def test_revoke_key_command_with_reason() -> None:
    """Test revoke-key with a reason."""
    with patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        key = MagicMock()
        key.name = "test-key"
        key.revoked = False
        key.description = "Original description"

        mock_session.query.return_value.filter.return_value.first.return_value = key

        result = runner.invoke(
            app,
            ["revoke-key", "test-key", "--reason", "Key compromised"],
            input="y\n",
        )

        assert result.exit_code == 0
        assert "Key compromised" in key.description


def test_revoke_key_command_not_found() -> None:
    """Test revoke-key with non-existent key."""
    with patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_session.query.return_value.filter.return_value.first.return_value = None

        result = runner.invoke(app, ["revoke-key", "nonexistent"])

        assert result.exit_code == 1
        assert "not found" in result.stdout


def test_revoke_key_command_already_revoked() -> None:
    """Test revoke-key with already revoked key."""
    with patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        key = MagicMock()
        key.name = "test-key"
        key.revoked = True

        mock_session.query.return_value.filter.return_value.first.return_value = key

        result = runner.invoke(app, ["revoke-key", "test-key"])

        assert result.exit_code == 1
        assert "already revoked" in result.stdout


def test_revoke_key_command_cancelled() -> None:
    """Test revoke-key when user cancels."""
    with patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        key = MagicMock()
        key.name = "test-key"
        key.revoked = False

        mock_session.query.return_value.filter.return_value.first.return_value = key

        result = runner.invoke(app, ["revoke-key", "test-key"], input="n\n")

        assert result.exit_code == 1
        assert "cancelled" in result.stdout
        mock_session.commit.assert_not_called()


# =============================================================================
# Health Check Tests
# =============================================================================


def test_check_health_command_healthy() -> None:
    """Test check-health command with healthy registry."""
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "status": "healthy",
        "version": "1.0.0",
        "environment": "production",
        "database": {"type": "postgresql"},
        "schemas_count": 42,
        "uptime_seconds": 3600.5,
    }

    with patch("httpx.get", return_value=mock_response):
        result = runner.invoke(app, ["check-health"])

        assert result.exit_code == 0
        assert "Registry is healthy" in result.stdout
        assert "Version: 1.0.0" in result.stdout
        assert "Schemas: 42" in result.stdout


def test_check_health_command_unhealthy() -> None:
    """Test check-health command with unhealthy registry."""
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "status": "unhealthy",
        "error": "Database connection failed",
    }

    with patch("httpx.get", return_value=mock_response):
        result = runner.invoke(app, ["check-health"])

        assert result.exit_code == 1
        assert "Registry is unhealthy" in result.stdout
        assert "Database connection failed" in result.stdout


def test_check_health_command_with_custom_url() -> None:
    """Test check-health command with custom URL."""
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "status": "healthy",
        "version": "1.0.0",
        "environment": "production",
        "database": {"type": "postgresql"},
        "schemas_count": 10,
        "uptime_seconds": 100.5,
    }

    with patch("httpx.get", return_value=mock_response) as mock_get:
        result = runner.invoke(
            app, ["check-health", "--url", "https://registry.example.com"]
        )

        assert result.exit_code == 0
        mock_get.assert_called_once_with(
            "https://registry.example.com/health", timeout=5.0
        )


def test_check_health_command_connection_error() -> None:
    """Test check-health command handles connection errors."""
    with patch("httpx.get", side_effect=httpx.ConnectError("Connection refused")):
        result = runner.invoke(app, ["check-health"])

        assert result.exit_code == 1
        assert "Failed to connect" in result.stdout


def test_check_health_command_http_error() -> None:
    """Test check-health command handles HTTP errors."""
    mock_response = MagicMock()
    mock_response.status_code = 503

    with patch(
        "httpx.get",
        side_effect=httpx.HTTPStatusError(
            "Service unavailable", request=MagicMock(), response=mock_response
        ),
    ):
        result = runner.invoke(app, ["check-health"])

        assert result.exit_code == 1
        assert "Health check failed" in result.stdout


# =============================================================================
# Info Commands Tests
# =============================================================================


def test_version_command() -> None:
    """Test version command."""
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "Pyrmute Schema Registry" in result.stdout
    assert "v1.0.0" in result.stdout


def test_config_command() -> None:
    """Test config command displays configuration."""
    result = runner.invoke(app, ["config"])

    assert result.exit_code == 0
    assert "Current Configuration" in result.stdout
    assert "App Name:" in result.stdout
    assert "Version:" in result.stdout
    assert "Environment:" in result.stdout
    assert "Server:" in result.stdout
    assert "Database:" in result.stdout
    assert "Authentication:" in result.stdout


def test_config_command_masks_database_password() -> None:
    """Test that config command masks database password."""
    with patch("pyrmute_registry.server.cli.get_settings") as mock_get_settings:
        mock_settings = MagicMock()
        mock_settings.app_name = "Test Registry"
        mock_settings.app_version = "1.0.0"
        mock_settings.environment = "test"
        mock_settings.debug = False
        mock_settings.host = "0.0.0.0"
        mock_settings.port = 8000
        mock_settings.reload = False
        mock_settings.workers = 1
        mock_settings.database_url = "postgresql://user:password@localhost/db"
        mock_settings.database_echo = False
        mock_settings.enable_auth = True
        mock_settings.cors_origins = ["*"]
        mock_settings.cors_allow_credentials = True
        mock_settings.log_level = "INFO"
        mock_get_settings.return_value = mock_settings

        result = runner.invoke(app, ["config"])

        assert result.exit_code == 0
        # Should mask password in database URL
        assert "password" not in result.stdout
        assert "postgresql://***" in result.stdout


# =============================================================================
# Environment File Generation Tests
# =============================================================================


def test_generate_env_command_default() -> None:
    """Test generate-env command creates default file."""
    with runner.isolated_filesystem():
        result = runner.invoke(app, ["generate-env"])

        assert result.exit_code == 0
        assert "Generated .env.example" in result.stdout
        assert Path(".env.example").exists()

        content = Path(".env.example").read_text()
        assert "PYRMUTE_REGISTRY_APP_NAME" in content
        assert "PYRMUTE_REGISTRY_DATABASE_URL" in content
        assert "PYRMUTE_REGISTRY_ENABLE_AUTH" in content


def test_generate_env_command_custom_output() -> None:
    """Test generate-env command with custom output path."""
    with runner.isolated_filesystem():
        result = runner.invoke(app, ["generate-env", "--output", ".env.local"])

        assert result.exit_code == 0
        assert "Generated .env.local" in result.stdout
        assert Path(".env.local").exists()


def test_generate_env_command_file_exists_without_force() -> None:
    """Test generate-env command fails when file exists without force."""
    with runner.isolated_filesystem():
        # Create existing file
        Path(".env.example").write_text("existing content")

        result = runner.invoke(app, ["generate-env"])

        assert result.exit_code == 1
        assert "already exists" in result.stdout
        assert "Use --force" in result.stdout


def test_generate_env_command_with_force() -> None:
    """Test generate-env command overwrites with force flag."""
    with runner.isolated_filesystem():
        # Create existing file
        Path(".env.example").write_text("existing content")

        result = runner.invoke(app, ["generate-env", "--force"])

        assert result.exit_code == 0
        assert "Generated .env.example" in result.stdout

        content = Path(".env.example").read_text()
        assert "existing content" not in content
        assert "PYRMUTE_REGISTRY" in content


def test_generate_env_command_no_legacy_api_key() -> None:
    """Test that generated env file mentions database-backed keys, not legacy key."""
    with runner.isolated_filesystem():
        result = runner.invoke(app, ["generate-env"])

        assert result.exit_code == 0

        content = Path(".env.example").read_text()

        # Should NOT have legacy API key field
        assert "PYRMUTE_REGISTRY_API_KEY=" not in content

        # Should have authentication section with instructions
        assert "PYRMUTE_REGISTRY_ENABLE_AUTH" in content
        assert "create-admin-key" in content or "pyrmute-registry" in content


def test_generate_env_command_content_includes_all_options() -> None:
    """Test that generated env file includes all configuration options."""
    with runner.isolated_filesystem():
        result = runner.invoke(app, ["generate-env"])

        assert result.exit_code == 0

        content = Path(".env.example").read_text()

        # Check all major configuration sections
        assert "PYRMUTE_REGISTRY_APP_NAME" in content
        assert "PYRMUTE_REGISTRY_ENVIRONMENT" in content
        assert "PYRMUTE_REGISTRY_HOST" in content
        assert "PYRMUTE_REGISTRY_PORT" in content
        assert "PYRMUTE_REGISTRY_DATABASE_URL" in content
        assert "PYRMUTE_REGISTRY_ENABLE_AUTH" in content
        assert "PYRMUTE_REGISTRY_CORS_ORIGINS" in content
        assert "PYRMUTE_REGISTRY_LOG_LEVEL" in content

        # Check comments
        assert "# Application" in content
        assert "# Server" in content
        assert "# Database" in content
        assert "# Authentication" in content


# =============================================================================
# Help Text Tests
# =============================================================================


def test_cli_app_has_help() -> None:
    """Test that CLI app has help text."""
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Pyrmute Schema Registry" in result.stdout
    assert "serve" in result.stdout
    assert "init-db" in result.stdout
    assert "check-health" in result.stdout
    assert "version" in result.stdout
    assert "config" in result.stdout
    assert "generate-env" in result.stdout
    assert "create-admin-key" in result.stdout
    assert "list-keys" in result.stdout
    assert "revoke-key" in result.stdout


def test_serve_command_has_help() -> None:
    """Test that serve command has help text."""
    result = runner.invoke(app, ["serve", "--help"])

    assert result.exit_code == 0
    assert "Start the Pyrmute Schema Registry server" in result.stdout
    assert "--host" in result.stdout
    assert "--port" in result.stdout
    assert "--reload" in result.stdout
    assert "--workers" in result.stdout


def test_init_db_command_has_help() -> None:
    """Test that init-db command has help text."""
    result = runner.invoke(app, ["init-db", "--help"])

    assert result.exit_code == 0
    assert "Initialize the database tables" in result.stdout
    assert "--database-url" in result.stdout


def test_create_admin_key_command_has_help() -> None:
    """Test that create-admin-key command has help text."""
    result = runner.invoke(app, ["create-admin-key", "--help"])

    assert result.exit_code == 0
    assert "Create an API key" in result.stdout
    assert "--name" in result.stdout
    assert "--permission" in result.stdout
    assert "--description" in result.stdout
    assert "--expires-in-days" in result.stdout


def test_list_keys_command_has_help() -> None:
    """Test that list-keys command has help text."""
    result = runner.invoke(app, ["list-keys", "--help"])

    assert result.exit_code == 0
    assert "List all API keys" in result.stdout
    assert "--include-revoked" in result.stdout


def test_revoke_key_command_has_help() -> None:
    """Test that revoke-key command has help text."""
    result = runner.invoke(app, ["revoke-key", "--help"])

    assert result.exit_code == 0
    assert "Revoke an API key" in result.stdout
    assert "--reason" in result.stdout


def test_check_health_command_has_help() -> None:
    """Test that check-health command has help text."""
    result = runner.invoke(app, ["check-health", "--help"])

    assert result.exit_code == 0
    assert "Check the health" in result.stdout
    assert "--url" in result.stdout


def test_generate_env_command_has_help() -> None:
    """Test that generate-env command has help text."""
    result = runner.invoke(app, ["generate-env", "--help"])

    assert result.exit_code == 0
    assert "Generate an example .env file" in result.stdout
    assert "--output" in result.stdout
    assert "--force" in result.stdout


def test_main_entry_point() -> None:
    """Test that main entry point works."""
    with patch("pyrmute_registry.server.cli.app") as mock_app:
        main()
        mock_app.assert_called_once()


# =============================================================================
# Integration Tests
# =============================================================================


def test_create_and_list_keys_integration() -> None:
    """Test creating a key and then listing it."""
    with (
        patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class,
        patch("pyrmute_registry.server.cli.hash_api_key"),
        patch("pyrmute_registry.server.cli.secrets.token_urlsafe") as mock_token,
    ):
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_token.return_value = "test-key-12345"

        # First create a key
        mock_session.query.return_value.filter.return_value.first.return_value = None

        create_result = runner.invoke(
            app,
            ["create-admin-key", "--name", "integration-test"],
        )

        assert create_result.exit_code == 0

        # Then list keys
        key = MagicMock()
        key.name = "integration-test"
        key.id = 1
        key.permission = "admin"
        key.created_at = "2025-01-01T00:00:00"
        key.created_by = "cli"
        key.last_used_at = None
        key.use_count = 0
        key.expires_at = None
        key.revoked = False
        key.description = None

        mock_session_filter = mock_session.query.return_value.filter
        mock_session_filter.return_value.order_by.return_value.all.return_value = [key]

        list_result = runner.invoke(app, ["list-keys"])

        assert list_result.exit_code == 0
        assert "integration-test" in list_result.stdout


def test_create_and_revoke_keys_integration() -> None:
    """Test creating a key and then revoking it."""
    with (
        patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class,
        patch("pyrmute_registry.server.cli.hash_api_key"),
        patch("pyrmute_registry.server.cli.secrets.token_urlsafe") as mock_token,
    ):
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_token.return_value = "test-key-12345"

        # Create key
        mock_session.query.return_value.filter.return_value.first.return_value = None

        create_result = runner.invoke(
            app,
            ["create-admin-key", "--name", "revoke-test"],
        )

        assert create_result.exit_code == 0

        # Revoke key
        key = MagicMock()
        key.name = "revoke-test"
        key.revoked = False
        key.description = None

        mock_session.query.return_value.filter.return_value.first.return_value = key

        revoke_result = runner.invoke(app, ["revoke-key", "revoke-test"], input="y\n")

        assert revoke_result.exit_code == 0
        assert key.revoked is True


# =============================================================================
# Error Handling Tests
# =============================================================================


def test_create_admin_key_database_error() -> None:
    """Test create-admin-key handles database errors."""
    with (
        patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class,
        patch("pyrmute_registry.server.cli.hash_api_key"),
        patch("pyrmute_registry.server.cli.secrets.token_urlsafe"),
    ):
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_session.query.return_value.filter.return_value.first.return_value = None
        mock_session.commit.side_effect = Exception("Database error")

        result = runner.invoke(
            app,
            ["create-admin-key", "--name", "error-test"],
        )

        assert result.exit_code == 1
        assert "Failed to create API key" in result.stdout


def test_list_keys_database_error() -> None:
    """Test list-keys handles database errors gracefully."""
    with patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_session.query.side_effect = Exception("Database connection failed")

        # Should handle the error gracefully
        result = runner.invoke(app, ["list-keys"])

        # The command will raise an exception, but we verify it doesn't succeed
        assert result.exit_code != 0


def test_revoke_key_database_error() -> None:
    """Test revoke-key handles database errors."""
    with patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        key = MagicMock()
        key.name = "test-key"
        key.revoked = False
        key.description = None

        mock_session.query.return_value.filter.return_value.first.return_value = key
        mock_session.commit.side_effect = Exception("Database error")

        result = runner.invoke(app, ["revoke-key", "test-key"], input="y\n")

        assert result.exit_code == 1
        assert "Failed to revoke key" in result.stdout


# =============================================================================
# Edge Case Tests
# =============================================================================


def test_create_admin_key_with_all_options() -> None:
    """Test create-admin-key with all options specified."""
    with (
        patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class,
        patch("pyrmute_registry.server.cli.hash_api_key"),
        patch("pyrmute_registry.server.cli.secrets.token_urlsafe") as mock_token,
    ):
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_token.return_value = "test-key-12345"
        mock_session.query.return_value.filter.return_value.first.return_value = None

        result = runner.invoke(
            app,
            [
                "create-admin-key",
                "--name",
                "full-options",
                "--permission",
                "write",
                "--description",
                "Full options test",
                "--expires-in-days",
                "365",
            ],
        )

        assert result.exit_code == 0
        assert "API Key created successfully" in result.stdout
        assert "test-key-12345" in result.stdout


def test_list_keys_shows_expired_status() -> None:
    """Test that list-keys shows expired status."""
    with patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        key = MagicMock()
        key.name = "expired-key"
        key.id = 1
        key.permission = "read"
        key.created_at = "2024-01-01T00:00:00"
        key.created_by = "cli"
        key.last_used_at = None
        key.use_count = 0
        key.expires_at = "2024-12-31T00:00:00"
        key.revoked = False
        key.description = None
        key.is_expired = True

        mock_session_filter = mock_session.query.return_value.filter
        mock_session_filter.return_value.order_by.return_value.all.return_value = [key]

        result = runner.invoke(app, ["list-keys"])

        assert result.exit_code == 0
        assert "expired-key" in result.stdout
        assert "EXPIRED" in result.stdout


def test_list_keys_shows_usage_stats() -> None:
    """Test that list-keys displays usage statistics."""
    with patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        key = MagicMock()
        key.name = "active-key"
        key.id = 1
        key.permission = "write"
        key.created_at = "2025-01-01T00:00:00"
        key.created_by = "cli"
        key.last_used_at = "2025-01-15T10:30:00"
        key.use_count = 150
        key.expires_at = None
        key.revoked = False
        key.description = "High usage key"
        key.is_expired = False

        mock_session_filter = mock_session.query.return_value.filter
        mock_session_filter.return_value.order_by.return_value.all.return_value = [key]

        result = runner.invoke(app, ["list-keys"])

        assert result.exit_code == 0
        assert "150 times" in result.stdout or "use_count" in result.stdout.lower()
        assert "High usage key" in result.stdout


def test_revoke_key_preserves_existing_description() -> None:
    """Test that revoking a key preserves and appends to existing description."""
    with patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        key = MagicMock()
        key.name = "test-key"
        key.revoked = False
        key.description = "Original description"

        mock_session.query.return_value.filter.return_value.first.return_value = key

        result = runner.invoke(
            app,
            ["revoke-key", "test-key", "--reason", "Security audit"],
            input="y\n",
        )

        assert result.exit_code == 0
        # Should preserve original description and add reason
        assert "Original description" in key.description
        assert "Security audit" in key.description


def test_create_admin_key_shows_usage_examples() -> None:
    """Test that create-admin-key shows usage examples in output."""
    with (
        patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class,
        patch("pyrmute_registry.server.cli.hash_api_key"),
        patch("pyrmute_registry.server.cli.secrets.token_urlsafe") as mock_token,
    ):
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_token.return_value = "test-key-12345"
        mock_session.query.return_value.filter.return_value.first.return_value = None

        result = runner.invoke(
            app,
            ["create-admin-key", "--name", "example-key"],
        )

        assert result.exit_code == 0
        # Should show curl examples
        assert "curl" in result.stdout
        assert "X-API-Key" in result.stdout or "Authorization" in result.stdout


# =============================================================================
# Permission-Specific Tests
# =============================================================================


def test_create_admin_key_all_permission_levels() -> None:
    """Test creating keys with all permission levels."""
    permissions = ["read", "write", "delete", "admin"]

    for perm in permissions:
        with (
            patch("pyrmute_registry.server.cli.SessionLocal") as mock_session_class,
            patch("pyrmute_registry.server.cli.hash_api_key"),
            patch("pyrmute_registry.server.cli.secrets.token_urlsafe") as mock_token,
        ):
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            mock_token.return_value = f"test-key-{perm}"
            mock_session.query.return_value.filter.return_value.first.return_value = (
                None
            )

            result = runner.invoke(
                app,
                [
                    "create-admin-key",
                    "--name",
                    f"{perm}-key",
                    "--permission",
                    perm,
                ],
            )

            assert result.exit_code == 0, f"Failed to create {perm} key"
            assert "API Key created successfully" in result.stdout
