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


def test_config_command_masks_sensitive_values() -> None:
    """Test that config command masks sensitive values."""
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
        mock_settings.api_key = "secret-key-12345"
        mock_settings.cors_origins = ["*"]
        mock_settings.cors_allow_credentials = True
        mock_settings.log_level = "INFO"
        mock_get_settings.return_value = mock_settings

        result = runner.invoke(app, ["config"])

        assert result.exit_code == 0
        # Should mask password in database URL
        assert "password" not in result.stdout
        assert "postgresql://***" in result.stdout
        # Should mask API key
        assert "secret-key-12345" not in result.stdout
        assert "********" in result.stdout


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
        assert "PYRMUTE_REGISTRY_API_KEY" in content
        assert "PYRMUTE_REGISTRY_CORS_ORIGINS" in content
        assert "PYRMUTE_REGISTRY_LOG_LEVEL" in content
        # Check comments
        assert "# Application" in content
        assert "# Server" in content
        assert "# Database" in content
        assert "# Authentication" in content


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
