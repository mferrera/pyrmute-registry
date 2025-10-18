"""Command-line interface for the Pyrmute Schema Registry server."""

import sys
from pathlib import Path
from typing import Annotated

import httpx
import typer
import uvicorn

from .auth import generate_api_key as gen_key
from .config import get_settings
from .db import init_db as db_init

app = typer.Typer(
    name="pyrmute-registry",
    help=(
        "Pyrmute Schema Registry - Centralized registry for versioned Pydantic schemas"
    ),
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)


@app.command()
def serve(  # noqa: PLR0913
    host: Annotated[
        str,
        typer.Option(
            "--host",
            "-h",
            help="Host to bind the server to",
            envvar="PYRMUTE_REGISTRY_HOST",
        ),
    ] = "0.0.0.0",
    port: Annotated[
        int,
        typer.Option(
            "--port",
            "-p",
            help="Port to bind the server to",
            envvar="PYRMUTE_REGISTRY_PORT",
        ),
    ] = 8000,
    reload: Annotated[
        bool,
        typer.Option(
            "--reload",
            help="Enable auto-reload for development",
            envvar="PYRMUTE_REGISTRY_RELOAD",
        ),
    ] = False,
    workers: Annotated[
        int,
        typer.Option(
            "--workers",
            "-w",
            help="Number of worker processes",
            envvar="PYRMUTE_REGISTRY_WORKERS",
        ),
    ] = 1,
    log_level: Annotated[
        str,
        typer.Option(
            "--log-level",
            help="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
            envvar="PYRMUTE_REGISTRY_LOG_LEVEL",
        ),
    ] = "INFO",
    access_log: Annotated[
        bool,
        typer.Option(
            "--access-log/--no-access-log",
            help="Enable/disable access logging",
        ),
    ] = True,
) -> None:
    """Start the Pyrmute Schema Registry server.

    [bold]Examples:[/bold]

      [dim]# Start with default settings[/dim]
      $ pyrmute-registry serve

      [dim]# Start on custom host and port[/dim]
      $ pyrmute-registry serve --host 127.0.0.1 --port 8080

      [dim]# Start in development mode with auto-reload[/dim]
      $ pyrmute-registry serve --reload

      [dim]# Start in production with multiple workers[/dim]
      $ pyrmute-registry serve --workers 4 --log-level warning
    """
    settings = get_settings()

    # Use CLI arguments, but fall back to settings if not provided
    final_host = host
    final_port = port
    final_workers = workers if not reload else 1  # Force 1 worker with reload

    typer.echo(f"Starting {settings.app_name} v{settings.app_version}")
    typer.echo(f"Environment: {settings.environment}")
    typer.echo(f"Server: http://{final_host}:{final_port}")
    typer.echo(f"Workers: {final_workers}")
    typer.echo(f"Reload: {reload}")

    if not settings.is_production:
        typer.echo(f"Docs: http://{final_host}:{final_port}/docs")
        typer.echo(f"ReDoc: http://{final_host}:{final_port}/redoc")

    typer.echo("")

    try:
        uvicorn.run(
            "pyrmute_registry.server.main:app",
            host=final_host,
            port=final_port,
            reload=reload,
            workers=final_workers,
            log_level=log_level.lower(),
            access_log=access_log,
        )
    except KeyboardInterrupt:
        typer.echo("\nShutting down gracefully...")
        sys.exit(0)


@app.command()
def init_db(
    database_url: Annotated[
        str | None,
        typer.Option(
            "--database-url",
            help="Database URL (overrides config)",
            envvar="PYRMUTE_REGISTRY_DATABASE_URL",
        ),
    ] = None,
) -> None:
    """Initialize the database tables.

    Creates all required tables in the database. This is safe to run multiple times as
    it will not drop existing tables.

    [bold]Examples:[/bold]

      [dim]# Initialize with default database[/dim]
      pyrmute-registry init-db

      [dim]# Initialize with custom database URL[/dim]
      pyrmute-registry init-db --database-url postgresql://user:pass@localhost/db
    """
    settings = get_settings()
    db_url = database_url or settings.database_url

    typer.echo(f"Initializing database: {db_url.split('://')[0]}...")

    try:
        db_init()
        typer.secho("✓ Database initialized successfully!", fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f"✗ Failed to initialize database: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from e


@app.command()
def check_health(
    url: Annotated[
        str,
        typer.Option(
            "--url",
            help="Registry URL to check",
        ),
    ] = "http://localhost:8000",
) -> None:
    """Check the health of a running registry instance.

    [bold]Examples:[/bold]

      [dim]# Check local instance[/dim]
      $ pyrmute-registry check-health

      [dim]# Check remote instance[/dim]
      $ pyrmute-registry check-health --url https://registry.example.com
    """
    health_url = f"{url.rstrip('/')}/health"

    typer.echo(f"Checking health at {health_url}...")

    try:
        response = httpx.get(health_url, timeout=5.0)
        response.raise_for_status()

        data = response.json()

        if data.get("status") == "healthy":
            typer.secho("✓ Registry is healthy!", fg=typer.colors.GREEN)
            typer.echo(f"  Version: {data.get('version')}")
            typer.echo(f"  Environment: {data.get('environment')}")
            typer.echo(f"  Database: {data.get('database', {}).get('type')}")
            typer.echo(f"  Schemas: {data.get('schemas_count')}")
            typer.echo(f"  Uptime: {data.get('uptime_seconds'):.2f}s")
        else:
            typer.secho("✗ Registry is unhealthy!", fg=typer.colors.RED)
            typer.echo(f"  Error: {data.get('error')}")
            raise typer.Exit(code=1)

    except httpx.RequestError as e:
        typer.secho(f"✗ Failed to connect: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from e
    except httpx.HTTPStatusError as e:
        typer.secho(
            f"✗ Health check failed with status {e.response.status_code}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1) from e


@app.command()
def version() -> None:
    """Show the registry version information."""
    settings = get_settings()

    typer.echo(f"{settings.app_name} v{settings.app_version}")
    typer.echo(f"Environment: {settings.environment}")


@app.command()
def config() -> None:
    """Show the current configuration.

    Displays all configuration values from environment variables and the .env file.
    Sensitive values like API keys are masked.
    """
    settings = get_settings()

    typer.echo("Current Configuration:")
    typer.echo("=" * 50)
    typer.echo(f"App Name: {settings.app_name}")
    typer.echo(f"Version: {settings.app_version}")
    typer.echo(f"Environment: {settings.environment}")
    typer.echo(f"Debug: {settings.debug}")
    typer.echo("")
    typer.echo("Server:")
    typer.echo(f"  Host: {settings.host}")
    typer.echo(f"  Port: {settings.port}")
    typer.echo(f"  Reload: {settings.reload}")
    typer.echo(f"  Workers: {settings.workers}")
    typer.echo("")
    typer.echo("Database:")
    typer.echo(f"  URL: {settings.database_url.split('://')[0]}://***")
    typer.echo(f"  Echo: {settings.database_echo}")
    typer.echo("")
    typer.echo("Authentication:")
    typer.echo(f"  Enabled: {settings.enable_auth}")
    if settings.api_key:
        typer.echo(f"  API Key: {'*' * 8}")
    else:
        typer.echo("  API Key: (not set)")
    typer.echo("")
    typer.echo("CORS:")
    typer.echo(f"  Origins: {settings.cors_origins}")
    typer.echo(f"  Allow Credentials: {settings.cors_allow_credentials}")
    typer.echo("")
    typer.echo("Logging:")
    typer.echo(f"  Level: {settings.log_level}")


@app.command()
def generate_api_key(
    length: Annotated[
        int,
        typer.Option(
            "--length",
            "-l",
            help="Length of the key in bytes (output will be 2x in hex)",
        ),
    ] = 32,
) -> None:
    """Generate a secure random API key.

    The generated key can be used for the PYRMUTE_REGISTRY_API_KEY environment variable.

    [bold]Examples:[/bold]

      [dim]# Generate default 32-byte key (64 characters)[/dim]
      $ pyrmute-registry generate-api-key

      [dim]# Generate shorter 16-byte key (32 characters)[/dim]
      $ pyrmute-registry generate-api-key --length 16
    """
    key = gen_key(length)

    typer.echo("Generated API Key:")
    typer.secho(key, fg=typer.colors.GREEN, bold=True)
    typer.echo("")
    typer.echo("Add this to your .env file:")
    typer.secho(f"PYRMUTE_REGISTRY_API_KEY={key}", fg=typer.colors.CYAN)
    typer.echo("")
    typer.echo("⚠️  Keep this key secure and never commit it to version control!")


@app.command()
def generate_env(
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            "-o",
            help="Output file path",
        ),
    ] = Path(".env.example"),
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Overwrite existing file",
        ),
    ] = False,
) -> None:
    """Generate an example .env file with all configuration options.

    [bold]Examples:[/bold]

        [dim]# Generate .env.example[/dim]
        $ pyrmute-registry generate-env

        [dim]# Generate to custom file[/dim]
        $ pyrmute-registry generate-env --output .env.local

        [dim]# Overwrite existing file[/dim]
        $ pyrmute-registry generate-env --force
    """
    if output.exists() and not force:
        typer.secho(
            f"File {output} already exists. Use --force to overwrite.",
            fg=typer.colors.YELLOW,
        )
        raise typer.Exit(code=1)

    env_template = """# Pyrmute Schema Registry Configuration

# Application
PYRMUTE_REGISTRY_APP_NAME="Pyrmute Schema Registry"
PYRMUTE_REGISTRY_APP_VERSION="1.0.0"
PYRMUTE_REGISTRY_ENVIRONMENT=development  # development, production, test
PYRMUTE_REGISTRY_DEBUG=false

# Server
PYRMUTE_REGISTRY_HOST=0.0.0.0
PYRMUTE_REGISTRY_PORT=8000
PYRMUTE_REGISTRY_RELOAD=false
PYRMUTE_REGISTRY_WORKERS=1

# Database
PYRMUTE_REGISTRY_DATABASE_URL=sqlite:///./registry.db
# For PostgreSQL: postgresql://user:password@localhost:5432/pyrmute_registry
# For MySQL: mysql://user:password@localhost:3306/registry
PYRMUTE_REGISTRY_DATABASE_ECHO=false

# Authentication
PYRMUTE_REGISTRY_ENABLE_AUTH=false
PYRMUTE_REGISTRY_API_KEY=your-secret-api-key-here

# CORS
PYRMUTE_REGISTRY_CORS_ORIGINS=["*"]
PYRMUTE_REGISTRY_CORS_ALLOW_CREDENTIALS=true
PYRMUTE_REGISTRY_CORS_ALLOW_METHODS=["*"]
PYRMUTE_REGISTRY_CORS_ALLOW_HEADERS=["*"]

# Logging
PYRMUTE_REGISTRY_LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR, CRITICAL

# Rate Limiting
PYRMUTE_REGISTRY_RATE_LIMIT_ENABLED=false
PYRMUTE_REGISTRY_RATE_LIMIT_PER_MINUTE=60
"""

    output.write_text(env_template)
    typer.secho(f"✓ Generated {output}", fg=typer.colors.GREEN)


def main() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
