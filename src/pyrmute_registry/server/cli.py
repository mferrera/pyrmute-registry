"""Command-line interface for the Pyrmute Schema Registry server."""

import secrets
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import httpx
import typer
import uvicorn

from .auth import hash_api_key
from .config import get_settings
from .db import SessionLocal, init_db as db_init
from .models.api_key import ApiKey, Permission

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
      $ pyrmute-registry init-db

      [dim]# Initialize with custom database URL[/dim]
      $ pyrmute-registry init-db --database-url postgresql://user:pass@localhost/db
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
def create_admin_key(
    name: Annotated[
        str,
        typer.Option(
            "--name",
            "-n",
            help="Name for the API key",
            prompt="API key name",
        ),
    ],
    permission: Annotated[
        str,
        typer.Option(
            "--permission",
            "-p",
            help="Permission level (read, write, delete, admin)",
        ),
    ] = "admin",
    description: Annotated[
        str | None,
        typer.Option(
            "--description",
            "-d",
            help="Description of the key's purpose",
        ),
    ] = None,
    expires_in_days: Annotated[
        int | None,
        typer.Option(
            "--expires-in-days",
            "-e",
            help="Number of days until expiration (omit for no expiration)",
        ),
    ] = None,
) -> None:
    r"""Create an API key for authentication.

    This command creates a new API key in the database. The plaintext key is only shown
    once, so make sure to save it securely.

    [bold]Examples:[/bold]

      [dim]# Create an admin key interactively[/dim]
      $ pyrmute-registry create-admin-key

      [dim]# Create a read-only key[/dim]
      $ pyrmute-registry create-admin-key --name readonly --permission read

      [dim]# Create a key that expires in 90 days[/dim]
      $ pyrmute-registry create-admin-key --name temp-key --expires-in-days 90

      [dim]# Create a write key with description[/dim]
      $ pyrmute-registry create-admin-key \\
          --name ci-cd \\
          --permission write \\
          --description "CI/CD pipeline key"
    """
    # Validate permission
    try:
        perm = Permission(permission.lower())
    except ValueError as e:
        typer.secho(
            f"✗ Invalid permission: {permission}. "
            f"Must be one of: read, write, delete, admin",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1) from e

    # Generate secure API key
    plaintext_key = secrets.token_urlsafe(32)
    key_hash = hash_api_key(plaintext_key)

    # Calculate expiration
    expires_at = None
    if expires_in_days:
        expires_at = datetime.now(UTC) + timedelta(days=expires_in_days)

    # Create database record
    db = SessionLocal()
    try:
        # Check if name already exists
        existing = db.query(ApiKey).filter(ApiKey.name == name).first()
        if existing:
            typer.secho(
                f"✗ API key with name '{name}' already exists",
                fg=typer.colors.RED,
            )
            raise typer.Exit(code=1)

        api_key = ApiKey(
            name=name,
            key_hash=key_hash,
            permission=perm.value,
            created_by="cli",
            description=description or f"Created via CLI on {datetime.now(UTC).date()}",
            expires_at=expires_at,
        )

        db.add(api_key)
        db.commit()
        db.refresh(api_key)

        # Display success message with key details
        typer.secho("✓ API Key created successfully!", fg=typer.colors.GREEN, bold=True)
        typer.echo("")
        typer.echo("Key Details:")
        typer.echo("=" * 60)
        typer.echo(f"Name:        {api_key.name}")
        typer.echo(f"Permission:  {api_key.permission}")
        typer.echo(f"Created:     {api_key.created_at}")
        if api_key.expires_at:
            typer.echo(f"Expires:     {api_key.expires_at}")
        else:
            typer.echo("Expires:     Never")
        typer.echo("")
        typer.echo("API Key (save this - it won't be shown again):")
        typer.secho(plaintext_key, fg=typer.colors.CYAN, bold=True)
        typer.echo("")
        typer.echo("Usage:")
        typer.echo(
            f"  curl -H 'X-API-Key: {plaintext_key}' http://localhost:8000/schemas"
        )
        typer.echo("  or")
        typer.echo(
            f"  curl -H 'Authorization: Bearer {plaintext_key}' http://localhost:8000/schemas"
        )
        typer.echo("")
        typer.secho(
            "⚠️  IMPORTANT: Save this key securely. It cannot be recovered!",
            fg=typer.colors.YELLOW,
            bold=True,
        )

    except Exception as e:
        db.rollback()
        typer.secho(f"✗ Failed to create API key: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from e
    finally:
        db.close()


@app.command()
def list_keys(
    include_revoked: Annotated[
        bool,
        typer.Option(
            "--include-revoked",
            help="Include revoked keys in the list",
        ),
    ] = False,
) -> None:
    """List all API keys in the database.

    [bold]Examples:[/bold]

      [dim]# List active keys[/dim]
      $ pyrmute-registry list-keys

      [dim]# List all keys including revoked[/dim]
      $ pyrmute-registry list-keys --include-revoked
    """
    db = SessionLocal()
    try:
        query = db.query(ApiKey)

        if not include_revoked:
            query = query.filter(ApiKey.revoked == False)  # noqa: E712

        keys = query.order_by(ApiKey.created_at.desc()).all()

        if not keys:
            typer.echo("No API keys found.")
            return

        typer.echo(f"Found {len(keys)} API key(s):")
        typer.echo("=" * 80)

        for key in keys:
            status = "REVOKED" if key.revoked else "ACTIVE"
            if key.is_expired:
                status = "EXPIRED"

            color = (
                typer.colors.RED
                if key.revoked or key.is_expired
                else typer.colors.GREEN
            )

            typer.secho(f"\n{key.name} [{status}]", fg=color, bold=True)
            typer.echo(f"  ID:         {key.id}")
            typer.echo(f"  Permission: {key.permission}")
            typer.echo(f"  Created:    {key.created_at} by {key.created_by}")
            if key.last_used_at:
                typer.echo(f"  Last used:  {key.last_used_at} ({key.use_count} times)")
            else:
                typer.echo("  Last used:  Never")
            if key.expires_at:
                typer.echo(f"  Expires:    {key.expires_at}")
            if key.description:
                typer.echo(f"  Description: {key.description}")
            if key.revoked:
                typer.echo(f"  Revoked:    {key.revoked_at} by {key.revoked_by}")

    finally:
        db.close()


@app.command()
def revoke_key(
    name: Annotated[
        str,
        typer.Argument(help="Name of the API key to revoke"),
    ],
    reason: Annotated[
        str | None,
        typer.Option(
            "--reason",
            "-r",
            help="Reason for revocation",
        ),
    ] = None,
) -> None:
    """Revoke an API key.

    [bold]Examples:[/bold]

      [dim]# Revoke a key[/dim]
      $ pyrmute-registry revoke-key my-key

      [dim]# Revoke with reason[/dim]
      $ pyrmute-registry revoke-key my-key --reason "Key compromised"
    """
    db = SessionLocal()
    try:
        key = db.query(ApiKey).filter(ApiKey.name == name).first()

        if not key:
            typer.secho(f"✗ API key '{name}' not found", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        if key.revoked:
            typer.secho(
                f"✗ API key '{name}' is already revoked", fg=typer.colors.YELLOW
            )
            raise typer.Exit(code=1)

        # Confirm revocation
        if not typer.confirm(f"Are you sure you want to revoke '{name}'?"):
            typer.echo("Revocation cancelled.")
            raise typer.Abort

        # Revoke the key
        key.revoked = True
        key.revoked_at = datetime.now(UTC)
        key.revoked_by = "cli"

        if reason:
            if key.description:
                key.description += f"\n\nRevocation reason: {reason}"
            else:
                key.description = f"Revocation reason: {reason}"

        db.commit()

        typer.secho(f"✓ API key '{name}' has been revoked", fg=typer.colors.GREEN)

    except Exception as e:
        db.rollback()
        typer.secho(f"✗ Failed to revoke key: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from e
    finally:
        db.close()


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
    typer.echo("")
    typer.echo("CORS:")
    typer.echo(f"  Origins: {settings.cors_origins}")
    typer.echo(f"  Allow Credentials: {settings.cors_allow_credentials}")
    typer.echo("")
    typer.echo("Logging:")
    typer.echo(f"  Level: {settings.log_level}")


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
# Set to true and create API keys using: pyrmute-registry create-admin-key
PYRMUTE_REGISTRY_ENABLE_AUTH=false

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
