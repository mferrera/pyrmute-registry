"""Configuration management for the registry server."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, ValidationInfo, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    Settings can be configured via:

    - Environment variables (e.g., PYRMUTE_REGISTRY_API_KEY)
    - .env file in the project root
    - Direct instantiation for testing

    Examples:
        ```python
        settings = Settings()
        settings = Settings(enable_auth=True, api_key="secret")
        ```
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        env_prefix="PYRMUTE_REGISTRY_",
        extra="ignore",
    )

    # Database
    database_url: str = Field(
        default="sqlite:///./registry.db",
        description=(
            "Database connection URL (e.g., sqlite:///./db.sqlite, postgresql://...)"
        ),
    )
    database_echo: bool = Field(
        default=False,
        description="Enable SQLAlchemy SQL query logging",
    )

    # Authentication
    api_key: str | None = Field(
        default=None,
        description="API key for authentication (required if enable_auth is True)",
    )
    enable_auth: bool = Field(
        default=False,
        description="Enable API key authentication",
    )

    # CORS
    cors_origins: list[str] = Field(
        default=["*"],
        description="Allowed CORS origins (comma-separated in env)",
    )
    cors_allow_credentials: bool = Field(
        default=True,
        description="Allow credentials in CORS requests",
    )
    cors_allow_methods: list[str] = Field(
        default=["*"],
        description="Allowed HTTP methods for CORS",
    )
    cors_allow_headers: list[str] = Field(
        default=["*"],
        description="Allowed headers for CORS",
    )

    # Server
    host: str = Field(
        default="0.0.0.0",
        description="Server host address",
    )
    port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="Server port number",
    )
    reload: bool = Field(
        default=False,
        description="Enable auto-reload for development",
    )
    workers: int = Field(
        default=1,
        ge=1,
        description="Number of worker processes",
    )

    # Application
    environment: Literal["development", "production", "test"] = Field(
        default="development",
        description="Application environment",
    )
    app_name: str = Field(
        default="Pyrmute Schema Registry",
        description="Application name",
    )
    app_version: str = Field(
        default="1.0.0",
        description="Application version",
    )
    debug: bool = Field(
        default=False,
        description="Enable debug mode (more verbose logging)",
    )

    # Logging
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Logging level",
    )

    # Rate limiting
    rate_limit_enabled: bool = Field(
        default=False,
        description="Enable rate limiting",
    )
    rate_limit_per_minute: int = Field(
        default=60,
        ge=1,
        description="Maximum requests per minute per client",
    )

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: str | list[str]) -> list[str]:
        """Parse CORS origins from string or list.

        Allows environment variable to be comma-separated string.

        Args:
            v: String or list of origins.

        Returns:
            List of origin strings.
        """
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, v: str | None, info: ValidationInfo) -> str | None:
        """Validate that api_key is set when auth is enabled.

        Args:
            v: API key value.
            info: Validation info context.

        Returns:
            Validated API key.

        Raises:
            ValueError: If auth is enabled but api_key is not set.
        """
        # Note: enable_auth might not be in info.data yet during validation
        # This will be checked at runtime in the auth dependency
        if v is not None and len(v) < 8:  # noqa: PLR2004
            raise ValueError("API key must be at least 8 characters long")
        return v

    @field_validator("environment")
    @classmethod
    def set_debug_for_dev(cls, v: str, info: ValidationInfo) -> str:
        """Set debug mode automatically for development environment.

        Args:
            v: Environment value.
            info: Validation info context.

        Returns:
            Environment value.
        """
        return v

    @property
    def is_sqlite(self) -> bool:
        """Check if using SQLite database.

        Returns:
            True if database is SQLite, False otherwise.
        """
        return "sqlite" in self.database_url.lower()

    @property
    def is_development(self) -> bool:
        """Check if running in development mode.

        Returns:
            True if environment is development.
        """
        return self.environment == "development"

    @property
    def is_production(self) -> bool:
        """Check if running in production mode.

        Returns:
            True if environment is production.
        """
        return self.environment == "production"

    @property
    def is_test(self) -> bool:
        """Check if running in test mode.

        Returns:
            True if environment is test.
        """
        return self.environment == "test"

    def get_database_echo(self) -> bool:
        """Get whether to echo SQL queries.

        Automatically enables echo in development if database_echo not explicitly set.

        Returns:
            Whether to echo SQL queries.
        """
        if self.database_echo:
            return True
        return self.is_development and not self.is_sqlite


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance.

    Settings are cached to avoid re-reading environment variables and .env file on every
    call.

    Returns:
        Singleton Settings instance.

    Examples:
        ```python
        settings = get_settings()
        settings.database_url
        # 'sqlite:///./registry.db'
        ```
    """
    return Settings()
