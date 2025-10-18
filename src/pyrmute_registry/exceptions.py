"""Custom exceptions."""


class RegistryError(Exception):
    """Base exception for registry errors."""


class RegistryConnectionError(RegistryError):
    """Raised when unable to connect to registry."""


class SchemaNotFoundError(RegistryError):
    """Raised when a schema is not found."""


class SchemaConflictError(RegistryError):
    """Raised when attempting to register a schema that conflicts with existing."""


class RegistryPluginError(Exception):
    """Base exception for registry plugin errors."""
