"""pyrmute-registry - A registrar for pyrmute schemas."""

from ._version import __version__
from .client import RegistryClient
from .plugin import RegistryPlugin

__all__ = [
    "RegistryClient",
    "RegistryPlugin",
    "__version__",
]
