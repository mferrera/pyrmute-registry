# Pyrmute Registry

A centralized schema registry for
[pyrmute](https://github.com/mferrera/pyrmute), enabling teams to discover,
version, and manage Pydantic model schemas across services.

## Overview

Pyrmute Registry provides both a **client** and **plugin** for integrating
your pyrmute-based applications with a central schema registry server. Think
of it as a "Confluence for schemas" - a single source of truth for all your
data models.

### Key Features

- **Automatic Schema Registration** - Schemas are registered as you define models
- **Schema Discovery** - Find and compare schemas across services
- **Version Management** - Track schema evolution and breaking changes
- **Multi-Tenant Support** - Namespace schemas by service or use globally
- **Multi-Service Coordination** - Share schemas between services
- **Zero-Config Integration** - Drop-in plugin for existing pyrmute projects
- **Robust Error Handling** - Graceful degradation when registry is unavailable
- **Authentication Support** - API key-based security

## Installation

```bash
pip install pyrmute-registry
```

Or with extras:

```bash
pip install pyrmute-registry[server]  # Include FastAPI server components
```

## Quick Start

### Basic Usage (Namespaced)

```python
from pyrmute import ModelManager
from pyrmute_registry import RegistryPlugin
from pydantic import BaseModel

# Create your ModelManager
manager = ModelManager()

# Wrap it with the registry plugin
with RegistryPlugin(
    manager,
    registry_url="http://registry:8000",
    namespace="user-service",  # Service-specific namespace
):

    # Define models as usual - they're automatically registered!
    @manager.model("User", "1.0.0")
    class UserV1(BaseModel):
        name: str
        email: str

    # That's it! The schema is now in the registry under user-service namespace.
```

### Global Schemas

For schemas that should be shared across all services:

```python
# Register as global schemas (no namespace)
plugin = RegistryPlugin(
    manager,
    registry_url="http://registry:8000",
    namespace=None,  # Global schemas
)

@manager.model("CommonModel", "1.0.0")
class CommonModel(BaseModel):
    id: str
    created_at: str
```

### Environment Variables

Set configuration via environment variables:

```bash
export PYRMUTE_REGISTRY_URL="http://registry:8000"
export PYRMUTE_REGISTRY_NAMESPACE="user-service"  # Optional, None for global
export PYRMUTE_REGISTRY_API_KEY="your-api-key"    # Optional
```

Then use without explicit configuration:

```python
from pyrmute import ModelManager
from pyrmute_registry import create_plugin

manager = ModelManager()
plugin = create_plugin(manager)  # Reads from environment

@manager.model("User", "1.0.0")
class UserV1(BaseModel):
    name: str
```

## Configuration

### Plugin Options

```python
plugin = RegistryPlugin(
    manager=manager,                      # Your ModelManager instance
    registry_url="http://registry:8000",  # Registry server URL
    namespace="my-service",               # Optional namespace (None for global)
    auto_register=True,                   # Auto-register on model definition
    fail_on_error=False,                  # Raise exceptions on registry errors
    verify_ssl=True,                      # Verify SSL certificates
    api_key=None,                         # Optional API key for auth
    allow_overwrite=False,                # Allow overwriting existing schemas
    metadata={"team": "platform"},        # Default metadata for all schemas
)
```

### Client Options

```python
from pyrmute_registry import RegistryClient

client = RegistryClient(
    base_url="http://registry:8000",
    timeout=30.0,           # Request timeout in seconds
    max_retries=3,          # Retry attempts for transient failures
    verify_ssl=True,        # Verify SSL certificates
    api_key=None,           # Optional API key
)
```

## Namespaces

Pyrmute Registry supports multi-tenant schema organization through namespaces:

### When to Use Namespaces

- **Namespaced schemas**: Service-specific schemas that may differ between services
  - Example: `user-service::User@1.0.0` vs `admin-service::User@1.0.0`
- **Global schemas**: Shared schemas used across all services
  - Example: `CommonTypes@1.0.0` (no namespace)

### Working with Namespaces

```python
# Register namespaced schema
client.register_schema(
    "User",
    "1.0.0",
    schema,
    "user-service",
    namespace="auth-service",  # Scoped to auth-service
)

# Register global schema
client.register_schema(
    "CommonModel",
    "1.0.0",
    schema,
    "platform-team",
    namespace=None,  # Available to all services
)

# Get namespaced schema
schema = client.get_schema("User", "1.0.0", namespace="auth-service")

# Get global schema
schema = client.get_schema("CommonModel", "1.0.0", namespace=None)

# List schemas in a namespace
schemas = client.list_schemas(namespace="auth-service")

# List all global schemas
schemas = client.list_schemas(namespace="")

# List schemas across all namespaces
schemas = client.list_schemas()  # namespace=None means all
```

## Usage Patterns

### Manual Registration Control

Disable auto-registration and register selectively:

```python
plugin = RegistryPlugin(
    manager,
    registry_url="http://registry:8000",
    namespace="user-service",
    auto_register=False,  # Don't auto-register
)

# Define your models
@manager.model("User", "1.0.0")
class UserV1(BaseModel):
    name: str

@manager.model("InternalModel", "1.0.0")
class InternalModelV1(BaseModel):
    secret: str

# Only register public models
plugin.register_existing_models([
    ("User", "1.0.0"),
    # InternalModel not registered
])
```

### Registering Existing Models

If you have models defined before creating the plugin:

```python
# Models already defined
@manager.model("User", "1.0.0")
class UserV1(BaseModel):
    name: str

@manager.model("Product", "1.0.0")
class ProductV1(BaseModel):
    title: str

# Create plugin and register all existing
plugin = RegistryPlugin(
    manager,
    registry_url="...",
    namespace="catalog-service",
    auto_register=False
)
results = plugin.register_existing_models()

print(results)
# {"User@1.0.0": True, "Product@1.0.0": True}
```

### Schema Discovery

Find schemas from other services:

```python
from pyrmute_registry import RegistryClient

client = RegistryClient("http://registry:8000")

# List all schemas (across all namespaces)
schemas = client.list_schemas()
for schema_info in schemas["schemas"]:
    ns = schema_info["namespace"] or "global"
    print(f"[{ns}] {schema_info['model_name']}: {schema_info['versions']}")

# List schemas in specific namespace
user_schemas = client.list_schemas(namespace="user-service")

# List only global schemas
global_schemas = client.list_schemas(namespace="")

# Get specific schema
user_schema = client.get_schema("User", "1.0.0", namespace="user-service")
print(user_schema)

# Get latest version
latest_user = client.get_latest_schema("User", namespace="user-service")
print(f"Latest: {latest_user['version']}")
```

### Schema Comparison

Compare schemas across versions:

```python
# Compare two versions in same namespace
diff = client.compare_schemas(
    "User",
    "1.0.0",
    "2.0.0",
    namespace="user-service"
)
print(diff["changes"])

# Using the plugin
comparison = plugin.compare_with_registry("User", "1.0.0")
if not comparison["matches"]:
    print("Schema drift detected!")
    print(f"Added: {comparison['differences']['properties_added']}")
    print(f"Removed: {comparison['differences']['properties_removed']}")
```

### Schema Deprecation

Mark schemas as deprecated:

```python
# Deprecate a schema version
client.deprecate_schema(
    "User",
    "1.0.0",
    namespace="user-service",
    message="Security vulnerability. Please upgrade to 2.0.0"
)

# List including deprecated schemas
schemas = client.list_schemas(
    namespace="user-service",
    include_deprecated=True
)

for schema in schemas["schemas"]:
    if schema["deprecated_versions"]:
        print(f"Deprecated: {schema['deprecated_versions']}")
```

### Synchronization

Check sync status between local and registry:

```python
status = plugin.sync_with_registry()

if not status["in_sync"]:
    if status["local_only"]:
        print("Models only in local:")
        for model, versions in status["local_only"].items():
            print(f"  {model}: {versions}")

    if status["registry_only"]:
        print("Models only in registry:")
        for model, versions in status["registry_only"].items():
            print(f"  {model}: {versions}")

    if status["version_mismatches"]:
        print("Version mismatches:")
        for model, diff in status["version_mismatches"].items():
            print(f"  {model}:")
            print(f"    Local only: {diff['local_only']}")
            print(f"    Registry only: {diff['registry_only']}")
```

### Validation

Ensure your local schema matches the registry:

```python
# Check if schemas match
is_valid = plugin.validate_against_registry("User", "1.0.0")
if not is_valid:
    print("Warning: Local schema differs from registry!")

# Or raise on mismatch
try:
    plugin.validate_against_registry(
        "User", "1.0.0",
        raise_on_mismatch=True
    )
except RegistryPluginError as e:
    print(f"Schema validation failed: {e}")
```

### Error Handling Modes

#### Fail-Fast Mode

Raise exceptions immediately on any registry error:

```python
plugin = RegistryPlugin(
    manager,
    registry_url="http://registry:8000",
    namespace="user-service",
    fail_on_error=True,  # Raise on errors
)

try:
    @manager.model("User", "1.0.0")
    class UserV1(BaseModel):
        name: str
except RegistryPluginError as e:
    print(f"Registration failed: {e}")
    # Handle the error
```

#### Graceful Degradation Mode (Default)

Continue operation even if registry is unavailable:

```python
plugin = RegistryPlugin(
    manager,
    registry_url="http://registry:8000",
    namespace="user-service",
    fail_on_error=False,  # Default: warn but continue
)

# Even if registry is down, models are still usable
@manager.model("User", "1.0.0")
class UserV1(BaseModel):
    name: str

# User model works normally, registry registration just failed silently
user = UserV1(name="Alice")
```

### Schema Metadata

Add custom metadata to schemas:

```python
# Default metadata for all schemas
plugin = RegistryPlugin(
    manager,
    registry_url="http://registry:8000",
    namespace="user-service",
    metadata={
        "team": "platform",
        "owner": "alice@example.com",
        "criticality": "high",
    }
)

# Update metadata later
plugin.set_metadata({"last_reviewed": "2025-01-15"})

@manager.model("User", "1.0.0")
class UserV1(BaseModel):
    name: str
# Schema includes all metadata
```

### Health Checks

Monitor plugin and registry health:

```python
health = plugin.health_check()

print(f"Plugin active: {health['plugin_active']}")
print(f"Registry healthy: {health['registry_healthy']}")
print(f"Registered models: {health['registered_models']}")
print(f"Namespace: {health['namespace']}")

if not health["registry_healthy"]:
    print(f"Registry error: {health.get('registry_error')}")
```

### Using the Client Directly

For advanced use cases, use the client without the plugin:

```python
from pyrmute_registry import RegistryClient

with RegistryClient("http://registry:8000") as client:
    # Register a namespaced schema
    client.register_schema(
        model_name="User",
        version="1.0.0",
        schema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
            }
        },
        registered_by="user-service",
        namespace="user-service",
        metadata={"author": "Alice"},
    )

    # Register a global schema
    client.register_schema(
        model_name="CommonType",
        version="1.0.0",
        schema={"type": "object"},
        registered_by="platform-team",
        namespace=None,  # Global
    )

    # List all versions in namespace
    versions = client.list_versions("User", namespace="user-service")
    print(f"Available versions: {versions}")

    # Delete a schema (use with caution!)
    client.delete_schema(
        "User",
        "0.9.0",
        namespace="user-service",
        force=True
    )
```

## Best Practices

### Namespace Strategy

Choose the right namespace approach for your use case:

```python
# Service-specific schemas (most common)
plugin = RegistryPlugin(
    manager,
    registry_url="http://registry:8000",
    namespace="user-service",  # Scoped to this service
)

# Global schemas (shared models)
plugin = RegistryPlugin(
    manager,
    registry_url="http://registry:8000",
    namespace=None,  # Available to all services
)
```

**When to use namespaces:**

- Different services need different versions of the same model
- Service-specific schemas that shouldn't be shared
- Multi-tenant deployments

**When to use global schemas:**

- Common types shared across all services
- Standard contracts between services
- Platform-wide data models

### Namespace Naming

Use consistent, descriptive namespace names:

```python
# Good
namespace = "user-api"
namespace = "payment-service"
namespace = "analytics-worker"

# Avoid
namespace = "service1"
namespace = "test"
namespace = "my-namespace"
```

### Version Management

Follow semantic versioning principles:

```python
# Breaking change: Increment major version
@manager.model("User", "2.0.0")  # Was 1.x.x
class UserV2(BaseModel):
    id: str  # Changed from int to str (breaking)

# New field: Increment minor version
@manager.model("User", "1.1.0")  # Was 1.0.x
class UserV1_1(BaseModel):
    name: str
    email: str  # New optional field

# Bug fix: Increment patch version
@manager.model("User", "1.0.1")  # Was 1.0.0
class UserV1_0_1(BaseModel):
    name: str  # Fixed validation logic
```

### Metadata Usage

Add meaningful metadata for discoverability:

```python
plugin = RegistryPlugin(
    manager,
    registry_url="http://registry:8000",
    namespace="user-service",
    metadata={
        "team": "platform-team",
        "owner": "alice@company.com",
        "repo": "github.com/company/user-service",
        "docs": "https://docs.company.com/schemas/user",
        "environment": "production",
    }
)
```

### Error Handling Strategy

Choose the right mode for your use case:

```python
# Production services: Graceful degradation
plugin = RegistryPlugin(
    manager,
    registry_url="http://registry:8000",
    namespace="user-service",
    fail_on_error=False,  # Don't break service if registry is down
)

# CI/CD pipelines: Fail-fast
plugin = RegistryPlugin(
    manager,
    registry_url="http://registry:8000",
    namespace="user-service",
    fail_on_error=True,  # Catch schema issues early
)
```

### Validation in CI

Validate schemas in your CI pipeline:

```python
# In your CI script
plugin = RegistryPlugin(
    manager,
    registry_url="...",
    namespace="user-service",
    auto_register=False
)

# Define all models
# ...

# Validate against registry
all_valid = True
for model_name in manager.list_models():
    for version in manager.list_versions(model_name):
        if not plugin.validate_against_registry(str(model_name), str(version)):
            print(f"Schema drift detected: {model_name} {version}")
            all_valid = False

if not all_valid:
    sys.exit(1)
```

## Troubleshooting

### Registry Connection Issues

```python
# Check connectivity
plugin = RegistryPlugin(
    manager,
    registry_url="http://registry:8000",
    namespace="user-service"
)
health = plugin.health_check()

if not health["registry_healthy"]:
    print(f"Registry is down: {health.get('registry_error')}")
    # Check network, DNS, firewall rules
```

### Schema Conflicts

```python
# Enable overwrite mode
plugin = RegistryPlugin(
    manager,
    registry_url="http://registry:8000",
    namespace="user-service",
    allow_overwrite=True,  # Allow replacing schemas
)

# Or handle conflicts manually
from pyrmute_registry.exceptions import SchemaConflictError

try:
    plugin._register_schema_safe("User", "1.0.0", schema)
except SchemaConflictError:
    # Delete old schema first
    client.delete_schema("User", "1.0.0", namespace="user-service", force=True)
    # Then register new one
    plugin._register_schema_safe("User", "1.0.0", schema)
```

### Schema Drift

```python
# Detect drift
comparison = plugin.compare_with_registry("User", "1.0.0")
if not comparison["matches"]:
    print("Schemas differ:")
    print(f"  Local: {comparison['local_schema']}")
    print(f"  Registry: {comparison['registry_schema']}")

    # Decide: update registry or fix local?
```

### Namespace Issues

```python
# Wrong namespace
schema = client.get_schema("User", "1.0.0", namespace="wrong-service")
# SchemaNotFoundError

# Check which namespaces have this model
namespaces = client.list_schemas(model_name="User")
for schema in namespaces["schemas"]:
    print(f"Found in: {schema['namespace']}")
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines.

## Reporting a Security Vulnerability

See our [security
policy](https://github.com/mferrera/pyrmute/security/policy).

## License

MIT License - see [LICENSE](LICENSE) for details.
