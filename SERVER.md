# Pyrmute Registry Server

The Pyrmute Registry Server is a FastAPI-based REST API for centralized schema
management. It provides a solution for storing, versioning, and discovering
Pydantic model schemas across your microservices architecture.

## Features

- **RESTful API** - Clean, well-documented REST endpoints
- **Multi-Tenant Support** - Namespace-based schema isolation
- **Database-Backed Authentication** - Secure API key management with granular permissions
- **PostgreSQL/SQLite** - Database support
- **Health Checks** - Kubernetes/Docker-ready health endpoints
- **Deprecation Tracking** - Mark schemas as deprecated with messages
- **Audit Trail** - Track API key usage and schema changes

## Installation

```sh
pip install pyrmute-registry[server]
```

## Quick Start

Pyrmute Registry comes with a command line interface.

```sh
pyrmute-registry --help
pyrmute-registry init-db
pyrmute-registry serve
```

### Using Docker Compose

See the [`docker-compose.yml`](docker-compose.yml) configuration included in
the repository.

Start the server:

```sh
docker-compose up -d
```

Visit http://localhost:8000/docs for interactive API documentation.

## Configuration

The server is configured via environment variables or a `.env` file.

### `.env` file

Run `pyrmute-registry generate-env` to generate an example `.env` file with
configuration options.

### Database Configuration

```sh
# SQLite (development)
PYRMUTE_REGISTRY_DATABASE_URL="sqlite:///./registry.db"

# PostgreSQL (production)
PYRMUTE_REGISTRY_DATABASE_URL="postgresql://user:password@host:5432/database"

# Enable SQL query logging (development)
PYRMUTE_REGISTRY_DATABASE_ECHO=true
```

### Authentication

The registry uses **database-backed API keys** for authentication with
granular permission levels:

- **READ** - View schemas only
- **WRITE** - Read and create/update schemas
- **DELETE** - Read, write, and delete schemas
- **ADMIN** - Full access including API key management

```sh
# Enable authentication (disabled by default for development)
PYRMUTE_REGISTRY_ENABLE_AUTH=true
```

### CORS Configuration

```sh
# Allow specific origins
PYRMUTE_REGISTRY_CORS_ORIGINS="https://app.example.com,https://admin.example.com"

# Or allow all origins (development only!)
PYRMUTE_REGISTRY_CORS_ORIGINS="*"

# Additional CORS settings
PYRMUTE_REGISTRY_CORS_ALLOW_CREDENTIALS=true
PYRMUTE_REGISTRY_CORS_ALLOW_METHODS="*"
PYRMUTE_REGISTRY_CORS_ALLOW_HEADERS="*"
```

### Server Configuration

```sh
# Server settings
PYRMUTE_REGISTRY_HOST="0.0.0.0"
PYRMUTE_REGISTRY_PORT=8000
PYRMUTE_REGISTRY_WORKERS=4

# Environment mode
PYRMUTE_REGISTRY_ENVIRONMENT="production"  # or "development", "test"

# Application info
PYRMUTE_REGISTRY_APP_NAME="Pyrmute Schema Registry"
PYRMUTE_REGISTRY_APP_VERSION="1.0.0"

# Logging
PYRMUTE_REGISTRY_LOG_LEVEL="INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
PYRMUTE_REGISTRY_DEBUG=false
```

See the current config with:

```sh
pyrmute-registry config
```

### Rate Limiting (Optional)

```sh
PYRMUTE_REGISTRY_RATE_LIMIT_ENABLED=true
PYRMUTE_REGISTRY_RATE_LIMIT_PER_MINUTE=60
```

### Complete Example

```sh
# .env file for production
PYRMUTE_REGISTRY_DATABASE_URL="postgresql://registry:secure_password@db.example.com:5432/registry"
PYRMUTE_REGISTRY_ENABLE_AUTH=true
PYRMUTE_REGISTRY_ENVIRONMENT="production"
PYRMUTE_REGISTRY_CORS_ORIGINS="https://app.example.com"
PYRMUTE_REGISTRY_HOST="0.0.0.0"
PYRMUTE_REGISTRY_PORT=8000
PYRMUTE_REGISTRY_WORKERS=4
PYRMUTE_REGISTRY_LOG_LEVEL="INFO"
```

## Authentication

When authentication is enabled, all endpoints except `/health/*` and `/`
require valid API keys with appropriate permissions.

### Setting Up Authentication

#### 1. Enable Authentication

```sh
export PYRMUTE_REGISTRY_ENABLE_AUTH=true
pyrmute-registry serve
```

#### 2. Create Your First Admin Key

Use the CLI to create an admin key:

```sh
pyrmute-registry create-admin-key --name "admin" --description "Initial admin key"
```

**IMPORTANT:** Save the generated API key securely - it will only be shown
once!

Example output:
```
✓ Admin API key created successfully!

Name: admin
Permission: admin
API Key: v7x9K8mN3pL2qR5tY8wZ1aB4cD6eF0gH9iJ2kL5mN8pQ1rS4tU7vW0xY3zA6bC9

⚠️  SAVE THIS KEY NOW - It will never be shown again!
```

#### 3. Use API Keys in Requests

Include the API key in requests using either method:

**X-API-Key Header (Recommended):**
```sh
curl -H "X-API-Key: v7x9K8mN3pL..." \
  http://localhost:8000/schemas
```

**Authorization Bearer Token:**
```sh
curl -H "Authorization: Bearer v7x9K8mN3pL..." \
  http://localhost:8000/schemas
```

### Managing API Keys

#### Create Additional Keys

Use the admin key to create more keys via the API:

```sh
# Create a read-only key
curl -X POST http://localhost:8000/api-keys \
  -H "X-API-Key: <your-admin-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "monitoring-service",
    "permission": "read",
    "description": "Read-only key for monitoring dashboards",
    "expires_in_days": 365
  }'

# Create a write key for CI/CD
curl -X POST http://localhost:8000/api-keys \
  -H "X-API-Key: <your-admin-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ci-cd-pipeline",
    "permission": "write",
    "description": "CI/CD deployment key"
  }'

# Create a delete key
curl -X POST http://localhost:8000/api-keys \
  -H "X-API-Key: <your-admin-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "cleanup-service",
    "permission": "delete",
    "description": "Automated cleanup service"
  }'
```

#### List All Keys

```sh
curl http://localhost:8000/api-keys \
  -H "X-API-Key: <your-admin-key>"
```

#### View Key Details

```sh
curl http://localhost:8000/api-keys/1 \
  -H "X-API-Key: <your-admin-key>"
```

#### Revoke a Key

```sh
curl -X POST http://localhost:8000/api-keys/1/revoke \
  -H "X-API-Key: <your-admin-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "revoked_by": "admin",
    "reason": "Key compromised"
  }'
```

#### Delete a Key (Permanent)

```sh
curl -X DELETE http://localhost:8000/api-keys/1 \
  -H "X-API-Key: <your-admin-key>"
```

**Warning:** Deletion is permanent and removes all audit trail. Consider
revoking instead.

#### View Key Statistics

```sh
curl http://localhost:8000/api-keys/stats \
  -H "X-API-Key: <your-admin-key>"
```

### Permission Levels

| Permission | Read Schemas | Create/Update | Deprecate | Delete Schemas | Manage API Keys |
|------------|--------------|---------------|-----------|----------------|-----------------|
| READ       | ✅           | ❌            | ❌        | ❌             | ❌              |
| WRITE      | ✅           | ✅            | ✅        | ❌             | ❌              |
| DELETE     | ✅           | ✅            | ✅        | ✅             | ❌              |
| ADMIN      | ✅           | ✅            | ✅        | ✅             | ✅              |

### Security Features

- **Bcrypt Hashing** - API keys are hashed using bcrypt before storage
- **Usage Tracking** - Track when keys were last used and how many times
- **Expiration** - Set automatic expiration dates for keys
- **Revocation** - Instantly disable compromised keys
- **Audit Trail** - Track who created, revoked, or deleted each key

### Example with curl

```sh
# Register a schema (requires WRITE permission)
curl -X POST "http://localhost:8000/schemas/user-service/User/versions" \
  -H "X-API-Key: <your-write-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "version": "1.0.0",
    "json_schema": {
      "type": "object",
      "properties": {
        "name": {"type": "string"}
      }
    },
    "registered_by": "user-service"
  }'

# Get a schema (requires READ permission)
curl -H "X-API-Key: <your-read-key>" \
  "http://localhost:8000/schemas/user-service/User/versions/1.0.0"

# Delete a schema (requires DELETE permission)
curl -X DELETE \
  "http://localhost:8000/schemas/user-service/User/versions/1.0.0?force=true" \
  -H "X-API-Key: <your-delete-key>"
```

## Database Setup

### SQLite (Development)

SQLite requires no setup - the database file is created automatically:

```sh
PYRMUTE_REGISTRY_DATABASE_URL="sqlite:///./registry.db"
```

### PostgreSQL (Production)

1. Create a database:

```sql
CREATE DATABASE registry;
CREATE USER registry_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE registry TO registry_user;
```

2. Configure the connection:

```bash
PYRMUTE_REGISTRY_DATABASE_URL="postgresql://registry_user:secure_password@localhost:5432/registry"
```

3. Tables are created automatically on first startup, including:
   - `schemas` - Schema versions
   - `api_keys` - API key credentials and metadata

### Database Migrations

The server automatically creates tables on startup. For production
deployments, you may want to run migrations separately:

```python
from pyrmute_registry.server.db import init_db

init_db()
```

## Deployment

### Production Checklist

- [ ] Use PostgreSQL instead of SQLite
- [ ] Enable authentication (`PYRMUTE_REGISTRY_ENABLE_AUTH=true`)
- [ ] Create admin API key via CLI
- [ ] Generate unique API keys for each service/user
- [ ] Set appropriate permission levels for each key
- [ ] Set `PYRMUTE_REGISTRY_ENVIRONMENT=production`
- [ ] Configure appropriate CORS origins
- [ ] Use HTTPS/TLS termination (nginx, load balancer, etc.)
- [ ] Set up database backups (includes API keys table)
- [ ] Configure logging and monitoring
- [ ] Use multiple workers (`PYRMUTE_REGISTRY_WORKERS=4`)
- [ ] Set resource limits (memory, CPU)
- [ ] Enable rate limiting if needed
- [ ] Rotate API keys periodically
- [ ] Monitor API key usage via audit logs

### Docker Deployment

**Development (Auth Disabled):**

```sh
docker-compose up -d

# No authentication required
curl http://localhost:8000/schemas
```

**Production (Auth Enabled):**

```sh
# 1. Start with auth enabled
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# 2. Create admin API key
docker-compose exec registry pyrmute-registry create-admin-key --name admin

# 3. Save the returned key securely
# Example: v7x9K8mN3pL2qR5tY8wZ1aB4cD6eF0gH9iJ2kL5mN8pQ1rS4tU7vW0xY3zA6bC9

# 4. Use the key in requests
curl -H "X-API-Key: v7x9K8mN3pL..." http://localhost:8000/schemas

# 5. Create additional keys as needed
curl -X POST http://localhost:8000/api-keys \
  -H "X-API-Key: v7x9K8mN3pL..." \
  -H "Content-Type: application/json" \
  -d '{
    "name": "service-key",
    "permission": "write",
    "description": "Service deployment key"
  }'
```

**Dockerfile:**

```dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create non-root user
RUN useradd -m -u 1000 registry && chown -R registry:registry /app
USER registry

EXPOSE 8000

CMD ["python", "-m", "pyrmute_registry.server.main"]
```

**Build and run:**

```sh
docker build -t pyrmute-registry-server .
docker run -d \
  -p 8000:8000 \
  -e PYRMUTE_REGISTRY_DATABASE_URL="postgresql://..." \
  -e PYRMUTE_REGISTRY_ENABLE_AUTH="true" \
  pyrmute-registry-server

# Create admin key after container starts
docker exec <container-id> pyrmute-registry create-admin-key --name admin
```

### Kubernetes Deployment

**deployment.yaml:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: registry-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: registry-server
  template:
    metadata:
      labels:
        app: registry-server
    spec:
      containers:
      - name: registry
        image: pyrmute-registry-server:latest
        ports:
        - containerPort: 8000
        env:
        - name: PYRMUTE_REGISTRY_DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: registry-secrets
              key: database-url
        - name: PYRMUTE_REGISTRY_ENABLE_AUTH
          value: "true"
        - name: PYRMUTE_REGISTRY_ENVIRONMENT
          value: "production"
        - name: PYRMUTE_REGISTRY_WORKERS
          value: "4"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5

---
apiVersion: v1
kind: Service
metadata:
  name: registry-service
spec:
  selector:
    app: registry-server
  ports:
  - port: 8000
    targetPort: 8000
  type: ClusterIP

---
apiVersion: v1
kind: Secret
metadata:
  name: registry-secrets
type: Opaque
stringData:
  database-url: "postgresql://user:pass@postgres:5432/registry"

---
# Job to create initial admin key
apiVersion: batch/v1
kind: Job
metadata:
  name: registry-init-admin-key
spec:
  template:
    spec:
      containers:
      - name: init-admin
        image: pyrmute-registry-server:latest
        command:
        - pyrmute-registry
        - create-admin-key
        - --name
        - kubernetes-admin
        env:
        - name: PYRMUTE_REGISTRY_DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: registry-secrets
              key: database-url
        - name: PYRMUTE_REGISTRY_ENABLE_AUTH
          value: "true"
      restartPolicy: OnFailure
```

**Note:** Save the admin key output from the init job and store it securely
(e.g., in a Kubernetes Secret or external secret manager).

### Nginx Reverse Proxy

```nginx
upstream registry {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name registry.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name registry.example.com;

    ssl_certificate /etc/ssl/certs/registry.crt;
    ssl_certificate_key /etc/ssl/private/registry.key;

    location / {
        proxy_pass http://registry;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Forward authentication headers
        proxy_set_header X-API-Key $http_x_api_key;
        proxy_set_header Authorization $http_authorization;
    }
}
```

## Monitoring

### Health Endpoints

**Liveness Probe** (`/health/live`):

- Checks if server process is running
- Returns 200 if alive
- Use for Kubernetes liveness probes

**Readiness Probe** (`/health/ready`):

- Checks database connectivity
- Returns 200 if ready to accept traffic
- Returns 503 if database is down
- Use for Kubernetes readiness probes

**Detailed Health** (`/health`):

- Returns comprehensive health information
- Includes database status, schema count, uptime
- Use for monitoring dashboards

### API Key Usage Tracking

Monitor API key usage patterns:

```sh
# Get statistics
curl http://localhost:8000/api-keys/stats \
  -H "X-API-Key: <admin-key>"

# View specific key usage
curl http://localhost:8000/api-keys/1 \
  -H "X-API-Key: <admin-key>"
```

Response includes:
- `last_used_at` - When the key was last used
- `use_count` - Total number of requests
- `created_at` - When the key was created
- `expires_at` - Expiration date (if set)

### Metrics

The server logs all requests with timing and authentication information:

```bash
# Example log output
2025-01-15 10:30:00 - INFO - POST /schemas/user-service/User/versions - 201
2025-01-15 10:30:01 - INFO - Authenticated with key: ci-cd-key (permission: write)
2025-01-15 10:30:01 - INFO - GET /schemas - 200
2025-01-15 10:30:02 - WARNING - Invalid API key provided
2025-01-15 10:30:03 - ERROR - Database error: connection timeout
```

## Troubleshooting

### Database Connection Issues

```sh
# Check database connectivity
docker-compose exec registry python -c "
from pyrmute_registry.server.db import engine
try:
    engine.connect()
    print('Database connection successful')
except Exception as e:
    print(f'Database connection failed: {e}')
"
```

### Authentication Issues

```sh
# Verify auth is enabled
docker-compose exec registry env | grep ENABLE_AUTH

# Test with invalid key
curl -v -H "X-API-Key: invalid-key" http://localhost:8000/schemas
# Should return 401 Unauthorized

# Test with valid key
curl -v -H "X-API-Key: <your-key>" http://localhost:8000/schemas
# Should return 200 OK

# Check if key is revoked or expired
curl http://localhost:8000/api-keys/1 -H "X-API-Key: <admin-key>"
```

### Lost Admin Key

If you lose your admin key:

```sh
# Option 1: Disable auth temporarily
export PYRMUTE_REGISTRY_ENABLE_AUTH=false
pyrmute-registry serve

# Option 2: Direct database access (PostgreSQL)
psql -d registry -U registry_user -c "SELECT name, permission, revoked FROM api_keys;"

# Option 3: Create new admin key via database
# Connect to container and use Python
docker-compose exec registry python
>>> from pyrmute_registry.server.db import SessionLocal
>>> from pyrmute_registry.server.models.api_key import ApiKey, Permission
>>> from pyrmute_registry.server.auth import hash_api_key
>>> import secrets
>>>
>>> key = secrets.token_urlsafe(32)
>>> print(f"New key: {key}")
>>>
>>> db = SessionLocal()
>>> api_key = ApiKey(
...     name="recovery-admin",
...     key_hash=hash_api_key(key),
...     permission=Permission.ADMIN.value,
...     created_by="recovery"
... )
>>> db.add(api_key)
>>> db.commit()
```

### Performance Issues

```sh
# Check worker count
ps aux | grep uvicorn | wc -l

# Increase workers
export PYRMUTE_REGISTRY_WORKERS=8

# Check database performance and add indexes
CREATE INDEX idx_namespace_model ON schemas(namespace, model_name);
CREATE INDEX idx_api_keys_active ON api_keys(revoked, expires_at);
CREATE INDEX idx_api_keys_permission ON api_keys(permission);
```

### Logs

```sh
# View logs (Docker)
docker-compose logs -f registry

# View logs (Kubernetes)
kubectl logs -f deployment/registry-server

# Enable debug logging
export PYRMUTE_REGISTRY_LOG_LEVEL=DEBUG
export PYRMUTE_REGISTRY_DEBUG=true
```

## Development

### Running Tests

```sh
# Install development dependencies
uv sync --all-groups

# Run tests
uv run pytest

# Run with coverage
uv run pytest --cov=src/ --cov-report=html

# Run specific test file
uv run pytest tests/test_server/test_routers/test_api_keys_routes.py
```

### Code Quality

```sh
# Lint
ruff format --check src/ tests/
ruff check src/ tests/

# Type checking
mypy src/ tests/
```

### Local Development

```bash
# Auth disabled (default)
pyrmute-registry serve --reload --port 8000

# Auth enabled
export PYRMUTE_REGISTRY_ENABLE_AUTH=true
pyrmute-registry serve --reload

# Create test admin key
pyrmute-registry create-admin-key --name dev-admin

# Run with debug logging
export PYRMUTE_REGISTRY_LOG_LEVEL=DEBUG
pyrmute-registry serve
```

## API Examples

### Schema Management

#### Register Schema

```sh
curl -X POST "http://localhost:8000/schemas/user-service/User/versions" \
  -H "X-API-Key: <write-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "version": "1.0.0",
    "json_schema": {
      "type": "object",
      "properties": {
        "id": {"type": "string"},
        "name": {"type": "string"},
        "email": {"type": "string", "format": "email"}
      },
      "required": ["id", "name"]
    },
    "registered_by": "user-service",
    "meta": {
      "team": "platform",
      "environment": "production"
    }
  }'
```

#### Get Schema

```sh
curl "http://localhost:8000/schemas/user-service/User/versions/1.0.0" \
  -H "X-API-Key: <read-key>"
```

#### List Schemas

```sh
# All schemas
curl "http://localhost:8000/schemas" -H "X-API-Key: <read-key>"

# Filter by namespace
curl "http://localhost:8000/schemas?namespace=user-service" \
  -H "X-API-Key: <read-key>"

# Include deprecated
curl "http://localhost:8000/schemas?include_deprecated=true" \
  -H "X-API-Key: <read-key>"
```

#### Compare Versions

```sh
curl "http://localhost:8000/schemas/user-service/User/compare?from_version=1.0.0&to_version=2.0.0" \
  -H "X-API-Key: <read-key>"
```

#### Deprecate Schema

```sh
curl -X POST \
  "http://localhost:8000/schemas/user-service/User/versions/1.0.0/deprecate?message=Security+vulnerability" \
  -H "X-API-Key: <write-key>"
```

#### Delete Schema

```sh
curl -X DELETE \
  "http://localhost:8000/schemas/user-service/User/versions/1.0.0?force=true" \
  -H "X-API-Key: <delete-key>"
```

### API Key Management

All API key management endpoints require ADMIN permission.

#### Create API Key

```sh
curl -X POST http://localhost:8000/api-keys \
  -H "X-API-Key: <admin-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "service-api-key",
    "permission": "write",
    "description": "API key for microservice",
    "expires_in_days": 365
  }'
```

#### List API Keys

```sh
# All active keys
curl http://localhost:8000/api-keys \
  -H "X-API-Key: <admin-key>"

# Include revoked keys
curl "http://localhost:8000/api-keys?include_revoked=true" \
  -H "X-API-Key: <admin-key>"

# Filter by permission
curl "http://localhost:8000/api-keys?permission=write" \
  -H "X-API-Key: <admin-key>"
```

#### Get Key Details

```sh
curl http://localhost:8000/api-keys/1 \
  -H "X-API-Key: <admin-key>"
```

#### Revoke API Key

```sh
curl -X POST http://localhost:8000/api-keys/1/revoke \
  -H "X-API-Key: <admin-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "revoked_by": "security-team",
    "reason": "Suspected compromise"
  }'
```

#### Delete API Key

```sh
curl -X DELETE http://localhost:8000/api-keys/1 \
  -H "X-API-Key: <admin-key>"
```

#### Get Key Statistics

```sh
curl http://localhost:8000/api-keys/stats \
  -H "X-API-Key: <admin-key>"
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.
