# Pyrmute Registry Server

The Pyrmute Registry Server is a FastAPI-based REST API for centralized schema
management. It provides a solution for storing, versioning, and discovering
Pydantic model schemas across your microservices architecture.

## Features

- **RESTful API** - Clean, well-documented REST endpoints
- **Multi-Tenant Support** - Namespace-based schema isolation
- **Authentication** - API key-based security
- **PostgreSQL/SQLite** - Database support
- **Health Checks** - Kubernetes/Docker-ready health endpoints
- **Deprecation Tracking** - Mark schemas as deprecated with messages

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

See the [`docker-compose.yml`](docker-compose.yml) configuration included in the repository.

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

```sh
# Enable authentication
PYRMUTE_REGISTRY_ENABLE_AUTH=true

# Set API key (required if auth enabled)
PYRMUTE_REGISTRY_API_KEY="your-secret-key-minimum-8-chars"
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
DATABASE_URL="postgresql://registry:secure_password@db.example.com:5432/registry"
PYRMUTE_REGISTRY_ENABLE_AUTH=true
PYRMUTE_REGISTRY_API_KEY="your-very-secret-key-at-least-32-chars"
PYRMUTE_REGISTRY_ENVIRONMENT="production"
PYRMUTE_REGISTRY_CORS_ORIGINS="https://app.example.com"
PYRMUTE_REGISTRY_HOST="0.0.0.0"
PYRMUTE_REGISTRY_PORT=8000
PYRMUTE_REGISTRY_WORKERS=4
PYRMUTE_REGISTRY_LOG_LEVEL="INFO"
```

## Authentication

When authentication is enabled, all endpoints except `/health/*` and `/`
require authentication.

### Using API Keys

Include the API key in requests using either method:

**X-API-Key Header:**
```sh
curl -H "X-API-Key: your-secret-key" \
  http://localhost:8000/schemas
```

**Authorization Bearer Token:**
```sh
curl -H "Authorization: Bearer your-secret-key" \
  http://localhost:8000/schemas
```

### Example with curl

```sh
# Register a schema
curl -X POST "http://localhost:8000/schemas/user-service/User/versions" \
  -H "X-API-Key: your-secret-key" \
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

# Get a schema
curl -H "X-API-Key: your-secret-key" \
  "http://localhost:8000/schemas/user-service/User/versions/1.0.0"
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

3. Tables are created automatically on first startup.

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
- [ ] Enable authentication with strong API key
- [ ] Set `PYRMUTE_REGISTRY_ENVIRONMENT=production`
- [ ] Configure appropriate CORS origins
- [ ] Use HTTPS/TLS termination (nginx, load balancer, etc.)
- [ ] Set up database backups
- [ ] Configure logging and monitoring
- [ ] Use multiple workers (`PYRMUTE_REGISTRY_WORKERS=4`)
- [ ] Set resource limits (memory, CPU)
- [ ] Enable rate limiting if needed

### Docker Deployment

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
  -e PYRMUTE_REGISTRY_API_KEY="..." \
  pyrmute-registry-server
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
        - name: PYRMUTE_REGISTRY_API_KEY
          valueFrom:
            secretKeyRef:
              name: registry-secrets
              key: api-key
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
  api-key: "your-very-secret-api-key-here"
```

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

### Metrics

The server logs all requests with timing information. Integrate with your
logging infrastructure:

```bash
# Example log output
2025-01-15 10:30:00 - INFO - POST /schemas/user-service/User/versions - 201
2025-01-15 10:30:01 - INFO - GET /schemas - 200
2025-01-15 10:30:02 - ERROR - Database error: connection timeout
```

### Prometheus Integration (Optional)

Add prometheus metrics if needed:

```python
# Custom middleware for metrics
from prometheus_client import Counter, Histogram

request_count = Counter('registry_requests_total', 'Total requests')
request_duration = Histogram('registry_request_duration_seconds', 'Request duration')
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
# Verify API key is set
docker-compose exec registry env | grep API_KEY

# Test authentication
curl -v -H "X-API-Key: wrong-key" http://localhost:8000/schemas
# Should return 401 Unauthorized
```

### Performance Issues

```sh
# Check worker count
ps aux | grep uvicorn | wc -l

# Increase workers
export PYRMUTE_REGISTRY_WORKERS=8

# Check database performance
# Add indexes if slow:
CREATE INDEX idx_namespace_model ON schemas(namespace, model_name);
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
uv run pytest tests/test_server/test_main.py
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
pyrmute-registry serve --reload --port 8000

# Run with debug logging
export PYRMUTE_REGISTRY_LOG_LEVEL=DEBUG
pyrmute-registry serve
```

## API Examples

### Register Schema

```sh
curl -X POST "http://localhost:8000/schemas/user-service/User/versions" \
  -H "X-API-Key: your-key" \
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

### Get Schema

```sh
curl "http://localhost:8000/schemas/user-service/User/versions/1.0.0" \
  -H "X-API-Key: your-key"
```

### List Schemas

```sh
# All schemas
curl "http://localhost:8000/schemas" -H "X-API-Key: your-key"

# Filter by namespace
curl "http://localhost:8000/schemas?namespace=user-service" \
  -H "X-API-Key: your-key"

# Include deprecated
curl "http://localhost:8000/schemas?include_deprecated=true" \
  -H "X-API-Key: your-key"
```

### Compare Versions

```sh
curl "http://localhost:8000/schemas/user-service/User/compare?from_version=1.0.0&to_version=2.0.0" \
  -H "X-API-Key: your-key"
```

### Deprecate Schema

```sh
curl -X POST \
  "http://localhost:8000/schemas/user-service/User/versions/1.0.0/deprecate?message=Security+vulnerability" \
  -H "X-API-Key: your-key"
```
## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.
