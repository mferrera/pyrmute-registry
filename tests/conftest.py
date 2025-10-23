"""Main fixtures for the client/plugin."""

from unittest.mock import Mock

import httpx
import pytest
from httpx import codes
from pyrmute import AvroRecordSchema, ModelManager

from pyrmute_registry.types import JsonSchema, RegistrySchemaResponse


@pytest.fixture
def model_manager() -> ModelManager:
    """Create a fresh ModelManager for testing."""
    return ModelManager()


@pytest.fixture
def sample_schema() -> JsonSchema:
    """Sample JSON schema for testing."""
    return {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "name": {"type": "string"},
            "email": {"type": "string", "format": "email"},
        },
        "required": ["id", "name"],
    }


@pytest.fixture
def mock_response() -> Mock:
    """Create a mock httpx Response."""
    response = Mock(spec=httpx.Response)
    response.status_code = codes.OK
    response.json.return_value = {}
    return response


@pytest.fixture
def sample_avro_schema() -> AvroRecordSchema:
    """Sample Avro schema for testing."""
    return {
        "type": "record",
        "name": "User",
        "namespace": "com.example",
        "fields": [
            {"name": "id", "type": "string"},
            {"name": "name", "type": "string"},
            {"name": "email", "type": "string"},
        ],
    }


@pytest.fixture
def full_schema_response(sample_schema: JsonSchema) -> RegistrySchemaResponse:
    """Full schema response from registry (new API format)."""
    return {
        "id": 1,
        "namespace": None,
        "model_name": "User",
        "version": "1.0.0",
        "json_schema": sample_schema,
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
        "meta": {},
        "deprecated": False,
    }


@pytest.fixture
def full_schema_response_with_avro(
    sample_schema: JsonSchema,
    sample_avro_schema: AvroRecordSchema,
) -> RegistrySchemaResponse:
    """Full schema response with both JSON Schema and Avro."""
    return {
        "id": 1,
        "namespace": None,
        "model_name": "User",
        "version": "1.0.0",
        "json_schema": sample_schema,
        "avro_schema": sample_avro_schema,
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
        "meta": {},
        "deprecated": False,
    }
