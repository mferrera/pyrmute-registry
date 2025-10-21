"""Tests for audit service business logic."""

import pytest
from sqlalchemy.orm import Session

from pyrmute_registry.server.models.api_key import ApiKey
from pyrmute_registry.server.models.audit_log import AuditLog
from pyrmute_registry.server.services.audit import AuditService

# ruff: noqa: PLR2004


def test_log_action_creates_audit_log(
    db_session: Session,
    sample_api_key: ApiKey,
) -> None:
    """Test that log_action creates an audit log entry."""
    audit_service = AuditService(db_session)

    log = audit_service.log_action(
        action="test_action",
        resource_type="test_resource",
        method="POST",
        path="/test/path",
        api_key=sample_api_key,
        resource_id="test-123",
        status_code=201,
        client_ip="192.168.1.1",
        user_agent="test-client/1.0",
    )

    assert log is not None
    assert log.action == "test_action"
    assert log.resource_type == "test_resource"
    assert log.method == "POST"
    assert log.path == "/test/path"
    assert log.api_key_id == sample_api_key.id
    assert log.api_key_name == sample_api_key.name
    assert log.permission_level == sample_api_key.permission
    assert log.resource_id == "test-123"
    assert log.status_code == 201
    assert log.client_ip == "192.168.1.1"
    assert log.user_agent == "test-client/1.0"


def test_log_action_without_api_key(
    db_session: Session,
) -> None:
    """Test that log_action works without an API key."""
    audit_service = AuditService(db_session)

    log = audit_service.log_action(
        action="test_action",
        resource_type="test_resource",
        method="GET",
        path="/test/path",
        api_key=None,
        status_code=200,
    )

    assert log is not None
    assert log.api_key_id is None
    assert log.api_key_name is None
    assert log.permission_level is None


def test_log_action_with_request_params(
    db_session: Session,
    sample_api_key: ApiKey,
) -> None:
    """Test that log_action stores request parameters."""
    audit_service = AuditService(db_session)

    params = {
        "version": "1.0.0",
        "namespace": "test",
    }

    log = audit_service.log_action(
        action="test_action",
        resource_type="schema",
        method="POST",
        path="/schemas/test/Model/versions",
        api_key=sample_api_key,
        request_params=params,
        status_code=201,
    )

    assert log is not None
    assert log.request_params is not None
    assert log.request_params["version"] == "1.0.0"
    assert log.request_params["namespace"] == "test"


def test_log_action_with_response_summary(
    db_session: Session,
    sample_api_key: ApiKey,
) -> None:
    """Test that log_action stores response summary."""
    audit_service = AuditService(db_session)

    summary = {
        "schema_id": "test::Model@1.0.0",
        "created": True,
    }

    log = audit_service.log_action(
        action="register_schema",
        resource_type="schema",
        method="POST",
        path="/schemas/test/Model/versions",
        api_key=sample_api_key,
        response_summary=summary,
        status_code=201,
    )

    assert log is not None
    assert log.response_summary is not None
    assert log.response_summary["schema_id"] == "test::Model@1.0.0"
    assert log.response_summary["created"] is True


def test_log_action_with_error_message(
    db_session: Session,
    sample_api_key: ApiKey,
) -> None:
    """Test that log_action stores error messages."""
    audit_service = AuditService(db_session)

    log = audit_service.log_action(
        action="delete_schema",
        resource_type="schema",
        method="DELETE",
        path="/schemas/test/Model/versions/1.0.0",
        api_key=sample_api_key,
        error_message="Schema not found",
        status_code=404,
    )

    assert log is not None
    assert log.error_message == "Schema not found"
    assert log.status_code == 404


def test_sanitize_params_redacts_api_key(
    db_session: Session,
) -> None:
    """Test that _sanitize_params redacts API key values."""
    audit_service = AuditService(db_session)

    params = {
        "api_key": "secret-key-value",
        "name": "test-key",
    }

    sanitized = audit_service._sanitize_params(params)

    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["name"] == "test-key"


def test_sanitize_params_redacts_password(
    db_session: Session,
) -> None:
    """Test that _sanitize_params redacts password values."""
    audit_service = AuditService(db_session)

    params = {
        "password": "secret-password",
        "username": "testuser",
    }

    sanitized = audit_service._sanitize_params(params)

    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["username"] == "testuser"


def test_sanitize_params_redacts_token(
    db_session: Session,
) -> None:
    """Test that _sanitize_params redacts token values."""
    audit_service = AuditService(db_session)

    params = {
        "token": "secret-token-value",
        "refresh_token": "refresh-secret",
        "version": "1.0.0",
    }

    sanitized = audit_service._sanitize_params(params)

    assert sanitized["token"] == "[REDACTED]"
    assert sanitized["refresh_token"] == "[REDACTED]"
    assert sanitized["version"] == "1.0.0"


def test_sanitize_params_redacts_secret(
    db_session: Session,
) -> None:
    """Test that _sanitize_params redacts secret values."""
    audit_service = AuditService(db_session)

    params = {
        "client_secret": "very-secret-value",
        "name": "test",
    }

    sanitized = audit_service._sanitize_params(params)

    assert sanitized["client_secret"] == "[REDACTED]"
    assert sanitized["name"] == "test"


def test_sanitize_params_redacts_authorization(
    db_session: Session,
) -> None:
    """Test that _sanitize_params redacts authorization values."""
    audit_service = AuditService(db_session)

    params = {
        "authorization": "Bearer secret-token",
        "method": "POST",
    }

    sanitized = audit_service._sanitize_params(params)

    assert sanitized["authorization"] == "[REDACTED]"
    assert sanitized["method"] == "POST"


def test_sanitize_params_redacts_key_hash(
    db_session: Session,
) -> None:
    """Test that _sanitize_params redacts key_hash values."""
    audit_service = AuditService(db_session)

    params = {
        "key_hash": "hashed-secret-value",
        "name": "test-key",
    }

    sanitized = audit_service._sanitize_params(params)

    assert sanitized["key_hash"] == "[REDACTED]"
    assert sanitized["name"] == "test-key"


def test_sanitize_params_case_insensitive(
    db_session: Session,
) -> None:
    """Test that _sanitize_params is case insensitive."""
    audit_service = AuditService(db_session)

    params = {
        "API_KEY": "secret-value",
        "Password": "secret-password",
        "TOKEN": "secret-token",
    }

    sanitized = audit_service._sanitize_params(params)

    assert sanitized["API_KEY"] == "[REDACTED]"
    assert sanitized["Password"] == "[REDACTED]"
    assert sanitized["TOKEN"] == "[REDACTED]"


def test_sanitize_params_handles_empty_dict(
    db_session: Session,
) -> None:
    """Test that _sanitize_params handles empty dictionary."""
    audit_service = AuditService(db_session)

    sanitized = audit_service._sanitize_params({})

    assert sanitized == {}


def test_sanitize_params_handles_none(
    db_session: Session,
) -> None:
    """Test that _sanitize_params handles None input."""
    audit_service = AuditService(db_session)

    sanitized = audit_service._sanitize_params(None)  # type: ignore[arg-type]

    assert sanitized == {}


def test_log_action_sanitizes_request_params(
    db_session: Session,
    sample_api_key: ApiKey,
) -> None:
    """Test that log_action automatically sanitizes request parameters."""
    audit_service = AuditService(db_session)

    params = {
        "api_key": "secret-key",
        "version": "1.0.0",
        "password": "secret-pass",
    }

    log = audit_service.log_action(
        action="test_action",
        resource_type="test_resource",
        method="POST",
        path="/test/path",
        api_key=sample_api_key,
        request_params=params,
        status_code=201,
    )

    assert log is not None
    assert log.request_params is not None
    assert log.request_params["api_key"] == "[REDACTED]"
    assert log.request_params["password"] == "[REDACTED]"
    assert log.request_params["version"] == "1.0.0"


def test_log_operation_context_manager_success(
    db_session: Session,
    sample_api_key: ApiKey,
) -> None:
    """Test log_operation context manager for successful operations."""
    audit_service = AuditService(db_session)

    with audit_service.log_operation(
        action="test_operation",
        resource_type="test_resource",
        method="POST",
        path="/test/path",
        api_key=sample_api_key,
    ) as context:
        context["resource_id"] = "test-123"
        context["status_code"] = 201

    logs = db_session.query(AuditLog).all()
    assert len(logs) == 1

    log = logs[0]
    assert log.action == "test_operation"
    assert log.resource_id == "test-123"
    assert log.status_code == 201


def test_log_operation_context_manager_default_status(
    db_session: Session,
    sample_api_key: ApiKey,
) -> None:
    """Test log_operation defaults to status 200 on success."""
    audit_service = AuditService(db_session)

    with audit_service.log_operation(
        action="test_operation",
        resource_type="test_resource",
        method="GET",
        path="/test/path",
        api_key=sample_api_key,
    ) as context:
        context["resource_id"] = "test-123"

    logs = db_session.query(AuditLog).all()
    assert len(logs) == 1

    log = logs[0]
    assert log.status_code == 200


def test_log_operation_context_manager_with_exception(
    db_session: Session,
    sample_api_key: ApiKey,
) -> None:
    """Test log_operation context manager handles exceptions."""
    audit_service = AuditService(db_session)

    with (
        pytest.raises(ValueError, match="Test error"),
        audit_service.log_operation(
            action="test_operation",
            resource_type="test_resource",
            method="POST",
            path="/test/path",
            api_key=sample_api_key,
        ) as context,
    ):
        context["resource_id"] = "test-123"
        raise ValueError("Test error")

    logs = db_session.query(AuditLog).all()
    assert len(logs) == 1

    log = logs[0]
    assert log.action == "test_operation"
    assert log.resource_id == "test-123"
    assert log.status_code == 500
    assert log.error_message == "Test error"


def test_log_operation_context_manager_custom_error_status(
    db_session: Session,
    sample_api_key: ApiKey,
) -> None:
    """Test log_operation with custom error status code."""
    audit_service = AuditService(db_session)

    with (
        pytest.raises(ValueError),
        audit_service.log_operation(
            action="test_operation",
            resource_type="test_resource",
            method="DELETE",
            path="/test/path",
            api_key=sample_api_key,
        ) as context,
    ):
        context["status_code"] = 404
        raise ValueError("Not found")

    logs = db_session.query(AuditLog).all()
    assert len(logs) == 1

    log = logs[0]
    assert log.status_code == 404


def test_log_operation_with_request_params(
    db_session: Session,
    sample_api_key: ApiKey,
) -> None:
    """Test log_operation context manager with request parameters."""
    audit_service = AuditService(db_session)

    with audit_service.log_operation(
        action="test_operation",
        resource_type="test_resource",
        method="POST",
        path="/test/path",
        api_key=sample_api_key,
    ) as context:
        context["request_params"] = {"version": "1.0.0", "name": "test"}
        context["resource_id"] = "test-123"

    logs = db_session.query(AuditLog).all()
    assert len(logs) == 1

    log = logs[0]
    assert log.request_params is not None
    assert log.request_params["version"] == "1.0.0"
    assert log.request_params["name"] == "test"


def test_log_operation_with_response_summary(
    db_session: Session,
    sample_api_key: ApiKey,
) -> None:
    """Test log_operation context manager with response summary."""
    audit_service = AuditService(db_session)

    with audit_service.log_operation(
        action="test_operation",
        resource_type="test_resource",
        method="POST",
        path="/test/path",
        api_key=sample_api_key,
    ) as context:
        context["response_summary"] = {"created": True, "id": "123"}
        context["resource_id"] = "test-123"

    logs = db_session.query(AuditLog).all()
    assert len(logs) == 1

    log = logs[0]
    assert log.response_summary is not None
    assert log.response_summary["created"] is True
    assert log.response_summary["id"] == "123"


def test_log_action_persists_to_database(
    db_session: Session,
    sample_api_key: ApiKey,
) -> None:
    """Test that log_action persists audit log to database."""
    audit_service = AuditService(db_session)

    audit_service.log_action(
        action="test_action",
        resource_type="test_resource",
        method="POST",
        path="/test/path",
        api_key=sample_api_key,
        status_code=201,
    )

    logs = db_session.query(AuditLog).all()
    assert len(logs) == 1
    assert logs[0].action == "test_action"


def test_log_action_with_all_fields(
    db_session: Session,
    sample_api_key: ApiKey,
) -> None:
    """Test log_action with all optional fields populated."""
    audit_service = AuditService(db_session)

    log = audit_service.log_action(
        action="full_test",
        resource_type="schema",
        method="POST",
        path="/schemas/ns/Model/versions",
        api_key=sample_api_key,
        resource_id="ns::Model@1.0.0",
        status_code=201,
        client_ip="10.0.0.1",
        user_agent="test-agent/2.0",
        request_params={"version": "1.0.0"},
        response_summary={"success": True},
        error_message=None,
    )

    assert log is not None
    assert log.action == "full_test"
    assert log.resource_type == "schema"
    assert log.method == "POST"
    assert log.path == "/schemas/ns/Model/versions"
    assert log.api_key_id == sample_api_key.id
    assert log.resource_id == "ns::Model@1.0.0"
    assert log.status_code == 201
    assert log.client_ip == "10.0.0.1"
    assert log.user_agent == "test-agent/2.0"
    assert log.request_params is not None
    assert log.response_summary is not None
