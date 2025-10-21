"""Tests for audit logging middleware."""

from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from pyrmute_registry.server.models.api_key import ApiKey
from pyrmute_registry.server.models.audit_log import AuditLog

# ruff: noqa: PLR2004


def test_audit_log_created_on_schema_post(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
) -> None:
    """Test that audit log is created when registering a schema."""
    payload = {
        "version": "1.0.0",
        "json_schema": {"type": "object", "properties": {"name": {"type": "string"}}},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    response = auth_enabled_client.post(
        "/schemas/test-ns/TestModel/versions",
        json=payload,
        headers=write_key_header,
    )
    assert response.status_code == status.HTTP_201_CREATED

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 1

    log = audit_logs[0]
    assert log.action == "post_schema"
    assert log.resource_type == "schema"
    assert log.method == "POST"
    assert log.path == "/schemas/test-ns/TestModel/versions"
    assert log.status_code == status.HTTP_201_CREATED
    assert log.api_key_name is not None


def test_audit_log_created_on_schema_delete(
    auth_enabled_client: TestClient,
    db_session: Session,
    delete_key_header: dict[str, str],
) -> None:
    """Test that audit log is created when deleting a schema."""
    payload = {
        "version": "1.0.0",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    auth_enabled_client.post(
        "/schemas/test-namespace/DeleteModel/versions",
        json=payload,
        headers=delete_key_header,
    )

    db_session.query(AuditLog).delete()
    db_session.commit()

    response = auth_enabled_client.delete(
        "/schemas/test-namespace/DeleteModel/versions/1.0.0?force=true",
        headers=delete_key_header,
    )
    assert response.status_code == status.HTTP_200_OK

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 1

    log = audit_logs[0]
    assert log.action == "delete_schema"
    assert log.resource_type == "schema"
    assert log.method == "DELETE"
    assert log.status_code == status.HTTP_200_OK


def test_audit_log_created_on_api_key_creation(
    auth_enabled_client: TestClient,
    db_session: Session,
    admin_key_header: dict[str, str],
) -> None:
    """Test that audit log is created when creating an API key."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    payload = {
        "name": "audit-test-key",
        "permission": "read",
    }
    response = auth_enabled_client.post(
        "/api-keys",
        json=payload,
        headers=admin_key_header,
    )
    assert response.status_code == status.HTTP_201_CREATED

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 1

    log = audit_logs[0]
    assert log.action == "post_key"
    assert log.resource_type == "key"
    assert log.method == "POST"
    assert log.path == "/api-keys"
    assert log.status_code == status.HTTP_201_CREATED


def test_audit_log_created_on_api_key_revocation(
    auth_enabled_client: TestClient,
    db_session: Session,
    admin_key_header: dict[str, str],
    sample_api_key: ApiKey,
) -> None:
    """Test that audit log is created when revoking an API key."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    payload = {
        "revoked_by": "admin-user",
        "reason": "Test revocation",
    }
    response = auth_enabled_client.post(
        f"/api-keys/{sample_api_key.id}/revoke",
        json=payload,
        headers=admin_key_header,
    )
    assert response.status_code == status.HTTP_200_OK

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 1

    log = audit_logs[0]
    assert log.action == "post_key"
    assert log.resource_type == "key"
    assert log.method == "POST"
    assert "revoke" in log.path
    assert log.status_code == status.HTTP_200_OK


def test_audit_log_not_created_on_get_request(
    auth_enabled_client: TestClient,
    db_session: Session,
    read_key_header: dict[str, str],
) -> None:
    """Test that audit log is NOT created for GET requests."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    response = auth_enabled_client.get(
        "/schemas",
        headers=read_key_header,
    )
    assert response.status_code == status.HTTP_200_OK

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 0


def test_audit_log_not_created_when_unauthenticated(
    auth_enabled_client: TestClient,
    db_session: Session,
) -> None:
    """Test that audit log is NOT created for unauthenticated requests."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    payload = {
        "version": "1.0.0",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    response = auth_enabled_client.post(
        "/schemas/test-namespace/UnauthedModel/versions",
        json=payload,
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 0


def test_audit_log_not_created_when_auth_disabled(
    app_client: TestClient,
    db_session: Session,
) -> None:
    """Test that audit log is NOT created when auth is disabled."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    payload = {
        "version": "1.0.0",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    response = app_client.post(
        "/schemas/NoAuthModel/versions",
        json=payload,
    )
    assert response.status_code == status.HTTP_201_CREATED

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 0


def test_audit_log_captures_client_ip(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
) -> None:
    """Test that audit log captures client IP address."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    payload = {
        "version": "1.0.0",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    response = auth_enabled_client.post(
        "/schemas/test-namespace/IpTest/versions",
        json=payload,
        headers=write_key_header,
    )
    assert response.status_code == status.HTTP_201_CREATED

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 1

    log = audit_logs[0]
    assert log.client_ip is not None
    # TestClient typically uses "testclient" as the IP
    assert log.client_ip == "testclient"


def test_audit_log_captures_user_agent(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
) -> None:
    """Test that audit log captures user agent."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    headers = {**write_key_header, "user-agent": "test-client/1.0"}

    payload = {
        "version": "1.0.0",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    response = auth_enabled_client.post(
        "/schemas/test-namespace/UserAgentTest/versions",
        json=payload,
        headers=headers,
    )
    assert response.status_code == status.HTTP_201_CREATED

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 1

    log = audit_logs[0]
    assert log.user_agent == "test-client/1.0"


def test_audit_log_records_failed_requests(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
) -> None:
    """Test that audit log records failed requests with error status codes."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    payload = {
        "version": "invalid-version",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    response = auth_enabled_client.post(
        "/schemas/test-namespace/FailTest/versions",
        json=payload,
        headers=write_key_header,
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 1

    log = audit_logs[0]
    assert log.action == "post_schema"
    assert log.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert log.was_client_error is True
    assert log.was_successful is False


def test_audit_log_tracks_different_api_keys(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
    admin_key_header: dict[str, str],
) -> None:
    """Test that audit log tracks which API key performed each action."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    payload1 = {
        "version": "1.0.0",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    auth_enabled_client.post(
        "/schemas/test-namespace/WriteKeyTest/versions",
        json=payload1,
        headers=write_key_header,
    )

    payload2 = {
        "name": "admin-test-key",
        "permission": "read",
    }
    auth_enabled_client.post(
        "/api-keys",
        json=payload2,
        headers=admin_key_header,
    )

    audit_logs = db_session.query(AuditLog).order_by(AuditLog.timestamp).all()
    assert len(audit_logs) == 2

    assert audit_logs[0].permission_level == "write"
    assert audit_logs[0].action == "post_schema"

    assert audit_logs[1].permission_level == "admin"
    assert audit_logs[1].action == "post_key"


def test_audit_log_multiple_operations(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
) -> None:
    """Test that multiple operations create separate audit logs."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    for i in range(3):
        payload = {
            "version": f"{i}.0.0",
            "json_schema": {"type": "object"},
            "registered_at": "2024-01-01T00:00:00Z",
            "registered_by": "test-service",
        }
        auth_enabled_client.post(
            f"/schemas/test-namespace/MultiTest{i}/versions",
            json=payload,
            headers=write_key_header,
        )

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 3

    for log in audit_logs:
        assert log.action == "post_schema"
        assert log.method == "POST"
        assert log.status_code == status.HTTP_201_CREATED


def test_audit_log_extracts_resource_id_for_namespaced_schema(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
) -> None:
    """Test that audit log correctly extracts resource ID for namespaced schemas."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    payload = {
        "version": "2.0.0",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    response = auth_enabled_client.post(
        "/schemas/my-service/NamespacedModel/versions",
        json=payload,
        headers=write_key_header,
    )
    assert response.status_code == status.HTTP_201_CREATED

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 1

    log = audit_logs[0]
    assert log.resource_id is not None
    assert "my-service" in log.resource_id or log.resource_id == "NamespacedModel"


def test_audit_log_extracts_resource_id_for_global_schema(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
) -> None:
    """Test that audit log correctly extracts resource ID for global schemas."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    payload = {
        "version": "2.0.0",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    response = auth_enabled_client.post(
        "/schemas/GlobalModel/versions",
        json=payload,
        headers=write_key_header,
    )
    assert response.status_code == status.HTTP_201_CREATED

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 1

    log = audit_logs[0]
    assert log.resource_id == "GlobalModel" or log.resource_id is None


def test_audit_log_is_authenticated_property(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
) -> None:
    """Test the is_authenticated property of audit logs."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    payload = {
        "version": "1.0.0",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    auth_enabled_client.post(
        "/schemas/test-namespace/AuthPropTest/versions",
        json=payload,
        headers=write_key_header,
    )

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 1

    log = audit_logs[0]
    assert log.is_authenticated is True
    assert log.api_key_id is not None


def test_audit_log_deprecate_operation(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
) -> None:
    """Test that audit log captures deprecation operations."""
    payload = {
        "version": "1.0.0",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    auth_enabled_client.post(
        "/schemas/test-namespace/DeprecateTest/versions",
        json=payload,
        headers=write_key_header,
    )

    db_session.query(AuditLog).delete()
    db_session.commit()

    response = auth_enabled_client.post(
        "/schemas/test-namespace/DeprecateTest/versions/1.0.0/deprecate?message=Old",
        headers=write_key_header,
    )
    assert response.status_code == status.HTTP_200_OK

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 1

    log = audit_logs[0]
    assert log.action == "post_schema"
    assert log.method == "POST"
    assert "deprecate" in log.path
    assert log.status_code == status.HTTP_200_OK


def test_audit_log_not_created_for_non_audited_paths(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
) -> None:
    """Test that audit log is NOT created for paths not in audit_paths.

    Health check endpoints should not be audited even when authenticated,
    since they're not included in the audit_paths configuration.
    """
    db_session.query(AuditLog).delete()
    db_session.commit()

    # Make a request to health endpoint with authentication
    response = auth_enabled_client.get(
        "/health",
        headers=write_key_header,
    )
    assert response.status_code == 200

    # No audit log should be created for health endpoints
    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 0


def test_audit_log_not_created_for_liveness_probe(
    auth_enabled_client: TestClient,
    db_session: Session,
    admin_key_header: dict[str, str],
) -> None:
    """Test that liveness probe is not audited even with admin key."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    response = auth_enabled_client.get(
        "/health/live",
        headers=admin_key_header,
    )
    assert response.status_code == 200

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 0


def test_audit_log_not_created_for_readiness_probe(
    auth_enabled_client: TestClient,
    db_session: Session,
    admin_key_header: dict[str, str],
) -> None:
    """Test that readiness probe is not audited even with admin key."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    response = auth_enabled_client.get(
        "/health/ready",
        headers=admin_key_header,
    )
    assert response.status_code == 200

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 0
