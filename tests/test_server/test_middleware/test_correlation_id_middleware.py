"""Tests for correlation ID middleware."""

import uuid

from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from pyrmute_registry.server.models.audit_log import AuditLog

# ruff: noqa: PLR2004


def test_correlation_id_generated_when_not_provided(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
) -> None:
    """Test that correlation ID is generated when not provided in request."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    payload = {
        "version": "1.0.0",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    response = auth_enabled_client.post(
        "/schemas/test-ns/CorrelationTest/versions",
        json=payload,
        headers=write_key_header,
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert "X-Correlation-ID" in response.headers

    correlation_id = response.headers["X-Correlation-ID"]
    assert correlation_id is not None
    assert len(correlation_id) > 0

    try:
        uuid.UUID(correlation_id)
    except ValueError as e:
        raise AssertionError(
            f"Generated correlation ID is not a valid UUID: {correlation_id}"
        ) from e


def test_correlation_id_preserved_from_request_header(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
) -> None:
    """Test that correlation ID from X-Correlation-ID header is preserved."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    custom_correlation_id = "test-correlation-abc-123"
    headers = {**write_key_header, "X-Correlation-ID": custom_correlation_id}

    payload = {
        "version": "1.0.0",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    response = auth_enabled_client.post(
        "/schemas/test-ns/PreserveCorrelation/versions",
        json=payload,
        headers=headers,
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.headers["X-Correlation-ID"] == custom_correlation_id


def test_correlation_id_preserved_from_x_request_id_header(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
) -> None:
    """Test that correlation ID from X-Request-ID header is preserved."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    custom_request_id = "request-xyz-789"
    headers = {**write_key_header, "X-Request-ID": custom_request_id}

    payload = {
        "version": "1.0.0",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    response = auth_enabled_client.post(
        "/schemas/test-ns/RequestIdTest/versions",
        json=payload,
        headers=headers,
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.headers["X-Correlation-ID"] == custom_request_id


def test_correlation_id_priority_prefers_x_correlation_id(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
) -> None:
    """Test that X-Correlation-ID takes priority over X-Request-ID."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    correlation_id = "correlation-preferred"
    request_id = "request-not-used"
    headers = {
        **write_key_header,
        "X-Correlation-ID": correlation_id,
        "X-Request-ID": request_id,
    }

    payload = {
        "version": "1.0.0",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    response = auth_enabled_client.post(
        "/schemas/test-ns/PriorityTest/versions",
        json=payload,
        headers=headers,
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.headers["X-Correlation-ID"] == correlation_id


def test_correlation_id_stored_in_audit_log(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
) -> None:
    """Test that correlation ID is stored in audit log."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    custom_correlation_id = "audit-correlation-456"
    headers = {**write_key_header, "X-Correlation-ID": custom_correlation_id}

    payload = {
        "version": "1.0.0",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    response = auth_enabled_client.post(
        "/schemas/test-ns/AuditCorrelation/versions",
        json=payload,
        headers=headers,
    )

    assert response.status_code == status.HTTP_201_CREATED

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 1

    log = audit_logs[0]
    assert log.correlation_id == custom_correlation_id


def test_correlation_id_generated_and_stored_in_audit_log(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
) -> None:
    """Test that generated correlation ID is stored in audit log."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    payload = {
        "version": "1.0.0",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    response = auth_enabled_client.post(
        "/schemas/test-ns/GeneratedCorrelation/versions",
        json=payload,
        headers=write_key_header,
    )

    assert response.status_code == status.HTTP_201_CREATED

    correlation_id = response.headers["X-Correlation-ID"]
    assert correlation_id is not None

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 1

    log = audit_logs[0]
    assert log.correlation_id == correlation_id


def test_correlation_id_on_failed_request(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
) -> None:
    """Test that correlation ID is returned even on failed requests."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    custom_correlation_id = "failed-request-789"
    headers = {**write_key_header, "X-Correlation-ID": custom_correlation_id}

    payload = {
        "version": "invalid-version",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    response = auth_enabled_client.post(
        "/schemas/test-ns/FailedRequest/versions",
        json=payload,
        headers=headers,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert response.headers["X-Correlation-ID"] == custom_correlation_id

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 1

    log = audit_logs[0]
    assert log.correlation_id == custom_correlation_id
    assert log.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


def test_correlation_id_on_unauthorized_request(
    auth_enabled_client: TestClient,
    db_session: Session,
) -> None:
    """Test that correlation ID is returned on unauthorized requests."""
    custom_correlation_id = "unauthorized-request-xyz"
    headers = {"X-Correlation-ID": custom_correlation_id}

    payload = {
        "version": "1.0.0",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    response = auth_enabled_client.post(
        "/schemas/test-ns/UnauthorizedTest/versions",
        json=payload,
        headers=headers,
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.headers["X-Correlation-ID"] == custom_correlation_id


def test_correlation_id_on_health_endpoint(
    auth_enabled_client: TestClient,
) -> None:
    """Test that correlation ID is returned on health endpoints."""
    custom_correlation_id = "health-check-123"
    headers = {"X-Correlation-ID": custom_correlation_id}

    response = auth_enabled_client.get(
        "/health",
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.headers["X-Correlation-ID"] == custom_correlation_id


def test_correlation_id_consistent_across_multiple_requests(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
) -> None:
    """Test that different requests get different correlation IDs."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    correlation_ids = []

    for i in range(3):
        payload = {
            "version": f"{i}.0.0",
            "json_schema": {"type": "object"},
            "registered_at": "2024-01-01T00:00:00Z",
            "registered_by": "test-service",
        }
        response = auth_enabled_client.post(
            f"/schemas/test-ns/MultiRequest{i}/versions",
            json=payload,
            headers=write_key_header,
        )

        assert response.status_code == status.HTTP_201_CREATED
        correlation_ids.append(response.headers["X-Correlation-ID"])

    assert len(set(correlation_ids)) == 3

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 3

    stored_correlation_ids = [log.correlation_id for log in audit_logs]
    assert set(correlation_ids) == set(stored_correlation_ids)


def test_correlation_id_on_get_request(
    auth_enabled_client: TestClient,
    read_key_header: dict[str, str],
) -> None:
    """Test that correlation ID is returned on GET requests."""
    custom_correlation_id = "get-request-abc"
    headers = {**read_key_header, "X-Correlation-ID": custom_correlation_id}

    response = auth_enabled_client.get(
        "/schemas",
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.headers["X-Correlation-ID"] == custom_correlation_id


def test_correlation_id_on_delete_request(
    auth_enabled_client: TestClient,
    db_session: Session,
    delete_key_header: dict[str, str],
) -> None:
    """Test that correlation ID is returned on DELETE requests."""
    payload = {
        "version": "1.0.0",
        "json_schema": {"type": "object"},
        "registered_at": "2024-01-01T00:00:00Z",
        "registered_by": "test-service",
    }
    auth_enabled_client.post(
        "/schemas/test-ns/DeleteCorrelation/versions",
        json=payload,
        headers=delete_key_header,
    )

    db_session.query(AuditLog).delete()
    db_session.commit()

    custom_correlation_id = "delete-request-def"
    headers = {**delete_key_header, "X-Correlation-ID": custom_correlation_id}

    response = auth_enabled_client.delete(
        "/schemas/test-ns/DeleteCorrelation/versions/1.0.0?force=true",
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.headers["X-Correlation-ID"] == custom_correlation_id

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 1

    log = audit_logs[0]
    assert log.correlation_id == custom_correlation_id


def test_correlation_id_format_validation(
    auth_enabled_client: TestClient,
    db_session: Session,
    write_key_header: dict[str, str],
) -> None:
    """Test that various correlation ID formats are accepted."""
    db_session.query(AuditLog).delete()
    db_session.commit()

    test_ids = [
        "simple-id",
        "uuid-550e8400-e29b-41d4-a716-446655440000",
        "with_underscores",
        "with-dashes-123",
        "MixedCase123",
    ]

    for i, test_id in enumerate(test_ids):
        headers = {**write_key_header, "X-Correlation-ID": test_id}

        payload = {
            "version": f"{i}.0.0",
            "json_schema": {"type": "object"},
            "registered_at": "2024-01-01T00:00:00Z",
            "registered_by": "test-service",
        }
        response = auth_enabled_client.post(
            f"/schemas/test-ns/FormatTest{i}/versions",
            json=payload,
            headers=headers,
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert response.headers["X-Correlation-ID"] == test_id

    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == len(test_ids)

    stored_ids = [log.correlation_id for log in audit_logs]
    assert set(stored_ids) == set(test_ids)
