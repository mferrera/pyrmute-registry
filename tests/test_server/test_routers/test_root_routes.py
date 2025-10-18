"""Tests for the root endpoint."""

from fastapi import status
from fastapi.testclient import TestClient


def test_root_endpoint(app_client: TestClient) -> None:
    """Test root endpoint returns API information."""
    response = app_client.get("/")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["name"] == "Pyrmute Schema Registry"
    assert data["version"] == "1.0.0"
    assert data["environment"] in ["test", "development"]
    assert "documentation" in data
    assert "endpoints" in data


def test_root_endpoint_includes_documentation_links(
    app_client: TestClient,
) -> None:
    """Test that root endpoint includes documentation links."""
    response = app_client.get("/")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "documentation" in data
    assert "swagger" in data["documentation"]
    assert "redoc" in data["documentation"]
    assert "openapi" in data["documentation"]
    assert data["documentation"]["openapi"] == "/openapi.json"


def test_root_endpoint_includes_endpoint_links(
    app_client: TestClient,
) -> None:
    """Test that root endpoint includes key endpoint links."""
    response = app_client.get("/")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "endpoints" in data
    assert data["endpoints"]["health"] == "/health"
    assert data["endpoints"]["schemas"] == "/schemas"


def test_endpoint_returns_json_by_default(
    app_client: TestClient,
) -> None:
    """Test that endpoints return JSON responses."""
    response = app_client.get("/")

    assert response.status_code == status.HTTP_200_OK
    assert response.headers["content-type"] == "application/json"


def test_request_with_accept_json(
    app_client: TestClient,
) -> None:
    """Test that requests with Accept: application/json work correctly."""
    response = app_client.get(
        "/",
        headers={"Accept": "application/json"},
    )

    assert response.status_code == status.HTTP_200_OK
    assert "application/json" in response.headers["content-type"]


def test_root_endpoint_in_production_mode(production_client: TestClient) -> None:
    """Test root endpoint behavior in production mode."""
    response = production_client.get("/")
    data = response.json()

    assert data["documentation"]["swagger"] is None
    assert data["documentation"]["redoc"] is None


def test_repository_link_in_root(app_client: TestClient) -> None:
    """Test that root endpoint includes repository link."""
    response = app_client.get("/")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "repository" in data
    assert isinstance(data["repository"], str)
    assert data["repository"].startswith("http")
