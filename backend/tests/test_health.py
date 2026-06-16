from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_root_endpoint_returns_api_status() -> None:
    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["project"] == "SecureSight360"
    assert data["status"] == "online"
    assert data["environment"] == "development"
    assert data["version"] == "1.0.0"
    assert data["docs"] == "/docs"


def test_health_endpoint_returns_healthy_status() -> None:
    response = client.get("/api/v1/health/")

    assert response.status_code == 200

    data = response.json()

    assert data["service"] == "SecureSight360 Backend"
    assert data["status"] == "healthy"
    assert data["environment"] == "development"
    assert "timestamp" in data


def test_readiness_endpoint_returns_ready_status() -> None:
    response = client.get("/api/v1/health/readiness")

    assert response.status_code == 200

    data = response.json()

    assert data["service"] == "SecureSight360 Backend"
    assert data["ready"] is True
    assert data["message"] == "API is ready to receive requests"
    assert "timestamp" in data