from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.api.v1.website import _build_model
from app.main import app
from app.core.admin_auth import require_authenticated_user
from app.schemas.website import WebsiteScanResult

client = TestClient(app)

@pytest.fixture()
def authenticated_client() -> Iterator[TestClient]:
    fake_user = SimpleNamespace(
        id=1,
        email="tester@example.com",
        role="user",
        full_name="Test User",
        is_active=True,
        company_domain="example.com",
    )

    app.dependency_overrides[require_authenticated_user] = lambda: fake_user

    try:
        yield client
    finally:
        app.dependency_overrides.pop(require_authenticated_user, None)


def test_website_scan_route_is_registered() -> None:
    route_paths = {
        path
        for route in app.routes
        if isinstance(path := getattr(route, "path", None), str)
    }

    assert "/api/v1/website/scan" in route_paths


def test_website_scan_rejects_missing_authorization(authenticated_client: TestClient) -> None:
    response = authenticated_client.post(
        "/api/v1/website/scan",
        json={
            "target_url": "https://example.com",
            "scan_profile": "basic",
            "authorization_confirmed": False,
        },
    )

    assert response.status_code == 403
    assert "Authorization confirmation is required" in response.json()["detail"]


def test_website_scan_returns_successful_response(
    monkeypatch: pytest.MonkeyPatch,
    authenticated_client: TestClient,
) -> None:
    class FakeWebsiteScanner:
        def scan(self, target_url: str) -> SimpleNamespace:
            return SimpleNamespace(target_url=target_url, risk_assessment=None)

    monkeypatch.setattr(
        "app.api.v1.website.WebsiteScanner",
        FakeWebsiteScanner,
    )
    monkeypatch.setattr(
        "app.api.v1.website._build_scan_result",
        _fake_build_scan_result,
    )
    monkeypatch.setattr(
        "app.api.v1.website._build_finding_previews",
        lambda _scanner_result: [],
    )
    monkeypatch.setattr(
        "app.api.v1.website._get_security_score",
        lambda _scanner_result: 88,
    )
    monkeypatch.setattr(
        "app.api.v1.website.WebsiteScanPersistenceService.save_completed_website_scan",
        _fake_save_completed_website_scan,
    )

    response = authenticated_client.post(
        "/api/v1/website/scan",
        json={
            "target_url": "https://example.com",
            "scan_profile": "basic",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["scan_id"] == 101
    assert data["target_url"].startswith("https://example.com")
    assert data["status"] in {"completed", "COMPLETED"}
    assert data["security_score"] == 88
    assert data["findings_count"] == 0
    assert data["findings"] == []
    assert data["message"] == "Website scan completed successfully."

    result = data["result"]

    assert result["original_url"].startswith("https://example.com")
    assert result["domain"] == "example.com"
    assert result["is_available"] is True
    assert result["https_enabled"] is True


def test_website_scan_response_contains_safe_scan_metadata(
    monkeypatch: pytest.MonkeyPatch,
    authenticated_client: TestClient,
) -> None:
    class FakeWebsiteScanner:
        def scan(self, target_url: str) -> SimpleNamespace:
            return SimpleNamespace(target_url=target_url, risk_assessment=None)

    monkeypatch.setattr(
        "app.api.v1.website.WebsiteScanner",
        FakeWebsiteScanner,
    )
    monkeypatch.setattr(
        "app.api.v1.website._build_scan_result",
        _fake_build_scan_result,
    )
    monkeypatch.setattr(
        "app.api.v1.website._build_finding_previews",
        lambda _scanner_result: [],
    )
    monkeypatch.setattr(
        "app.api.v1.website._get_security_score",
        lambda _scanner_result: 88,
    )
    monkeypatch.setattr(
        "app.api.v1.website.WebsiteScanPersistenceService.save_completed_website_scan",
        _fake_save_completed_website_scan,
    )

    response = authenticated_client.post(
        "/api/v1/website/scan",
        json={
            "target_url": "https://example.com",
            "scan_profile": "basic",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 200

    metadata = response.json()["result"]["metadata"]

    assert metadata["scanner"] == "CyberShield360 Website Scanner MVP"
    assert metadata["safe_scan"] is True
    assert metadata["active_exploitation"] is False


def _fake_build_scan_result(
    scanner_result: Any,
    original_target_url: str,
) -> WebsiteScanResult:
    """
    Build a valid WebsiteScanResult for API endpoint testing.

    The API test verifies endpoint behavior without performing a real
    network scan or depending on external websites.
    """

    del scanner_result

    result_payload: dict[str, Any] = {
        "original_url": original_target_url,
        "normalized_url": original_target_url,
        "final_url": original_target_url,
        "domain": "example.com",
        "is_available": True,
        "is_reachable": True,
        "https_enabled": True,
        "status_code": 200,
        "response_time_ms": 120,
        "security_headers": {
            "strict_transport_security": "max-age=31536000; includeSubDomains",
            "content_security_policy": "default-src 'self'",
            "x_frame_options": "DENY",
            "x_content_type_options": "nosniff",
            "referrer_policy": "strict-origin-when-cross-origin",
            "permissions_policy": "geolocation=()",
        },
        "ssl_tls": {
            "https_enabled": True,
            "certificate_valid": True,
            "tls_version": "TLS 1.3",
        },
        "dns_email_security": {
            "spf": True,
            "dmarc": True,
            "mx": True,
        },
        "risk_assessment": None,
        "metadata": {
            "scanner": "CyberShield360 Website Scanner MVP",
            "scan_profile": "basic",
            "safe_scan": True,
            "active_exploitation": False,
        },
    }

    return _build_model(WebsiteScanResult, result_payload)


def _fake_save_completed_website_scan(**kwargs: Any) -> SimpleNamespace:
    """
    Return a fake persisted database scan for endpoint tests.
    """

    assert kwargs["target_url"].startswith("https://example.com")
    assert kwargs["security_score"] == 88
    assert kwargs["authorization_confirmed"] is True

    return SimpleNamespace(id=101)