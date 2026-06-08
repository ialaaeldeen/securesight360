from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import TracebackType
from typing import cast
from urllib.parse import urlparse

import pytest
from requests.exceptions import ConnectionError

from app.scanners.website.availability_checker import (
    AvailabilityCheckResult,
    WebsiteAvailabilityChecker,
)
from app.scanners.website.dns_checker import DNSChecker, DNSCheckResult
from app.scanners.website.header_checker import (
    HeaderStatus,
    SecurityHeaderChecker,
)
from app.scanners.website.ssl_checker import SSLChecker, SSLCheckResult
from app.scanners.website.website_scanner import WebsiteScanner


@dataclass
class FakeResponse:
    """
    Minimal fake HTTP response used for testing availability checks
    without sending real network requests.
    """

    url: str
    status_code: int
    headers: dict[str, str]
    closed: bool = False

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self.closed = True


class FakeAvailabilityChecker:
    """
    Fake availability checker used to test WebsiteScanner without real HTTP requests.
    """

    def check(self, target_url: str) -> AvailabilityCheckResult:
        return AvailabilityCheckResult(
            original_url=target_url,
            final_url="https://example.com/",
            is_available=True,
            http_status_code=200,
            response_time_ms=120,
            raw_headers={
                "Server": "ExampleServer",
                "X-Powered-By": "FastAPI",
                "Content-Type": "text/html",
                "Content-Security-Policy": "default-src 'self'",
            },
            error=None,
        )


class FakeSSLChecker:
    """
    Fake SSL checker used to test WebsiteScanner without real TLS connections.
    """

    def check(self, target_url: str) -> SSLCheckResult:
        return SSLCheckResult(
            https_enabled=True,
            ssl_valid=True,
            hostname="example.com",
            port=443,
            issuer="Example Issuer",
            subject="CN=example.com",
            expiry_date=None,
            days_until_expiry=90,
            protocol_version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384 (TLSv1.3, 256 bits)",
            error=None,
        )


class FakeDNSChecker:
    """
    Fake DNS checker used to test WebsiteScanner without real DNS lookups.
    """

    def check(self, domain: str) -> DNSCheckResult:
        return DNSCheckResult(
            domain=domain,
            records={
                "A": ["93.184.216.34"],
                "MX": ["10 mail.example.com."],
                "TXT": ["v=spf1 include:_spf.example.com -all"],
                "DMARC": ["v=DMARC1; p=reject"],
            },
            spf_found=True,
            dmarc_found=True,
            dkim_guidance="DKIM requires a known selector.",
            errors={},
        )


def test_availability_checker_returns_success_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_get(*args: object, **kwargs: object) -> FakeResponse:
        return FakeResponse(
            url="https://example.com/",
            status_code=200,
            headers={
                "Content-Type": "text/html",
                "Server": "ExampleServer",
            },
        )

    monkeypatch.setattr(
        "app.scanners.website.availability_checker.requests.get",
        fake_get,
    )

    checker = WebsiteAvailabilityChecker(timeout_seconds=5)
    result = checker.check("https://example.com")

    assert result.original_url == "https://example.com"
    assert result.final_url == "https://example.com/"
    assert result.is_available is True
    assert result.http_status_code == 200
    assert result.response_time_ms is not None
    assert result.response_time_ms >= 0
    assert result.raw_headers["Content-Type"] == "text/html"
    assert result.error is None


def test_availability_checker_returns_safe_error_on_request_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_get(*args: object, **kwargs: object) -> None:
        raise ConnectionError("Connection failed")

    monkeypatch.setattr(
        "app.scanners.website.availability_checker.requests.get",
        fake_get,
    )

    checker = WebsiteAvailabilityChecker(timeout_seconds=5)
    result = checker.check("https://example.com")

    assert result.original_url == "https://example.com"
    assert result.final_url is None
    assert result.is_available is False
    assert result.http_status_code is None
    assert result.response_time_ms is not None
    assert result.error is not None
    assert "Website availability check failed" in result.error


def test_security_header_checker_detects_present_headers() -> None:
    raw_headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }

    checker = SecurityHeaderChecker()
    result = checker.check(raw_headers)

    assert len(result.present_headers) == 6
    assert len(result.missing_headers) == 0

    csp_header = result.checked_headers["Content-Security-Policy"]
    assert csp_header.status == HeaderStatus.PRESENT
    assert csp_header.value == "default-src 'self'"


def test_security_header_checker_detects_missing_headers() -> None:
    raw_headers = {
        "Content-Type": "text/html",
        "Server": "ExampleServer",
    }

    checker = SecurityHeaderChecker()
    result = checker.check(raw_headers)

    assert len(result.present_headers) == 0
    assert len(result.missing_headers) == 6

    missing_header_names = {header.name for header in result.missing_headers}

    assert "Content-Security-Policy" in missing_header_names
    assert "X-Frame-Options" in missing_header_names
    assert "Strict-Transport-Security" in missing_header_names


def test_ssl_checker_returns_https_not_enabled_for_http_url() -> None:
    checker = SSLChecker(timeout_seconds=5)

    result = checker.check("http://example.com")

    assert result.https_enabled is False
    assert result.ssl_valid is None
    assert result.hostname == "example.com"
    assert result.port == 443
    assert result.error is not None
    assert "HTTPS is not enabled" in result.error


def test_ssl_checker_extracts_normalized_hostname() -> None:
    parsed_url = urlparse("https://Example.com/login")

    hostname = SSLChecker._extract_hostname(parsed_url)

    assert hostname == "example.com"


def test_ssl_checker_extracts_default_https_port() -> None:
    parsed_url = urlparse("https://example.com")

    port = SSLChecker._extract_port(parsed_url)

    assert port == 443


def test_ssl_checker_extracts_custom_https_port() -> None:
    parsed_url = urlparse("https://example.com:8443")

    port = SSLChecker._extract_port(parsed_url)

    assert port == 8443


def test_ssl_checker_formats_certificate_name() -> None:
    certificate_name = (
        (("countryName", "US"),),
        (("organizationName", "Example CA"),),
        (("commonName", "Example Root CA"),),
    )

    formatted_name = SSLChecker._format_certificate_name(certificate_name)

    assert formatted_name == (
        "countryName=US, organizationName=Example CA, commonName=Example Root CA"
    )


def test_ssl_checker_calculates_days_until_expiry() -> None:
    future_date = datetime.now(timezone.utc) + timedelta(days=30)

    days_until_expiry = SSLChecker._calculate_days_until_expiry(future_date)

    assert days_until_expiry is not None
    assert 28 <= days_until_expiry <= 30


def test_ssl_checker_returns_zero_days_for_expired_certificate() -> None:
    expired_date = datetime.now(timezone.utc) - timedelta(days=5)

    days_until_expiry = SSLChecker._calculate_days_until_expiry(expired_date)

    assert days_until_expiry == 0


def test_ssl_checker_formats_cipher() -> None:
    cipher = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    formatted_cipher = SSLChecker._format_cipher(cipher)

    assert formatted_cipher == "TLS_AES_256_GCM_SHA384 (TLSv1.3, 256 bits)"


def test_dns_checker_normalizes_domain() -> None:
    normalized_domain = DNSChecker._normalize_domain(" Example.COM. ")

    assert normalized_domain == "example.com"


def test_dns_checker_rejects_empty_domain() -> None:
    with pytest.raises(ValueError, match="Domain cannot be empty"):
        DNSChecker._normalize_domain("   ")


def test_dns_checker_detects_spf_record() -> None:
    txt_records = [
        "google-site-verification=abc123",
        "v=spf1 include:_spf.example.com -all",
    ]

    assert DNSChecker._has_spf_record(txt_records) is True


def test_dns_checker_returns_false_when_spf_missing() -> None:
    txt_records = [
        "google-site-verification=abc123",
        "some-other-txt-record",
    ]

    assert DNSChecker._has_spf_record(txt_records) is False


def test_dns_checker_detects_dmarc_record() -> None:
    txt_records = [
        "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    ]

    assert DNSChecker._has_dmarc_record(txt_records) is True


def test_dns_checker_returns_false_when_dmarc_missing() -> None:
    txt_records = [
        "v=spf1 include:_spf.example.com -all",
    ]

    assert DNSChecker._has_dmarc_record(txt_records) is False


def test_dns_checker_formats_dns_answer() -> None:
    formatted_answer = DNSChecker._format_dns_answer(
        '"v=spf1 include:_spf.example.com -all"'
    )

    assert formatted_answer == "v=spf1 include:_spf.example.com -all"


def test_dns_checker_builds_dkim_guidance() -> None:
    guidance = DNSChecker._build_dkim_guidance("example.com")

    assert "DKIM requires a known selector" in guidance
    assert "selector1._domainkey.example.com" in guidance


def test_website_scanner_combines_all_safe_checks() -> None:
    scanner = WebsiteScanner(
        availability_checker=cast(
            WebsiteAvailabilityChecker,
            FakeAvailabilityChecker(),
        ),
        ssl_checker=cast(
            SSLChecker,
            FakeSSLChecker(),
        ),
        header_checker=SecurityHeaderChecker(),
        dns_checker=cast(
            DNSChecker,
            FakeDNSChecker(),
        ),
    )

    result = scanner.scan("https://example.com")

    assert result.original_url == "https://example.com"
    assert result.domain == "example.com"

    assert result.availability.is_available is True
    assert result.availability.http_status_code == 200

    assert result.ssl.https_enabled is True
    assert result.ssl.ssl_valid is True
    assert result.ssl.protocol_version == "TLSv1.3"

    assert result.dns.spf_found is True
    assert result.dns.dmarc_found is True

    assert result.technologies_detected["server"] == "ExampleServer"
    assert result.technologies_detected["powered_by"] == "FastAPI"
    assert result.technologies_detected["content_type"] == "text/html"


def test_website_scanner_detects_basic_technologies_from_headers() -> None:
    raw_headers = {
        "Server": "nginx",
        "X-Powered-By": "Next.js",
        "Content-Type": "text/html; charset=utf-8",
    }

    detected = WebsiteScanner._detect_basic_technologies(raw_headers)

    assert detected["server"] == "nginx"
    assert detected["powered_by"] == "Next.js"
    assert detected["content_type"] == "text/html; charset=utf-8"