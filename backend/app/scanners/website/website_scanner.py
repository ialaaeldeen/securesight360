from __future__ import annotations

from dataclasses import dataclass, field

from app.scanners.website.availability_checker import (
    AvailabilityCheckResult,
    WebsiteAvailabilityChecker,
)
from app.scanners.website.dns_checker import DNSCheckResult, DNSChecker
from app.scanners.website.header_checker import HeaderCheckResult, SecurityHeaderChecker
from app.scanners.website.ssl_checker import SSLCheckResult, SSLChecker
from app.utils.validators import extract_domain_from_url, validate_website_url


@dataclass(frozen=True, slots=True)
class WebsiteScannerResult:
    """
    Complete result returned by the CyberShield360 website scanner.

    This combines safe website checks:
    - Availability
    - HTTPS and SSL/TLS certificate status
    - Security headers
    - DNS records
    - SPF, DMARC, and DKIM guidance
    """

    original_url: str
    domain: str
    availability: AvailabilityCheckResult
    ssl: SSLCheckResult
    headers: HeaderCheckResult
    dns: DNSCheckResult
    technologies_detected: dict[str, str | None] = field(default_factory=dict)


class WebsiteScanner:
    """
    Main website scanner orchestrator.

    This class combines multiple safe website security checks into one
    structured result. It does not perform exploitation, brute forcing,
    fuzzing, login testing, or intrusive vulnerability testing.
    """

    def __init__(
        self,
        availability_checker: WebsiteAvailabilityChecker | None = None,
        ssl_checker: SSLChecker | None = None,
        header_checker: SecurityHeaderChecker | None = None,
        dns_checker: DNSChecker | None = None,
    ) -> None:
        self.availability_checker = availability_checker or WebsiteAvailabilityChecker()
        self.ssl_checker = ssl_checker or SSLChecker()
        self.header_checker = header_checker or SecurityHeaderChecker()
        self.dns_checker = dns_checker or DNSChecker()

    def scan(self, target_url: str) -> WebsiteScannerResult:
        """
        Run the complete safe website scan.
        """

        normalized_url = validate_website_url(target_url)
        domain = extract_domain_from_url(normalized_url)

        availability_result = self.availability_checker.check(normalized_url)
        ssl_result = self.ssl_checker.check(normalized_url)
        header_result = self.header_checker.check(availability_result.raw_headers)
        dns_result = self.dns_checker.check(domain)

        technologies_detected = self._detect_basic_technologies(
            availability_result.raw_headers
        )

        return WebsiteScannerResult(
            original_url=normalized_url,
            domain=domain,
            availability=availability_result,
            ssl=ssl_result,
            headers=header_result,
            dns=dns_result,
            technologies_detected=technologies_detected,
        )

    @staticmethod
    def _detect_basic_technologies(raw_headers: dict[str, str]) -> dict[str, str | None]:
        """
        Detect basic technology hints from HTTP headers only.

        This is intentionally lightweight and safe. It does not fingerprint
        aggressively or send additional probes.
        """

        normalized_headers = {
            header_name.lower(): header_value
            for header_name, header_value in raw_headers.items()
        }

        return {
            "server": normalized_headers.get("server"),
            "powered_by": normalized_headers.get("x-powered-by"),
            "content_type": normalized_headers.get("content-type"),
        }