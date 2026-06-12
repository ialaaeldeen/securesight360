from __future__ import annotations

from dataclasses import dataclass, field

from app.scanners.website.availability_checker import (
    AvailabilityCheckResult,
    WebsiteAvailabilityChecker,
)
from app.scanners.website.dns_checker import DNSCheckResult, DNSChecker
from app.scanners.website.header_checker import HeaderCheckResult, SecurityHeaderChecker
from app.scanners.website.redirect_checker import (
    HTTPToHTTPSRedirectChecker,
    RedirectCheckResult,
)
from app.scanners.website.ssl_checker import SSLCheckResult, SSLChecker
from app.scoring.risk_engine import RiskAssessment, assess_website_risk
from app.utils.validators import extract_domain_from_url, validate_website_url


@dataclass(frozen=True, slots=True)
class WebsiteScannerResult:
    """
    Complete result returned by the CyberShield360 website scanner.

    This combines safe website checks:
    - Availability
    - HTTPS and SSL/TLS certificate status
    - HTTP to HTTPS redirect enforcement
    - Security headers
    - DNS records
    - SPF, DMARC, DKIM, and DNSSEC guidance
    - Lightweight technology hints
    - Explainable business-friendly risk assessment
    """

    original_url: str
    domain: str
    availability: AvailabilityCheckResult
    ssl: SSLCheckResult
    redirect: RedirectCheckResult
    headers: HeaderCheckResult
    dns: DNSCheckResult
    technologies_detected: dict[str, str | None] = field(default_factory=dict)
    risk_assessment: RiskAssessment | None = None


class WebsiteScanner:
    """
    Main website scanner orchestrator.

    This class combines multiple safe website security checks into one
    structured result. It does not perform exploitation, brute forcing,
    fuzzing, login testing, or intrusive vulnerability testing.

    The orchestrator also runs the explainable CyberShield360 risk engine
    after collecting scanner evidence. The risk engine converts technical
    findings into a client-friendly score, grade, risk level, summary,
    risk drivers, and priority actions.
    """

    def __init__(
        self,
        availability_checker: WebsiteAvailabilityChecker | None = None,
        ssl_checker: SSLChecker | None = None,
        header_checker: SecurityHeaderChecker | None = None,
        dns_checker: DNSChecker | None = None,
        redirect_checker: HTTPToHTTPSRedirectChecker | None = None,
    ) -> None:
        self.availability_checker = availability_checker or WebsiteAvailabilityChecker()
        self.ssl_checker = ssl_checker or SSLChecker()
        self.header_checker = header_checker or SecurityHeaderChecker()
        self.dns_checker = dns_checker or DNSChecker()
        self.redirect_checker = redirect_checker or HTTPToHTTPSRedirectChecker()

    def scan(self, target_url: str) -> WebsiteScannerResult:
        """
        Run the complete safe website scan and attach an explainable risk assessment.
        """

        normalized_url = validate_website_url(target_url)
        domain = extract_domain_from_url(normalized_url)

        availability_result = self.availability_checker.check(normalized_url)
        ssl_result = self.ssl_checker.check(normalized_url)
        redirect_result = self.redirect_checker.check(normalized_url)
        header_result = self.header_checker.check(availability_result.raw_headers)
        dns_result = self.dns_checker.check(domain)

        technologies_detected = self._detect_basic_technologies(
            availability_result.raw_headers
        )

        scanner_result_without_risk = WebsiteScannerResult(
            original_url=normalized_url,
            domain=domain,
            availability=availability_result,
            ssl=ssl_result,
            redirect=redirect_result,
            headers=header_result,
            dns=dns_result,
            technologies_detected=technologies_detected,
        )

        risk_assessment = assess_website_risk(
            scanner_result_without_risk,
            target=normalized_url,
        )

        return WebsiteScannerResult(
            original_url=normalized_url,
            domain=domain,
            availability=availability_result,
            ssl=ssl_result,
            redirect=redirect_result,
            headers=header_result,
            dns=dns_result,
            technologies_detected=technologies_detected,
            risk_assessment=risk_assessment,
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