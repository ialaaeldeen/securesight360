from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class HeaderStatus(str, Enum):
    """
    Status of a website security header check.
    """

    PRESENT = "present"
    MISSING = "missing"


@dataclass(frozen=True, slots=True)
class SecurityHeaderDefinition:
    """
    Defines one expected security header and its recommendation.
    """

    name: str
    description: str
    recommendation: str
    owasp_mapping: str = "A05: Security Misconfiguration"


@dataclass(frozen=True, slots=True)
class SecurityHeaderCheck:
    """
    Result for one checked security header.
    """

    name: str
    status: HeaderStatus
    value: str | None
    description: str
    recommendation: str
    owasp_mapping: str


@dataclass(frozen=True, slots=True)
class HeaderCheckResult:
    """
    Final result returned by the security header checker.
    """

    checked_headers: dict[str, SecurityHeaderCheck] = field(default_factory=dict)

    @property
    def missing_headers(self) -> list[SecurityHeaderCheck]:
        """
        Return all missing security headers.
        """

        return [
            header
            for header in self.checked_headers.values()
            if header.status == HeaderStatus.MISSING
        ]

    @property
    def present_headers(self) -> list[SecurityHeaderCheck]:
        """
        Return all present security headers.
        """

        return [
            header
            for header in self.checked_headers.values()
            if header.status == HeaderStatus.PRESENT
        ]


class SecurityHeaderChecker:
    """
    Safe website security header checker.

    This checker only analyzes HTTP response headers that were already
    collected by the availability checker. It does not send additional
    intrusive requests.
    """

    REQUIRED_SECURITY_HEADERS: tuple[SecurityHeaderDefinition, ...] = (
        SecurityHeaderDefinition(
            name="Content-Security-Policy",
            description=(
                "Content-Security-Policy helps reduce the risk of cross-site "
                "scripting and content injection attacks."
            ),
            recommendation=(
                "Configure a strong Content-Security-Policy header that restricts "
                "untrusted scripts, styles, frames, and external content sources."
            ),
        ),
        SecurityHeaderDefinition(
            name="X-Frame-Options",
            description=(
                "X-Frame-Options helps protect pages from clickjacking attacks."
            ),
            recommendation=(
                "Set X-Frame-Options to DENY or SAMEORIGIN, or use the frame-ancestors "
                "directive in Content-Security-Policy."
            ),
        ),
        SecurityHeaderDefinition(
            name="X-Content-Type-Options",
            description=(
                "X-Content-Type-Options prevents browsers from MIME-sniffing files "
                "away from the declared content type."
            ),
            recommendation="Set X-Content-Type-Options to nosniff.",
        ),
        SecurityHeaderDefinition(
            name="Strict-Transport-Security",
            description=(
                "Strict-Transport-Security tells browsers to access the website only "
                "over HTTPS for a defined period."
            ),
            recommendation=(
                "Enable HSTS using Strict-Transport-Security with an appropriate "
                "max-age value after confirming HTTPS is correctly configured."
            ),
        ),
        SecurityHeaderDefinition(
            name="Referrer-Policy",
            description=(
                "Referrer-Policy controls how much referrer information is shared "
                "when users navigate away from the website."
            ),
            recommendation=(
                "Set Referrer-Policy to strict-origin-when-cross-origin or a stricter "
                "policy based on business requirements."
            ),
        ),
        SecurityHeaderDefinition(
            name="Permissions-Policy",
            description=(
                "Permissions-Policy limits access to browser features such as camera, "
                "microphone, geolocation, and payment APIs."
            ),
            recommendation=(
                "Configure Permissions-Policy to disable unnecessary browser features."
            ),
        ),
    )

    def check(self, raw_headers: dict[str, str]) -> HeaderCheckResult:
        """
        Check expected security headers from a raw response header dictionary.
        """

        normalized_headers = self._normalize_headers(raw_headers)
        checked_headers: dict[str, SecurityHeaderCheck] = {}

        for header_definition in self.REQUIRED_SECURITY_HEADERS:
            header_name = header_definition.name
            header_value = normalized_headers.get(header_name.lower())

            status = (
                HeaderStatus.PRESENT
                if header_value is not None and header_value.strip()
                else HeaderStatus.MISSING
            )

            checked_headers[header_name] = SecurityHeaderCheck(
                name=header_name,
                status=status,
                value=header_value,
                description=header_definition.description,
                recommendation=header_definition.recommendation,
                owasp_mapping=header_definition.owasp_mapping,
            )

        return HeaderCheckResult(checked_headers=checked_headers)

    @staticmethod
    def _normalize_headers(raw_headers: dict[str, str]) -> dict[str, str]:
        """
        Normalize header names to lowercase for case-insensitive lookup.
        """

        return {
            str(header_name).lower(): str(header_value)
            for header_name, header_value in raw_headers.items()
        }