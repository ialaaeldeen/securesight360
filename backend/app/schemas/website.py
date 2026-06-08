from __future__ import annotations

from enum import Enum

try:
    # pydantic v2
    from pydantic import BaseModel, ConfigDict, Field, field_validator
except Exception:  # pragma: no cover - fallback for pydantic v1
    from pydantic import BaseModel, Field, validator as field_validator

    # lightweight shim for ConfigDict used in v2; using dict is fine for v1
    ConfigDict = dict

from app.utils.validators import validate_website_url


class WebsiteScanProfile(str, Enum):
    """
    Supported website scan profiles.

    The MVP starts with a safe basic profile only.
    More profiles can be added later, such as:
    - standard
    - advanced_authorized
    """

    BASIC = "basic"


class WebsiteScanStatus(str, Enum):
    """
    Website scan response status.
    """

    COMPLETED = "completed"
    FAILED = "failed"


class WebsiteFindingSeverity(str, Enum):
    """
    Severity levels returned in website scan responses.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class WebsiteScanRequest(BaseModel):
    """
    Request body for starting a safe website security scan.

    The backend will only accept the scan when the user confirms
    that they own the target or have explicit authorization.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "target_url": "https://example.com",
                "scan_profile": "basic",
                "authorization_confirmed": True,
            }
        },
    )

    target_url: str = Field(
        ...,
        min_length=8,
        max_length=500,
        description=(
            "Authorized website URL to scan. "
            "The URL must start with http:// or https://."
        ),
    )

    scan_profile: WebsiteScanProfile = Field(
        default=WebsiteScanProfile.BASIC,
        description="Website scan profile. The MVP supports only basic safe checks.",
    )

    authorization_confirmed: bool = Field(
        ...,
        description=(
            "Must be true only if the user owns the target "
            "or has explicit permission to scan it."
        ),
    )

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, value: str) -> str:
        """
        Validate and normalize the website URL before scanning.
        """

        return validate_website_url(value)


class WebsiteFindingPreview(BaseModel):
    """
    Lightweight finding object returned after a website scan.

    The full finding details will be stored in the database and shown
    in the findings page/report later.
    """

    model_config = ConfigDict(extra="forbid")

    title: str = Field(
        ...,
        min_length=3,
        max_length=255,
        description="Short finding title.",
    )

    severity: WebsiteFindingSeverity = Field(
        ...,
        description="Finding severity level.",
    )

    category: str = Field(
        ...,
        min_length=2,
        max_length=100,
        description="Finding category, such as security_headers or ssl_tls.",
    )

    description: str = Field(
        ...,
        min_length=5,
        description="Technical explanation of the finding.",
    )

    recommendation: str = Field(
        ...,
        min_length=5,
        description="Recommended remediation step.",
    )


class WebsiteScanResult(BaseModel):
    """
    Structured website scan result returned by the scanner service.

    This object contains safe, non-invasive evidence collected from:
    - HTTP availability check
    - HTTPS status
    - SSL/TLS certificate check
    - Security headers check
    - DNS/email security checks
    - Basic technology detection from headers
    """

    model_config = ConfigDict(extra="forbid")

    original_url: str = Field(
        ...,
        description="Original URL submitted by the user.",
    )

    final_url: str | None = Field(
        default=None,
        description="Final URL after redirects, if applicable.",
    )

    domain: str = Field(
        ...,
        description="Extracted domain name from the website URL.",
    )

    is_available: bool = Field(
        ...,
        description="True if the website responded to the availability check.",
    )

    http_status_code: int | None = Field(
        default=None,
        ge=100,
        le=599,
        description="HTTP status code returned by the website.",
    )

    response_time_ms: int | None = Field(
        default=None,
        ge=0,
        description="Website response time in milliseconds.",
    )

    https_enabled: bool = Field(
        ...,
        description="True if the website uses HTTPS.",
    )

    ssl_valid: bool | None = Field(
        default=None,
        description="True if the SSL/TLS certificate is valid.",
    )

    ssl_issuer: str | None = Field(
        default=None,
        max_length=255,
        description="SSL/TLS certificate issuer.",
    )

    ssl_subject: str | None = Field(
        default=None,
        max_length=255,
        description="SSL/TLS certificate subject.",
    )

    ssl_expiry_date: str | None = Field(
        default=None,
        description="SSL/TLS certificate expiry date in ISO format.",
    )

    security_headers: dict[str, bool | str | None] = Field(
        default_factory=dict,
        description="Detected and missing security headers.",
    )

    dns_records: dict[str, list[str]] = Field(
        default_factory=dict,
        description="DNS records such as A, AAAA, MX, NS, and TXT.",
    )

    spf_found: bool | None = Field(
        default=None,
        description="True if SPF record is found.",
    )

    dmarc_found: bool | None = Field(
        default=None,
        description="True if DMARC record is found.",
    )

    dkim_guidance: str | None = Field(
        default=None,
        description="DKIM guidance because selectors cannot always be detected safely.",
    )

    technologies_detected: dict[str, str | None] = Field(
        default_factory=dict,
        description="Basic technology hints detected from safe HTTP headers only.",
    )

    raw_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Raw HTTP response headers collected during the safe check.",
    )


class WebsiteScanResponse(BaseModel):
    """
    API response returned after a website scan completes.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "scan_id": 1,
                "status": "completed",
                "target_url": "https://example.com",
                "security_score": 82,
                "findings_count": 2,
                "findings": [
                    {
                        "title": "Missing Content-Security-Policy Header",
                        "severity": "medium",
                        "category": "security_headers",
                        "description": "The website does not define a Content-Security-Policy header.",
                        "recommendation": "Add a strong Content-Security-Policy header.",
                    }
                ],
                "result": None,
                "message": "Website scan completed successfully.",
            }
        },
    )

    scan_id: int = Field(
        ...,
        ge=1,
        description="Database ID of the completed scan.",
    )

    status: WebsiteScanStatus = Field(
        ...,
        description="Final scan status.",
    )

    target_url: str = Field(
        ...,
        description="Scanned website URL.",
    )

    security_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Calculated security score from 0 to 100.",
    )

    findings_count: int = Field(
        ...,
        ge=0,
        description="Total number of findings returned by the scan.",
    )

    findings: list[WebsiteFindingPreview] = Field(
        default_factory=list,
        description="List of lightweight findings returned to the frontend.",
    )

    result: WebsiteScanResult | None = Field(
        default=None,
        description="Structured website scan result.",
    )

    message: str = Field(
        ...,
        description="Human-readable response message.",
    )