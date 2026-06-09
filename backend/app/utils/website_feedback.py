from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


class FeedbackStatus(str, Enum):
    PASSED = "passed"
    WARNING = "warning"
    NEEDS_ATTENTION = "needs_attention"
    NOT_CHECKED = "not_checked"


@dataclass(frozen=True)
class WebsiteFeedbackItem:
    """
    Clear, client-friendly feedback item for website scan results.

    Each item explains:
    - what was checked
    - what the result means
    - why it matters
    - what the user should do next
    """

    title: str
    status: FeedbackStatus
    summary: str
    why_it_matters: str
    recommendation: str
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "status": self.status.value,
            "summary": self.summary,
            "why_it_matters": self.why_it_matters,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }


def build_website_feedback(scan_data: Mapping[str, Any]) -> list[dict[str, Any]]:
    """
    Build simple, useful feedback from website scan data.

    This function is designed for:
    - API responses
    - frontend dashboard cards
    - future PDF/HTML reports
    """

    data = dict(scan_data)

    feedback_items = [
        _availability_feedback(data),
        _https_feedback(data),
        _ssl_feedback(data),
        _security_headers_feedback(data),
        _spf_feedback(data),
        _dmarc_feedback(data),
        _dkim_feedback(data),
        _technology_feedback(data),
        _risk_score_feedback(data),
    ]

    return [item.to_dict() for item in feedback_items]


def _availability_feedback(data: Mapping[str, Any]) -> WebsiteFeedbackItem:
    is_available = _bool_or_none(
        _first_not_none(
            data.get("is_available"),
            data.get("available"),
            data.get("reachable"),
            data.get("is_reachable"),
        )
    )

    http_status = data.get("http_status_code")
    response_time = data.get("response_time_ms")

    if is_available is True:
        status = FeedbackStatus.PASSED
        summary = "The website is reachable and responded to the scan request."
        recommendation = (
            "Keep monitoring uptime and response time to ensure visitors can "
            "access the website reliably."
        )
    elif is_available is False:
        status = FeedbackStatus.NEEDS_ATTENTION
        summary = "The website could not be reached during the scan."
        recommendation = (
            "Check hosting, DNS configuration, firewall rules, and whether the "
            "website is temporarily offline."
        )
    else:
        status = FeedbackStatus.NOT_CHECKED
        summary = "Website availability could not be confirmed."
        recommendation = "Run the scan again and verify the target URL is correct."

    return WebsiteFeedbackItem(
        title="Website Availability",
        status=status,
        summary=summary,
        why_it_matters=(
            "If the website is unavailable, users and customers cannot access "
            "your services, and monitoring tools may report downtime."
        ),
        recommendation=recommendation,
        evidence={
            "is_available": is_available,
            "http_status_code": http_status,
            "response_time_ms": response_time,
        },
    )


def _https_feedback(data: Mapping[str, Any]) -> WebsiteFeedbackItem:
    https_enabled = _bool_or_none(data.get("https_enabled"))
    final_url = _string_or_none(
        _first_not_none(data.get("final_url"), data.get("normalized_url"))
    )

    if https_enabled is True:
        status = FeedbackStatus.PASSED
        summary = "HTTPS is enabled for the website."
        recommendation = (
            "Keep HTTPS enabled and make sure all pages redirect to HTTPS by default."
        )
    elif https_enabled is False:
        status = FeedbackStatus.NEEDS_ATTENTION
        summary = "HTTPS does not appear to be enabled."
        recommendation = (
            "Install a valid TLS/SSL certificate and redirect HTTP traffic to HTTPS."
        )
    else:
        status = FeedbackStatus.NOT_CHECKED
        summary = "HTTPS status could not be confirmed."
        recommendation = "Review the SSL/TLS scan output and rerun the scan if needed."

    return WebsiteFeedbackItem(
        title="HTTPS Protection",
        status=status,
        summary=summary,
        why_it_matters=(
            "HTTPS encrypts traffic between the visitor and the website. Without it, "
            "data can be exposed or modified in transit."
        ),
        recommendation=recommendation,
        evidence={
            "https_enabled": https_enabled,
            "final_url": final_url,
        },
    )


def _ssl_feedback(data: Mapping[str, Any]) -> WebsiteFeedbackItem:
    ssl_valid = _bool_or_none(
        _first_not_none(
            data.get("ssl_valid"),
            data.get("certificate_valid"),
        )
    )
    ssl_issuer = _string_or_none(data.get("ssl_issuer"))
    ssl_expiry = _string_or_none(
        _first_not_none(
            data.get("ssl_expiry_date"),
            data.get("ssl_expiry"),
            data.get("certificate_expires_at"),
        )
    )

    if ssl_valid is True:
        status = FeedbackStatus.PASSED
        summary = "The SSL/TLS certificate appears to be valid."
        recommendation = (
            "Track the certificate expiry date and renew it before it expires."
        )
    elif ssl_valid is False:
        status = FeedbackStatus.NEEDS_ATTENTION
        summary = "The SSL/TLS certificate may be invalid or untrusted."
        recommendation = (
            "Check the certificate chain, issuer, hostname match, and expiry date."
        )
    else:
        status = FeedbackStatus.WARNING
        summary = "SSL certificate details were not fully available."
        recommendation = (
            "Review the SSL checker output. Some certificate details may not be "
            "available depending on the target configuration."
        )

    return WebsiteFeedbackItem(
        title="SSL/TLS Certificate",
        status=status,
        summary=summary,
        why_it_matters=(
            "A valid certificate helps users trust the website and protects encrypted "
            "connections from interception."
        ),
        recommendation=recommendation,
        evidence={
            "ssl_valid": ssl_valid,
            "ssl_issuer": ssl_issuer,
            "ssl_expiry_date": ssl_expiry,
        },
    )


def _security_headers_feedback(data: Mapping[str, Any]) -> WebsiteFeedbackItem:
    missing_headers = _as_list(data.get("missing_headers"))
    present_headers = _as_list(data.get("present_headers"))

    if not missing_headers and present_headers:
        status = FeedbackStatus.PASSED
        summary = "Important security headers were detected."
        recommendation = "Keep these headers enabled and review them after major changes."
    elif missing_headers:
        status = FeedbackStatus.WARNING
        summary = "Some recommended security headers are missing."
        recommendation = (
            "Add missing headers such as HSTS, Content-Security-Policy, "
            "X-Frame-Options, and X-Content-Type-Options where appropriate."
        )
    else:
        status = FeedbackStatus.NOT_CHECKED
        summary = "Security header information was not available."
        recommendation = "Run the scan again and review the response headers."

    return WebsiteFeedbackItem(
        title="HTTP Security Headers",
        status=status,
        summary=summary,
        why_it_matters=(
            "Security headers help reduce common web risks such as clickjacking, "
            "content injection, MIME sniffing, and insecure browser behavior."
        ),
        recommendation=recommendation,
        evidence={
            "present_headers": present_headers,
            "missing_headers": missing_headers,
        },
    )


def _spf_feedback(data: Mapping[str, Any]) -> WebsiteFeedbackItem:
    spf_found = _bool_or_none(data.get("spf_found"))

    if spf_found is True:
        status = FeedbackStatus.PASSED
        summary = "An SPF record was found for the domain."
        recommendation = (
            "Keep the SPF record updated and include only trusted mail servers."
        )
    elif spf_found is False:
        status = FeedbackStatus.WARNING
        summary = "No SPF record was detected."
        recommendation = (
            "Add an SPF record to reduce the chance of attackers sending fake emails "
            "using your domain."
        )
    else:
        status = FeedbackStatus.NOT_CHECKED
        summary = "SPF status was not available."
        recommendation = "Review DNS TXT records and rerun the DNS/email check."

    return WebsiteFeedbackItem(
        title="SPF Email Protection",
        status=status,
        summary=summary,
        why_it_matters=(
            "SPF helps email providers verify which servers are allowed to send "
            "email for your domain."
        ),
        recommendation=recommendation,
        evidence={"spf_found": spf_found},
    )


def _dmarc_feedback(data: Mapping[str, Any]) -> WebsiteFeedbackItem:
    dmarc_found = _bool_or_none(data.get("dmarc_found"))

    if dmarc_found is True:
        status = FeedbackStatus.PASSED
        summary = "A DMARC record was found for the domain."
        recommendation = (
            "Review the DMARC policy and consider moving toward quarantine or reject "
            "when monitoring confirms it is safe."
        )
    elif dmarc_found is False:
        status = FeedbackStatus.WARNING
        summary = "No DMARC record was detected."
        recommendation = (
            "Add a DMARC record to improve protection against phishing and email spoofing."
        )
    else:
        status = FeedbackStatus.NOT_CHECKED
        summary = "DMARC status was not available."
        recommendation = "Review DNS TXT records and rerun the DNS/email check."

    return WebsiteFeedbackItem(
        title="DMARC Email Protection",
        status=status,
        summary=summary,
        why_it_matters=(
            "DMARC helps protect your domain from spoofing and gives domain owners "
            "visibility into email authentication failures."
        ),
        recommendation=recommendation,
        evidence={"dmarc_found": dmarc_found},
    )


def _dkim_feedback(data: Mapping[str, Any]) -> WebsiteFeedbackItem:
    guidance = _string_or_none(data.get("dkim_guidance"))

    if guidance:
        status = FeedbackStatus.WARNING
        summary = "DKIM guidance is available for this domain."
        recommendation = guidance
    else:
        status = FeedbackStatus.NOT_CHECKED
        summary = "DKIM could not be fully verified automatically."
        recommendation = (
            "DKIM requires a known selector. Verify DKIM through your email provider "
            "or authorized mail administration panel."
        )

    return WebsiteFeedbackItem(
        title="DKIM Email Protection",
        status=status,
        summary=summary,
        why_it_matters=(
            "DKIM helps prove that emails were authorized by the domain and were not "
            "modified during delivery."
        ),
        recommendation=recommendation,
        evidence={"dkim_guidance": guidance},
    )


def _technology_feedback(data: Mapping[str, Any]) -> WebsiteFeedbackItem:
    technologies = _as_mapping(data.get("technologies"))

    if technologies:
        status = FeedbackStatus.PASSED
        summary = "Basic technology information was detected."
        recommendation = (
            "Review exposed technology information and avoid revealing unnecessary "
            "server or framework details."
        )
    else:
        status = FeedbackStatus.NOT_CHECKED
        summary = "Technology detection is limited in the current scanner version."
        recommendation = (
            "A dedicated technology fingerprinting module can be added later for "
            "more detailed detection."
        )

    return WebsiteFeedbackItem(
        title="Technology Information",
        status=status,
        summary=summary,
        why_it_matters=(
            "Technology details can help defenders understand their stack, but too "
            "much exposed information may also help attackers fingerprint the website."
        ),
        recommendation=recommendation,
        evidence={"technologies": technologies},
    )


def _risk_score_feedback(data: Mapping[str, Any]) -> WebsiteFeedbackItem:
    score = _int_or_none(
        _first_not_none(
            data.get("security_score"),
            data.get("score"),
            data.get("risk_score"),
        )
    )

    if score is None:
        status = FeedbackStatus.NOT_CHECKED
        summary = "Security score was not available."
        recommendation = "Run a full website scan to calculate the security score."
    elif score >= 85:
        status = FeedbackStatus.PASSED
        summary = "The website has a strong security score."
        recommendation = "Maintain the current controls and continue monitoring."
    elif score >= 65:
        status = FeedbackStatus.WARNING
        summary = "The website has a moderate security score."
        recommendation = "Review medium-priority findings and improve missing controls."
    else:
        status = FeedbackStatus.NEEDS_ATTENTION
        summary = "The website has a low security score."
        recommendation = "Fix high-impact findings first, then rerun the scan."

    return WebsiteFeedbackItem(
        title="Overall Security Score",
        status=status,
        summary=summary,
        why_it_matters=(
            "The score gives a simple overview of the website security posture, "
            "but it should be reviewed together with the detailed findings."
        ),
        recommendation=recommendation,
        evidence={"security_score": score},
    )


def _first_not_none(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None

    value_as_string = str(value).strip()
    return value_as_string or None


def _bool_or_none(value: Any) -> bool | None:
    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "y", "1", "found", "present", "enabled"}:
            return True
        if normalized in {"false", "no", "n", "0", "missing", "absent", "disabled"}:
            return False

    if isinstance(value, (int, float)):
        return bool(value)

    return None


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None

    try:
        return int(round(float(value)))
    except (TypeError, ValueError):
        return None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, tuple | set):
        return list(value)

    return [value]


def _as_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)

    return {}
