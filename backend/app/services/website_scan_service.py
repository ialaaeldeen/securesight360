from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.finding import Finding, FindingCategory, FindingSeverity
from app.models.scan import Scan, ScanStatus, ScanType, TargetType
from app.models.website_check import WebsiteCheck

DEFAULT_AUTHORIZATION_TEXT = (
    "The requester confirmed that they own the target or have explicit "
    "authorization to perform this CyberShield360 website scan."
)


class WebsiteScanPersistenceService:
    """
    Handles database persistence for CyberShield360 website scans.

    This service stores:
    - Main scan metadata in the scans table
    - Website-specific evidence in the website_checks table
    - Explainable risk findings in the findings table

    The API layer should call this service after the scanner and risk engine
    complete successfully.
    """

    @staticmethod
    def save_completed_website_scan(
        *,
        db: Session,
        target_url: str,
        scan_result: Any,
        security_score: int | None,
        authorization_confirmed: bool,
        risk_assessment: Any | None = None,
        finding_previews: Sequence[Any] | None = None,
        authorization_text: str = DEFAULT_AUTHORIZATION_TEXT,
    ) -> Scan:
        """
        Save a completed website scan and related evidence.

        Returns the persisted Scan record. The caller can use scan.id as the
        real database-backed scan_id in the API response.
        """

        now = datetime.now(UTC)

        scan = _build_scan_record(
            target_url=target_url,
            security_score=security_score,
            authorization_confirmed=authorization_confirmed,
            authorization_text=authorization_text,
            started_at=now,
            completed_at=now,
        )

        try:
            db.add(scan)
            db.flush()

            website_check = _build_website_check_record(
                scan_id=scan.id,
                target_url=target_url,
                scan_result=scan_result,
            )
            db.add(website_check)

            findings = _build_finding_records(
                scan_id=scan.id,
                risk_assessment=risk_assessment,
                finding_previews=finding_previews,
            )

            for finding in findings:
                db.add(finding)

            db.commit()
            db.refresh(scan)

            return scan

        except Exception:
            db.rollback()
            raise

    @staticmethod
    def save_failed_website_scan(
        *,
        db: Session,
        target_url: str,
        error_message: str,
        authorization_confirmed: bool,
        authorization_text: str = DEFAULT_AUTHORIZATION_TEXT,
    ) -> Scan:
        """
        Save a failed website scan attempt.

        This is useful later when we want scan history to show failed scans
        instead of losing failed attempts.
        """

        now = datetime.now(UTC)

        scan = _build_scan_record(
            target_url=target_url,
            security_score=None,
            authorization_confirmed=authorization_confirmed,
            authorization_text=authorization_text,
            started_at=now,
            completed_at=now,
        )

        scan.status = ScanStatus.FAILED
        scan.error_message = error_message

        try:
            db.add(scan)
            db.commit()
            db.refresh(scan)

            return scan

        except Exception:
            db.rollback()
            raise


def _build_scan_record(
    *,
    target_url: str,
    security_score: int | None,
    authorization_confirmed: bool,
    authorization_text: str,
    started_at: datetime,
    completed_at: datetime,
) -> Scan:
    scan = Scan()

    scan.target = target_url
    scan.target_type = TargetType.WEBSITE
    scan.scan_type = ScanType.WEBSITE_BASIC
    scan.status = ScanStatus.COMPLETED
    scan.security_score = _normalize_security_score(security_score)
    scan.authorization_confirmed = authorization_confirmed
    scan.authorization_text = authorization_text
    scan.started_at = started_at
    scan.completed_at = completed_at
    scan.error_message = None

    return scan


def _build_website_check_record(
    *,
    scan_id: int,
    target_url: str,
    scan_result: Any,
) -> WebsiteCheck:
    ssl_tls = _as_dict(_get_field(scan_result, "ssl_tls"))
    dns_email_security = _as_dict(_get_field(scan_result, "dns_email_security"))
    metadata = _as_dict(_get_field(scan_result, "metadata"))

    original_url = _string_or_default(
        _first_not_none(
            _get_field(scan_result, "original_url"),
            target_url,
        ),
        default=target_url,
    )

    final_url = _string_or_none(
        _first_not_none(
            _get_field(scan_result, "final_url"),
            _get_field(scan_result, "normalized_url"),
            original_url,
        )
    )

    domain = _string_or_default(
        _first_not_none(
            _get_field(scan_result, "domain"),
            _extract_domain(final_url),
            _extract_domain(original_url),
        ),
        default="unknown",
    )

    security_headers = _as_dict(_get_field(scan_result, "security_headers"))

    website_check = WebsiteCheck()

    website_check.scan_id = scan_id
    website_check.original_url = original_url
    website_check.final_url = final_url
    website_check.domain = domain
    website_check.is_available = bool(
        _first_not_none(
            _get_field(scan_result, "is_available"),
            _get_field(scan_result, "is_reachable"),
            False,
        )
    )
    website_check.http_status_code = _to_int_or_none(
        _first_not_none(
            _get_field(scan_result, "http_status_code"),
            _get_field(scan_result, "status_code"),
        )
    )
    website_check.response_time_ms = _to_int_or_none(
        _get_field(scan_result, "response_time_ms")
    )
    website_check.https_enabled = bool(
        _first_not_none(
            _get_field(scan_result, "https_enabled"),
            _extract_bool_from_mapping(
                ssl_tls,
                keys=(
                    "https_enabled",
                    "https",
                    "enabled",
                ),
            ),
            _url_uses_https(final_url),
            False,
        )
    )

    website_check.ssl_valid = _extract_bool_from_mapping(
        ssl_tls,
        keys=(
            "ssl_valid",
            "certificate_valid",
            "cert_valid",
            "valid",
        ),
    )
    website_check.ssl_issuer = _string_or_none(
        _first_not_none(
            _get_field(ssl_tls, "ssl_issuer"),
            _get_field(ssl_tls, "issuer"),
            _get_field(ssl_tls, "certificate_issuer"),
        )
    )
    website_check.ssl_subject = _string_or_none(
        _first_not_none(
            _get_field(ssl_tls, "ssl_subject"),
            _get_field(ssl_tls, "subject"),
            _get_field(ssl_tls, "certificate_subject"),
        )
    )
    website_check.ssl_expiry_date = _to_datetime_or_none(
        _first_not_none(
            _get_field(ssl_tls, "ssl_expiry_date"),
            _get_field(ssl_tls, "expiry_date"),
            _get_field(ssl_tls, "expires_at"),
            _get_field(ssl_tls, "not_after"),
        )
    )

    website_check.security_headers = _to_jsonable(security_headers)
    website_check.dns_records = _to_jsonable(dns_email_security)
    website_check.spf_found = _extract_bool_from_mapping(
        dns_email_security,
        keys=(
            "spf_found",
            "spf",
            "has_spf",
            "spf_record_found",
        ),
    )
    website_check.dmarc_found = _extract_bool_from_mapping(
        dns_email_security,
        keys=(
            "dmarc_found",
            "dmarc",
            "has_dmarc",
            "dmarc_record_found",
        ),
    )
    website_check.dkim_guidance = _string_or_none(
        _first_not_none(
            _find_value_recursively(
                dns_email_security,
                keys=(
                    "dkim_guidance",
                    "dkim",
                    "dkim_note",
                ),
            ),
            _get_field(metadata, "dkim_guidance"),
        )
    )
    website_check.technologies_detected = _to_jsonable(
        _first_not_none(
            _get_field(scan_result, "technologies_detected"),
            _get_field(metadata, "technologies_detected"),
            _get_field(metadata, "technologies"),
        )
    )
    website_check.raw_headers = _to_jsonable(
        _first_not_none(
            _get_field(scan_result, "raw_headers"),
            _get_field(metadata, "raw_headers"),
            _get_field(security_headers, "raw_headers"),
        )
    )

    return website_check


def _build_finding_records(
    *,
    scan_id: int,
    risk_assessment: Any | None,
    finding_previews: Sequence[Any] | None,
) -> list[Finding]:
    risk_deductions = _extract_risk_deductions(risk_assessment)

    if risk_deductions:
        return [
            _build_finding_from_risk_item(scan_id=scan_id, risk_item=risk_item)
            for risk_item in risk_deductions
        ]

    if finding_previews:
        return [
            _build_finding_from_preview(scan_id=scan_id, preview=preview)
            for preview in finding_previews
        ]

    return []


def _build_finding_from_risk_item(
    *,
    scan_id: int,
    risk_item: Any,
) -> Finding:
    item = _as_dict(risk_item)

    title = _string_or_default(
        _first_not_none(
            _get_field(item, "title"),
            _get_field(item, "name"),
            "Website security finding",
        ),
        default="Website security finding",
    )

    category = _map_finding_category(
        category_value=_get_field(item, "category"),
        title=title,
    )

    finding = Finding()

    finding.scan_id = scan_id
    finding.title = title
    finding.severity = _map_finding_severity(_get_field(item, "severity"))
    finding.category = category
    finding.description = _string_or_default(
        _first_not_none(
            _get_field(item, "description"),
            _get_field(item, "evidence"),
            _get_field(item, "business_impact"),
            title,
        ),
        default=title,
    )
    finding.evidence = _string_or_none(_get_field(item, "evidence"))
    finding.business_impact = _string_or_none(_get_field(item, "business_impact"))
    finding.recommendation = _string_or_default(
        _first_not_none(
            _get_field(item, "recommendation"),
            _get_field(item, "remediation"),
            "Review and remediate this website security weakness.",
        ),
        default="Review and remediate this website security weakness.",
    )
    finding.owasp_mapping = _string_or_none(
        _first_not_none(
            _get_field(item, "owasp_mapping"),
            _get_field(item, "owasp"),
            _get_field(item, "owasp_reference"),
        )
    )
    finding.nist_mapping = _string_or_none(
        _first_not_none(
            _get_field(item, "nist_mapping"),
            _get_field(item, "nist"),
            _get_field(item, "nist_reference"),
        )
    )
    finding.mitre_mapping = _string_or_none(
        _first_not_none(
            _get_field(item, "mitre_mapping"),
            _get_field(item, "mitre"),
            _get_field(item, "mitre_reference"),
        )
    )

    return finding


def _build_finding_from_preview(
    *,
    scan_id: int,
    preview: Any,
) -> Finding:
    item = _as_dict(preview)

    title = _string_or_default(
        _first_not_none(
            _get_field(item, "title"),
            "Website security finding",
        ),
        default="Website security finding",
    )

    finding = Finding()

    finding.scan_id = scan_id
    finding.title = title
    finding.severity = _map_finding_severity(_get_field(item, "severity"))
    finding.category = _map_finding_category(
        category_value=_get_field(item, "category"),
        title=title,
    )
    finding.description = _string_or_default(
        _first_not_none(
            _get_field(item, "description"),
            title,
        ),
        default=title,
    )
    finding.evidence = None
    finding.business_impact = None
    finding.recommendation = _string_or_default(
        _first_not_none(
            _get_field(item, "recommendation"),
            "Review and remediate this website security weakness.",
        ),
        default="Review and remediate this website security weakness.",
    )
    finding.owasp_mapping = None
    finding.nist_mapping = None
    finding.mitre_mapping = None

    return finding


def _extract_risk_deductions(risk_assessment: Any | None) -> list[Any]:
    if risk_assessment is None:
        return []

    deductions = _first_not_none(
        _get_field(risk_assessment, "scoring_deductions"),
        _get_field(risk_assessment, "deductions"),
        _get_field(risk_assessment, "findings"),
    )

    if isinstance(deductions, list | tuple):
        return list(deductions)

    return []


def _map_finding_severity(value: Any) -> FindingSeverity:
    normalized_value = str(_to_plain_data(value) or "").strip().lower()

    if normalized_value in {severity.value for severity in FindingSeverity}:
        return FindingSeverity(normalized_value)

    if "critical" in normalized_value:
        return FindingSeverity.CRITICAL

    if "high" in normalized_value:
        return FindingSeverity.HIGH

    if "medium" in normalized_value or "moderate" in normalized_value:
        return FindingSeverity.MEDIUM

    if "low" in normalized_value:
        return FindingSeverity.LOW

    if "info" in normalized_value or "informational" in normalized_value:
        return FindingSeverity.INFO

    return FindingSeverity.LOW


def _map_finding_category(
    *,
    category_value: Any,
    title: str,
) -> FindingCategory:
    combined_text = f"{category_value or ''} {title}".strip().lower()

    if "header" in combined_text:
        return FindingCategory.SECURITY_HEADERS

    if (
        "ssl" in combined_text
        or "tls" in combined_text
        or "certificate" in combined_text
    ):
        return FindingCategory.SSL_TLS

    if (
        "email" in combined_text
        or "spf" in combined_text
        or "dmarc" in combined_text
        or "dkim" in combined_text
    ):
        return FindingCategory.EMAIL_SECURITY

    if "dns" in combined_text:
        return FindingCategory.DNS_SECURITY

    if "network" in combined_text:
        return FindingCategory.NETWORK_EXPOSURE

    if "service" in combined_text or "port" in combined_text:
        return FindingCategory.SERVICE_EXPOSURE

    if "misconfig" in combined_text or "configuration" in combined_text:
        return FindingCategory.MISCONFIGURATION

    if "compliance" in combined_text or "standard" in combined_text:
        return FindingCategory.COMPLIANCE

    return FindingCategory.WEBSITE_SECURITY


def _normalize_security_score(value: Any) -> int | None:
    if value is None:
        return None

    try:
        score = int(value)
    except (TypeError, ValueError):
        return None

    return max(0, min(score, 100))


def _extract_bool_from_mapping(
    data: Mapping[str, Any],
    *,
    keys: Sequence[str],
) -> bool | None:
    value = _find_value_recursively(data, keys=keys)

    return _coerce_bool_or_none(value)


def _find_value_recursively(
    value: Any,
    *,
    keys: Sequence[str],
) -> Any:
    normalized_keys = {key.lower() for key in keys}

    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).lower() in normalized_keys:
                return item

        for item in value.values():
            discovered = _find_value_recursively(item, keys=keys)

            if discovered is not None:
                return discovered

    if isinstance(value, list | tuple):
        for item in value:
            discovered = _find_value_recursively(item, keys=keys)

            if discovered is not None:
                return discovered

    return None


def _coerce_bool_or_none(value: Any) -> bool | None:
    value = _to_plain_data(value)

    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, int | float):
        return bool(value)

    if isinstance(value, Mapping):
        for key in ("present", "found", "enabled", "valid", "configured", "exists"):
            if key in value:
                return _coerce_bool_or_none(value[key])

        return None

    if isinstance(value, str):
        normalized_value = value.strip().lower()

        if normalized_value in {"true", "yes", "y", "1", "present", "found", "valid"}:
            return True

        if normalized_value in {
            "false",
            "no",
            "n",
            "0",
            "missing",
            "not found",
            "invalid",
            "none",
            "",
        }:
            return False

        return True

    return None


def _to_datetime_or_none(value: Any) -> datetime | None:
    plain_value = _to_plain_data(value)

    if isinstance(plain_value, datetime):
        return plain_value

    if not isinstance(plain_value, str):
        return None

    normalized_value = plain_value.strip()

    if not normalized_value:
        return None

    if normalized_value.endswith("Z"):
        normalized_value = normalized_value[:-1] + "+00:00"

    try:
        return datetime.fromisoformat(normalized_value)
    except ValueError:
        return None


def _as_dict(value: Any) -> dict[str, Any]:
    plain_data = _to_plain_data(value)

    if isinstance(plain_data, Mapping):
        return {str(key): item for key, item in plain_data.items()}

    return {}


def _to_jsonable(value: Any) -> Any:
    plain_data = _to_plain_data(value)

    if isinstance(plain_data, datetime):
        return plain_data.isoformat()

    if isinstance(plain_data, Enum):
        return plain_data.value

    if isinstance(plain_data, Mapping):
        return {str(key): _to_jsonable(item) for key, item in plain_data.items()}

    if isinstance(plain_data, list):
        return [_to_jsonable(item) for item in plain_data]

    if isinstance(plain_data, tuple):
        return [_to_jsonable(item) for item in plain_data]

    return plain_data


def _to_plain_data(value: Any) -> Any:
    if value is None:
        return None

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, datetime):
        return value

    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _to_plain_data(model_dump())

    dict_method = getattr(value, "dict", None)
    if callable(dict_method):
        return _to_plain_data(dict_method())

    if isinstance(value, Mapping):
        return {str(key): _to_plain_data(item) for key, item in value.items()}

    if isinstance(value, list):
        return [_to_plain_data(item) for item in value]

    if isinstance(value, tuple):
        return [_to_plain_data(item) for item in value]

    if hasattr(value, "__dict__"):
        return {
            key: _to_plain_data(item)
            for key, item in vars(value).items()
            if not key.startswith("_")
        }

    return value


def _get_field(value: Any, name: str) -> Any:
    if value is None:
        return None

    if isinstance(value, Mapping):
        return value.get(name)

    return getattr(value, name, None)


def _first_not_none(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value

    return None


def _string_or_none(value: Any) -> str | None:
    plain_value = _to_plain_data(value)

    if plain_value is None:
        return None

    if isinstance(plain_value, str):
        return plain_value

    if isinstance(plain_value, Enum):
        return plain_value.value

    return str(plain_value)


def _string_or_default(value: Any, *, default: str) -> str:
    text_value = _string_or_none(value)

    if text_value is None or not text_value.strip():
        return default

    return text_value


def _to_int_or_none(value: Any) -> int | None:
    plain_value = _to_plain_data(value)

    if plain_value is None:
        return None

    try:
        return int(plain_value)
    except (TypeError, ValueError):
        return None


def _extract_domain(url: str | None) -> str | None:
    if not url:
        return None

    parsed_url = urlparse(url)

    if parsed_url.netloc:
        return parsed_url.netloc

    if parsed_url.path and "." in parsed_url.path:
        return parsed_url.path.split("/")[0]

    return None


def _url_uses_https(url: str | None) -> bool:
    if not url:
        return False

    return urlparse(url).scheme.lower() == "https"