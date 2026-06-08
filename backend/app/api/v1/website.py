from __future__ import annotations

from enum import Enum
from typing import Any, Mapping, TypeVar, cast
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.scanners.website.website_scanner import WebsiteScanner, WebsiteScannerResult
from app.schemas.website import (
    WebsiteFindingPreview,
    WebsiteFindingSeverity,
    WebsiteRiskAssessment,
    WebsiteScanRequest,
    WebsiteScanResponse,
    WebsiteScanResult,
    WebsiteScanStatus,
)
from app.services.website_scan_service import WebsiteScanPersistenceService

router = APIRouter(prefix="/website", tags=["Website Scanner"])

ModelT = TypeVar("ModelT", bound=BaseModel)


@router.post(
    "/scan",
    response_model=WebsiteScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Run an authorized website security scan",
    description=(
        "Runs a safe CyberShield360 website security scan for an authorized target. "
        "The scan checks availability, HTTPS posture, security headers, SSL/TLS, "
        "DNS/email security signals, and produces an explainable risk assessment."
    ),
)
def scan_website(
    payload: WebsiteScanRequest,
    db: Session = Depends(get_db),
) -> WebsiteScanResponse:
    """
    Run the Website Scanner MVP endpoint.

    The scan is intentionally safe and non-invasive. The requester must confirm
    that they own the target website or have explicit permission to scan it.

    Completed scans are saved to the database and returned with the real
    database-backed scan ID.
    """

    if not payload.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Authorization confirmation is required. "
                "Only scan websites you own or have explicit permission to test."
            ),
        )

    target_url = str(payload.target_url)

    scanner = WebsiteScanner()
    scanner_result = scanner.scan(target_url)

    findings = _build_finding_previews(scanner_result)
    scan_result = _build_scan_result(
        scanner_result=scanner_result,
        original_target_url=target_url,
    )
    security_score = _get_security_score(scanner_result)

    persisted_scan = WebsiteScanPersistenceService.save_completed_website_scan(
        db=db,
        target_url=target_url,
        scan_result=scan_result,
        security_score=security_score,
        authorization_confirmed=payload.authorization_confirmed,
        risk_assessment=_get_attr(scanner_result, "risk_assessment"),
        finding_previews=findings,
    )

    response_payload: dict[str, Any] = {
        "scan_id": persisted_scan.id,
        "target_url": target_url,
        "status": WebsiteScanStatus.COMPLETED,
        "security_score": security_score,
        "findings_count": len(findings),
        "findings": findings,
        "result": scan_result,
        "message": "Website scan completed successfully.",
    }

    return _build_model(WebsiteScanResponse, response_payload)


def _build_scan_result(
    scanner_result: WebsiteScannerResult,
    original_target_url: str,
) -> WebsiteScanResult:
    availability = _first_not_none(
        _get_attr(scanner_result, "availability"),
        _get_attr(scanner_result, "availability_result"),
        _get_attr(scanner_result, "website_availability"),
    )

    ssl_tls = _first_not_none(
        _get_attr(scanner_result, "ssl_tls"),
        _get_attr(scanner_result, "ssl_result"),
        _get_attr(scanner_result, "tls_result"),
    )

    dns_email_security = _first_not_none(
        _get_attr(scanner_result, "dns_email_security"),
        _get_attr(scanner_result, "dns_result"),
        _get_attr(scanner_result, "dns_email_result"),
    )

    normalized_url = _string_or_none(
        _first_not_none(
            _get_attr(scanner_result, "normalized_url"),
            _get_attr(scanner_result, "url"),
            original_target_url,
        )
    )

    final_url = _string_or_none(
        _first_not_none(
            _get_attr(scanner_result, "final_url"),
            _get_attr(availability, "final_url"),
            normalized_url,
        )
    )

    domain = _string_or_none(
        _first_not_none(
            _get_attr(scanner_result, "domain"),
            _extract_domain(final_url),
            _extract_domain(normalized_url),
            _extract_domain(original_target_url),
        )
    )

    is_available = bool(
        _first_not_none(
            _get_attr(scanner_result, "is_available"),
            _get_attr(scanner_result, "is_reachable"),
            _get_attr(availability, "is_available"),
            _get_attr(availability, "is_reachable"),
            False,
        )
    )

    https_enabled = bool(
        _first_not_none(
            _get_attr(scanner_result, "https_enabled"),
            _get_attr(ssl_tls, "https_enabled"),
            _url_uses_https(final_url),
            _url_uses_https(normalized_url),
            False,
        )
    )

    result_payload: dict[str, Any] = {
        "original_url": original_target_url,
        "normalized_url": normalized_url,
        "final_url": final_url,
        "domain": domain,
        "is_available": is_available,
        "is_reachable": is_available,
        "https_enabled": https_enabled,
        "status_code": _first_not_none(
            _get_attr(scanner_result, "status_code"),
            _get_attr(availability, "status_code"),
        ),
        "response_time_ms": _first_not_none(
            _get_attr(scanner_result, "response_time_ms"),
            _get_attr(availability, "response_time_ms"),
        ),
        "security_headers": _build_security_headers_payload(scanner_result),
        "ssl_tls": _to_plain_data(ssl_tls),
        "dns_email_security": _to_plain_data(dns_email_security),
        "risk_assessment": _build_risk_assessment(scanner_result),
        "metadata": {
            "scanner": "CyberShield360 Website Scanner MVP",
            "scan_profile": "basic",
            "safe_scan": True,
            "active_exploitation": False,
        },
    }

    return _build_model(WebsiteScanResult, result_payload)


def _build_risk_assessment(
    scanner_result: WebsiteScannerResult,
) -> WebsiteRiskAssessment | None:
    risk_assessment = _get_attr(scanner_result, "risk_assessment")

    if risk_assessment is None:
        return None

    risk_payload = _to_plain_data(risk_assessment)

    if not isinstance(risk_payload, dict):
        return None

    return _build_model(WebsiteRiskAssessment, risk_payload)


def _build_security_headers_payload(
    scanner_result: WebsiteScannerResult,
) -> dict[str, Any]:
    security_headers = _first_not_none(
        _get_attr(scanner_result, "security_headers"),
        _get_attr(scanner_result, "headers"),
        _get_attr(scanner_result, "header_result"),
        _get_attr(scanner_result, "security_header_result"),
    )

    plain_data = _to_plain_data(security_headers)

    if not isinstance(plain_data, dict):
        return {}

    return {
        str(header_name): _normalize_security_header_value(header_value)
        for header_name, header_value in plain_data.items()
    }


def _normalize_security_header_value(value: Any) -> Any:
    """
    Normalize security header scan output into schema-friendly values.

    Some internal scanners may return rich dictionaries such as:
    {"present": True, "value": "DENY"}.

    The API schema expects simpler values, so this method extracts the most
    useful field while preserving booleans and strings.
    """

    if value is None:
        return None

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, bool | int | float | str):
        return value

    if isinstance(value, dict):
        preferred_keys = (
            "value",
            "header_value",
            "raw_value",
            "present",
            "enabled",
            "configured",
            "status",
        )

        for key in preferred_keys:
            if key in value and value[key] is not None:
                return _normalize_security_header_value(value[key])

        return str(value)

    return str(value)


def _build_finding_previews(
    scanner_result: WebsiteScannerResult,
) -> list[WebsiteFindingPreview]:
    risk_assessment = _get_attr(scanner_result, "risk_assessment")

    if risk_assessment is None:
        return []

    scoring_deductions = _get_attr(risk_assessment, "scoring_deductions", [])

    findings: list[WebsiteFindingPreview] = []

    for deduction in scoring_deductions:
        finding_payload: dict[str, Any] = {
            "title": _string_or_none(
                _first_not_none(
                    _get_attr(deduction, "title"),
                    "Website security finding",
                )
            ),
            "severity": _coerce_finding_severity(
                _first_not_none(
                    _get_attr(deduction, "severity"),
                    WebsiteFindingSeverity.LOW,
                )
            ),
            "category": _string_or_none(
                _first_not_none(
                    _get_attr(deduction, "category"),
                    "Website Security",
                )
            ),
            "description": _string_or_none(
                _first_not_none(
                    _get_attr(deduction, "business_impact"),
                    _get_attr(deduction, "description"),
                    _get_attr(deduction, "evidence"),
                    "A website security control requires attention.",
                )
            ),
            "recommendation": _string_or_none(
                _first_not_none(
                    _get_attr(deduction, "recommendation"),
                    "Review and remediate this security weakness.",
                )
            ),
        }

        findings.append(_build_model(WebsiteFindingPreview, finding_payload))

    return findings


def _get_security_score(scanner_result: WebsiteScannerResult) -> int:
    risk_assessment = _get_attr(scanner_result, "risk_assessment")

    if risk_assessment is None:
        return 0

    score = _get_attr(risk_assessment, "security_score", 0)

    try:
        return int(score)
    except (TypeError, ValueError):
        return 0


def _build_model(model_cls: type[ModelT], data: Mapping[str, Any]) -> ModelT:
    """
    Build a Pydantic model safely using only fields that exist in the schema.

    This keeps the API layer resilient if the schema changes later and avoids
    Pylance/Pyright call-signature errors from dynamic Pydantic model creation.
    """

    allowed_fields = _get_model_field_names(model_cls)
    filtered_data = {
        key: value
        for key, value in data.items()
        if key in allowed_fields and value is not None
    }

    model_validate = getattr(model_cls, "model_validate", None)

    if callable(model_validate):
        return cast(ModelT, model_validate(filtered_data))

    return cast(ModelT, model_cls(**filtered_data))


def _get_model_field_names(model_cls: type[BaseModel]) -> set[str]:
    pydantic_v2_fields = getattr(model_cls, "model_fields", None)

    if isinstance(pydantic_v2_fields, dict):
        return set(pydantic_v2_fields.keys())

    pydantic_v1_fields = getattr(model_cls, "__fields__", None)

    if isinstance(pydantic_v1_fields, dict):
        return set(pydantic_v1_fields.keys())

    return set()


def _coerce_finding_severity(value: Any) -> WebsiteFindingSeverity:
    if isinstance(value, WebsiteFindingSeverity):
        return value

    normalized_value = str(value).strip().lower()

    for severity in WebsiteFindingSeverity:
        if severity.name.lower() == normalized_value:
            return severity

        if str(severity.value).lower() == normalized_value:
            return severity

    return WebsiteFindingSeverity.LOW


def _to_plain_data(value: Any) -> Any:
    if value is None:
        return None

    if isinstance(value, Enum):
        return value.value

    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _to_plain_data(model_dump())

    dict_method = getattr(value, "dict", None)
    if callable(dict_method):
        return _to_plain_data(dict_method())

    if isinstance(value, list):
        return [_to_plain_data(item) for item in value]

    if isinstance(value, tuple):
        return [_to_plain_data(item) for item in value]

    if isinstance(value, dict):
        return {key: _to_plain_data(item) for key, item in value.items()}

    if hasattr(value, "__dict__"):
        return {
            key: _to_plain_data(item)
            for key, item in vars(value).items()
            if not key.startswith("_")
        }

    return value


def _first_not_none(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value

    return None


def _get_attr(value: Any, name: str, default: Any = None) -> Any:
    if value is None:
        return default

    return getattr(value, name, default)


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None

    return str(value)


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