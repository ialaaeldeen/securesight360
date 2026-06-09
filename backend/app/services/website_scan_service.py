from __future__ import annotations

import json
from dataclasses import asdict, dataclass, is_dataclass
from datetime import date, datetime, timezone
from enum import Enum
from typing import Any, Mapping, Sequence

from sqlalchemy import Date, DateTime, JSON, MetaData, Table, insert
from sqlalchemy import Enum as SqlEnum
from sqlalchemy.exc import NoSuchTableError
from sqlalchemy.orm import Session
from sqlalchemy.sql.schema import Column
from sqlalchemy.sql.sqltypes import String, Text

DEFAULT_AUTHORIZATION_TEXT = (
    "The user confirmed they are authorized to scan this website asset."
)


@dataclass(frozen=True)
class PersistedWebsiteScan:
    """
    Lightweight return object for persistence operations.

    The API only needs the persisted scan identifier, while keeping this as a
    dataclass avoids depending on a specific ORM model shape.
    """

    id: Any


class WebsiteScanPersistenceService:
    """
    Persist completed Website Scanner MVP results.

    The service stores data from two sources:
    1. The cleaned API scan result.
    2. The raw scanner result.

    This makes persistence more resilient and reduces avoidable NULL / empty
    JSON values when one representation has richer evidence than the other.
    """

    @staticmethod
    def save_completed_website_scan(
        db: Session,
        target_url: str,
        scan_result: Any,
        security_score: int | float | None,
        authorization_confirmed: bool,
        raw_scanner_result: Any | None = None,
        risk_assessment: Any | None = None,
        finding_previews: Sequence[Any] | None = None,
        authorization_text: str = DEFAULT_AUTHORIZATION_TEXT,
    ) -> PersistedWebsiteScan:
        now = _utc_now()
        metadata = MetaData()
        bind = db.get_bind()

        try:
            scans_table = _require_table(
                _reflect_table(
                    metadata=metadata,
                    bind=bind,
                    table_name="scans",
                    required=True,
                )
            )

            scan_payload = _build_scan_row(
                target_url=target_url,
                scan_result=scan_result,
                raw_scanner_result=raw_scanner_result,
                risk_assessment=risk_assessment,
                security_score=security_score,
                authorization_confirmed=authorization_confirmed,
                authorization_text=authorization_text,
                now=now,
            )

            scan_id = _insert_row(
                db=db,
                table=scans_table,
                payload=scan_payload,
            )

            website_checks_table = _reflect_table(
                metadata=metadata,
                bind=bind,
                table_name="website_checks",
                required=False,
            )

            if website_checks_table is not None:
                website_check_payload = _build_website_check_row(
                    scan_id=scan_id,
                    target_url=target_url,
                    scan_result=scan_result,
                    raw_scanner_result=raw_scanner_result,
                    risk_assessment=risk_assessment,
                    security_score=security_score,
                    now=now,
                )

                _insert_row(
                    db=db,
                    table=_require_table(website_checks_table),
                    payload=website_check_payload,
                )

            findings_table = _reflect_table(
                metadata=metadata,
                bind=bind,
                table_name="findings",
                required=False,
            )

            if findings_table is not None:
                finding_rows = _build_finding_rows(
                    scan_id=scan_id,
                    risk_assessment=risk_assessment,
                    finding_previews=finding_previews,
                    now=now,
                )

                for finding_payload in finding_rows:
                    _insert_row(
                        db=db,
                        table=_require_table(findings_table),
                        payload=finding_payload,
                    )

            db.commit()
            return PersistedWebsiteScan(id=scan_id)

        except Exception as exc:
            db.rollback()
            raise RuntimeError("Failed to persist website scan result.") from exc


def _build_scan_row(
    target_url: str,
    scan_result: Any,
    raw_scanner_result: Any | None,
    risk_assessment: Any | None,
    security_score: int | float | None,
    authorization_confirmed: bool,
    authorization_text: str,
    now: datetime,
) -> dict[str, Any]:
    scan_payload = _to_mapping(_compact_plain_data(scan_result))
    raw_payload = _to_mapping(_compact_plain_data(raw_scanner_result))
    risk_payload = _risk_payload(
        explicit_risk_assessment=risk_assessment,
        scan_payload=scan_payload,
        raw_payload=raw_payload,
    )

    normalized_url = _string_or_none(
        _first_not_none(
            scan_payload.get("normalized_url"),
            raw_payload.get("normalized_url"),
            raw_payload.get("final_url"),
            target_url,
        )
    )

    score = _coerce_score(
        _first_not_none(
            security_score,
            risk_payload.get("security_score"),
            scan_payload.get("security_score"),
        )
    )

    executive_summary = _string_or_none(
        _first_not_none(
            risk_payload.get("executive_summary"),
            risk_payload.get("summary"),
        )
    )

    return _compact_mapping(
        {
            "target": target_url,
            "target_url": target_url,
            "url": target_url,
            "normalized_url": normalized_url,
            "scan_type": "website",
            "type": "website",
            "module": "website_scanner",
            "status": "completed",
            "scan_status": "completed",
            "security_score": score,
            "score": score,
            "risk_score": score,
            "risk_level": _string_or_none(risk_payload.get("risk_level")),
            "grade": _string_or_none(risk_payload.get("grade")),
            "summary": executive_summary,
            "executive_summary": executive_summary,
            "authorization_confirmed": authorization_confirmed,
            "authorized": authorization_confirmed,
            "authorization_text": authorization_text,
            "started_at": _first_not_none(
                raw_payload.get("started_at"),
                raw_payload.get("scan_started_at"),
                scan_payload.get("started_at"),
                now,
            ),
            "completed_at": _first_not_none(
                raw_payload.get("completed_at"),
                raw_payload.get("finished_at"),
                raw_payload.get("scan_finished_at"),
                scan_payload.get("completed_at"),
                scan_payload.get("scanned_at"),
                now,
            ),
            "scanned_at": _first_not_none(scan_payload.get("scanned_at"), now),
            "created_at": now,
            "updated_at": now,
            "metadata": _compact_mapping(
                {
                    "source": "website_scanner_mvp",
                    "persistence_version": "1.0",
                    "authorization_confirmed": authorization_confirmed,
                    "normalized_url": normalized_url,
                    "risk_engine_version": risk_payload.get("version"),
                    "coverage": risk_payload.get("coverage"),
                }
            ),
            "raw_result": raw_payload,
            "raw_scan_result": raw_payload,
            "scan_result": scan_payload,
            "result": scan_payload,
            "result_json": scan_payload,
            "risk_assessment": risk_payload,
            "risk_assessment_json": risk_payload,
        }
    )


def _build_website_check_row(
    scan_id: Any,
    target_url: str,
    scan_result: Any,
    raw_scanner_result: Any | None,
    risk_assessment: Any | None,
    security_score: int | float | None,
    now: datetime,
) -> dict[str, Any]:
    scan_payload = _to_mapping(_compact_plain_data(scan_result))
    raw_payload = _to_mapping(_compact_plain_data(raw_scanner_result))
    risk_payload = _risk_payload(
        explicit_risk_assessment=risk_assessment,
        scan_payload=scan_payload,
        raw_payload=raw_payload,
    )

    availability_payload = _first_mapping(
        scan_payload,
        raw_payload,
        keys=("availability", "availability_result", "availability_check"),
    )
    headers_payload = _first_mapping(
        scan_payload,
        raw_payload,
        keys=(
            "security_headers",
            "security_header_result",
            "header_result",
            "headers_result",
            "headers",
        ),
    )
    ssl_tls_payload = _first_mapping(
        scan_payload,
        raw_payload,
        keys=("ssl_tls", "ssl_result", "tls_result", "certificate_result"),
    )
    dns_email_payload = _first_mapping(
        scan_payload,
        raw_payload,
        keys=(
            "dns_email_security",
            "dns_security",
            "dns_result",
            "email_security",
            "dns_email_result",
        ),
    )

    score = _coerce_score(
        _first_not_none(
            security_score,
            risk_payload.get("security_score"),
            scan_payload.get("security_score"),
        )
    )

    reachable = _first_not_none(
        availability_payload.get("is_reachable"),
        availability_payload.get("reachable"),
        availability_payload.get("available"),
    )

    return _compact_mapping(
        {
            "scan_id": scan_id,
            "target": target_url,
            "target_url": target_url,
            "url": target_url,
            "normalized_url": _string_or_none(
                _first_not_none(
                    scan_payload.get("normalized_url"),
                    raw_payload.get("normalized_url"),
                    raw_payload.get("final_url"),
                    target_url,
                )
            ),
            "status": "completed",
            "scan_status": "completed",
            "reachable": reachable,
            "is_reachable": reachable,
            "http_status_code": _first_not_none(
                availability_payload.get("status_code"),
                availability_payload.get("http_status_code"),
                availability_payload.get("response_status"),
            ),
            "response_time_ms": _first_not_none(
                availability_payload.get("response_time_ms"),
                availability_payload.get("latency_ms"),
                availability_payload.get("elapsed_ms"),
            ),
            "final_url": _string_or_none(
                _first_not_none(
                    availability_payload.get("final_url"),
                    raw_payload.get("final_url"),
                    scan_payload.get("normalized_url"),
                )
            ),
            "server": _string_or_none(
                _first_not_none(
                    availability_payload.get("server"),
                    headers_payload.get("server"),
                )
            ),
            "security_score": score,
            "score": score,
            "risk_level": _string_or_none(risk_payload.get("risk_level")),
            "grade": _string_or_none(risk_payload.get("grade")),
            "security_headers": headers_payload,
            "headers": headers_payload,
            "headers_json": headers_payload,
            "missing_headers": _first_not_none(
                headers_payload.get("missing_headers"),
                headers_payload.get("missing"),
            ),
            "present_headers": _first_not_none(
                headers_payload.get("present_headers"),
                headers_payload.get("present"),
            ),
            "has_hsts": _header_is_present(
                headers_payload,
                "Strict-Transport-Security",
            ),
            "has_csp": _header_is_present(
                headers_payload,
                "Content-Security-Policy",
            ),
            "has_x_frame_options": _header_is_present(
                headers_payload,
                "X-Frame-Options",
            ),
            "has_x_content_type_options": _header_is_present(
                headers_payload,
                "X-Content-Type-Options",
            ),
            "ssl_tls": ssl_tls_payload,
            "ssl": ssl_tls_payload,
            "ssl_tls_json": ssl_tls_payload,
            "https_enabled": _first_not_none(
                ssl_tls_payload.get("https_enabled"),
                ssl_tls_payload.get("tls_enabled"),
                ssl_tls_payload.get("ssl_enabled"),
            ),
            "certificate_valid": _first_not_none(
                ssl_tls_payload.get("certificate_valid"),
                ssl_tls_payload.get("is_valid"),
                ssl_tls_payload.get("valid"),
            ),
            "certificate_issuer": _string_or_none(
                _first_not_none(
                    ssl_tls_payload.get("issuer"),
                    ssl_tls_payload.get("certificate_issuer"),
                )
            ),
            "certificate_expires_at": _first_not_none(
                ssl_tls_payload.get("expires_at"),
                ssl_tls_payload.get("not_after"),
                ssl_tls_payload.get("valid_until"),
            ),
            "dns_email_security": dns_email_payload,
            "dns_security": dns_email_payload,
            "dns_json": dns_email_payload,
            "raw_result": raw_payload,
            "raw_scan_result": raw_payload,
            "metadata": _compact_mapping(
                {
                    "source": "website_scanner_mvp",
                    "availability_collected": bool(availability_payload),
                    "security_headers_collected": bool(headers_payload),
                    "ssl_tls_collected": bool(ssl_tls_payload),
                    "dns_email_security_collected": bool(dns_email_payload),
                    "risk_assessment_collected": bool(risk_payload),
                }
            ),
            "created_at": now,
            "updated_at": now,
        }
    )


def _build_finding_rows(
    scan_id: Any,
    risk_assessment: Any | None,
    finding_previews: Sequence[Any] | None,
    now: datetime,
) -> list[dict[str, Any]]:
    risk_payload = _to_mapping(_compact_plain_data(risk_assessment))

    source_items: list[Any] = [
        item for item in (finding_previews or []) if _has_meaningful_value(item)
    ]

    if not source_items:
        source_items = _to_list(
            _first_not_none(
                risk_payload.get("scoring_deductions"),
                risk_payload.get("deductions"),
                risk_payload.get("key_risk_drivers"),
            )
        )

    finding_rows: list[dict[str, Any]] = []

    for item in source_items:
        item_payload = _to_mapping(_compact_plain_data(item))
        if not item_payload:
            continue

        title = _string_or_none(
            _first_not_none(
                item_payload.get("title"),
                item_payload.get("name"),
                item_payload.get("rule_name"),
                item_payload.get("driver"),
            )
        )

        description = _string_or_none(
            _first_not_none(
                item_payload.get("description"),
                item_payload.get("summary"),
                item_payload.get("business_impact"),
                title,
            )
        )

        if not title and not description:
            continue

        evidence_payload = _compact_plain_data(item_payload.get("evidence"))
        standards_payload = _compact_plain_data(
            _first_not_none(
                item_payload.get("references"),
                item_payload.get("standards"),
                item_payload.get("mappings"),
            )
        )

        metadata_payload = _compact_mapping(
            {
                "rule_id": item_payload.get("rule_id"),
                "deduction_points": item_payload.get("deduction_points"),
                "detection_method": item_payload.get("detection_method"),
                "standards": standards_payload,
            }
        )

        finding_rows.append(
            _compact_mapping(
                {
                    "scan_id": scan_id,
                    "title": title or description,
                    "name": title or description,
                    "description": description or title,
                    "severity": _string_or_none(
                        _first_not_none(
                            item_payload.get("severity"),
                            item_payload.get("risk_level"),
                            "medium",
                        )
                    ),
                    "category": _string_or_none(
                        _first_not_none(
                            item_payload.get("category"),
                            item_payload.get("control_area"),
                            item_payload.get("type"),
                            "website_security",
                        )
                    ),
                    "evidence": evidence_payload,
                    "evidence_json": evidence_payload,
                    "recommendation": _string_or_none(
                        _first_not_none(
                            item_payload.get("recommendation"),
                            item_payload.get("recommended_action"),
                            item_payload.get("action"),
                        )
                    ),
                    "business_impact": _string_or_none(
                        item_payload.get("business_impact")
                    ),
                    "detection_method": _string_or_none(
                        item_payload.get("detection_method")
                    ),
                    "reference": standards_payload,
                    "references": standards_payload,
                    "standards": standards_payload,
                    "status": "open",
                    "source": "risk_engine",
                    "metadata": metadata_payload,
                    "details": metadata_payload,
                    "created_at": now,
                    "updated_at": now,
                }
            )
        )

    return finding_rows


def _reflect_table(
    metadata: MetaData,
    bind: Any,
    table_name: str,
    required: bool,
) -> Table | None:
    try:
        return Table(table_name, metadata, autoload_with=bind)
    except NoSuchTableError:
        if required:
            raise
        return None


def _require_table(table: Table | None) -> Table:
    if table is None:
        raise RuntimeError("Expected database table to be available.")
    return table


def _insert_row(db: Session, table: Table, payload: Mapping[str, Any]) -> Any:
    filtered_payload = _filter_payload_for_table(table=table, payload=payload)
    result = db.execute(insert(table).values(**filtered_payload))

    inserted_primary_key = getattr(result, "inserted_primary_key", None)
    if inserted_primary_key:
        primary_key = inserted_primary_key[0]
        if primary_key is not None:
            return primary_key

    lastrowid = getattr(result, "lastrowid", None)
    if lastrowid is not None:
        return lastrowid

    return filtered_payload.get("id")


def _filter_payload_for_table(
    table: Table,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    filtered_payload: dict[str, Any] = {}

    for key, value in payload.items():
        if key not in table.c:
            continue

        compact_value = _compact_plain_data(value)
        if not _has_meaningful_value(compact_value):
            continue

        column = table.c[key]
        filtered_payload[key] = _coerce_for_column(
            value=compact_value,
            column=column,
        )

    return filtered_payload


def _coerce_for_column(value: Any, column: Column[Any]) -> Any:
    value = _to_plain_data(value)
    column_type = column.type

    enum_value = _coerce_enum_for_column(value=value, column_type=column_type)
    if enum_value is not None:
        return enum_value

    if isinstance(value, Enum):
        value = value.value

    if isinstance(value, (dict, list)):
        if isinstance(column_type, JSON):
            return value
        return json.dumps(value, ensure_ascii=False, default=str)

    if isinstance(value, (datetime, date)):
        if isinstance(column_type, (DateTime, Date)):
            return value
        return value.isoformat()

    if isinstance(column_type, (String, Text)) and not isinstance(
        value,
        (str, int, float, bool),
    ):
        return json.dumps(value, ensure_ascii=False, default=str)

    return value


def _coerce_enum_for_column(value: Any, column_type: Any) -> Any | None:
    if not isinstance(column_type, SqlEnum):
        return None

    enum_class = getattr(column_type, "enum_class", None)
    if enum_class is not None:
        if isinstance(value, enum_class):
            return value

        if isinstance(value, Enum):
            value = value.value

        if isinstance(value, str):
            for candidate in (value, value.upper(), value.lower()):
                try:
                    return enum_class(candidate)
                except ValueError:
                    pass

                try:
                    return enum_class[candidate]
                except KeyError:
                    pass

    allowed_values = list(getattr(column_type, "enums", []) or [])
    if isinstance(value, Enum):
        value = value.value

    if isinstance(value, str):
        for candidate in (value, value.upper(), value.lower()):
            if candidate in allowed_values:
                return candidate

    return None


def _risk_payload(
    explicit_risk_assessment: Any | None,
    scan_payload: Mapping[str, Any],
    raw_payload: Mapping[str, Any],
) -> dict[str, Any]:
    explicit_payload = _to_mapping(_compact_plain_data(explicit_risk_assessment))
    if explicit_payload:
        return explicit_payload

    scan_risk_payload = _to_mapping(scan_payload.get("risk_assessment"))
    if scan_risk_payload:
        return scan_risk_payload

    raw_risk_payload = _to_mapping(raw_payload.get("risk_assessment"))
    if raw_risk_payload:
        return raw_risk_payload

    return {}


def _first_mapping(
    *containers: Mapping[str, Any],
    keys: tuple[str, ...],
) -> dict[str, Any]:
    for container in containers:
        if not isinstance(container, Mapping):
            continue

        for key in keys:
            value = _compact_plain_data(container.get(key))
            if isinstance(value, Mapping) and value:
                return dict(value)

    return {}


def _header_is_present(
    headers_payload: Mapping[str, Any],
    header_name: str,
) -> bool | None:
    if not headers_payload:
        return None

    lowered_name = header_name.lower()

    present_headers = _to_list(
        _first_not_none(
            headers_payload.get("present_headers"),
            headers_payload.get("present"),
        )
    )
    for present_header in present_headers:
        if str(present_header).lower() == lowered_name:
            return True

    missing_headers = _to_list(
        _first_not_none(
            headers_payload.get("missing_headers"),
            headers_payload.get("missing"),
        )
    )
    for missing_header in missing_headers:
        if str(missing_header).lower() == lowered_name:
            return False

    header_sections = (
        headers_payload.get("headers"),
        headers_payload.get("raw"),
        headers_payload.get("observed_headers"),
        headers_payload.get("security_headers"),
    )

    for section in header_sections:
        section_payload = _to_mapping(section)
        if not section_payload:
            continue

        for key, value in section_payload.items():
            if str(key).lower() != lowered_name:
                continue

            if isinstance(value, Mapping):
                return bool(
                    _first_not_none(
                        value.get("present"),
                        value.get("is_present"),
                        value.get("exists"),
                        True,
                    )
                )

            return bool(value)

    return None


def _to_plain_data(value: Any) -> Any:
    """
    Convert dataclasses, Pydantic models, mappings, iterables, objects with
    __dict__, and objects with __slots__ into JSON-friendly plain data.

    This intentionally uses safe getattr(...) calls for dynamic attributes such
    as model_dump, dict, and __slots__ to avoid Pylance/Pydantic issues.
    """

    if value is None:
        return None

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if is_dataclass(value) and not isinstance(value, type):
        return _compact_plain_data(asdict(value))

    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        try:
            return _compact_plain_data(model_dump(mode="json"))
        except TypeError:
            return _compact_plain_data(model_dump())

    legacy_dict = getattr(value, "dict", None)
    if callable(legacy_dict):
        try:
            return _compact_plain_data(legacy_dict())
        except TypeError:
            pass

    if isinstance(value, Mapping):
        return _compact_mapping(
            {str(key): _to_plain_data(item) for key, item in value.items()}
        )

    if isinstance(value, (list, tuple, set)):
        return [
            item
            for item in (_to_plain_data(item) for item in value)
            if _has_meaningful_value(item)
        ]

    instance_dict = getattr(value, "__dict__", None)
    if isinstance(instance_dict, Mapping):
        return _compact_mapping(
            {
                str(key): _to_plain_data(item)
                for key, item in instance_dict.items()
                if not str(key).startswith("_")
            }
        )

    slots = getattr(value, "__slots__", None)
    if slots:
        slot_names = [slots] if isinstance(slots, str) else list(slots)
        return _compact_mapping(
            {
                str(slot_name): _to_plain_data(getattr(value, slot_name, None))
                for slot_name in slot_names
                if not str(slot_name).startswith("_")
            }
        )

    return value


def _compact_plain_data(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value if _has_meaningful_value(value) else None

    plain_value = _to_plain_data(value)

    if isinstance(plain_value, Mapping):
        return _compact_mapping(plain_value) or None

    if isinstance(plain_value, list):
        compacted_list = [
            _compact_plain_data(item)
            for item in plain_value
            if _has_meaningful_value(item)
        ]
        return [
            item for item in compacted_list if _has_meaningful_value(item)
        ] or None

    return plain_value if _has_meaningful_value(plain_value) else None


def _compact_mapping(mapping: Mapping[str, Any]) -> dict[str, Any]:
    compacted: dict[str, Any] = {}

    for key, value in mapping.items():
        if not _has_meaningful_value(value):
            continue

        compacted_value = _compact_plain_data(value)
        if not _has_meaningful_value(compacted_value):
            continue

        compacted[str(key)] = compacted_value

    return compacted


def _to_mapping(value: Any) -> dict[str, Any]:
    plain_value = _compact_plain_data(value)

    if isinstance(plain_value, Mapping):
        return dict(plain_value)

    return {}


def _to_list(value: Any) -> list[Any]:
    if value is None:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, (tuple, set)):
        return list(value)

    return [value]


def _first_not_none(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value

    return None


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, Enum):
        value = value.value

    value_as_string = str(value).strip()
    return value_as_string or None


def _coerce_score(value: Any) -> int | None:
    if value is None:
        return None

    try:
        numeric_value = int(round(float(value)))
    except (TypeError, ValueError):
        return None

    return max(0, min(100, numeric_value))


def _has_meaningful_value(value: Any) -> bool:
    if value is None:
        return False

    if isinstance(value, str):
        return bool(value.strip())

    if isinstance(value, Mapping):
        return bool(value)

    if isinstance(value, (list, tuple, set)):
        return bool(value)

    return True


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)