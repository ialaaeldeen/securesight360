from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.admin_auth import AuthenticatedUser, require_authenticated_user
from app.database.session import get_db
from app.schemas.email_threat import (
    EmailThreatAnalysisRequest,
    EmailThreatCompactResponse,
    EmailThreatHistoryDetailResponse,
    EmailThreatHistoryItem,
    EmailThreatHistoryListResponse,
)
from app.services.email_threat_analyzer import analyze_email_threat
from app.services.email_ml_classifier import classify_email_parts

router = APIRouter(prefix="/email", tags=["AI Email Threat Analyzer"])


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _json_dumps(value: Any) -> str:
    return json.dumps(value or [], ensure_ascii=False)


def _json_loads_list(value: Any) -> list[str]:
    if value in (None, "", [], {}):
        return []

    if isinstance(value, list):
        return [str(item) for item in value]

    try:
        parsed = json.loads(value)
    except Exception:
        return []

    if isinstance(parsed, list):
        return [str(item) for item in parsed]

    return []


def _preview(value: str | None, limit: int = 180) -> str | None:
    cleaned = " ".join((value or "").strip().split())

    if not cleaned:
        return None

    if len(cleaned) <= limit:
        return cleaned

    return cleaned[: limit - 1].rstrip() + "…"


def _ensure_email_analyses_table(db: Session) -> None:
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS email_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                user_email VARCHAR(255),
                user_full_name VARCHAR(255),

                subject_preview VARCHAR(255),
                sender_preview VARCHAR(255),

                verdict VARCHAR(80) NOT NULL,
                confidence VARCHAR(20) NOT NULL,
                evidence_strength VARCHAR(20) NOT NULL,
                summary TEXT NOT NULL,

                key_indicators TEXT,
                recommended_actions TEXT,
                attachment_alerts TEXT,
                safety_notes TEXT,

                links_count INTEGER DEFAULT 0,
                attachments_count INTEGER DEFAULT 0,
                headers_provided BOOLEAN DEFAULT 0,

                analyzer_version VARCHAR(80),

                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL
            )
            """
        )
    )

    db.execute(
        text(
            """
            CREATE INDEX IF NOT EXISTS ix_email_analyses_user_created
            ON email_analyses (user_id, created_at)
            """
        )
    )

    db.execute(
        text(
            """
            CREATE INDEX IF NOT EXISTS ix_email_analyses_verdict
            ON email_analyses (verdict)
            """
        )
    )



def _link_alerts_from_analysis(analysis) -> list[str]:
    alerts: list[str] = []

    evidence = getattr(analysis, "technical_evidence", {}) or {}
    link_count = int(evidence.get("link_count") or 0)
    link_domains = evidence.get("link_domains") or []

    if link_count > 0:
        alerts.append(f"{link_count} link(s) were submitted or detected in the email.")

    behaviors = getattr(analysis, "detected_behaviors", []) or []

    for finding in behaviors:
        behavior = str(getattr(finding, "behavior", "") or "").lower()
        explanation = str(getattr(finding, "explanation", "") or "")
        evidence_text = str(getattr(finding, "evidence", "") or "")

        if "url shortener" in behavior:
            alerts.append("Shortened link detected. URL shorteners can hide the real destination from the recipient.")

        if "suspicious links" in behavior:
            if evidence_text:
                alerts.append(f"Suspicious link or domain indicator detected: {evidence_text}.")
            else:
                alerts.append("Suspicious link characteristics were detected.")

    if link_domains:
        visible_domains = ", ".join(str(domain) for domain in link_domains[:5])
        alerts.append(f"Detected link domain(s): {visible_domains}.")

    if link_count > 0:
        alerts.append("Links were inspected as text only and were not opened automatically.")

    unique: list[str] = []
    for alert in alerts:
        if alert not in unique:
            unique.append(alert)

    return unique[:6]

def _compact_response_from_analysis(
    analysis,
    payload: EmailThreatAnalysisRequest | None = None,
) -> EmailThreatCompactResponse:
    attachment_alerts: list[str] = []

    for attachment in analysis.attachment_analysis:
        for indicator in attachment.risk_indicators:
            attachment_alerts.append(f"{attachment.file_name}: {indicator}")

    ml_email_signal = None

    if payload is not None:
        ml_email_signal = classify_email_parts(
            subject=payload.subject,
            sender=payload.sender,
            body=payload.body,
        ).to_dict()

    return EmailThreatCompactResponse(
        verdict=analysis.verdict,
        confidence=analysis.confidence,
        evidence_strength=analysis.evidence_strength,
        summary=analysis.summary,
        key_indicators=analysis.key_indicators[:6],
        recommended_actions=analysis.recommended_actions[:5],
        attachment_alerts=attachment_alerts[:5],
        link_alerts=_link_alerts_from_analysis(analysis),
        safety_notes=[
            "Links were not opened automatically.",
            "Attachments were not executed.",
            "Only user-submitted content was analyzed.",
            "No numeric risk score was used.",
        ],
        analyzer_version=analysis.analyzer_version,
        ml_email_signal=ml_email_signal,
    )


def _save_email_analysis_history(
    *,
    db: Session,
    current_user: AuthenticatedUser,
    payload: EmailThreatAnalysisRequest,
    compact: EmailThreatCompactResponse,
) -> int:
    _ensure_email_analyses_table(db)

    now = _utc_now()

    db.execute(
        text(
            """
            INSERT INTO email_analyses (
                user_id,
                user_email,
                user_full_name,
                subject_preview,
                sender_preview,
                verdict,
                confidence,
                evidence_strength,
                summary,
                key_indicators,
                recommended_actions,
                attachment_alerts,
                safety_notes,
                links_count,
                attachments_count,
                headers_provided,
                analyzer_version,
                created_at,
                updated_at
            )
            VALUES (
                :user_id,
                :user_email,
                :user_full_name,
                :subject_preview,
                :sender_preview,
                :verdict,
                :confidence,
                :evidence_strength,
                :summary,
                :key_indicators,
                :recommended_actions,
                :attachment_alerts,
                :safety_notes,
                :links_count,
                :attachments_count,
                :headers_provided,
                :analyzer_version,
                :created_at,
                :updated_at
            )
            """
        ),
        {
            "user_id": current_user.id,
            "user_email": current_user.email,
            "user_full_name": current_user.full_name,
            "subject_preview": _preview(payload.subject, 220),
            "sender_preview": _preview(payload.sender, 220),
            "verdict": compact.verdict,
            "confidence": compact.confidence,
            "evidence_strength": compact.evidence_strength,
            "summary": compact.summary,
            "key_indicators": _json_dumps(compact.key_indicators),
            "recommended_actions": _json_dumps(compact.recommended_actions),
            "attachment_alerts": _json_dumps(compact.attachment_alerts),
            "safety_notes": _json_dumps(compact.safety_notes),
            "links_count": len(payload.links or []),
            "attachments_count": len(payload.attachments or []),
            "headers_provided": bool((payload.headers or "").strip()),
            "analyzer_version": compact.analyzer_version,
            "created_at": now,
            "updated_at": now,
        },
    )

    analysis_id = db.execute(text("SELECT last_insert_rowid()")).scalar_one()
    db.commit()

    return int(analysis_id)


def _history_item_from_row(row: Any, *, include_detail: bool = False):
    data = dict(row)

    base = {
        "id": int(data["id"]),
        "created_at": str(data["created_at"]),
        "subject_preview": data.get("subject_preview"),
        "sender_preview": data.get("sender_preview"),
        "verdict": data["verdict"],
        "confidence": data["confidence"],
        "evidence_strength": data["evidence_strength"],
        "summary": data["summary"],
        "key_indicators": _json_loads_list(data.get("key_indicators")),
        "attachment_alerts": _json_loads_list(data.get("attachment_alerts")),
        "links_count": int(data.get("links_count") or 0),
        "attachments_count": int(data.get("attachments_count") or 0),
        "headers_provided": bool(data.get("headers_provided")),
        "analyzer_version": data.get("analyzer_version"),
    }

    if include_detail:
        base["recommended_actions"] = _json_loads_list(data.get("recommended_actions"))
        base["safety_notes"] = _json_loads_list(data.get("safety_notes"))
        return EmailThreatHistoryDetailResponse(**base)

    return EmailThreatHistoryItem(**base)


@router.post(
    "/analyze",
    response_model=EmailThreatCompactResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze a suspicious email without opening links or executing attachments",
)
def analyze_suspicious_email(
    payload: EmailThreatAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> EmailThreatCompactResponse:
    analysis = analyze_email_threat(payload)
    compact = _compact_response_from_analysis(analysis, payload)

    _save_email_analysis_history(
        db=db,
        current_user=current_user,
        payload=payload,
        compact=compact,
    )

    return compact


@router.get(
    "/history/me",
    response_model=EmailThreatHistoryListResponse,
    summary="List current user's email analysis history",
)
def get_my_email_analysis_history(
    limit: int = 25,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> EmailThreatHistoryListResponse:
    _ensure_email_analyses_table(db)

    safe_limit = max(1, min(int(limit), 100))
    safe_offset = max(0, int(offset))

    total = db.execute(
        text(
            """
            SELECT COUNT(*)
            FROM email_analyses
            WHERE user_id = :user_id
            """
        ),
        {"user_id": current_user.id},
    ).scalar_one()

    rows = db.execute(
        text(
            """
            SELECT *
            FROM email_analyses
            WHERE user_id = :user_id
            ORDER BY created_at DESC, id DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        {
            "user_id": current_user.id,
            "limit": safe_limit,
            "offset": safe_offset,
        },
    ).mappings().all()

    return EmailThreatHistoryListResponse(
        total=int(total or 0),
        limit=safe_limit,
        offset=safe_offset,
        history=[_history_item_from_row(row) for row in rows],
    )


@router.get(
    "/history/{analysis_id}",
    response_model=EmailThreatHistoryDetailResponse,
    summary="Get current user's email analysis history detail",
)
def get_my_email_analysis_history_detail(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> EmailThreatHistoryDetailResponse:
    _ensure_email_analyses_table(db)

    row = db.execute(
        text(
            """
            SELECT *
            FROM email_analyses
            WHERE id = :analysis_id
              AND user_id = :user_id
            """
        ),
        {
            "analysis_id": analysis_id,
            "user_id": current_user.id,
        },
    ).mappings().first()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Email analysis history item not found.",
        )

    return _history_item_from_row(row, include_detail=True)

