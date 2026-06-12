from __future__ import annotations

import json
from typing import Any

from fastapi import Request
from sqlalchemy import text
from sqlalchemy.orm import Session


def ensure_audit_log_table(db: Session) -> None:
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                action TEXT,
                outcome TEXT NOT NULL DEFAULT 'success',
                actor_user_id INTEGER,
                actor_email TEXT,
                actor_role TEXT,
                target_user_id INTEGER,
                target_email TEXT,
                target_resource_type TEXT,
                target_resource_id TEXT,
                ip_address TEXT,
                user_agent TEXT,
                details_json TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
    )

    db.execute(
        text(
            """
            CREATE INDEX IF NOT EXISTS ix_audit_logs_created_at
            ON audit_logs(created_at)
            """
        )
    )

    db.execute(
        text(
            """
            CREATE INDEX IF NOT EXISTS ix_audit_logs_event_type
            ON audit_logs(event_type)
            """
        )
    )

    db.execute(
        text(
            """
            CREATE INDEX IF NOT EXISTS ix_audit_logs_actor_user_id
            ON audit_logs(actor_user_id)
            """
        )
    )


def _request_ip(request: Request | None) -> str | None:
    if request is None or request.client is None:
        return None

    forwarded_for = request.headers.get("x-forwarded-for")

    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()

    return request.client.host


def _request_user_agent(request: Request | None) -> str | None:
    if request is None:
        return None

    return request.headers.get("user-agent")


def write_audit_log(
    db: Session,
    *,
    event_type: str,
    outcome: str = "success",
    action: str | None = None,
    actor_user_id: int | None = None,
    actor_email: str | None = None,
    actor_role: str | None = None,
    target_user_id: int | None = None,
    target_email: str | None = None,
    target_resource_type: str | None = None,
    target_resource_id: str | None = None,
    details: dict[str, Any] | None = None,
    request: Request | None = None,
) -> None:
    """
    Best-effort audit logging.

    Audit failures should not break authentication, scanning, or admin workflows.
    """
    try:
        ensure_audit_log_table(db)

        db.execute(
            text(
                """
                INSERT INTO audit_logs (
                    event_type,
                    action,
                    outcome,
                    actor_user_id,
                    actor_email,
                    actor_role,
                    target_user_id,
                    target_email,
                    target_resource_type,
                    target_resource_id,
                    ip_address,
                    user_agent,
                    details_json
                )
                VALUES (
                    :event_type,
                    :action,
                    :outcome,
                    :actor_user_id,
                    :actor_email,
                    :actor_role,
                    :target_user_id,
                    :target_email,
                    :target_resource_type,
                    :target_resource_id,
                    :ip_address,
                    :user_agent,
                    :details_json
                )
                """
            ),
            {
                "event_type": event_type,
                "action": action,
                "outcome": outcome,
                "actor_user_id": actor_user_id,
                "actor_email": actor_email,
                "actor_role": actor_role,
                "target_user_id": target_user_id,
                "target_email": target_email,
                "target_resource_type": target_resource_type,
                "target_resource_id": target_resource_id,
                "ip_address": _request_ip(request),
                "user_agent": _request_user_agent(request),
                "details_json": json.dumps(details or {}, ensure_ascii=False, default=str),
            },
        )

        db.commit()
    except Exception:
        db.rollback()
