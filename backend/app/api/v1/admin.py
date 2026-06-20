from __future__ import annotations

import json

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.core.admin_auth import (
    AuthenticatedUser,
    ensure_auth_tables,
    require_admin_user,
)
from app.database.session import get_db
from app.database.compat import table_columns as db_table_columns, table_exists as db_table_exists
from app.services.audit_log_service import ensure_audit_log_table, write_audit_log

router = APIRouter(prefix="/admin", tags=["Admin"])


ALLOWED_ADMIN_ROLES = {"user", "admin"}


class UpdateUserRoleRequest(BaseModel):
    role: str = Field(..., min_length=1, max_length=20)


class UpdateUserStatusRequest(BaseModel):
    is_active: bool


def _normalize_admin_role(role: str) -> str:
    normalized = str(role or "").strip().lower()

    if normalized not in ALLOWED_ADMIN_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Role must be either 'user' or 'admin'.",
        )

    return normalized


def _get_user_row_by_id(db: Session, user_id: int) -> dict[str, Any]:
    ensure_auth_tables(db)

    row = db.execute(
        text(
            """
            SELECT
                id,
                email,
                full_name,
                role,
                is_active,
                created_at,
                updated_at,
                last_login_at
            FROM users
            WHERE id = :user_id
            LIMIT 1
            """
        ),
        {"user_id": user_id},
    ).mappings().first()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User was not found.",
        )

    return dict(row)


def _count_active_admins(db: Session) -> int:
    ensure_auth_tables(db)

    row = db.execute(
        text(
            """
            SELECT COUNT(*) AS total
            FROM users
            WHERE LOWER(role) = 'admin'
              AND is_active = 1
            """
        )
    ).mappings().first()

    return int(row["total"] or 0) if row else 0


def _serialize_admin_user(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "email": row["email"],
        "full_name": row["full_name"],
        "role": row["role"],
        "is_active": bool(row["is_active"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "last_login_at": row["last_login_at"],
    }


def _refresh_user_row(db: Session, user_id: int) -> dict[str, Any]:
    return _serialize_admin_user(_get_user_row_by_id(db, user_id))



def _table_exists(db: Session, table_name: str) -> bool:
    return db_table_exists(db, table_name)


def _table_columns(db: Session, table_name: str) -> set[str]:
    return db_table_columns(db, table_name)


def _safe_count(
    db: Session,
    table_name: str,
    where_clause: str = "",
    params: dict[str, Any] | None = None,
) -> int:
    if not _table_exists(db, table_name):
        return 0

    query = f"SELECT COUNT(*) AS total FROM {table_name} {where_clause}"

    row = db.execute(text(query), params or {}).mappings().first()

    if row is None:
        return 0

    return int(row["total"] or 0)


def _scan_datetime_column(db: Session) -> str | None:
    columns = _table_columns(db, "scans")

    for candidate in ("created_at", "started_at", "completed_at", "updated_at"):
        if candidate in columns:
            return candidate

    return None


def _scan_target_expression(columns: set[str]) -> str:
    for candidate in ("target_url", "target", "domain", "url"):
        if candidate in columns:
            return candidate

    return "NULL"


def _scan_score_expression(columns: set[str]) -> str:
    for candidate in ("score", "risk_score", "security_score", "overall_score"):
        if candidate in columns:
            return candidate

    return "NULL"


def _scan_risk_expression(columns: set[str]) -> str:
    for candidate in ("risk_level", "risk", "severity"):
        if candidate in columns:
            return candidate

    return "NULL"


def _scan_status_expression(columns: set[str]) -> str:
    for candidate in ("status", "scan_status"):
        if candidate in columns:
            return candidate

    return "NULL"


def _scan_created_expression(columns: set[str]) -> str:
    for candidate in ("created_at", "started_at", "completed_at", "updated_at"):
        if candidate in columns:
            return candidate

    return "NULL"


@router.get(
    "/dashboard",
    response_model=dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Get admin dashboard statistics",
)
def get_admin_dashboard(
    db: Session = Depends(get_db),
    _: AuthenticatedUser = Depends(require_admin_user),
) -> dict[str, Any]:
    ensure_auth_tables(db)

    total_users = _safe_count(db, "users")
    total_admins = _safe_count(db, "users", "WHERE LOWER(role) = 'admin'")
    total_normal_users = _safe_count(db, "users", "WHERE LOWER(role) = 'user'")
    active_users = _safe_count(db, "users", "WHERE is_active = 1")
    disabled_users = _safe_count(db, "users", "WHERE is_active = 0")
    active_admins = _safe_count(
        db,
        "users",
        "WHERE LOWER(role) = 'admin' AND is_active = 1",
    )

    total_scans = _safe_count(db, "scans")

    completed_scans = 0
    failed_scans = 0
    high_risk_scans = 0
    scans_today = 0

    scan_columns = _table_columns(db, "scans")

    if "status" in scan_columns:
        completed_scans = _safe_count(
            db,
            "scans",
            "WHERE LOWER(status) = 'completed'",
        )
        failed_scans = _safe_count(
            db,
            "scans",
            "WHERE LOWER(status) = 'failed'",
        )

    risk_column = None
    for candidate in ("risk_level", "risk", "severity"):
        if candidate in scan_columns:
            risk_column = candidate
            break

    if risk_column:
        high_risk_scans = _safe_count(
            db,
            "scans",
            f"WHERE LOWER({risk_column}) IN ('high', 'critical')",
        )

    date_column = _scan_datetime_column(db)

    if date_column:
        scans_today = _safe_count(
            db,
            "scans",
            f"WHERE date({date_column}) = date('now')",
        )

    # === SecureSight360 Admin Email Oversight Metrics START ===
    total_email_analyses = 0
    suspicious_email_count = 0
    high_confidence_email_count = 0
    email_links_reviewed = 0
    email_attachments_reviewed = 0
    email_headers_provided = 0
    email_verdict_distribution: dict[str, int] = {}
    recent_email_analyses: list[dict[str, Any]] = []
    most_active_email_users: list[dict[str, Any]] = []

    if _table_exists(db, "email_analyses"):
        email_rows = [
            dict(row)
            for row in db.execute(
                text(
                    """
                    SELECT
                        id,
                        user_id,
                        user_email,
                        user_full_name,
                        subject_preview,
                        sender_preview,
                        verdict,
                        confidence,
                        evidence_strength,
                        summary,
                        links_count,
                        attachments_count,
                        headers_provided,
                        analyzer_version,
                        created_at
                    FROM email_analyses
                    ORDER BY created_at DESC, id DESC
                    """
                )
            ).mappings().all()
        ]

        total_email_analyses = len(email_rows)
        email_user_activity: dict[str, dict[str, Any]] = {}

        for row in email_rows:
            verdict = str(row.get("verdict") or "Unknown").strip() or "Unknown"
            verdict_lower = verdict.lower()
            confidence = str(row.get("confidence") or "").strip().lower()

            _increase(email_verdict_distribution, verdict)

            is_safe = "safe" in verdict_lower or "no obvious threat" in verdict_lower
            if not is_safe:
                suspicious_email_count += 1

            if confidence == "high":
                high_confidence_email_count += 1

            try:
                email_links_reviewed += int(row.get("links_count") or 0)
            except (TypeError, ValueError):
                pass

            try:
                email_attachments_reviewed += int(row.get("attachments_count") or 0)
            except (TypeError, ValueError):
                pass

            if bool(row.get("headers_provided")):
                email_headers_provided += 1

            user_key = str(
                row.get("user_id")
                or row.get("user_email")
                or "unknown"
            )

            if user_key not in email_user_activity:
                email_user_activity[user_key] = {
                    "id": row.get("user_id"),
                    "email": row.get("user_email"),
                    "full_name": row.get("user_full_name"),
                    "email_analysis_count": 0,
                    "total_email_analyses": 0,
                }

            email_user_activity[user_key]["email_analysis_count"] += 1
            email_user_activity[user_key]["total_email_analyses"] += 1

        for row in email_rows[:10]:
            recent_email_analyses.append(
                {
                    "id": row.get("id"),
                    "user_id": row.get("user_id"),
                    "user_email": row.get("user_email"),
                    "user_full_name": row.get("user_full_name"),
                    "subject_preview": row.get("subject_preview"),
                    "sender_preview": row.get("sender_preview"),
                    "verdict": row.get("verdict"),
                    "confidence": row.get("confidence"),
                    "evidence_strength": row.get("evidence_strength"),
                    "summary": row.get("summary"),
                    "links_count": row.get("links_count"),
                    "attachments_count": row.get("attachments_count"),
                    "headers_provided": bool(row.get("headers_provided")),
                    "analyzer_version": row.get("analyzer_version"),
                    "created_at": row.get("created_at"),
                }
            )

        most_active_email_users = sorted(
            email_user_activity.values(),
            key=lambda item: int(item.get("email_analysis_count") or 0),
            reverse=True,
        )[:8]

    # === SecureSight360 Admin Email Oversight Metrics END ===

    return {
        "total_users": total_users,
        "total_admins": total_admins,
        "total_normal_users": total_normal_users,
        "active_users": active_users,
        "disabled_users": disabled_users,
        "active_admins": active_admins,
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "failed_scans": failed_scans,
        "high_risk_scans": high_risk_scans,
        "scans_today": scans_today,
    }


@router.get(
    "/users",
    response_model=list[dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="List all users",
)
def list_admin_users(
    db: Session = Depends(get_db),
    _: AuthenticatedUser = Depends(require_admin_user),
) -> list[dict[str, Any]]:
    ensure_auth_tables(db)

    rows = db.execute(
        text(
            """
            SELECT
                id,
                email,
                full_name,
                role,
                is_active,
                created_at,
                updated_at,
                last_login_at
            FROM users
            ORDER BY id DESC
            """
        )
    ).mappings().all()

    users: list[dict[str, Any]] = []

    for row in rows:
        users.append(
            {
                "id": row["id"],
                "email": row["email"],
                "full_name": row["full_name"],
                "role": row["role"],
                "is_active": bool(row["is_active"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "last_login_at": row["last_login_at"],
            }
        )

    return users



@router.patch(
    "/users/{user_id}/role",
    response_model=dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Update a user's role",
)
def update_admin_user_role(
    user_id: int,
    payload: UpdateUserRoleRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: AuthenticatedUser = Depends(require_admin_user),
) -> dict[str, Any]:
    target_user = _get_user_row_by_id(db, user_id)
    new_role = _normalize_admin_role(payload.role)
    current_role = str(target_user["role"] or "").strip().lower()
    target_is_active = bool(target_user["is_active"])

    if int(current_admin.id) == int(user_id) and new_role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot remove your own admin role.",
        )

    if (
        current_role == "admin"
        and new_role != "admin"
        and target_is_active
        and _count_active_admins(db) <= 1
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot remove the last active admin account.",
        )

    db.execute(
        text(
            """
            UPDATE users
            SET role = :role,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = :user_id
            """
        ),
        {"role": new_role, "user_id": user_id},
    )
    db.commit()

    write_audit_log(
        db,
        event_type="admin.user_role_updated",
        action="update_user_role",
        outcome="success",
        actor_user_id=current_admin.id,
        actor_email=current_admin.email,
        actor_role=current_admin.role,
        target_user_id=user_id,
        target_email=target_user["email"],
        target_resource_type="user",
        target_resource_id=str(user_id),
        details={"old_role": current_role, "new_role": new_role},
        request=request,
    )

    return {
        "status": "success",
        "message": "User role updated successfully.",
        "user": _refresh_user_row(db, user_id),
    }


@router.patch(
    "/users/{user_id}/status",
    response_model=dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Activate or deactivate a user",
)
def update_admin_user_status(
    user_id: int,
    payload: UpdateUserStatusRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: AuthenticatedUser = Depends(require_admin_user),
) -> dict[str, Any]:
    target_user = _get_user_row_by_id(db, user_id)
    new_is_active = bool(payload.is_active)
    current_role = str(target_user["role"] or "").strip().lower()
    target_is_active = bool(target_user["is_active"])

    if int(current_admin.id) == int(user_id) and not new_is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot deactivate your own admin account.",
        )

    if (
        current_role == "admin"
        and target_is_active
        and not new_is_active
        and _count_active_admins(db) <= 1
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot deactivate the last active admin account.",
        )

    db.execute(
        text(
            """
            UPDATE users
            SET is_active = :is_active,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = :user_id
            """
        ),
        {"is_active": 1 if new_is_active else 0, "user_id": user_id},
    )
    db.commit()

    write_audit_log(
        db,
        event_type="admin.user_status_updated",
        action="update_user_status",
        outcome="success",
        actor_user_id=current_admin.id,
        actor_email=current_admin.email,
        actor_role=current_admin.role,
        target_user_id=user_id,
        target_email=target_user["email"],
        target_resource_type="user",
        target_resource_id=str(user_id),
        details={"old_is_active": target_is_active, "new_is_active": new_is_active},
        request=request,
    )

    return {
        "status": "success",
        "message": "User status updated successfully.",
        "user": _refresh_user_row(db, user_id),
    }




@router.get(
    "/audit-logs",
    response_model=list[dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="List recent audit logs",
)
def list_admin_audit_logs(
    limit: int = 100,
    db: Session = Depends(get_db),
    _: AuthenticatedUser = Depends(require_admin_user),
) -> list[dict[str, Any]]:
    ensure_audit_log_table(db)

    safe_limit = max(1, min(int(limit), 500))

    rows = db.execute(
        text(
            """
            SELECT
                id,
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
                details_json,
                created_at
            FROM audit_logs
            ORDER BY id DESC
            LIMIT :limit
            """
        ),
        {"limit": safe_limit},
    ).mappings().all()

    logs: list[dict[str, Any]] = []

    for row in rows:
        details: dict[str, Any] = {}

        if row["details_json"]:
            try:
                parsed = json.loads(row["details_json"])
                if isinstance(parsed, dict):
                    details = parsed
            except json.JSONDecodeError:
                details = {"raw": row["details_json"]}

        logs.append(
            {
                "id": row["id"],
                "event_type": row["event_type"],
                "action": row["action"],
                "outcome": row["outcome"],
                "actor_user_id": row["actor_user_id"],
                "actor_email": row["actor_email"],
                "actor_role": row["actor_role"],
                "target_user_id": row["target_user_id"],
                "target_email": row["target_email"],
                "target_resource_type": row["target_resource_type"],
                "target_resource_id": row["target_resource_id"],
                "ip_address": row["ip_address"],
                "user_agent": row["user_agent"],
                "details": details,
                "created_at": row["created_at"],
            }
        )

    return logs


@router.get(
    "/scans",
    response_model=list[dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="List all scans for admin",
)
def list_admin_scans(
    db: Session = Depends(get_db),
    _: AuthenticatedUser = Depends(require_admin_user),
) -> list[dict[str, Any]]:
    if not _table_exists(db, "scans"):
        return []

    scan_columns = _table_columns(db, "scans")
    user_columns = _table_columns(db, "users")

    target_expr = _scan_target_expression(scan_columns)
    score_expr = _scan_score_expression(scan_columns)
    risk_expr = _scan_risk_expression(scan_columns)
    status_expr = _scan_status_expression(scan_columns)
    created_expr = _scan_created_expression(scan_columns)

    has_user_join = (
        "user_id" in scan_columns
        and "id" in user_columns
        and _table_exists(db, "users")
    )

    if has_user_join:
        query = f"""
            SELECT
                s.id AS id,
                {target_expr if target_expr == "NULL" else "s." + target_expr} AS domain,
                {score_expr if score_expr == "NULL" else "s." + score_expr} AS score,
                {risk_expr if risk_expr == "NULL" else "s." + risk_expr} AS risk,
                {status_expr if status_expr == "NULL" else "s." + status_expr} AS status,
                {created_expr if created_expr == "NULL" else "s." + created_expr} AS created_at,
                s.user_id AS user_id,
                u.email AS user_email
            FROM scans s
            LEFT JOIN users u ON u.id = s.user_id
            ORDER BY s.id DESC
            LIMIT 200
        """
    else:
        query = f"""
            SELECT
                id AS id,
                {target_expr} AS domain,
                {score_expr} AS score,
                {risk_expr} AS risk,
                {status_expr} AS status,
                {created_expr} AS created_at,
                NULL AS user_id,
                NULL AS user_email
            FROM scans
            ORDER BY id DESC
            LIMIT 200
        """

    rows = db.execute(text(query)).mappings().all()

    scans: list[dict[str, Any]] = []

    for row in rows:
        scans.append(
            {
                "id": row["id"],
                "domain": row["domain"],
                "url": row["domain"],
                "score": row["score"],
                "grade": None,
                "risk": row["risk"],
                "status": row["status"],
                "user_id": row["user_id"],
                "user_email": row["user_email"],
                "created_at": row["created_at"],
            }
        )

    return scans


def _safe_group_counts(
    db: Session,
    table_name: str,
    column_name: str,
    where_clause: str = "",
    params: dict[str, Any] | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    if not _table_exists(db, table_name):
        return []

    columns = _table_columns(db, table_name)

    if column_name not in columns:
        return []

    query = f"""
        SELECT
            COALESCE(NULLIF(TRIM({column_name}), ''), 'unknown') AS label,
            COUNT(*) AS total
        FROM {table_name}
        {where_clause}
        GROUP BY COALESCE(NULLIF(TRIM({column_name}), ''), 'unknown')
        ORDER BY total DESC
        LIMIT :limit
    """

    safe_params = dict(params or {})
    safe_params["limit"] = limit

    rows = db.execute(text(query), safe_params).mappings().all()

    return [{"label": str(row["label"]), "total": int(row["total"] or 0)} for row in rows]


def _safe_average_score(db: Session) -> int | None:
    if not _table_exists(db, "scans"):
        return None

    columns = _table_columns(db, "scans")
    score_column = None

    for candidate in ("security_score", "score", "risk_score", "overall_score"):
        if candidate in columns:
            score_column = candidate
            break

    if not score_column:
        return None

    row = db.execute(
        text(
            f"""
            SELECT AVG({score_column}) AS average_score
            FROM scans
            WHERE {score_column} IS NOT NULL
            """
        )
    ).mappings().first()

    if row is None or row["average_score"] is None:
        return None

    return int(round(float(row["average_score"])))


def _safe_recent_scans(db: Session, limit: int = 8) -> list[dict[str, Any]]:
    if not _table_exists(db, "scans"):
        return []

    columns = _table_columns(db, "scans")
    target_expr = _scan_target_expression(columns)
    score_expr = _scan_score_expression(columns)
    risk_expr = _scan_risk_expression(columns)
    status_expr = _scan_status_expression(columns)
    created_expr = _scan_created_expression(columns)

    grade_expr = "grade" if "grade" in columns else "NULL"
    user_email_expr = "user_email" if "user_email" in columns else "NULL"

    order_column = _scan_datetime_column(db)

    order_clause = f"{order_column} DESC" if order_column else "id DESC"

    rows = db.execute(
        text(
            f"""
            SELECT
                id,
                {target_expr} AS target,
                {score_expr} AS security_score,
                {grade_expr} AS security_rating,
                {risk_expr} AS risk_level,
                {status_expr} AS status,
                {user_email_expr} AS user_email,
                {created_expr} AS created_at
            FROM scans
            ORDER BY {order_clause}
            LIMIT :limit
            """
        ),
        {"limit": limit},
    ).mappings().all()

    return [
        {
            "id": row["id"],
            "target": row["target"],
            "security_score": row["security_score"],
            "security_rating": row["security_rating"],
            "risk_level": row["risk_level"],
            "status": row["status"],
            "user_email": row["user_email"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]


def _safe_top_users_by_scans(db: Session, limit: int = 8) -> list[dict[str, Any]]:
    if not _table_exists(db, "scans"):
        return []

    columns = _table_columns(db, "scans")

    if "user_email" in columns:
        user_expr = "COALESCE(NULLIF(TRIM(user_email), ''), 'unknown')"
    elif "user_id" in columns:
        user_expr = "CAST(user_id AS TEXT)"
    else:
        return []

    rows = db.execute(
        text(
            f"""
            SELECT
                {user_expr} AS user_label,
                COUNT(*) AS total_scans
            FROM scans
            GROUP BY {user_expr}
            ORDER BY total_scans DESC
            LIMIT :limit
            """
        ),
        {"limit": limit},
    ).mappings().all()

    return [
        {
            "user": str(row["user_label"]),
            "total_scans": int(row["total_scans"] or 0),
        }
        for row in rows
    ]


def _safe_riskiest_targets(db: Session, limit: int = 8) -> list[dict[str, Any]]:
    if not _table_exists(db, "scans"):
        return []

    columns = _table_columns(db, "scans")
    target_expr = _scan_target_expression(columns)
    score_expr = _scan_score_expression(columns)
    risk_expr = _scan_risk_expression(columns)
    created_expr = _scan_created_expression(columns)

    if score_expr == "NULL":
        return []

    rows = db.execute(
        text(
            f"""
            SELECT
                {target_expr} AS target,
                MIN({score_expr}) AS lowest_score,
                {risk_expr} AS risk_level,
                MAX({created_expr}) AS last_seen
            FROM scans
            WHERE {score_expr} IS NOT NULL
            GROUP BY {target_expr}
            ORDER BY lowest_score ASC
            LIMIT :limit
            """
        ),
        {"limit": limit},
    ).mappings().all()

    return [
        {
            "target": row["target"],
            "lowest_score": row["lowest_score"],
            "risk_level": row["risk_level"],
            "last_seen": row["last_seen"],
        }
        for row in rows
    ]


@router.get(
    "/dashboard/analysis",
    response_model=dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Get professional admin security analytics",
)
def get_admin_dashboard_analysis(
    db: Session = Depends(get_db),
    _: AuthenticatedUser = Depends(require_admin_user),
) -> dict[str, Any]:
    """
    Return a professional admin analytics dashboard using raw SQL only.

    Important:
    - This project currently uses a raw SQL users table, not a User ORM model.
    - Older scan rows may not have grade/risk_level columns.
    - Security Rating and Risk Level are therefore derived from security_score when needed.
    """
    ensure_auth_tables(db)

    def _rating_from_score(score: Any) -> str:
        try:
            value = int(score)
        except (TypeError, ValueError):
            return "Unrated"

        if value >= 85:
            return "Excellent"
        if value >= 70:
            return "Strong"
        if value >= 50:
            return "Moderate"
        if value >= 30:
            return "Weak"
        return "Critical"

    def _risk_from_score(score: Any) -> str:
        try:
            value = int(score)
        except (TypeError, ValueError):
            return "Unknown"

        if value >= 70:
            return "Low"
        if value >= 50:
            return "Medium"
        if value >= 30:
            return "High"
        return "Critical"

    def _increase(counter: dict[str, int], key: str) -> None:
        normalized = str(key or "Unknown").strip() or "Unknown"
        counter[normalized] = counter.get(normalized, 0) + 1

    def _scan_time(row: dict[str, Any]) -> Any:
        return (
            row.get("created_at")
            or row.get("completed_at")
            or row.get("started_at")
            or row.get("updated_at")
        )

    total_users = _safe_count(db, "users")
    active_users = _safe_count(db, "users", "WHERE is_active = 1")
    inactive_users = _safe_count(db, "users", "WHERE is_active = 0")
    total_admins = _safe_count(db, "users", "WHERE LOWER(role) = 'admin'")
    active_admins = _safe_count(
        db,
        "users",
        "WHERE LOWER(role) = 'admin' AND is_active = 1",
    )

    scan_columns = _table_columns(db, "scans")
    total_scans = _safe_count(db, "scans")

    completed_scans = 0
    failed_scans = 0
    average_security_score: float | None = None
    high_critical_risk_scan_count = 0

    rating_distribution: dict[str, int] = {}
    risk_level_distribution: dict[str, int] = {}
    scan_status_distribution: dict[str, int] = {}

    recent_scans: list[dict[str, Any]] = []
    riskiest_targets: list[dict[str, Any]] = []
    most_active_users: list[dict[str, Any]] = []

    if _table_exists(db, "scans"):
        scan_rows = [
            dict(row)
            for row in db.execute(
                text(
                    """
                    SELECT
                        id,
                        target,
                        status,
                        security_score,
                        started_at,
                        completed_at,
                        created_at,
                        updated_at,
                        user_id,
                        user_email,
                        user_full_name
                    FROM scans
                    ORDER BY COALESCE(created_at, completed_at, started_at, updated_at) DESC,
                             id DESC
                    """
                )
            ).mappings().all()
        ]

        scores: list[int] = []

        for row in scan_rows:
            status_value = str(row.get("status") or "Unknown").strip() or "Unknown"
            status_lower = status_value.lower()

            if status_lower == "completed":
                completed_scans += 1
            elif status_lower == "failed":
                failed_scans += 1

            _increase(scan_status_distribution, status_value)

            score = row.get("security_score")
            rating = _rating_from_score(score)
            risk_level = _risk_from_score(score)

            if rating != "Unrated":
                _increase(rating_distribution, rating)

            if risk_level != "Unknown":
                _increase(risk_level_distribution, risk_level)

            if risk_level in {"High", "Critical"}:
                high_critical_risk_scan_count += 1

            try:
                scores.append(int(score))
            except (TypeError, ValueError):
                pass

        if scores:
            average_security_score = round(sum(scores) / len(scores), 1)

        for row in scan_rows[:10]:
            score = row.get("security_score")
            recent_scans.append(
                {
                    "id": row.get("id"),
                    "target": row.get("target"),
                    "target_url": row.get("target"),
                    "status": row.get("status"),
                    "security_score": score,
                    "security_rating": _rating_from_score(score),
                    "grade": _rating_from_score(score),
                    "risk_level": _risk_from_score(score),
                    "created_at": _scan_time(row),
                    "started_at": row.get("started_at"),
                    "completed_at": row.get("completed_at"),
                    "user_id": row.get("user_id"),
                    "user_email": row.get("user_email"),
                    "user_full_name": row.get("user_full_name"),
                }
            )

        scored_rows = [
            row
            for row in scan_rows
            if row.get("security_score") is not None
        ]

        lowest_by_target: dict[str, dict[str, Any]] = {}

        for row in scored_rows:
            target = str(row.get("target") or "Unknown target")
            current = lowest_by_target.get(target)

            if current is None:
                lowest_by_target[target] = row
                continue

            try:
                row_score = int(row.get("security_score"))
                current_score = int(current.get("security_score"))
            except (TypeError, ValueError):
                continue

            if row_score < current_score:
                lowest_by_target[target] = row

        for row in sorted(
            lowest_by_target.values(),
            key=lambda item: int(item.get("security_score") or 999),
        )[:8]:
            score = row.get("security_score")
            riskiest_targets.append(
                {
                    "id": row.get("id"),
                    "target": row.get("target"),
                    "target_url": row.get("target"),
                    "security_score": score,
                    "lowest_score": score,
                    "average_security_score": score,
                    "security_rating": _rating_from_score(score),
                    "grade": _rating_from_score(score),
                    "risk_level": _risk_from_score(score),
                    "last_seen": _scan_time(row),
                    "user_id": row.get("user_id"),
                    "user_email": row.get("user_email"),
                    "user_full_name": row.get("user_full_name"),
                }
            )

        user_activity: dict[str, dict[str, Any]] = {}

        for row in scan_rows:
            user_key = str(
                row.get("user_id")
                or row.get("user_email")
                or "unknown"
            )

            if user_key not in user_activity:
                user_activity[user_key] = {
                    "id": row.get("user_id"),
                    "email": row.get("user_email"),
                    "full_name": row.get("user_full_name"),
                    "scan_count": 0,
                    "total_scans": 0,
                }

            user_activity[user_key]["scan_count"] += 1
            user_activity[user_key]["total_scans"] += 1

        most_active_users = sorted(
            user_activity.values(),
            key=lambda item: int(item.get("scan_count") or 0),
            reverse=True,
        )[:8]

    # === SecureSight360 Admin Email Oversight Metrics START ===
    total_email_analyses = 0
    suspicious_email_count = 0
    high_confidence_email_count = 0
    email_links_reviewed = 0
    email_attachments_reviewed = 0
    email_headers_provided = 0
    email_verdict_distribution: dict[str, int] = {}
    recent_email_analyses: list[dict[str, Any]] = []
    most_active_email_users: list[dict[str, Any]] = []

    if _table_exists(db, "email_analyses"):
        email_rows = [
            dict(row)
            for row in db.execute(
                text(
                    """
                    SELECT
                        id,
                        user_id,
                        user_email,
                        user_full_name,
                        subject_preview,
                        sender_preview,
                        verdict,
                        confidence,
                        evidence_strength,
                        summary,
                        links_count,
                        attachments_count,
                        headers_provided,
                        analyzer_version,
                        created_at
                    FROM email_analyses
                    ORDER BY created_at DESC, id DESC
                    """
                )
            ).mappings().all()
        ]

        total_email_analyses = len(email_rows)
        email_user_activity: dict[str, dict[str, Any]] = {}

        for row in email_rows:
            verdict = str(row.get("verdict") or "Unknown").strip() or "Unknown"
            verdict_lower = verdict.lower()
            confidence = str(row.get("confidence") or "").strip().lower()

            _increase(email_verdict_distribution, verdict)

            is_safe = "safe" in verdict_lower or "no obvious threat" in verdict_lower
            if not is_safe:
                suspicious_email_count += 1

            if confidence == "high":
                high_confidence_email_count += 1

            try:
                email_links_reviewed += int(row.get("links_count") or 0)
            except (TypeError, ValueError):
                pass

            try:
                email_attachments_reviewed += int(row.get("attachments_count") or 0)
            except (TypeError, ValueError):
                pass

            if bool(row.get("headers_provided")):
                email_headers_provided += 1

            user_key = str(
                row.get("user_id")
                or row.get("user_email")
                or "unknown"
            )

            if user_key not in email_user_activity:
                email_user_activity[user_key] = {
                    "id": row.get("user_id"),
                    "email": row.get("user_email"),
                    "full_name": row.get("user_full_name"),
                    "email_analysis_count": 0,
                    "total_email_analyses": 0,
                }

            email_user_activity[user_key]["email_analysis_count"] += 1
            email_user_activity[user_key]["total_email_analyses"] += 1

        for row in email_rows[:10]:
            recent_email_analyses.append(
                {
                    "id": row.get("id"),
                    "user_id": row.get("user_id"),
                    "user_email": row.get("user_email"),
                    "user_full_name": row.get("user_full_name"),
                    "subject_preview": row.get("subject_preview"),
                    "sender_preview": row.get("sender_preview"),
                    "verdict": row.get("verdict"),
                    "confidence": row.get("confidence"),
                    "evidence_strength": row.get("evidence_strength"),
                    "summary": row.get("summary"),
                    "links_count": row.get("links_count"),
                    "attachments_count": row.get("attachments_count"),
                    "headers_provided": bool(row.get("headers_provided")),
                    "analyzer_version": row.get("analyzer_version"),
                    "created_at": row.get("created_at"),
                }
            )

        most_active_email_users = sorted(
            email_user_activity.values(),
            key=lambda item: int(item.get("email_analysis_count") or 0),
            reverse=True,
        )[:8]

    # === SecureSight360 Admin Email Oversight Metrics END ===

    return {
        "total_users": total_users,
        "active_users": active_users,
        "inactive_users": inactive_users,
        "total_admins": total_admins,
        "active_admins": active_admins,
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "failed_scans": failed_scans,
        "average_security_score": average_security_score,
        "high_critical_risk_scan_count": high_critical_risk_scan_count,
        "high_risk_scans": high_critical_risk_scan_count,
        "security_rating_distribution": rating_distribution,
        "rating_distribution": rating_distribution,
        "risk_level_distribution": risk_level_distribution,
        "scan_status_distribution": scan_status_distribution,
        "status_distribution": scan_status_distribution,
        "recent_scans": recent_scans,
        "riskiest_targets": riskiest_targets,
        "most_active_users": most_active_users,
        "top_users_by_scans": most_active_users,
        "total_email_analyses": total_email_analyses,
        "suspicious_email_count": suspicious_email_count,
        "high_confidence_email_count": high_confidence_email_count,
        "email_links_reviewed": email_links_reviewed,
        "email_attachments_reviewed": email_attachments_reviewed,
        "email_headers_provided": email_headers_provided,
        "email_verdict_distribution": email_verdict_distribution,
        "recent_email_analyses": recent_email_analyses,
        "most_active_email_users": most_active_email_users,
        "summary": {
            "total_users": total_users,
            "active_users": active_users,
            "inactive_users": inactive_users,
            "total_admins": total_admins,
            "active_admins": active_admins,
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "failed_scans": failed_scans,
            "average_security_score": average_security_score,
            "high_risk_scans": high_critical_risk_scan_count,
            "high_critical_risk_scan_count": high_critical_risk_scan_count,
            "total_email_analyses": total_email_analyses,
            "suspicious_email_count": suspicious_email_count,
            "high_confidence_email_count": high_confidence_email_count,
            "email_links_reviewed": email_links_reviewed,
            "email_attachments_reviewed": email_attachments_reviewed,
        },
        "distributions": {
            "security_ratings": rating_distribution,
            "risk_levels": risk_level_distribution,
            "scan_status": scan_status_distribution,
            "email_verdicts": email_verdict_distribution,
        },
    }

def _scan_count_for_user(db: Session, user_id: int, email: str) -> int:
    if not _table_exists(db, "scans"):
        return 0

    columns = _table_columns(db, "scans")
    clauses: list[str] = []
    params: dict[str, Any] = {"user_id": user_id, "email": email}

    if "user_id" in columns:
        clauses.append("user_id = :user_id")

    if "user_email" in columns:
        clauses.append("LOWER(user_email) = LOWER(:email)")

    if not clauses:
        return 0

    row = db.execute(
        text(f"SELECT COUNT(*) AS total FROM scans WHERE {' OR '.join(clauses)}"),
        params,
    ).mappings().first()

    return int(row["total"] or 0) if row else 0


@router.delete(
    "/users/{user_id}",
    response_model=dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Safely delete a user account",
)
def delete_admin_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: AuthenticatedUser = Depends(require_admin_user),
) -> dict[str, Any]:
    ensure_auth_tables(db)

    target_user = _get_user_row_by_id(db, user_id)

    if int(target_user["id"]) == int(current_admin.id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Admins cannot delete their own account.",
        )

    target_role = str(target_user["role"] or "").lower()
    target_active = bool(target_user["is_active"])

    if target_role == "admin" and target_active and _count_active_admins(db) <= 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot delete the last active admin account.",
        )

    scan_count = _scan_count_for_user(
        db,
        user_id=int(target_user["id"]),
        email=str(target_user["email"]),
    )

    deleted_email = f"deleted-user-{user_id}@deleted.securesight360.local"

    db.execute(
        text(
            """
            UPDATE users
            SET
                email = :deleted_email,
                full_name = 'Deleted User',
                role = 'user',
                is_active = 0,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = :user_id
            """
        ),
        {
            "deleted_email": deleted_email,
            "user_id": user_id,
        },
    )
    db.commit()

    try:
        write_audit_log(
            db=db,
            event_type="admin_user_deleted",
            actor_email=current_admin.email,
            target_email=str(target_user["email"]),
            details=json.dumps(
                {
                    "target_user_id": user_id,
                    "retained_scan_records": scan_count,
                    "method": "soft_delete_anonymize_user_account",
                    "client_host": request.client.host if request.client else None,
                }
            ),
        )
    except Exception:
        # Audit logging must never break admin account safety operations.
        pass

    return {
        "message": "User account deleted safely. Historical scan records were retained for audit integrity.",
        "deleted_user_id": user_id,
        "retained_scan_records": scan_count,
    }

# === SecureSight360 Admin Email Analyses API START ===

@router.get(
    "/email-analyses",
    response_model=list[dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="List all email analyses for admin oversight",
)
def list_admin_email_analyses(
    limit: int = 200,
    db: Session = Depends(get_db),
    _: AuthenticatedUser = Depends(require_admin_user),
) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 500))

    if not _table_exists(db, "email_analyses"):
        return []

    rows = db.execute(
        text(
            """
            SELECT
                id,
                user_id,
                user_email,
                user_full_name,
                subject_preview,
                sender_preview,
                verdict,
                confidence,
                evidence_strength,
                summary,
                links_count,
                attachments_count,
                headers_provided,
                analyzer_version,
                created_at
            FROM email_analyses
            ORDER BY created_at DESC, id DESC
            LIMIT :limit
            """
        ),
        {"limit": safe_limit},
    ).mappings().all()

    return [
        {
            "id": row["id"],
            "user_id": row["user_id"],
            "user_email": row["user_email"],
            "user_full_name": row["user_full_name"],
            "subject_preview": row["subject_preview"],
            "sender_preview": row["sender_preview"],
            "verdict": row["verdict"],
            "confidence": row["confidence"],
            "evidence_strength": row["evidence_strength"],
            "summary": row["summary"],
            "links_count": int(row["links_count"] or 0),
            "attachments_count": int(row["attachments_count"] or 0),
            "headers_provided": bool(row["headers_provided"]),
            "analyzer_version": row["analyzer_version"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]

# === SecureSight360 Admin Email Analyses API END ===

