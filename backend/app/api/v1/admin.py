from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.admin_auth import (
    AuthenticatedUser,
    ensure_auth_tables,
    require_admin_user,
)
from app.database.session import get_db

router = APIRouter(prefix="/admin", tags=["Admin"])


def _table_exists(db: Session, table_name: str) -> bool:
    row = db.execute(
        text(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = :table_name
            LIMIT 1
            """
        ),
        {"table_name": table_name},
    ).first()

    return row is not None


def _table_columns(db: Session, table_name: str) -> set[str]:
    if not _table_exists(db, table_name):
        return set()

    rows = db.execute(text(f"PRAGMA table_info({table_name})")).mappings().all()
    return {str(row["name"]) for row in rows}


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