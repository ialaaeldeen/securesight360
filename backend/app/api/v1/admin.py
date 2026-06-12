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