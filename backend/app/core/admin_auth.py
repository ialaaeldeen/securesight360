from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database.session import get_db

security_scheme = HTTPBearer(auto_error=False)

DEFAULT_ADMIN_EMAIL = "allouah30@outlook.com"
DEFAULT_TOKEN_EXPIRE_SECONDS = 60 * 60 * 8


@dataclass(frozen=True)
class AuthenticatedUser:
    id: int
    email: str
    role: str
    full_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "email": self.email,
            "role": self.role,
            "full_name": self.full_name,
        }


def _read_local_env_value(key: str) -> str:
    env_path = Path(__file__).resolve().parents[2] / ".env"

    if not env_path.exists():
        return ""

    for line in env_path.read_text(encoding="utf-8").splitlines():
        clean_line = line.strip()

        if not clean_line or clean_line.startswith("#") or "=" not in clean_line:
            continue

        current_key, current_value = clean_line.split("=", 1)

        if current_key.strip() == key:
            return current_value.strip().strip('"').strip("'")

    return ""


def _get_setting(key: str, default: str = "") -> str:
    return os.getenv(key, "").strip() or _read_local_env_value(key) or default


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(sep=" ")


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _get_auth_secret() -> str:
    secret = _get_setting("SECURESIGHT360_AUTH_SECRET_KEY", "")

    if not secret:
        raise RuntimeError(
            "SECURESIGHT360_AUTH_SECRET_KEY must be set in environment variables or backend/.env."
        )

    return secret

def _get_admin_email() -> str:
    return _normalize_email(
        _get_setting("SECURESIGHT360_ADMIN_EMAIL", DEFAULT_ADMIN_EMAIL)
    )


def _get_admin_password() -> str:
    password = _get_setting("SECURESIGHT360_ADMIN_PASSWORD", "")

    if not password:
        raise RuntimeError(
            "SECURESIGHT360_ADMIN_PASSWORD must be set in environment variables or backend/.env."
        )

    return password


def ensure_auth_tables(db: Session) -> None:
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email VARCHAR(255) NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                full_name VARCHAR(255),
                role VARCHAR(50) NOT NULL DEFAULT 'user',
                is_active BOOLEAN NOT NULL DEFAULT 1,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                last_login_at DATETIME
            )
            """
        )
    )
    db.commit()


def hash_password(password: str) -> str:
    iterations = 260000
    salt = secrets.token_bytes(16)

    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )

    encoded_salt = base64.urlsafe_b64encode(salt).decode("utf-8")
    encoded_key = base64.urlsafe_b64encode(derived_key).decode("utf-8")

    return f"pbkdf2_sha256${iterations}${encoded_salt}${encoded_key}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations_text, encoded_salt, encoded_key = stored_hash.split("$")
    except ValueError:
        return False

    if algorithm != "pbkdf2_sha256":
        return False

    try:
        iterations = int(iterations_text)
        salt = base64.urlsafe_b64decode(encoded_salt.encode("utf-8"))
        expected_key = base64.urlsafe_b64decode(encoded_key.encode("utf-8"))
    except (ValueError, TypeError):
        return False

    actual_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )

    return hmac.compare_digest(actual_key, expected_key)


def seed_admin_user(db: Session) -> None:
    """
    Create/update the local admin account inside the database.

    This is for the current MVP. Later, this can be replaced with a full user
    management page.
    """
    ensure_auth_tables(db)

    admin_email = _get_admin_email()
    admin_password = _get_admin_password()
    now = _utc_now_iso()

    existing = db.execute(
        text(
            """
            SELECT id
            FROM users
            WHERE LOWER(email) = :email
            LIMIT 1
            """
        ),
        {"email": admin_email},
    ).mappings().first()

    password_hash = hash_password(admin_password)

    if existing:
        db.execute(
            text(
                """
                UPDATE users
                SET
                    password_hash = :password_hash,
                    role = 'admin',
                    is_active = 1,
                    full_name = COALESCE(full_name, 'SecureSight360 Admin'),
                    updated_at = :updated_at
                WHERE id = :user_id
                """
            ),
            {
                "password_hash": password_hash,
                "updated_at": now,
                "user_id": existing["id"],
            },
        )
    else:
        db.execute(
            text(
                """
                INSERT INTO users (
                    email,
                    password_hash,
                    full_name,
                    role,
                    is_active,
                    created_at,
                    updated_at
                )
                VALUES (
                    :email,
                    :password_hash,
                    :full_name,
                    'admin',
                    1,
                    :created_at,
                    :updated_at
                )
                """
            ),
            {
                "email": admin_email,
                "password_hash": password_hash,
                "full_name": "SecureSight360 Admin",
                "created_at": now,
                "updated_at": now,
            },
        )

    db.commit()


def get_user_by_email(db: Session, email: str) -> dict[str, Any] | None:
    ensure_auth_tables(db)

    row = db.execute(
        text(
            """
            SELECT id, email, password_hash, full_name, role, is_active
            FROM users
            WHERE LOWER(email) = :email
            LIMIT 1
            """
        ),
        {"email": _normalize_email(email)},
    ).mappings().first()

    return dict(row) if row else None


def get_user_by_id(db: Session, user_id: int) -> dict[str, Any] | None:
    ensure_auth_tables(db)

    row = db.execute(
        text(
            """
            SELECT id, email, full_name, role, is_active
            FROM users
            WHERE id = :user_id
            LIMIT 1
            """
        ),
        {"user_id": user_id},
    ).mappings().first()

    return dict(row) if row else None


def authenticate_user(db: Session, email: str, password: str) -> AuthenticatedUser | None:
    ensure_auth_tables(db)

    user = get_user_by_email(db, email)

    if user is None:
        return None

    if not bool(user.get("is_active")):
        return None

    stored_hash = str(user.get("password_hash", ""))

    if not verify_password(password, stored_hash):
        return None

    db.execute(
        text(
            """
            UPDATE users
            SET last_login_at = :last_login_at
            WHERE id = :user_id
            """
        ),
        {
            "last_login_at": _utc_now_iso(),
            "user_id": user["id"],
        },
    )
    db.commit()

    return AuthenticatedUser(
        id=int(user["id"]),
        email=str(user["email"]),
        role=str(user["role"]).lower(),
        full_name=user.get("full_name"),
    )


def _base64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("utf-8")


def _base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("utf-8"))


def _json_dumps(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def create_access_token(
    *,
    user_id: int,
    email: str,
    role: str,
    expires_in_seconds: int = DEFAULT_TOKEN_EXPIRE_SECONDS,
) -> str:
    issued_at = int(time.time())
    expires_at = issued_at + expires_in_seconds

    header = {
        "alg": "HS256",
        "typ": "JWT",
    }

    payload = {
        "sub": str(user_id),
        "email": email.lower(),
        "role": role.lower(),
        "iat": issued_at,
        "exp": expires_at,
        "iss": "securesight360",
    }

    encoded_header = _base64url_encode(_json_dumps(header))
    encoded_payload = _base64url_encode(_json_dumps(payload))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")

    signature = hmac.new(
        _get_auth_secret().encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest()

    return f"{encoded_header}.{encoded_payload}.{_base64url_encode(signature)}"


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
        ) from exc

    signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
    expected_signature = hmac.new(
        _get_auth_secret().encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest()

    actual_signature = _base64url_decode(encoded_signature)

    if not hmac.compare_digest(expected_signature, actual_signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token signature.",
        )

    try:
        payload = json.loads(_base64url_decode(encoded_payload))
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token payload.",
        ) from exc

    if int(payload.get("exp", 0)) < int(time.time()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired.",
        )

    return payload


def require_authenticated_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
    db: Session = Depends(get_db),
) -> AuthenticatedUser:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication is required.",
        )

    payload = decode_access_token(credentials.credentials)

    try:
        user_id = int(payload.get("sub"))
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token subject.",
        ) from exc

    user = get_user_by_id(db, user_id)

    if user is None or not bool(user.get("is_active")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or no longer exists.",
        )

    return AuthenticatedUser(
        id=int(user["id"]),
        email=str(user["email"]),
        role=str(user["role"]).lower(),
        full_name=user.get("full_name"),
    )


def require_admin_user(
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> AuthenticatedUser:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access is required.",
        )

    return current_user
