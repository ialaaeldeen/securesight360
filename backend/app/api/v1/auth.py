from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.admin_auth import (
    DEFAULT_TOKEN_EXPIRE_SECONDS,
    AuthenticatedUser,
    authenticate_user,
    create_access_token,
    ensure_auth_tables,
    get_user_by_email,
    hash_password,
    require_authenticated_user,
    seed_admin_user,
)
from app.database.session import get_db

router = APIRouter(prefix="/auth", tags=["Authentication"])


EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PASSWORD_SPECIAL_PATTERN = re.compile(r"[^A-Za-z0-9]")

COMMON_WEAK_PASSWORDS = {
    "password",
    "password1",
    "password12",
    "password123",
    "password1234",
    "admin",
    "admin123",
    "admin1234",
    "qwerty",
    "qwerty123",
    "welcome",
    "welcome123",
    "letmein",
    "secure123",
    "changeme",
}

MAX_FAILED_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15

_LOGIN_FAILURES: dict[str, dict[str, object]] = {}


def _login_key(email: str) -> str:
    return _normalize_email(email)


def _get_login_lockout_until(email: str) -> datetime | None:
    record = _LOGIN_FAILURES.get(_login_key(email))

    if not record:
        return None

    lockout_until = record.get("lockout_until")

    if not isinstance(lockout_until, datetime):
        return None

    if lockout_until <= datetime.now(timezone.utc):
        _LOGIN_FAILURES.pop(_login_key(email), None)
        return None

    return lockout_until


def _raise_invalid_login() -> None:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password.",
    )


def _check_login_throttle(email: str) -> None:
    lockout_until = _get_login_lockout_until(email)

    if lockout_until is None:
        return

    retry_after_seconds = max(
        1,
        int((lockout_until - datetime.now(timezone.utc)).total_seconds()),
    )

    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many failed login attempts. Please try again later.",
        headers={"Retry-After": str(retry_after_seconds)},
    )


def _record_failed_login(email: str) -> None:
    key = _login_key(email)
    now = datetime.now(timezone.utc)
    record = _LOGIN_FAILURES.get(key, {"count": 0, "lockout_until": None})

    failed_count = int(record.get("count", 0)) + 1

    if failed_count >= MAX_FAILED_LOGIN_ATTEMPTS:
        _LOGIN_FAILURES[key] = {
            "count": failed_count,
            "lockout_until": now + timedelta(minutes=LOGIN_LOCKOUT_MINUTES),
        }
        return

    _LOGIN_FAILURES[key] = {
        "count": failed_count,
        "lockout_until": None,
    }


def _clear_failed_logins(email: str) -> None:
    _LOGIN_FAILURES.pop(_login_key(email), None)

PERSONAL_EMAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "yahoo.co.uk",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "mail.com",
    "zoho.com",
    "yandex.com",
    "gmx.com",
}


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, description="Account email address.")
    password: str = Field(..., min_length=1, description="Account password.")


class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=3, description="Account email address.")
    password: str = Field(..., min_length=8, description="Account password.")
    full_name: str | None = Field(default=None, max_length=255)
    company_name: str | None = Field(default=None, max_length=255)


class UserResponse(BaseModel):
    id: int
    email: str
    role: str
    full_name: str | None = None


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(sep=" ")


def _validate_email(email: str) -> str:
    normalized = _normalize_email(email)

    if not EMAIL_PATTERN.match(normalized):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Please enter a valid email address.",
        )

    return normalized


def _email_domain(email: str) -> str:
    return email.rsplit("@", 1)[-1].strip().lower()


def _validate_business_email(email: str) -> str:
    domain = _email_domain(email)

    if domain in PERSONAL_EMAIL_DOMAINS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Please use your company/work email address. "
                "Personal email providers such as Gmail, Yahoo, Outlook, and Hotmail are not allowed."
            ),
        )

    return email


def _validate_password(password: str) -> str:
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must be at least 8 characters.",
        )

    lowered_password = password.lower()

    if lowered_password in COMMON_WEAK_PASSWORDS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password is too common. Please choose a stronger password.",
        )

    if not any(character.islower() for character in password):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must include at least one lowercase letter.",
        )

    if not any(character.isupper() for character in password):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must include at least one uppercase letter.",
        )

    if PASSWORD_SPECIAL_PATTERN.search(password) is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must include at least one special character.",
        )

    return password

def _safe_name(value: str | None) -> str | None:
    if value is None:
        return None

    clean = value.strip()

    if not clean:
        return None

    return clean[:255]


def _create_normal_user(
    db: Session,
    *,
    email: str,
    password: str,
    full_name: str | None,
) -> AuthenticatedUser:
    ensure_auth_tables(db)

    existing = get_user_by_email(db, email)

    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    now = _utc_now_iso()
    password_hash = hash_password(password)

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
                'user',
                1,
                :created_at,
                :updated_at
            )
            """
        ),
        {
            "email": email,
            "password_hash": password_hash,
            "full_name": full_name,
            "created_at": now,
            "updated_at": now,
        },
    )
    db.commit()

    user = get_user_by_email(db, email)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User registration failed.",
        )

    return AuthenticatedUser(
        id=int(user["id"]),
        email=str(user["email"]),
        role=str(user["role"]).lower(),
        full_name=user.get("full_name"),
    )


def _login_response_for_user(user: AuthenticatedUser) -> LoginResponse:
    token = create_access_token(
        user_id=user.id,
        email=user.email,
        role=user.role,
        expires_in_seconds=DEFAULT_TOKEN_EXPIRE_SECONDS,
    )

    return LoginResponse(
        access_token=token,
        expires_in=DEFAULT_TOKEN_EXPIRE_SECONDS,
        user=UserResponse(**user.to_dict()),
    )


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Login with a database user account",
)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    email = _validate_email(payload.email)

    _check_login_throttle(email)

    user = authenticate_user(db=db, email=email, password=payload.password)

    if user is None:
        _record_failed_login(email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    _clear_failed_logins(email)

    return _login_response_for_user(user)


@router.post(
    "/register",
    response_model=LoginResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a normal user account",
)
def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> LoginResponse:
    email = _validate_business_email(_validate_email(payload.email))
    password = _validate_password(payload.password)

    full_name = _safe_name(payload.full_name)

    user = _create_normal_user(
        db,
        email=email,
        password=password,
        full_name=full_name,
    )

    return _login_response_for_user(user)


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current authenticated user",
)
def get_current_user_profile(
    current_user: AuthenticatedUser = Depends(require_authenticated_user),
) -> UserResponse:
    return UserResponse(**current_user.to_dict())


@router.post(
    "/seed-admin",
    response_model=dict[str, str],
    status_code=status.HTTP_200_OK,
    summary="Create or update local admin account",
)
def seed_local_admin(db: Session = Depends(get_db)) -> dict[str, str]:
    seed_admin_user(db)

    return {
        "status": "success",
        "message": "Admin user is available in the database.",
    }