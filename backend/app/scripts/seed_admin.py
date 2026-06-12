"""
Idempotent seeder for the SecureSight360 admin account.

Usage (from backend/ directory):
    python -m app.scripts.seed_admin

Credentials are read from env vars (or backend/.env):
    SECURESIGHT360_ADMIN_EMAIL     (default: allouah30@outlook.com)
    SECURESIGHT360_ADMIN_PASSWORD  (required)
"""
from __future__ import annotations

import sys

from app.database.session import SessionLocal
from app.core.admin_auth import (
    _get_admin_email,
    get_user_by_email,
    seed_admin_user,
)


def main() -> int:
    db = SessionLocal()
    try:
        email = _get_admin_email()

        existed_before = get_user_by_email(db, email) is not None

        # Idempotent: creates the admin if missing, otherwise resets password
        # + ensures role='admin' and is_active=1.
        seed_admin_user(db)

        user = get_user_by_email(db, email)
        if user is None:
            print("[seed_admin] ERROR: admin user not found after seeding.", file=sys.stderr)
            return 1

        action = "Updated existing" if existed_before else "Created"
        print(f"[seed_admin] {action} admin user id={user['id']} email={user['email']} role={user['role']}")
        print(f"[seed_admin] Admin login email: {email}")
        if not existed_before:
            print("[seed_admin] Admin user created. Keep the password stored securely in backend/.env.")
        return 0
    except Exception as exc:
        db.rollback()
        print(f"[seed_admin] ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
