from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter

from app.core.config import settings

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("")
def health_check() -> dict[str, Any]:
    """
    Return the basic health status of the SecureSight360 backend.
    """

    return {
        "status": "healthy",
        "service": "SecureSight360 Backend",
        "environment": _get_environment(),
        "message": "SecureSight360 Backend is healthy.",
        "timestamp": datetime.now(UTC).isoformat(),
    }


@router.get("/")
def health_check_with_slash() -> dict[str, Any]:
    """
    Support both /health and /health/.
    """

    return health_check()


@router.get("/readiness")
def readiness_check() -> dict[str, Any]:
    """
    Return the readiness status of the SecureSight360 backend.
    """

    return {
        "status": "ready",
        "ready": True,
        "service": "SecureSight360 Backend",
        "environment": _get_environment(),
        "message": "API is ready to receive requests",
        "timestamp": datetime.now(UTC).isoformat(),
        "checks": {
            "api": "ready",
            "database": "not_configured",
            "cache": "not_configured",
            "external_services": "not_configured",
        },
    }


def _get_environment() -> str:
    """
    Resolve the current application environment safely.
    """

    environment = (
        getattr(settings, "ENVIRONMENT", None)
        or getattr(settings, "APP_ENV", None)
        or getattr(settings, "ENV", None)
        or "development"
    )

    return str(environment)