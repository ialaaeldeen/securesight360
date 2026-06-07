from datetime import datetime, timezone

from fastapi import APIRouter

from app.core.config import settings

router = APIRouter()


@router.get("/")
def health_check():
    """
    Health check endpoint.

    Used to confirm that the CyberShield360 backend is running correctly.
    This endpoint can also be used later by Docker, monitoring tools,
    or deployment platforms.
    """
    return {
        "service": f"{settings.PROJECT_NAME} Backend",
        "status": "healthy",
        "environment": settings.APP_ENV,
        "debug": settings.DEBUG,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/readiness")
def readiness_check():
    """
    Readiness check endpoint.

    Used to confirm that the API is ready to receive requests.
    Later, we can extend this to check:
    - Database connection
    - Scanner availability
    - Report directory access
    """
    return {
        "service": f"{settings.PROJECT_NAME} Backend",
        "ready": True,
        "message": "API is ready to receive requests",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }