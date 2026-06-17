from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.admin import router as admin_router
from app.api.v1.auth import router as auth_router
from app.api.v1.email import router as email_router
from app.api.v1.health import router as health_router
from app.api.v1.website import router as website_router

api_router = APIRouter()

api_router.include_router(auth_router)
api_router.include_router(admin_router)
api_router.include_router(health_router)
api_router.include_router(email_router)
api_router.include_router(website_router)
