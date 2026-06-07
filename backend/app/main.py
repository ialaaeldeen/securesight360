import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.api import api_router
from app.core.config import settings


def configure_logging() -> None:
    """
    Configure backend logging for development and future production use.
    """
    logging.basicConfig(
        level=settings.LOG_LEVEL,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup and shutdown lifecycle.

    Later we can use this for:
    - Database initialization
    - Background scan worker setup
    - Report directory creation
    - Security audit logging
    """
    configure_logging()
    logging.getLogger(__name__).info("%s backend started", settings.PROJECT_NAME)

    yield

    logging.getLogger(__name__).info("%s backend stopped", settings.PROJECT_NAME)


def create_app() -> FastAPI:
    """
    Create and configure the CyberShield360 FastAPI application.
    """

    app = FastAPI(
        title=f"{settings.PROJECT_NAME} API",
        description=(
            "CyberShield360 backend API for authorized website security scanning, "
            "network assessment, risk scoring, SOC-style dashboards, and reporting."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url=f"{settings.API_PREFIX}/openapi.json",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    app.include_router(api_router, prefix=settings.API_PREFIX)

    return app


app = create_app()


@app.get("/", tags=["Root"])
def root():
    """
    Root endpoint to confirm that the API is running.
    """
    return {
        "project": settings.PROJECT_NAME,
        "message": "CyberShield360 API is running",
        "status": "online",
        "environment": settings.APP_ENV,
        "version": "1.0.0",
        "docs": "/docs",
    }
    