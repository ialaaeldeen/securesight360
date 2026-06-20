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


def _initialize_database_on_startup() -> None:
    """
    Initialize database tables at application startup.

    For the current MVP deployment this keeps Render + Neon PostgreSQL
    ready without manual database setup. Later, this can be replaced by
    Alembic migrations as the production schema process.
    """
    from app.database.init_db import init_db

    init_db()


def _seed_admin_user_on_startup() -> None:
    """
    Ensure the configured admin user exists.

    In production, missing admin credentials should fail startup so the
    deployment is not left without an admin account. In development, the
    app should still start even if local admin env values are not set.
    """
    logger = logging.getLogger(__name__)

    try:
        from app.core.admin_auth import seed_admin_user
        from app.database.session import SessionLocal

        with SessionLocal() as db:
            seed_admin_user(db)

        logger.info("Admin user seed check completed.")

    except RuntimeError as error:
        if settings.APP_ENV == "production":
            logger.exception("Admin user seed failed in production.")
            raise

        logger.warning("Admin user seed skipped in non-production: %s", error)


def _warm_up_email_ml_classifier_on_startup() -> None:
    """
    Warm up the local email ML classifier in the background.

    ML warmup must never block or break API startup.
    """
    import threading

    def _worker() -> None:
        try:
            from app.services.email_ml_classifier import warm_up_email_ml_classifier

            warm_up_email_ml_classifier()
        except Exception:
            logging.getLogger(__name__).debug(
                "Email ML classifier warmup failed; continuing startup.",
                exc_info=True,
            )

    threading.Thread(
        target=_worker,
        name="securesight360-email-ml-warmup",
        daemon=True,
    ).start()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup and shutdown lifecycle.
    """
    configure_logging()

    logger = logging.getLogger(__name__)
    logger.info("%s backend starting", settings.PROJECT_NAME)

    _initialize_database_on_startup()
    _seed_admin_user_on_startup()
    _warm_up_email_ml_classifier_on_startup()

    logger.info("%s backend started", settings.PROJECT_NAME)

    yield

    logger.info("%s backend stopped", settings.PROJECT_NAME)


def create_app() -> FastAPI:
    """
    Create and configure the SecureSight360 FastAPI application.
    """

    app = FastAPI(
        title=f"{settings.PROJECT_NAME} API",
        description=(
            "SecureSight360 backend API for authorized website security scanning, "
            "network assessment, risk scoring, SOC-style dashboards, and reporting."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url=f"{settings.API_PREFIX}/openapi.json",
        lifespan=lifespan,
    )

    configured_cors_origins = settings.CORS_ORIGINS

    if isinstance(configured_cors_origins, str):
        cors_origins = [
            origin.strip()
            for origin in configured_cors_origins.split(",")
            if origin.strip()
        ]
    else:
        cors_origins = list(configured_cors_origins)

    cors_origins.extend(
        [
            # Production frontend/API domains
            "https://securesight360.com",
            "https://www.securesight360.com",
            "https://api.securesight360.com",

            # Local development frontend origins
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://192.168.0.101:8080",
        ]
    )

    cors_origins = list(dict.fromkeys(cors_origins))

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
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
        "message": "SecureSight360 API is running",
        "status": "online",
        "environment": settings.APP_ENV,
        "version": "1.0.0",
        "docs": "/docs",
    }
