import logging

from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.database.base import Base
from app.database.session import engine

# Import all models so SQLAlchemy registers them before creating tables.
import app.models  # noqa: F401


logger = logging.getLogger(__name__)


def init_db() -> None:
    """
    Initialize the SecureSight360 database.

    This creates all database tables defined in SQLAlchemy models.

    For development:
        Used to quickly create SQLite tables.

    For production later:
        Alembic migrations should be used instead of direct table creation.
    """

    try:
        logger.info("Initializing database: %s", settings.DATABASE_URL)
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized successfully.")

    except SQLAlchemyError as error:
        logger.exception("Database initialization failed.")
        raise RuntimeError("Failed to initialize database.") from error


if __name__ == "__main__":
    logging.basicConfig(
        level=settings.LOG_LEVEL,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

    init_db()