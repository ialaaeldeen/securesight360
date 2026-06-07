from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings


def ensure_sqlite_directory_exists(database_url: str) -> None:
    """
    Ensure the SQLite database folder exists before connecting.

    Example:
        sqlite:///./data/cybershield360.db

    This creates:
        backend/data/
    if it does not already exist.
    """

    if not database_url.startswith("sqlite:///"):
        return

    database_path = database_url.replace("sqlite:///", "", 1)

    if database_path == ":memory:":
        return

    db_file_path = Path(database_path)
    db_directory = db_file_path.parent

    if db_directory and str(db_directory) != ".":
        db_directory.mkdir(parents=True, exist_ok=True)


ensure_sqlite_directory_exists(settings.DATABASE_URL)


engine: Engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False}
    if settings.DATABASE_URL.startswith("sqlite")
    else {},
    pool_pre_ping=True,
)


SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI database dependency.

    This creates a database session for each request,
    then safely closes it after the request is finished.
    """

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()