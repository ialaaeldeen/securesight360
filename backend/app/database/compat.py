from __future__ import annotations

import re
from typing import Any

from sqlalchemy import inspect, text
from sqlalchemy.orm import Session


_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _validate_identifier(value: str) -> str:
    """
    Validate table/column identifiers used in internal SQL helpers.

    Values are developer-controlled, but validation prevents accidental
    unsafe dynamic SQL if a helper is reused later.
    """
    if not _SAFE_IDENTIFIER.match(value):
        raise ValueError(f"Unsafe SQL identifier: {value!r}")

    return value


def database_dialect_name(db: Session) -> str:
    return str(db.get_bind().dialect.name).lower()


def is_sqlite_database(db: Session) -> bool:
    return database_dialect_name(db).startswith("sqlite")


def is_postgresql_database(db: Session) -> bool:
    return database_dialect_name(db).startswith("postgresql")


def id_primary_key_sql(db: Session) -> str:
    """
    Return a portable auto-incrementing primary key definition.

    SQLite:
        INTEGER PRIMARY KEY AUTOINCREMENT

    PostgreSQL:
        SERIAL PRIMARY KEY
    """
    if is_postgresql_database(db):
        return "SERIAL PRIMARY KEY"

    return "INTEGER PRIMARY KEY AUTOINCREMENT"


def timestamp_type_sql(db: Session) -> str:
    """
    SQLite accepts DATETIME.
    PostgreSQL should use TIMESTAMP.
    """
    if is_postgresql_database(db):
        return "TIMESTAMP"

    return "DATETIME"


def boolean_default_sql(db: Session, value: bool) -> str:
    if is_postgresql_database(db):
        return "TRUE" if value else "FALSE"

    return "1" if value else "0"


def table_exists(db: Session, table_name: str) -> bool:
    table_name = _validate_identifier(table_name)

    # Use the active Session connection instead of the Engine.
    # This is important for PostgreSQL because DDL is transactional, and
    # an Engine-level inspector may not see tables created in the current
    # uncommitted session.
    return bool(inspect(db.connection()).has_table(table_name))


def table_columns(db: Session, table_name: str) -> set[str]:
    table_name = _validate_identifier(table_name)

    if not table_exists(db, table_name):
        return set()

    # Same reason as table_exists(): inspect the active transaction/connection.
    return {str(column["name"]) for column in inspect(db.connection()).get_columns(table_name)}


def insert_returning_id(
    db: Session,
    sql: str,
    params: dict[str, Any],
) -> int:
    """
    Execute an INSERT and return the created row id.

    PostgreSQL supports RETURNING id.
    SQLite uses last_insert_rowid().
    """
    cleaned_sql = sql.strip().rstrip(";")

    if is_postgresql_database(db):
        row_id = db.execute(text(f"{cleaned_sql} RETURNING id"), params).scalar_one()
        return int(row_id)

    db.execute(text(cleaned_sql), params)
    row_id = db.execute(text("SELECT last_insert_rowid()")).scalar_one()
    return int(row_id)
