# ---------------------------------------------------------------------------
# database.py
# Sets up the SQLAlchemy database connection.
# Exports `engine`, `Base`, and `get_db` for use across the app.
# ---------------------------------------------------------------------------

from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import os

# Load environment variables from the .env file
load_dotenv()

# Read the database connection string from the environment
# Example: postgresql://user:password@localhost:5432/mydb
DATABASE_URL = os.getenv("DATABASE_URL")

# Create the SQLAlchemy engine (the core connection to the database)
engine = create_engine(DATABASE_URL)

# SessionLocal is a factory for creating new database sessions
# autocommit=False -> changes are not saved until we explicitly call db.commit()
# autoflush=False  -> changes are not sent to the DB until commit or an explicit flush
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class that all ORM models will inherit from
Base = declarative_base()


# ---------------------------------------------------------------------------
# Columns added after the initial release. Base.metadata.create_all() only
# creates missing *tables*, never missing columns, so an existing database
# would keep the old shape and every query touching a new column would fail.
# These statements are idempotent — running them on a fresh database is a no-op.
# ---------------------------------------------------------------------------
SCHEMA_UPDATES = [
    "ALTER TABLE uploads ADD COLUMN IF NOT EXISTS stage VARCHAR",
    "ALTER TABLE uploads ADD COLUMN IF NOT EXISTS error_message TEXT",
    "ALTER TABLE analysis_results ADD COLUMN IF NOT EXISTS risk_level VARCHAR",
    "ALTER TABLE analysis_results ADD COLUMN IF NOT EXISTS recommendations JSONB",
    "ALTER TABLE analysis_results ADD COLUMN IF NOT EXISTS detections JSONB",
]


def ensure_schema() -> None:
    """
    Brings an existing database up to date with the current models.

    Called once on startup, after create_all(). A real deployment would use
    Alembic migrations; this keeps a local dev database working across an
    upgrade without asking anyone to drop their Postgres volume.
    """
    with engine.begin() as conn:
        for statement in SCHEMA_UPDATES:
            conn.execute(text(statement))


def get_db():
    """
    FastAPI dependency that provides a database session to route handlers.

    Opens a new session, yields it for use, then closes it when the
    request is finished — even if an error occurred.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
