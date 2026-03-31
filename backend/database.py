# ---------------------------------------------------------------------------
# database.py
# Sets up the SQLAlchemy database connection.
# Exports `engine`, `Base`, and `get_db` for use across the app.
# ---------------------------------------------------------------------------

from sqlalchemy import create_engine
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
