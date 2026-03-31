# ---------------------------------------------------------------------------
# models.py
# SQLAlchemy ORM models — defines the shape of each database table.
#
# Three tables:
#   - users           -> registered user accounts
#   - uploads         -> log files uploaded by users
#   - analysis_results -> AI-generated analysis output for each upload
# ---------------------------------------------------------------------------

from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from database import Base
import uuid
import datetime


# ---------------------------------------------------------------------------
# User
# One row per registered account. Passwords are never stored in plain text.
# ---------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)  # auto-generated UUID
    username      = Column(String, unique=True, nullable=False)                        # must be unique across all users
    password_hash = Column(String, nullable=False)                                     # bcrypt hash — never plain text
    created_at    = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))  # set automatically on creation

    # One user can have many uploads (one-to-many)
    uploads = relationship("Upload", back_populates="user")


# ---------------------------------------------------------------------------
# Upload
# One row per log file a user submits. Tracks the file on disk and its
# current processing status through the analysis pipeline.
# ---------------------------------------------------------------------------
class Upload(Base):
    __tablename__ = "uploads"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)  # auto-generated UUID
    user_id     = Column(UUID(as_uuid=True), ForeignKey("users.id"))                # which user uploaded this file
    filename    = Column(String, nullable=False)                                     # original filename from the user
    file_path   = Column(String, nullable=False)                                     # where the file lives on disk
    uploaded_at = Column(DateTime, default=datetime.datetime.utcnow)                 # set automatically on creation
    status      = Column(String, default="pending")                                  # pending | analyzing | done | error

    # Link back to the user who owns this upload (many-to-one)
    user   = relationship("User", back_populates="uploads")

    # Each upload has at most one analysis result
    # uselist=False makes this a scalar (object) instead of a list
    result = relationship("AnalysisResult", back_populates="upload", uselist=False)


# ---------------------------------------------------------------------------
# AnalysisResult
# One row per completed analysis. Stores the full AI output as structured
# JSON so the frontend can render each section independently.
# ---------------------------------------------------------------------------
class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)  # auto-generated UUID
    upload_id        = Column(UUID(as_uuid=True), ForeignKey("uploads.id"))               # which upload this belongs to
    summary          = Column(Text)                                                        # plain English overview from Claude
    timeline         = Column(JSONB)                                                       # list of significant events in order
    anomalies        = Column(JSONB)                                                       # list of suspicious/flagged events
    top_users        = Column(JSONB)                                                       # most active users with risk notes
    threat_breakdown = Column(JSONB)                                                       # counts per threat category
    created_at       = Column(DateTime, default=datetime.datetime.utcnow)                  # set automatically on creation

    # Link back to the upload this result was generated for (many-to-one)
    upload = relationship("Upload", back_populates="result")
