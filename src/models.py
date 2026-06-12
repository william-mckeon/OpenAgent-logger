"""
SQLAlchemy ORM models for openagent-logger.

Three append-only, monthly-partitioned tables in the openagent_logger schema:
    - ops_events           : short retention (~90 days)
    - conversation_captures: medium retention (~180 days)
    - audit_events         : long retention (~7 years)

All tables share a common envelope mixin (request_id, source_service,
timestamps, session_id, user_id, hmac_signature, retention_class) so the
envelope shape is defined once and reused.

Partitioning is declared in SQL (database/init.sql) and maintained at
runtime by src/partitioning.py + src/scheduler.py. The SQLAlchemy models
describe the row shape only; they do not create or drop partitions.

There are intentionally NO foreign keys to other schemas. Cross-schema FKs
would couple services that should stay independent; any session_id
correlation is maintained by convention.
"""

import logging
import os
import uuid
from datetime import datetime
from typing import Optional
from urllib.parse import quote

from sqlalchemy import (
    DateTime,
    Index,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    sessionmaker,
)

logger = logging.getLogger("openagent.logger.models")


# ---------------------------------------------------------------------
# Database URL resolution
# ---------------------------------------------------------------------

def _build_database_url() -> str:
    """
    Resolve the PostgreSQL connection URL from environment.

    Preference order:
        1. LOGGER_DATABASE_URL  (full URL, used as-is - Render style)
        2. Component env vars   (LOGGER_DB_USER, _PASSWORD, _HOST, _PORT, _NAME)

    The full-URL path matches managed-Postgres conventions (Render injects
    DATABASE_URL automatically when a service is bound to a DB). The
    component-style fallback lets local Docker Compose deployments assemble
    the URL from individual env vars without forcing a full URL.

    Returns:
        str: A complete PostgreSQL connection URL.

    Raises:
        RuntimeError: If neither LOGGER_DATABASE_URL nor LOGGER_DB_PASSWORD
                      is set. (We refuse to fall back to an empty password.)
    """
    full_url = os.environ.get("LOGGER_DATABASE_URL", "").strip()
    if full_url:
        return full_url

    user = os.environ.get("LOGGER_DB_USER", "openagent_logger")
    password = os.environ.get("LOGGER_DB_PASSWORD", "").strip()
    host = os.environ.get("LOGGER_DB_HOST", "openagent-shared-db")
    port = os.environ.get("LOGGER_DB_PORT", "5432")
    name = os.environ.get("LOGGER_DB_NAME", "openagent_shared")

    if not password:
        raise RuntimeError(
            "Database is not configured. Set LOGGER_DATABASE_URL (full URL) "
            "or LOGGER_DB_PASSWORD plus the component env vars."
        )

    # URL-encode the credentials so characters that are reserved in a URL
    # (e.g. '@', ':', '/', '?', '#') in a password or username do not corrupt
    # the connection URL. safe='' encodes everything, including '/'.
    user_enc = quote(user, safe="")
    password_enc = quote(password, safe="")

    return f"postgresql://{user_enc}:{password_enc}@{host}:{port}/{name}"


DATABASE_URL: str = _build_database_url()

# Schema name for the logger's tables. Defaults to "openagent_logger" so the
# shared database can host another service's tables in a separate schema
# without colliding.
SCHEMA_NAME: str = os.environ.get("LOGGER_DB_SCHEMA", "openagent_logger")


# ---------------------------------------------------------------------
# Engine and session factory
# ---------------------------------------------------------------------

engine = create_engine(
    DATABASE_URL,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,
    pool_recycle=300,
    echo=os.environ.get("LOGGER_SQL_ECHO", "false").lower() == "true",
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


# ---------------------------------------------------------------------
# Declarative base + shared envelope mixin
# ---------------------------------------------------------------------

class Base(DeclarativeBase):
    """Declarative base for every openagent-logger model."""


class EnvelopeMixin:
    """
    Envelope columns present on every event table.

    Mixed into each table class so the envelope shape is defined once
    and stays consistent across event types.
    """

    event_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Server-assigned unique event identifier.",
    )

    request_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="Correlates events emitted from one /chat call.",
    )

    source_service: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        comment="Identifier of the emitting service (e.g., 'openagent-api').",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Server-side ingestion timestamp. Used as partition key.",
    )

    client_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Emitter-side timestamp. Used for replay-window verification.",
    )

    session_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        comment=(
            "Caller-supplied session correlation. Nullable; never validated - "
            "see README."
        ),
    )

    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True,
        index=True,
        comment="Reserved per-user identifier. Nullable; null in the reference stack.",
    )

    hmac_signature: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="HMAC-SHA256 stored for later integrity re-verification.",
    )

    retention_class: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="short",
        comment="Retention policy class (short, medium, long).",
    )


# ---------------------------------------------------------------------
# Table: ops_events
# ---------------------------------------------------------------------

class OpsEvent(Base, EnvelopeMixin):
    """
    Operational telemetry event.

    High-volume, short retention (~90 days). Examples:
        request_received, request_completed, auth_failure, auth_success,
        upstream_call, upstream_error, client_disconnect, stream_complete.

    Used for short-window operational debugging only.
    """

    __tablename__ = "ops_events"
    __table_args__ = (
        Index("ix_ops_events_session_created", "session_id", "created_at"),
        Index("ix_ops_events_service_created", "source_service", "created_at"),
        Index("ix_ops_events_action_created", "action", "created_at"),
        {
            "schema": SCHEMA_NAME,
            "comment": "Short-retention operational telemetry (monthly partitions).",
            # Inform SQLAlchemy of the partitioning strategy. Actual partition
            # tables are created by database/init.sql + src/partitioning.py.
            "postgresql_partition_by": "RANGE (created_at)",
        },
    )

    action: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="What happened (e.g., 'request_received').",
    )

    outcome: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Result of the action (e.g., 'success', 'failure').",
    )

    details: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Free-form structured context.",
    )

    def __repr__(self) -> str:
        return (
            f"<OpsEvent(event_id={self.event_id}, action='{self.action}', "
            f"outcome='{self.outcome}', created_at={self.created_at})>"
        )


# ---------------------------------------------------------------------
# Table: conversation_captures
# ---------------------------------------------------------------------

class ConversationCapture(Base, EnvelopeMixin):
    """
    Full conversation capture for one /chat call.

    Moderate volume (one row per /chat call), longer retention (~180 days).
    Stored for observability and audit; the schema is model-agnostic.
    """

    __tablename__ = "conversation_captures"
    __table_args__ = (
        Index("ix_capture_session_created", "session_id", "created_at"),
        Index("ix_capture_user_created", "user_id", "created_at"),
        Index("ix_capture_input_hash", "input_hash"),
        {
            "schema": SCHEMA_NAME,
            "comment": "Conversation captures (monthly partitions).",
            "postgresql_partition_by": "RANGE (created_at)",
        },
    )

    input_text: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Raw user input for this /chat call.",
    )

    output_text: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Full model response. May be empty on failure.",
    )

    input_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="SHA-256 of input_text. Survives downstream transformations.",
    )

    output_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="SHA-256 of output_text. Survives downstream transformations.",
    )

    model_used: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Model identifier reported by openagent-infra.",
    )

    reasoning_effort: Mapped[Optional[str]] = mapped_column(
        String(16),
        nullable=True,
        comment="Reasoning effort level (low, medium, high) if specified.",
    )

    latency_ms: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="End-to-end latency for the /chat call, milliseconds.",
    )

    input_tokens: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Token count of input_text as reported by the model.",
    )

    output_tokens: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Token count of output_text as reported by the model.",
    )

    def __repr__(self) -> str:
        return (
            f"<ConversationCapture(event_id={self.event_id}, "
            f"session={self.session_id}, model={self.model_used})>"
        )


# ---------------------------------------------------------------------
# Table: audit_events
# ---------------------------------------------------------------------

class AuditEvent(Base, EnvelopeMixin):
    """
    Security-relevant action record.

    Low volume, long retention (~7 years, compliance-driven). Examples:
        key_rotation, secret_changed, admin_endpoint_hit,
        retention_job_run, auth_threshold_crossed.
    """

    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_actor_created", "actor", "created_at"),
        Index("ix_audit_action_created", "action", "created_at"),
        Index("ix_audit_outcome_created", "outcome", "created_at"),
        {
            "schema": SCHEMA_NAME,
            "comment": "Compliance-grade audit log (monthly partitions).",
            "postgresql_partition_by": "RANGE (created_at)",
        },
    )

    actor: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="Who or what initiated the action.",
    )

    action: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="What was attempted (e.g., 'rotate_logger_api_key').",
    )

    target: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="What was acted on (resource id, table name, etc.).",
    )

    outcome: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Result of the action (e.g., 'success', 'failure', 'denied').",
    )

    ip_address: Mapped[Optional[str]] = mapped_column(
        INET,
        nullable=True,
        comment="Source IP for the actor (IPv4 or IPv6).",
    )

    details: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Additional structured context.",
    )

    def __repr__(self) -> str:
        return (
            f"<AuditEvent(event_id={self.event_id}, actor='{self.actor}', "
            f"action='{self.action}', outcome='{self.outcome}')>"
        )


# ---------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------

def get_db():
    """
    FastAPI dependency yielding a transactional database session.

    Usage:
        from fastapi import Depends
        from .models import get_db

        @app.post("/events")
        async def handler(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()