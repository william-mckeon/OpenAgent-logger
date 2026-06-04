"""
openagent-logger - FastAPI application.

Capture-only HTTP service. Receives signed events from openagent-api (and
any future emitters), validates them, and writes them append-only into
the correct partitioned table.

Endpoints:
    POST /events  - Accept a signed event envelope and persist it.
    GET  /health  - Service + database + scheduler readiness.
    GET  /stats   - Aggregate row counts and timestamp bounds.

All endpoints require X-API-Key. POST /events additionally requires a
valid HMAC signature embedded in the request body.

Lifespan:
    Startup  - validates secrets, probes DB, starts retention scheduler.
    Shutdown - stops the scheduler and closes resources.
"""

import logging
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Tuple, Type

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from . import __version__
from .models import (
    AuditEvent,
    ConversationCapture,
    OpsEvent,
    engine,
    get_db,
)
from .schemas import (
    AuditEventCreate,
    ConversationCaptureCreate,
    ErrorResponse,
    EventCreate,
    EventResponse,
    EventType,
    HealthResponse,
    OpsEventCreate,
    RetentionClass,
    StatsResponse,
)
from .scheduler import (
    get_scheduler,
    initialize_scheduler,
    shutdown_scheduler,
)
from .security import (
    configuration_status,
    require_logger_api_key,
    verify_event,
    warn_if_missing_secrets,
)


# ---------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------

def _setup_logging() -> logging.Logger:
    """
    Configure stdout logging for the service.

    Format matches openagent-infra and openagent-api for cross-service
    correlation when tailing multiple services in parallel.
    """
    level_name = os.environ.get("LOGGER_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger("openagent.logger")
    root.setLevel(level)

    # Avoid duplicate handlers if the module is re-imported under reload.
    if root.handlers:
        return root

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    root.addHandler(handler)
    return root


logger = _setup_logging()

APP_NAME = "openagent-logger"


# ---------------------------------------------------------------------
# Event-type dispatch table
# ---------------------------------------------------------------------

# Maps event_type -> (SQLAlchemy model, retention class).
# Used in create_event() to route a validated event to the correct table.
EVENT_DISPATCH: Dict[EventType, Tuple[Type[Any], RetentionClass]] = {
    EventType.OPS_EVENT: (OpsEvent, RetentionClass.SHORT),
    EventType.CONVERSATION_CAPTURE: (ConversationCapture, RetentionClass.MEDIUM),
    EventType.AUDIT_EVENT: (AuditEvent, RetentionClass.LONG),
}


# ---------------------------------------------------------------------
# Lifespan: startup and shutdown
# ---------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup and shutdown handler for the FastAPI app.

    Startup:
        - Emit secret-configuration warnings (does not fail startup).
        - Probe the database (logs error but does not fail startup;
          /health will report 'unhealthy' for operators to act on).
        - Start the retention scheduler.

    Shutdown:
        - Stop the retention scheduler.
    """
    logger.info("=" * 60)
    logger.info(f"{APP_NAME} v{__version__} starting")
    logger.info("=" * 60)

    warn_if_missing_secrets()
    logger.info(f"Configuration: {configuration_status()}")

    # Probe DB connectivity. We do not raise on failure - allowing /health
    # to report 'unhealthy' is more useful than a crash loop for operators.
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("Database connection: ok")
    except Exception as exc:
        logger.error(f"Database probe failed at startup: {exc}")

    # Start the retention scheduler.
    try:
        initialize_scheduler(engine)
        logger.info("Retention scheduler started")
    except Exception as exc:
        logger.error(
            f"Retention scheduler failed to start: {exc}", exc_info=True
        )

    logger.info(f"{APP_NAME} startup complete")

    yield

    logger.info(f"{APP_NAME} shutdown initiated")

    try:
        shutdown_scheduler()
    except Exception as exc:
        logger.error(f"Retention scheduler shutdown error: {exc}")

    logger.info(f"{APP_NAME} shutdown complete")


# ---------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------

app = FastAPI(
    title=APP_NAME,
    version=__version__,
    description=(
        "Capture layer for the OpenAgent system. Receives signed events and "
        "stores them append-only in monthly-partitioned tables. See "
        "docs/DATASHEET.md for the integration contract."
    ),
    docs_url=(
        "/docs"
        if os.environ.get("LOGGER_ENABLE_DOCS", "false").lower() == "true"
        else None
    ),
    redoc_url=None,
    lifespan=lifespan,
)


# ---------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Render HTTPExceptions through the ErrorResponse envelope."""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=f"HTTP_{exc.status_code}",
            message=str(exc.detail),
        ).model_dump(mode="json"),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Catch-all for unexpected errors. Logs and returns a generic 500."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error="INTERNAL_ERROR",
            message="An internal error occurred",
        ).model_dump(mode="json"),
    )


# ---------------------------------------------------------------------
# POST /events
# ---------------------------------------------------------------------

@app.post(
    "/events",
    response_model=EventResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Capture a signed event",
    description=(
        "Validates the X-API-Key header, verifies the HMAC signature and "
        "replay window, then writes the event append-only to the "
        "appropriate partitioned table."
    ),
    dependencies=[Depends(require_logger_api_key)],
)
async def create_event(
    event: EventCreate,
    db: Session = Depends(get_db),
) -> EventResponse:
    """
    Receive one signed event and write it append-only.

    Processing order:
        1. Pydantic has already validated the envelope and payload shape.
        2. Verify replay window (cheap, runs first).
        3. Verify HMAC signature against LOGGER_HMAC_SECRET.
        4. Insert into the appropriate table based on event_type.
        5. Return the server-assigned event_id.

    Args:
        event: Validated event payload (discriminated union of variants).
        db: Database session (injected via dependency).

    Returns:
        EventResponse with the assigned event_id.

    Raises:
        HTTPException(401): On HMAC or replay-window failure.
        HTTPException(500): On database persistence failure.
    """
    dispatch_entry = EVENT_DISPATCH.get(event.event_type)
    if dispatch_entry is None:
        # Defensive - Pydantic discrimination should make this unreachable.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown event_type: {event.event_type}",
        )

    model_cls, retention_class = dispatch_entry

    # Re-derive the payload dict so we can recompute the HMAC. We use
    # model_dump(mode='json') so datetime/UUID serialise the same way
    # they did on the emitter side. The emitter must call the same
    # canonical_payload_json() to produce a matching signature.
    payload_dict = event.payload.model_dump(mode="json")

    ok, error = verify_event(
        request_id=str(event.request_id),
        client_timestamp=event.client_timestamp,
        event_type=event.event_type.value,
        payload=payload_dict,
        signature=event.hmac_signature,
    )
    if not ok:
        logger.warning(
            f"Event rejected "
            f"(request_id={event.request_id}, type={event.event_type.value}): "
            f"{error}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error,
        )

    # Common envelope columns for every event type.
    now_utc = datetime.now(timezone.utc)
    common_kwargs: Dict[str, Any] = {
        "request_id": event.request_id,
        "source_service": event.source_service,
        "created_at": now_utc,
        "client_timestamp": event.client_timestamp,
        "session_id": event.session_id,
        "user_id": event.user_id,
        "hmac_signature": event.hmac_signature,
        "retention_class": retention_class.value,
    }

    # Per-type payload columns. The isinstance dispatch is safe because
    # Pydantic's discriminator guarantees the payload matches event_type.
    if isinstance(event, OpsEventCreate):
        row = model_cls(
            **common_kwargs,
            action=event.payload.action,
            outcome=event.payload.outcome,
            details=event.payload.details,
        )
    elif isinstance(event, ConversationCaptureCreate):
        row = model_cls(
            **common_kwargs,
            input_text=event.payload.input_text,
            output_text=event.payload.output_text,
            input_hash=event.payload.input_hash,
            output_hash=event.payload.output_hash,
            model_used=event.payload.model_used,
            reasoning_effort=event.payload.reasoning_effort,
            latency_ms=event.payload.latency_ms,
            input_tokens=event.payload.input_tokens,
            output_tokens=event.payload.output_tokens,
        )
    elif isinstance(event, AuditEventCreate):
        row = model_cls(
            **common_kwargs,
            actor=event.payload.actor,
            action=event.payload.action,
            target=event.payload.target,
            outcome=event.payload.outcome,
            ip_address=event.payload.ip_address,
            details=event.payload.details,
        )
    else:
        # Defensive - should be unreachable.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unhandled event variant: {type(event).__name__}",
        )

    try:
        db.add(row)
        db.commit()
        db.refresh(row)
    except Exception as exc:
        db.rollback()
        logger.error(
            f"Failed to persist event "
            f"(request_id={event.request_id}, type={event.event_type.value}): "
            f"{exc}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist event",
        )

    logger.info(
        f"Event captured "
        f"(event_id={row.event_id}, "
        f"request_id={event.request_id}, "
        f"type={event.event_type.value}, "
        f"session={event.session_id or 'null'})"
    )

    return EventResponse(
        success=True,
        event_id=row.event_id,
        event_type=event.event_type,
        message="Event captured",
    )


# ---------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------

@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Service readiness",
    description=(
        "Reports database connectivity and scheduler status. Authenticated "
        "because operational state at this boundary is internal information."
    ),
    dependencies=[Depends(require_logger_api_key)],
)
async def health() -> HealthResponse:
    """
    Report service readiness.

    The top-level `status` field reflects the worst of (database state,
    scheduler state). Operators key off this; nested fields provide the
    diagnostic detail.
    """
    db_status: str = "disconnected"
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as exc:
        logger.warning(f"Health probe: database connection failed: {exc}")

    scheduler = get_scheduler()
    scheduler_status: str = (
        "running"
        if scheduler is not None and scheduler.is_running
        else "stopped"
    )

    if db_status == "connected" and scheduler_status == "running":
        overall = "ok"
    elif db_status == "disconnected":
        overall = "unhealthy"
    else:
        overall = "degraded"

    return HealthResponse(
        status=overall,
        version=__version__,
        database=db_status,
        scheduler=scheduler_status,
    )


# ---------------------------------------------------------------------
# GET /stats
# ---------------------------------------------------------------------

@app.get(
    "/stats",
    response_model=StatsResponse,
    summary="Aggregate row statistics",
    description="Row counts per table and overall timestamp bounds.",
    dependencies=[Depends(require_logger_api_key)],
)
async def stats(db: Session = Depends(get_db)) -> StatsResponse:
    """
    Return row counts and timestamp bounds across the three tables.

    Args:
        db: Database session (injected).

    Returns:
        StatsResponse with counts and oldest/newest timestamps.
    """
    try:
        ops_count = db.query(func.count(OpsEvent.event_id)).scalar() or 0
        cap_count = db.query(func.count(ConversationCapture.event_id)).scalar() or 0
        audit_count = db.query(func.count(AuditEvent.event_id)).scalar() or 0

        # Overall oldest and newest timestamps across all three tables.
        timestamps_min = [
            db.query(func.min(OpsEvent.created_at)).scalar(),
            db.query(func.min(ConversationCapture.created_at)).scalar(),
            db.query(func.min(AuditEvent.created_at)).scalar(),
        ]
        timestamps_max = [
            db.query(func.max(OpsEvent.created_at)).scalar(),
            db.query(func.max(ConversationCapture.created_at)).scalar(),
            db.query(func.max(AuditEvent.created_at)).scalar(),
        ]
        oldest = min((t for t in timestamps_min if t is not None), default=None)
        newest = max((t for t in timestamps_max if t is not None), default=None)

    except Exception as exc:
        logger.error(f"Stats query failed: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve statistics",
        )

    return StatsResponse(
        ops_events_count=ops_count,
        conversation_captures_count=cap_count,
        audit_events_count=audit_count,
        oldest_event=oldest,
        newest_event=newest,
    )


# ---------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------

@app.get("/", include_in_schema=False)
async def root() -> Dict[str, Any]:
    """
    Lightweight identification endpoint.

    Not authenticated - exposes only the service name and version, the
    same information that's already visible in any HTTP response header.
    """
    return {
        "service": APP_NAME,
        "version": __version__,
    }


# ---------------------------------------------------------------------
# Entrypoint (local dev)
# ---------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("LOGGER_HOST", "0.0.0.0")
    port = int(os.environ.get("LOGGER_PORT", "8003"))

    logger.info(f"Starting {APP_NAME} on {host}:{port}")
    uvicorn.run(
        "src.api:app",
        host=host,
        port=port,
        reload=os.environ.get("LOGGER_RELOAD", "false").lower() == "true",
        log_level=os.environ.get("LOGGER_LOG_LEVEL", "info").lower(),
    )