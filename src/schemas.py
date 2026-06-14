"""
Pydantic schemas for openagent-logger.

Three event types share a common envelope and differ only in their payload
shape. The /events endpoint accepts a discriminated union of the three
variants and dispatches to the correct table based on event_type.

Envelope fields (every event):
    request_id        UUID, NOT NULL  - correlates events from one /chat call
    source_service    str,  NOT NULL  - emitter identifier (e.g., "openagent-api")
    client_timestamp  datetime,       - when the emitter constructed the event
    session_id        str,  NULL      - caller-supplied session correlation
    user_id           UUID, NULL      - reserved; null in the reference stack
    hmac_signature    str,  NOT NULL  - HMAC-SHA256 over canonical string

Per-type payloads:
    OpsEvent              - operational telemetry (request_received, etc.)
    ConversationCapture   - full /chat content captured for observability/audit
    AuditEvent            - security-relevant actions

retention_class is NOT part of the inbound contract - it is derived
server-side from event_type and stored on the row.
"""

import json
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Dict, Literal, Optional, Union
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


# Maximum serialized size of a `details` JSONB payload. JSONB columns are
# otherwise unbounded; this caps a single event so a pathological emitter
# cannot push multi-megabyte blobs into the capture tables.
MAX_DETAILS_JSON_BYTES: int = 16 * 1024  # 16 KB


def _validate_details_size(value: Dict[str, Any]) -> Dict[str, Any]:
    """Reject a details dict whose serialized JSON exceeds MAX_DETAILS_JSON_BYTES.

    Shared by the ops_event and audit_event payload validators. Measured in
    UTF-8 bytes against a compact JSON encoding so the limit matches the
    on-the-wire / stored size rather than character count.
    """
    encoded = json.dumps(value, separators=(",", ":"), default=str)
    size = len(encoded.encode("utf-8"))
    if size > MAX_DETAILS_JSON_BYTES:
        raise ValueError(
            f"details exceeds maximum size "
            f"({size} > {MAX_DETAILS_JSON_BYTES} bytes)"
        )
    return value


# ---------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------

class EventType(str, Enum):
    """Discriminator value identifying the event variant."""

    OPS_EVENT = "ops_event"
    CONVERSATION_CAPTURE = "conversation_capture"
    AUDIT_EVENT = "audit_event"


class RetentionClass(str, Enum):
    """
    Retention policy class for an event row.

    Derived server-side from event_type at insertion time. Stored on the
    row so retention policy is explicit at the data layer (audit trail)
    and survives any future table consolidation.
    """

    SHORT = "short"      # ~90 days (ops_events)
    MEDIUM = "medium"    # ~180 days (conversation_captures)
    LONG = "long"        # ~7 years (audit_events)


# ---------------------------------------------------------------------
# Shared envelope
# ---------------------------------------------------------------------

class EventEnvelope(BaseModel):
    """
    Common envelope fields present on every event variant.

    These are validated and stored for every row regardless of event type.
    The per-type schemas below extend this with their `event_type`
    discriminator and `payload` body.
    """

    model_config = ConfigDict(extra="forbid")

    request_id: UUID = Field(
        ...,
        description=(
            "Correlation ID from openagent-api for one /chat call. Always "
            "present, even on auth_failure events (the request still happened)."
        ),
    )

    source_service: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Name of the service emitting this event (e.g., 'openagent-api').",
    )

    client_timestamp: datetime = Field(
        ...,
        description=(
            "When the emitter constructed this event. Used for the replay "
            "window check in security.verify_replay_window()."
        ),
    )

    session_id: Optional[str] = Field(
        default=None,
        max_length=64,
        description=(
            "Caller-supplied session correlation. NULL is valid and is the "
            "default in the reference stack; the logger never validates it. "
            "See README."
        ),
    )

    user_id: Optional[UUID] = Field(
        default=None,
        description=(
            "Reserved per-user identifier. NULL in the reference stack; the "
            "logger never validates it."
        ),
    )

    hmac_signature: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description=(
            "HMAC-SHA256 over the canonical string "
            "'{request_id}|{client_timestamp}|{event_type}|{source_service}"
            "|{session_id}|{user_id}|{payload_hash}', where payload_hash = "
            "sha256(canonical_payload_json) and a NULL source_service, "
            "session_id, or user_id serializes as the empty string. "
            "Verified at ingestion and stored alongside the event so "
            "downstream consumers can re-verify integrity later."
        ),
    )

    @field_validator("hmac_signature")
    @classmethod
    def _signature_is_hex(cls, v: str) -> str:
        """Ensure hmac_signature is exactly 64 lowercase-hex characters.

        We use a strict regex rather than int(v, 16): int() accepts a leading
        sign and surrounding whitespace ('+...', '-...', ' ff '), which are not
        valid HMAC hex digests and would corrupt the canonical comparison.
        """
        if not re.fullmatch(r"[0-9a-f]{64}", v.lower()):
            raise ValueError("hmac_signature must be a 64-character hexadecimal string")
        return v.lower()


# ---------------------------------------------------------------------
# Per-type payload schemas
# ---------------------------------------------------------------------

class OpsEventPayload(BaseModel):
    """
    Payload for an operational telemetry event.

    Examples: request_received, auth_failure, upstream_call,
    upstream_error, client_disconnect, stream_complete.
    """

    model_config = ConfigDict(extra="forbid")

    action: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="What happened (e.g., 'request_received').",
    )

    outcome: str = Field(
        ...,
        min_length=1,
        max_length=32,
        description="Result of the action (e.g., 'success', 'failure', 'timeout').",
    )

    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form context. Persisted as JSONB. Keep payloads small.",
    )

    @field_validator("details")
    @classmethod
    def _details_within_cap(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Reject a details payload whose serialized JSON exceeds the cap."""
        return _validate_details_size(v)


class ConversationCapturePayload(BaseModel):
    """
    Payload for a captured /chat completion.

    One row per /chat call, written after the response has been delivered
    to the user, for observability and audit.
    """

    model_config = ConfigDict(extra="forbid")

    input_text: str = Field(
        ...,
        min_length=1,
        max_length=200_000,
        description="The user's raw input for this /chat call.",
    )

    output_text: str = Field(
        ...,
        min_length=0,
        max_length=1_000_000,
        description="The model's full response. May be empty on failure.",
    )

    input_hash: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description=(
            "SHA-256 hex of input_text. Stored so the HMAC signature "
            "remains verifiable even if input_text is later transformed "
            "(compressed, partially redacted, etc.)."
        ),
    )

    output_hash: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="SHA-256 hex of output_text. Same rationale as input_hash.",
    )

    model_used: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Model identifier reported by openagent-infra.",
    )

    reasoning_effort: Optional[Literal["low", "medium", "high"]] = Field(
        default=None,
        description="Reasoning effort level for this call, if specified.",
    )

    latency_ms: Optional[int] = Field(
        default=None,
        ge=0,
        description="End-to-end latency for the /chat call, in milliseconds.",
    )

    input_tokens: Optional[int] = Field(
        default=None,
        ge=0,
        description="Token count of input_text as reported by the model.",
    )

    output_tokens: Optional[int] = Field(
        default=None,
        ge=0,
        description="Token count of output_text as reported by the model.",
    )

    @field_validator("input_hash", "output_hash")
    @classmethod
    def _hash_is_hex(cls, v: str) -> str:
        """Ensure content hashes are exactly 64 lowercase-hex characters.

        Strict regex rather than int(v, 16), which would accept a leading sign
        or surrounding whitespace that are not valid SHA-256 hex digests.
        """
        if not re.fullmatch(r"[0-9a-f]{64}", v.lower()):
            raise ValueError("hash field must be a 64-character hexadecimal string")
        return v.lower()


class AuditEventPayload(BaseModel):
    """
    Payload for a security-relevant action.

    Examples: key_rotation, auth_threshold_crossed, admin_endpoint_hit,
    retention_job_run, schema_grant_changed.

    These have the longest retention and the strictest write discipline:
    every audit_event row is intended to survive ~7 years for compliance
    review.
    """

    model_config = ConfigDict(extra="forbid")

    actor: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Who or what initiated the action (service name, user_id, etc.).",
    )

    action: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="What was attempted (e.g., 'rotate_logger_api_key').",
    )

    target: Optional[str] = Field(
        default=None,
        max_length=255,
        description="What was acted on (resource id, table name, etc.).",
    )

    outcome: str = Field(
        ...,
        min_length=1,
        max_length=32,
        description="Result of the action (e.g., 'success', 'failure', 'denied').",
    )

    ip_address: Optional[str] = Field(
        default=None,
        max_length=45,
        description="Source IP for the actor (max length covers IPv6).",
    )

    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional structured context. Persisted as JSONB.",
    )

    @field_validator("details")
    @classmethod
    def _details_within_cap(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Reject a details payload whose serialized JSON exceeds the cap."""
        return _validate_details_size(v)


# ---------------------------------------------------------------------
# Full event variants
# ---------------------------------------------------------------------

class OpsEventCreate(EventEnvelope):
    """Inbound schema for an ops_event submission."""

    event_type: Literal[EventType.OPS_EVENT]
    payload: OpsEventPayload


class ConversationCaptureCreate(EventEnvelope):
    """Inbound schema for a conversation_capture submission."""

    event_type: Literal[EventType.CONVERSATION_CAPTURE]
    payload: ConversationCapturePayload


class AuditEventCreate(EventEnvelope):
    """Inbound schema for an audit_event submission."""

    event_type: Literal[EventType.AUDIT_EVENT]
    payload: AuditEventPayload


# Discriminated union used as the request body for POST /events.
# FastAPI + Pydantic select the correct variant based on event_type.
EventCreate = Annotated[
    Union[OpsEventCreate, ConversationCaptureCreate, AuditEventCreate],
    Field(discriminator="event_type"),
]


# ---------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------

def _utcnow() -> datetime:
    """Return a tz-aware UTC datetime. Replaces deprecated datetime.utcnow()."""
    return datetime.now(timezone.utc)


class EventResponse(BaseModel):
    """Response returned by a successful POST /events."""

    success: bool = Field(default=True)
    event_id: UUID = Field(..., description="Server-assigned event identifier.")
    event_type: EventType
    message: str = Field(default="Event captured")
    timestamp: datetime = Field(default_factory=_utcnow)


class ErrorResponse(BaseModel):
    """Uniform error envelope used by exception handlers."""

    success: bool = Field(default=False)
    error: str
    message: str
    timestamp: datetime = Field(default_factory=_utcnow)


class HealthResponse(BaseModel):
    """Response returned by GET /health."""

    status: Literal["ok", "degraded", "unhealthy"]
    service: str = Field(default="openagent-logger")
    version: str
    database: Literal["connected", "disconnected"]
    scheduler: Literal["running", "stopped"]
    timestamp: datetime = Field(default_factory=_utcnow)


class StatsResponse(BaseModel):
    """Response returned by GET /stats."""

    ops_events_count: int = Field(..., ge=0)
    conversation_captures_count: int = Field(..., ge=0)
    audit_events_count: int = Field(..., ge=0)
    oldest_event: Optional[datetime] = Field(default=None)
    newest_event: Optional[datetime] = Field(default=None)
    timestamp: datetime = Field(default_factory=_utcnow)