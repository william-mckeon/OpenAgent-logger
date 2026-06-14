"""
Security module for openagent-logger.

Two independent security checks per the compartmentalized auth design we
agreed on. Each one protects against a different threat; both must pass.

1. X-API-Key transport authentication (LOGGER_API_KEY)
   - Validates that the caller is allowed to talk to openagent-logger at all
   - Cheap header check at the door
   - Constant-time comparison (prevents timing attacks)

2. HMAC-SHA256 payload integrity (LOGGER_HMAC_SECRET)
   - Validates that the event payload has not been tampered with
   - Signature is stored alongside the event row, so downstream consumers
     (auditors, any reader) can re-verify integrity without trusting the
     original transport
   - Replay protection: client_timestamp must fall within a tolerance
     window of server time

These are two INDEPENDENT secrets. Compromise of one does not grant forge
ability on the other. See README's Security Model section for the full
threat-model walk-through.

The canonical string format is seven pipe-separated fields:
    {request_id}|{client_timestamp}|{event_type}|{source_service}|{session_id}|{user_id}|{payload_hash}
where payload_hash = sha256(canonical_payload_json) and the attribution fields
(source_service, session_id, user_id) serialize as the empty string "" when
None. This must match the emitter (openagent-api/src/client/logger.py) byte for
byte — see _canonical_string below.

We hash the payload rather than including it directly so the signature
stays valid even if the stored payload is later transformed (compressed,
partially redacted) - as long as the original payload hashes are kept.
"""

import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from fastapi import Header, HTTPException, status

logger = logging.getLogger("openagent.logger.security")


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

LOGGER_API_KEY: str = os.environ.get("LOGGER_API_KEY", "").strip()
LOGGER_HMAC_SECRET: str = os.environ.get("LOGGER_HMAC_SECRET", "").strip()

# Reject events whose client_timestamp is outside this skew window vs
# server time. Defaults to 5 minutes - tight enough to bound replay
# attack surface, loose enough to tolerate normal clock skew between
# emitter and receiver.
REPLAY_WINDOW_SECONDS: int = int(
    os.environ.get("LOGGER_REPLAY_WINDOW_SECONDS", "300")
)


def configuration_status() -> Dict[str, bool]:
    """
    Return a snapshot of which secrets are configured.

    Used by /health to expose configuration state without exposing
    the actual secret values.
    """
    return {
        "api_key_configured": bool(LOGGER_API_KEY),
        "hmac_secret_configured": bool(LOGGER_HMAC_SECRET),
    }


def warn_if_missing_secrets() -> None:
    """
    Emit startup warnings if either secret is unconfigured.

    Called once from the FastAPI lifespan handler. We do NOT raise here -
    the service still boots so /health can report the misconfiguration
    and operators can fix it without a restart loop.
    """
    if not LOGGER_API_KEY:
        logger.error(
            "LOGGER_API_KEY is not configured. All inbound requests will be rejected."
        )
    if not LOGGER_HMAC_SECRET:
        logger.error(
            "LOGGER_HMAC_SECRET is not configured. All HMAC verifications will fail."
        )


# ---------------------------------------------------------------------
# X-API-Key validation (transport gate)
# ---------------------------------------------------------------------

async def require_logger_api_key(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> None:
    """
    FastAPI dependency that validates the X-API-Key header.

    Used on every authenticated endpoint (POST /events, GET /health,
    GET /stats). Returns None on success so FastAPI proceeds to the
    route handler; raises HTTPException(401) on failure.

    Args:
        x_api_key: The X-API-Key header value (auto-extracted by FastAPI).

    Raises:
        HTTPException(500): If LOGGER_API_KEY is not configured server-side.
        HTTPException(401): If the header is missing or does not match.
    """
    if not LOGGER_API_KEY:
        logger.error(
            "Inbound request rejected: LOGGER_API_KEY is not configured server-side."
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error",
        )

    if not x_api_key:
        logger.warning("Inbound request rejected: X-API-Key header missing")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )

    # Constant-time comparison prevents timing-based key recovery attacks.
    if not hmac.compare_digest(x_api_key, LOGGER_API_KEY):
        logger.warning("Inbound request rejected: X-API-Key mismatch")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )

    return None


async def require_logger_api_key_for_health(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> None:
    """
    Auth for /health that still answers when the server is misconfigured.

    /health exists so an operator can observe the service — including when it is
    misconfigured. The lifespan deliberately boots even if LOGGER_API_KEY is
    unset so that state can be surfaced; but the standard dependency raises 500
    in exactly that case, which would make /health unable to report it. This
    variant instead lets the probe through when LOGGER_API_KEY is unset (so the
    unhealthy/misconfigured state is observable), and authenticates normally
    (401 on missing/wrong key) once a key IS configured.

    Args:
        x_api_key: The X-API-Key header value (auto-extracted by FastAPI).

    Raises:
        HTTPException(401): Only when a key IS configured and the header is
            missing or does not match.
    """
    if not LOGGER_API_KEY:
        logger.warning(
            "Health probe served without auth: LOGGER_API_KEY is not configured."
        )
        return None

    if not x_api_key or not hmac.compare_digest(x_api_key, LOGGER_API_KEY):
        logger.warning("Health probe rejected: X-API-Key missing or mismatch")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )

    return None


# ---------------------------------------------------------------------
# Canonical payload serialization
# ---------------------------------------------------------------------

def canonical_payload_json(payload: Dict[str, Any]) -> str:
    """
    Produce a deterministic JSON serialization of a payload dict.

    The same dict must produce the same string regardless of insertion
    order or platform. Both the emitter (openagent-api) and the receiver
    (openagent-logger) call this exact function so the resulting hash
    matches on both sides.

    Args:
        payload: The event payload as a dict (typically the output of
                 Pydantic's model_dump(mode='json')).

    Returns:
        str: Canonical JSON string - keys sorted, no whitespace, ASCII safe.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def canonical_timestamp(dt: datetime) -> str:
    """
    Render a datetime as the canonical client_timestamp string.

    Normalised to UTC with fixed microsecond precision and a '+00:00'
    offset, e.g. '2026-05-14T18:24:01.342000+00:00'. The emitter signs over
    this exact form, so we re-canonicalise the parsed timestamp before
    verifying rather than relying on the brittle assumption that
    `datetime.fromisoformat(s).isoformat() == s` for every emitter (a 'Z'
    suffix, non-UTC offset, or sub-second-zero would otherwise fail with a
    misleading 'Invalid HMAC signature').

    MUST match openagent-api/src/client/logger.py:_canonical_timestamp
    byte-for-byte.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _fmt_envelope_field(value: Optional[Any]) -> str:
    """
    Render an optional signed attribution field for the canonical string.

    None renders as the empty string. MUST match the emitter's
    _fmt_envelope_field byte-for-byte.
    """
    return "" if value is None else str(value)


def compute_signature(
    request_id: str,
    client_timestamp: str,
    event_type: str,
    source_service: str,
    session_id: Optional[str],
    user_id: Optional[Any],
    payload: Dict[str, Any],
) -> str:
    """
    Compute the HMAC-SHA256 signature for an event.

    Canonical string:
        {request_id}|{client_timestamp}|{event_type}
          |{source_service}|{session_id}|{user_id}|{sha256(payload_canonical)}

    The attribution fields (source_service, session_id, user_id) are signed
    so they cannot be rewritten in transit; they are persisted on the row and
    feed the audit trail. None session_id/user_id render as the empty string.

    Args:
        request_id: Stringified UUID for the originating /chat call.
        client_timestamp: Canonical timestamp string (see canonical_timestamp).
        event_type: The event-type discriminator value (e.g., 'ops_event').
        source_service: Emitter identifier (signed attribution field).
        session_id: Caller session correlation, or None (signed).
        user_id: Caller user id, or None (signed).
        payload: The event payload dict.

    Returns:
        str: 64-character lowercase hex HMAC-SHA256 signature.
    """
    payload_canonical = canonical_payload_json(payload)
    payload_hash = hashlib.sha256(payload_canonical.encode("utf-8")).hexdigest()

    canonical_string = "|".join(
        (
            request_id,
            client_timestamp,
            event_type,
            _fmt_envelope_field(source_service),
            _fmt_envelope_field(session_id),
            _fmt_envelope_field(user_id),
            payload_hash,
        )
    )

    return hmac.new(
        LOGGER_HMAC_SECRET.encode("utf-8"),
        canonical_string.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


# ---------------------------------------------------------------------
# Verification helpers
# ---------------------------------------------------------------------

def verify_signature(
    request_id: str,
    client_timestamp: str,
    event_type: str,
    source_service: str,
    session_id: Optional[str],
    user_id: Optional[Any],
    payload: Dict[str, Any],
    signature: str,
) -> Tuple[bool, str]:
    """
    Verify an event's HMAC signature.

    Args:
        request_id: The event's request_id (as string).
        client_timestamp: The event's canonical client_timestamp string.
        event_type: The event-type discriminator.
        source_service: Emitter identifier (signed attribution field).
        session_id: Caller session correlation, or None (signed).
        user_id: Caller user id, or None (signed).
        payload: The event payload dict (post-Pydantic model_dump).
        signature: The signature claimed by the emitter.

    Returns:
        Tuple of (is_valid, error_message). On success the error message
        is empty; on failure it describes the specific failure.
    """
    if not LOGGER_HMAC_SECRET:
        logger.error("HMAC verification failed: LOGGER_HMAC_SECRET is not configured")
        return False, "Server configuration error: HMAC secret not set"

    expected = compute_signature(
        request_id=request_id,
        client_timestamp=client_timestamp,
        event_type=event_type,
        source_service=source_service,
        session_id=session_id,
        user_id=user_id,
        payload=payload,
    )

    if not hmac.compare_digest(signature.lower(), expected.lower()):
        return False, "Invalid HMAC signature"

    return True, ""


def verify_replay_window(client_timestamp: datetime) -> Tuple[bool, str]:
    """
    Reject events whose client_timestamp falls outside the replay window.

    Protects against replay attacks (captured signed event re-submitted
    later) and catches grossly skewed emitter clocks (usually a
    misconfiguration symptom).

    Args:
        client_timestamp: The event's client_timestamp.

    Returns:
        Tuple of (is_within_window, error_message).
    """
    # Normalise to UTC for comparison. tz-naive inputs are interpreted as UTC.
    if client_timestamp.tzinfo is None:
        client_timestamp = client_timestamp.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    skew_seconds = abs((now - client_timestamp).total_seconds())

    if skew_seconds > REPLAY_WINDOW_SECONDS:
        return False, (
            f"client_timestamp outside replay window "
            f"(skew {skew_seconds:.0f}s > {REPLAY_WINDOW_SECONDS}s)"
        )

    return True, ""


def verify_event(
    request_id: str,
    client_timestamp: datetime,
    event_type: str,
    source_service: str,
    session_id: Optional[str],
    user_id: Optional[Any],
    payload: Dict[str, Any],
    signature: str,
) -> Tuple[bool, str]:
    """
    Run the full security check on an inbound event.

    Entry point used by the API layer. Order matters: replay-window
    check first (cheap), then HMAC verification (more expensive).

    Args:
        request_id: The event's request_id.
        client_timestamp: The event's client_timestamp (parsed datetime).
        event_type: The event-type discriminator.
        source_service: Emitter identifier (signed attribution field).
        session_id: Caller session correlation, or None (signed).
        user_id: Caller user id, or None (signed).
        payload: The event payload dict.
        signature: The claimed signature.

    Returns:
        (True, "") if all checks pass.
        (False, error_message) on the first failing check.
    """
    ok, error = verify_replay_window(client_timestamp)
    if not ok:
        return False, error

    # Re-canonicalise the parsed timestamp to the exact form the emitter
    # signed over, rather than trusting datetime.isoformat() to round-trip.
    iso_timestamp = canonical_timestamp(client_timestamp)
    ok, error = verify_signature(
        request_id=request_id,
        client_timestamp=iso_timestamp,
        event_type=event_type,
        source_service=source_service,
        session_id=session_id,
        user_id=user_id,
        payload=payload,
        signature=signature,
    )
    if not ok:
        return False, error

    return True, ""