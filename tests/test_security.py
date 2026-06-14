"""
Pinning tests for openagent-logger's HMAC security contract.

These guard the highest-value, drift-prone logic in ``src/security.py``:

  * the exact 7-field canonical string that the HMAC is computed over
    (this was mis-documented historically, so we pin it to a literal), and
  * the replay-window tolerance (absolute skew, past and future).

Everything here is a pure function — no DB, no network, no FastAPI app.

The HMAC secret is read into a module-level constant at import time. To make
signature round-trip tests deterministic we patch ``security.LOGGER_HMAC_SECRET``
to a fixed value inside the relevant tests rather than relying on the ambient
environment.
"""

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from src import security
from src.security import (
    canonical_payload_json,
    compute_signature,
    verify_signature,
    verify_replay_window,
    _fmt_envelope_field,
)


# ---------------------------------------------------------------------
# Fixed inputs shared across the canonical-string tests.
# ---------------------------------------------------------------------

REQUEST_ID = "11111111-1111-1111-1111-111111111111"
CLIENT_TIMESTAMP = "2026-06-14T01:19:45.003236+00:00"
EVENT_TYPE = "ops_event"
SOURCE_SERVICE = "openagent-api"
SESSION_ID = "sess-abc"
USER_ID = "user-xyz"
PAYLOAD = {"action": "test", "outcome": "ok"}

# (b) The pinned canonical_payload_json output for PAYLOAD.
GOLDEN_PAYLOAD_JSON = '{"action":"test","outcome":"ok"}'

# (a) The pinned full 7-field canonical string.
GOLDEN_CANONICAL_STRING = (
    "11111111-1111-1111-1111-111111111111"
    "|2026-06-14T01:19:45.003236+00:00"
    "|ops_event"
    "|openagent-api"
    "|sess-abc"
    "|user-xyz"
    "|c813d39ea439fd8205574b6d5779dd4ab00b85cf617bb381f2e8cd463cf54959"
)

FIXED_SECRET = "test-secret"


def _build_canonical_string(
    request_id,
    client_timestamp,
    event_type,
    source_service,
    session_id,
    user_id,
    payload,
):
    """Reconstruct the canonical string exactly as compute_signature does."""
    payload_hash = hashlib.sha256(
        canonical_payload_json(payload).encode("utf-8")
    ).hexdigest()
    return "|".join(
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


# ---------------------------------------------------------------------
# canonical_payload_json
# ---------------------------------------------------------------------

def test_canonical_payload_json_is_pinned_literal():
    assert canonical_payload_json(PAYLOAD) == GOLDEN_PAYLOAD_JSON


def test_canonical_payload_json_is_key_order_independent():
    reordered = {"outcome": "ok", "action": "test"}
    assert canonical_payload_json(reordered) == GOLDEN_PAYLOAD_JSON


# ---------------------------------------------------------------------
# GOLDEN canonical string
# ---------------------------------------------------------------------

def test_golden_canonical_string_is_seven_pipe_fields_in_order():
    canonical = _build_canonical_string(
        REQUEST_ID,
        CLIENT_TIMESTAMP,
        EVENT_TYPE,
        SOURCE_SERVICE,
        SESSION_ID,
        USER_ID,
        PAYLOAD,
    )

    # Exactly 7 pipe-separated fields.
    fields = canonical.split("|")
    assert len(fields) == 7

    # In the documented order.
    assert fields[0] == REQUEST_ID
    assert fields[1] == CLIENT_TIMESTAMP
    assert fields[2] == EVENT_TYPE
    assert fields[3] == SOURCE_SERVICE
    assert fields[4] == SESSION_ID
    assert fields[5] == USER_ID

    # Field 7 is sha256(canonical_payload_json(payload)).
    expected_hash = hashlib.sha256(
        canonical_payload_json(PAYLOAD).encode("utf-8")
    ).hexdigest()
    assert fields[6] == expected_hash

    # Pinned to the full literal.
    assert canonical == GOLDEN_CANONICAL_STRING


def test_none_attribution_fields_serialize_as_empty_string():
    # _fmt_envelope_field is what renders the optional signed attribution
    # fields (source_service, session_id, user_id) in the canonical string.
    assert _fmt_envelope_field(None) == ""
    assert _fmt_envelope_field("openagent-api") == "openagent-api"

    canonical = _build_canonical_string(
        REQUEST_ID,
        CLIENT_TIMESTAMP,
        EVENT_TYPE,
        None,  # source_service
        None,  # session_id
        None,  # user_id
        PAYLOAD,
    )
    fields = canonical.split("|")
    assert len(fields) == 7
    assert fields[3] == ""  # source_service
    assert fields[4] == ""  # session_id
    assert fields[5] == ""  # user_id


# ---------------------------------------------------------------------
# Signature round-trip
# ---------------------------------------------------------------------

@pytest.fixture
def fixed_secret(monkeypatch):
    """Pin the module-level HMAC secret to a known value for the test."""
    monkeypatch.setattr(security, "LOGGER_HMAC_SECRET", FIXED_SECRET)
    return FIXED_SECRET


def _sign(payload=PAYLOAD, **overrides):
    kwargs = dict(
        request_id=REQUEST_ID,
        client_timestamp=CLIENT_TIMESTAMP,
        event_type=EVENT_TYPE,
        source_service=SOURCE_SERVICE,
        session_id=SESSION_ID,
        user_id=USER_ID,
        payload=payload,
    )
    kwargs.update(overrides)
    return compute_signature(**kwargs)


def test_signature_round_trip_valid(fixed_secret):
    signature = _sign()
    ok, error = verify_signature(
        request_id=REQUEST_ID,
        client_timestamp=CLIENT_TIMESTAMP,
        event_type=EVENT_TYPE,
        source_service=SOURCE_SERVICE,
        session_id=SESSION_ID,
        user_id=USER_ID,
        payload=PAYLOAD,
        signature=signature,
    )
    assert ok is True
    assert error == ""


def test_signature_fails_on_flipped_payload_byte(fixed_secret):
    signature = _sign()
    tampered_payload = {"action": "test", "outcome": "Ok"}  # one byte flipped
    ok, error = verify_signature(
        request_id=REQUEST_ID,
        client_timestamp=CLIENT_TIMESTAMP,
        event_type=EVENT_TYPE,
        source_service=SOURCE_SERVICE,
        session_id=SESSION_ID,
        user_id=USER_ID,
        payload=tampered_payload,
        signature=signature,
    )
    assert ok is False
    assert error == "Invalid HMAC signature"


def test_signature_fails_on_flipped_canonical_field(fixed_secret):
    signature = _sign()
    ok, error = verify_signature(
        request_id=REQUEST_ID,
        client_timestamp=CLIENT_TIMESTAMP,
        event_type=EVENT_TYPE,
        source_service=SOURCE_SERVICE,
        session_id="sess-DIFFERENT",  # one canonical field changed
        user_id=USER_ID,
        payload=PAYLOAD,
        signature=signature,
    )
    assert ok is False
    assert error == "Invalid HMAC signature"


def test_signature_changes_with_secret(monkeypatch):
    monkeypatch.setattr(security, "LOGGER_HMAC_SECRET", "secret-a")
    sig_a = _sign()
    monkeypatch.setattr(security, "LOGGER_HMAC_SECRET", "secret-b")
    sig_b = _sign()
    assert sig_a != sig_b


def test_verify_fails_when_secret_unconfigured(monkeypatch):
    monkeypatch.setattr(security, "LOGGER_HMAC_SECRET", "")
    ok, error = verify_signature(
        request_id=REQUEST_ID,
        client_timestamp=CLIENT_TIMESTAMP,
        event_type=EVENT_TYPE,
        source_service=SOURCE_SERVICE,
        session_id=SESSION_ID,
        user_id=USER_ID,
        payload=PAYLOAD,
        signature="deadbeef",
    )
    assert ok is False
    assert "HMAC secret not set" in error


# ---------------------------------------------------------------------
# Replay window
# ---------------------------------------------------------------------

def test_replay_window_accepts_timestamp_within_tolerance():
    now = datetime.now(timezone.utc)
    ok, error = verify_replay_window(now)
    assert ok is True
    assert error == ""


def test_replay_window_rejects_far_future():
    far_future = datetime.now(timezone.utc) + timedelta(seconds=10000)
    ok, error = verify_replay_window(far_future)
    assert ok is False
    assert "replay window" in error


def test_replay_window_rejects_far_past():
    # abs() skew means past skew is rejected symmetrically.
    far_past = datetime.now(timezone.utc) - timedelta(seconds=10000)
    ok, error = verify_replay_window(far_past)
    assert ok is False
    assert "replay window" in error


def test_replay_window_tolerates_both_small_past_and_future_skew():
    inside = security.REPLAY_WINDOW_SECONDS - 1
    now = datetime.now(timezone.utc)

    ok_future, _ = verify_replay_window(now + timedelta(seconds=inside))
    ok_past, _ = verify_replay_window(now - timedelta(seconds=inside))

    assert ok_future is True
    assert ok_past is True


def test_replay_window_treats_naive_timestamp_as_utc():
    naive_now = datetime.now(timezone.utc).replace(tzinfo=None)
    ok, error = verify_replay_window(naive_now)
    assert ok is True
    assert error == ""
