"""
OpenAgent Logger.

Capture layer for the OpenAgent system. Receives signed events from
openagent-api (and future emitters) and stores them append-only in
monthly-partitioned PostgreSQL tables.

This package contains the FastAPI service that owns three concerns:

  1. The /events ingestion endpoint, with two independent security
     checks (X-API-Key transport + HMAC payload integrity).
  2. The three event tables (ops_events, conversation_captures,
     audit_events) and their shared envelope.
  3. The retention scheduler that drops expired partitions and
     creates next month's partitions ahead of time.

See README.md for the design rationale and integration contract.
See docs/DATASHEET.md for the cross-service reference.
"""

__version__ = "0.1.0"
__author__ = "William McKeon"

__all__ = ["__version__", "__author__"]