"""
Retention scheduler for openagent-logger.

Runs an AsyncIO scheduler that fires once a day to:

    1. Drop partitions whose end date is older than the configured
       retention window for each table.
    2. Create next month's partition for each table (idempotent) so
       writes never fail when the calendar rolls over.

Retention windows are configured via environment variables:
    LOGGER_RETENTION_OPS_DAYS              (default 90)
    LOGGER_RETENTION_CONVERSATION_DAYS     (default 180)
    LOGGER_RETENTION_AUDIT_DAYS            (default 2555  ~7 years)

The job runs daily at LOGGER_RETENTION_SCHEDULE_HOUR UTC (default 03:00).

This is a process-internal scheduler. With multiple uvicorn workers,
only ONE should run the schedule - either set workers=1 or run a
dedicated scheduler service. On Render the single-instance default
handles this naturally.

NOTE: We deliberately do NOT use pg_cron here. Application-level
scheduling keeps retention logic in the same codebase as the rest of
the service - easier to test, easier to log, easier to change without
touching the database.
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import text
from sqlalchemy.engine import Engine

from .partitioning import (
    MANAGED_TABLES,
    create_partition_for_month,
    current_month,
    drop_partitions_older_than,
    next_month,
)

logger = logging.getLogger("openagent.logger.scheduler")


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

RETENTION_DAYS: Dict[str, int] = {
    "ops_events": int(
        os.environ.get("LOGGER_RETENTION_OPS_DAYS", "90")
    ),
    "conversation_captures": int(
        os.environ.get("LOGGER_RETENTION_CONVERSATION_DAYS", "180")
    ),
    "audit_events": int(
        os.environ.get("LOGGER_RETENTION_AUDIT_DAYS", "2555")
    ),
}

SCHEDULE_HOUR: int = int(
    os.environ.get("LOGGER_RETENTION_SCHEDULE_HOUR", "3")
)

# Fixed bigint key for the session-level Postgres advisory lock that guards the
# retention run. Multiple instances / workers all hash to this same key, so only
# one acquires the lock and runs the job; the others skip. The value is an
# arbitrary constant unique to this job within the openagent_logger database.
RETENTION_ADVISORY_LOCK_KEY: int = 7264012025010301


# ---------------------------------------------------------------------
# Scheduler class
# ---------------------------------------------------------------------

class RetentionScheduler:
    """
    Owns the lifecycle of the retention + partition-rollover job.

    Construct once in the FastAPI lifespan handler, call start() at
    application startup and stop() at shutdown.
    """

    def __init__(self, engine: Engine) -> None:
        """
        Initialize but do not start the scheduler.

        Args:
            engine: SQLAlchemy engine bound to the logger DB.
        """
        self.engine = engine
        self.scheduler = AsyncIOScheduler(timezone="UTC")

    @property
    def is_running(self) -> bool:
        """True if the underlying APScheduler is running."""
        return self.scheduler.running

    def start(self) -> None:
        """
        Register the daily job and start the scheduler.

        Also runs an immediate one-shot partition-ensure call so the
        first event write after deploy does not fail because the
        current month's partition has not been created yet.
        """
        if self.scheduler.running:
            logger.warning("RetentionScheduler.start: already running, ignoring")
            return

        # One-shot partition ensure at startup. Don't wait for the daily
        # cron - the first write after deploy must succeed.
        try:
            self._ensure_partitions()
        except Exception as exc:
            logger.error(
                f"Initial partition ensure failed: {exc}", exc_info=True
            )

        self.scheduler.add_job(
            self._daily_run,
            trigger=CronTrigger(hour=SCHEDULE_HOUR, minute=0, timezone="UTC"),
            id="openagent_logger_retention",
            name="Daily retention + partition rollover",
            max_instances=1,
            coalesce=True,
            replace_existing=True,
        )

        self.scheduler.start()
        logger.info(
            f"RetentionScheduler started: daily at {SCHEDULE_HOUR:02d}:00 UTC, "
            f"retention_days={RETENTION_DAYS}"
        )

    def stop(self) -> None:
        """Stop the scheduler gracefully."""
        if not self.scheduler.running:
            logger.debug("RetentionScheduler.stop: not running, ignoring")
            return

        try:
            self.scheduler.shutdown(wait=False)
            logger.info("RetentionScheduler stopped")
        except Exception as exc:
            logger.error(f"RetentionScheduler shutdown failed: {exc}")

    # -----------------------------------------------------------------
    # Job implementations
    # -----------------------------------------------------------------

    async def _daily_run(self) -> None:
        """
        Wrapper invoked by the cron trigger.

        Runs the synchronous SQL work in an executor so we don't block
        the FastAPI event loop while SQL is executing.
        """
        logger.info("Daily retention job starting")
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, self._run_blocking)
            logger.info("Daily retention job finished")
        except Exception as exc:
            logger.error(f"Daily retention job failed: {exc}", exc_info=True)

    def _run_blocking(self) -> None:
        """Synchronous body of the daily job. Runs in the executor.

        Guards the whole run with a session-level Postgres advisory lock so
        that multiple service instances / workers don't run retention
        concurrently (double DROPs, redundant catalog churn). If another
        instance holds the lock we skip this run entirely and log; the lock is
        always released in finally on the same connection that took it.
        """
        with self.engine.connect() as conn:
            acquired = conn.execute(
                text("SELECT pg_try_advisory_lock(:key)"),
                {"key": RETENTION_ADVISORY_LOCK_KEY},
            ).scalar()

            if not acquired:
                logger.info(
                    "Retention job skipped: advisory lock held by another "
                    "instance (this is expected when multiple instances run)"
                )
                return

            try:
                self._ensure_partitions()
                self._drop_expired_partitions()
            finally:
                conn.execute(
                    text("SELECT pg_advisory_unlock(:key)"),
                    {"key": RETENTION_ADVISORY_LOCK_KEY},
                )

    def _ensure_partitions(self) -> None:
        """Ensure current and next month partitions exist for every managed table.

        create_partition_for_month returns False (logged inside) when creation
        fails. We surface that here with an error log rather than ignoring the
        bool, so a silent failure to create next month's partition - which
        would make writes start failing at the calendar boundary - is visible
        in operator logs instead of going unnoticed.
        """
        cur_year, cur_month = current_month()
        nxt_year, nxt_month = next_month(cur_year, cur_month)

        for table in MANAGED_TABLES:
            for yr, mo in ((cur_year, cur_month), (nxt_year, nxt_month)):
                if not create_partition_for_month(self.engine, table, yr, mo):
                    logger.error(
                        f"Partition ensure FAILED for {table} {yr:04d}-{mo:02d}; "
                        f"writes to that month may fail until this succeeds"
                    )

    def _drop_expired_partitions(self) -> None:
        """Drop partitions older than each table's retention window."""
        today = datetime.now(timezone.utc).date()

        for table in MANAGED_TABLES:
            retention_days = RETENTION_DAYS[table]
            cutoff = today - timedelta(days=retention_days)

            dropped = drop_partitions_older_than(self.engine, table, cutoff)

            if dropped > 0:
                logger.info(
                    f"Retention: dropped {dropped} partition(s) of {table} "
                    f"(retention {retention_days} days, cutoff {cutoff.isoformat()})"
                )
            else:
                logger.debug(
                    f"Retention: no partitions to drop for {table} "
                    f"(cutoff {cutoff.isoformat()})"
                )


# ---------------------------------------------------------------------
# Module-level singleton helpers
# ---------------------------------------------------------------------

_scheduler: Optional[RetentionScheduler] = None


def get_scheduler() -> Optional[RetentionScheduler]:
    """
    Return the global RetentionScheduler instance, or None if uninitialized.

    Used by /health to report scheduler status.
    """
    return _scheduler


def initialize_scheduler(engine: Engine) -> RetentionScheduler:
    """
    Create and start the global scheduler.

    Called from the FastAPI lifespan handler at startup. Idempotent -
    a second call while the scheduler is running returns the existing
    instance.

    Args:
        engine: SQLAlchemy engine for the logger DB.

    Returns:
        RetentionScheduler: The created and started scheduler.
    """
    global _scheduler

    if _scheduler is not None and _scheduler.is_running:
        logger.warning(
            "initialize_scheduler: already initialized, returning existing"
        )
        return _scheduler

    _scheduler = RetentionScheduler(engine)
    _scheduler.start()
    return _scheduler


def shutdown_scheduler() -> None:
    """
    Stop and clear the global scheduler.

    Called from the FastAPI lifespan handler at shutdown.
    """
    global _scheduler

    if _scheduler is not None:
        _scheduler.stop()
        _scheduler = None