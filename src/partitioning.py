"""
Partition management for openagent-logger.

Tables in the openagent_logger schema are PostgreSQL declarative-partitioned
by RANGE (created_at) on a monthly cadence. This module provides the
runtime helpers used by the retention scheduler to:

    1. Create next month's partition ahead of time so writes never fail
       at the calendar boundary.
    2. Drop partitions whose entire date range is older than the table's
       retention window so storage does not grow forever.

Partition naming convention:
    <parent_table>_y<YYYY>m<MM>
    e.g. ops_events_y2026m05

Only the three event tables defined in models.py are recognised; this
module refuses to touch any other table name.
"""

import logging
from datetime import date, datetime, timezone
from typing import List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.engine import Engine

logger = logging.getLogger("openagent.logger.partitioning")


# Tables this module is allowed to operate on. Anything else is rejected
# as a defensive measure - we never want to drop the wrong partition.
MANAGED_TABLES: List[str] = [
    "ops_events",
    "conversation_captures",
    "audit_events",
]


# ---------------------------------------------------------------------
# Naming convention
# ---------------------------------------------------------------------

def partition_name_for_month(table_name: str, year: int, month: int) -> str:
    """
    Build the partition table name for a (parent, year, month) tuple.

    Args:
        table_name: Parent table name (e.g., "ops_events").
        year: Four-digit year (e.g., 2026).
        month: 1-12.

    Returns:
        str: Partition table name (e.g., "ops_events_y2026m05").
    """
    return f"{table_name}_y{year:04d}m{month:02d}"


def _month_range(year: int, month: int) -> Tuple[date, date]:
    """
    Return the [start, end) date range for a calendar month.

    Args:
        year: Four-digit year.
        month: 1-12.

    Returns:
        Tuple of (start_date, end_date). end_date is the first day of the
        following month (exclusive upper bound).
    """
    start = date(year, month, 1)
    if month == 12:
        end = date(year + 1, 1, 1)
    else:
        end = date(year, month + 1, 1)
    return start, end


# ---------------------------------------------------------------------
# Create a partition for one month
# ---------------------------------------------------------------------

def create_partition_for_month(
    engine: Engine,
    table_name: str,
    year: int,
    month: int,
    schema: str = "openagent_logger",
) -> bool:
    """
    Ensure a partition exists for one parent table, for one calendar month.

    Idempotent - CREATE TABLE IF NOT EXISTS, so calling on an existing
    partition is a no-op.

    Args:
        engine: SQLAlchemy engine bound to the logger DB.
        table_name: Parent table name. Must be in MANAGED_TABLES.
        year: Four-digit year.
        month: 1-12.
        schema: Schema containing the parent table.

    Returns:
        bool: True if the SQL ran without error, False otherwise.
    """
    if table_name not in MANAGED_TABLES:
        logger.error(
            f"create_partition_for_month: refusing to operate on "
            f"unmanaged table '{table_name}'"
        )
        return False

    partition_name = partition_name_for_month(table_name, year, month)
    start_d, end_d = _month_range(year, month)

    sql = text(
        f"CREATE TABLE IF NOT EXISTS {schema}.{partition_name} "
        f"PARTITION OF {schema}.{table_name} "
        f"FOR VALUES FROM (:start_d) TO (:end_d)"
    )

    try:
        with engine.begin() as conn:
            conn.execute(sql, {"start_d": start_d, "end_d": end_d})
        logger.info(
            f"Partition ensured: {schema}.{partition_name} "
            f"[{start_d.isoformat()} -> {end_d.isoformat()})"
        )
        return True
    except Exception as exc:
        logger.error(
            f"Failed to create partition {schema}.{partition_name}: {exc}"
        )
        return False


# ---------------------------------------------------------------------
# Drop expired partitions
# ---------------------------------------------------------------------

def drop_partitions_older_than(
    engine: Engine,
    table_name: str,
    cutoff: date,
    schema: str = "openagent_logger",
) -> int:
    """
    Drop all partitions of a parent table whose end date is on or before cutoff.

    Uses PostgreSQL's pg_inherits + pg_class catalogs to enumerate the
    parent table's partition children and parse their date ranges from
    pg_get_expr(relpartbound). A partition is dropped only if its
    exclusive upper bound is <= cutoff (i.e., the entire range is
    strictly before the cutoff date).

    Args:
        engine: SQLAlchemy engine bound to the logger DB.
        table_name: Parent table name. Must be in MANAGED_TABLES.
        cutoff: Drop partitions whose end date is on or before this.
        schema: Schema containing the parent table.

    Returns:
        int: Number of partitions actually dropped.
    """
    if table_name not in MANAGED_TABLES:
        logger.error(
            f"drop_partitions_older_than: refusing to operate on "
            f"unmanaged table '{table_name}'"
        )
        return 0

    list_partitions_sql = text(
        "SELECT c.relname AS partition_name, "
        "       pg_get_expr(c.relpartbound, c.oid) AS bound_expr "
        "FROM pg_inherits i "
        "JOIN pg_class p ON p.oid = i.inhparent "
        "JOIN pg_class c ON c.oid = i.inhrelid "
        "JOIN pg_namespace n ON n.oid = p.relnamespace "
        "WHERE n.nspname = :schema "
        "  AND p.relname = :parent "
        "ORDER BY c.relname"
    )

    try:
        with engine.connect() as conn:
            rows = conn.execute(
                list_partitions_sql,
                {"schema": schema, "parent": table_name},
            ).fetchall()
    except Exception as exc:
        logger.error(
            f"Failed to list partitions for {schema}.{table_name}: {exc}"
        )
        return 0

    dropped_count = 0

    for partition_name, bound_expr in rows:
        end_date = _parse_partition_end(bound_expr)

        if end_date is None:
            logger.warning(
                f"Could not parse bound expression for "
                f"{schema}.{partition_name}: {bound_expr!r} - skipping"
            )
            continue

        if end_date <= cutoff:
            drop_sql = text(f"DROP TABLE {schema}.{partition_name}")
            try:
                with engine.begin() as conn:
                    conn.execute(drop_sql)
                logger.info(
                    f"Dropped partition {schema}.{partition_name} "
                    f"(ended {end_date.isoformat()}, cutoff {cutoff.isoformat()})"
                )
                dropped_count += 1
            except Exception as exc:
                logger.error(
                    f"Failed to drop partition {schema}.{partition_name}: {exc}"
                )

    return dropped_count


def _parse_partition_end(bound_expr: str) -> Optional[date]:
    """
    Extract the exclusive upper-bound date from a partition's bound expression.

    PostgreSQL formats range partition bounds as text like:
        FOR VALUES FROM ('2026-05-01') TO ('2026-06-01')

    We split on " TO " and parse the date portion of the right side. The
    date portion may be a plain date ('2026-06-01') or a timestamp
    ('2026-06-01 00:00:00+00') depending on the column type - we accept
    either by taking only the leading YYYY-MM-DD substring.

    Args:
        bound_expr: The bound expression from pg_get_expr().

    Returns:
        date | None: The exclusive upper bound, or None if unparseable.
    """
    if not bound_expr or " TO " not in bound_expr:
        return None

    try:
        to_part = bound_expr.split(" TO ", 1)[1].strip()
        # to_part now looks like "('2026-06-01')" or "('2026-06-01 00:00:00+00')"
        to_part = to_part.strip("()")
        to_part = to_part.strip("'\"")
        # to_part is now "2026-06-01" or "2026-06-01 00:00:00+00"
        # Take only the YYYY-MM-DD portion.
        date_str = to_part.split(" ")[0].split("T")[0]
        return datetime.strptime(date_str, "%Y-%m-%d").date()
    except (ValueError, IndexError):
        return None


# ---------------------------------------------------------------------
# Calendar helpers
# ---------------------------------------------------------------------

def next_month(year: int, month: int) -> Tuple[int, int]:
    """
    Return the (year, month) tuple for the month following the input.

    Args:
        year: Four-digit year.
        month: 1-12.

    Returns:
        Tuple of (next_year, next_month).
    """
    if month == 12:
        return year + 1, 1
    return year, month + 1


def current_month() -> Tuple[int, int]:
    """Return the current (year, month) in UTC."""
    today = datetime.now(timezone.utc).date()
    return today.year, today.month