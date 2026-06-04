-- =============================================================================
-- openagent-logger / database/init.sql
--
-- Bootstrap script for the openagent_logger schema in the shared OpenAgent
-- database (openagent_shared).
--
-- Creates:
--   1. openagent_logger role      (idempotent, password sourced from
--                                  the `logger.db_password` GUC at init time)
--   2. openagent_logger schema    (owned by the openagent_logger role)
--   3. Three parent partitioned tables, partitioned by RANGE (created_at):
--        - openagent_logger.ops_events             (short retention)
--        - openagent_logger.conversation_captures  (medium retention)
--        - openagent_logger.audit_events           (long retention)
--   4. Indexes on each parent table (auto-propagated to every partition)
--   5. Initial partitions for the current calendar month + the next month,
--      so the service has somewhere to write from the moment it boots
--   6. Schema-scoped grants for the openagent_logger role
--
-- The schema is scoped within a shared database so another service can later
-- share the same instance under its own schema and role without colliding with
-- this one. Schema separation gives loose coupling - no cross-schema foreign
-- keys, no shared tables, each service connects under its own role with grants
-- limited to its own schema.
--
-- Partition naming convention (must match src/partitioning.py):
--     <parent_table>_y<YYYY>m<MM>
--     e.g. ops_events_y2026m05
--
-- Idempotency:
--   This script can be re-run safely. Re-running on a populated schema is
--   a no-op for tables/indexes/partitions; the role password is re-applied
--   from `logger.db_password` on every run so `.env` is the single source
--   of truth.
--
-- Password handoff (no separate ALTER ROLE step required):
--   The `openagent_logger` role's password is read from the custom GUC
--   `logger.db_password`, which is set on the Postgres server via the
--   PGOPTIONS environment variable when the container starts. The README
--   step that brings up the shared Postgres passes:
--       -e PGOPTIONS="-c logger.db_password=<value-from-.env>"
--   so the value flows: .env -> docker run env -> PGOPTIONS -> server GUC
--   -> current_setting('logger.db_password') -> CREATE/ALTER ROLE.
--   If the GUC is missing or empty, this script aborts with a clear error
--   instead of creating an unusable role.
--
-- How this is executed:
--   * Local docker-compose / docker run: PostgreSQL's entrypoint runs all
--     .sql files in /docker-entrypoint-initdb.d/ on first container start,
--     as the POSTGRES_USER (superuser). PGOPTIONS is inherited by psql.
--   * Render: bootstrap by connecting as the admin user with PGOPTIONS set:
--       PGOPTIONS="-c logger.db_password=$LOGGER_DB_PASSWORD" \
--           psql "$DATABASE_URL" -f database/init.sql
--
-- This script must be kept in lockstep with src/models.py. Column names,
-- types, lengths, and indexes are mirrored on both sides.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- Extensions
-- -----------------------------------------------------------------------------
-- pgcrypto provides gen_random_uuid() on PostgreSQL < 13. On 13+ it's in core
-- but enabling the extension is harmless and keeps the script portable.

CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- -----------------------------------------------------------------------------
-- Role: openagent_logger
-- -----------------------------------------------------------------------------
-- Password is read from the `logger.db_password` GUC at init time. The
-- GUC is supplied by the Postgres container's PGOPTIONS env var, sourced
-- from LOGGER_DB_PASSWORD in .env (see README §"Prerequisites").
--
-- On first run:  the role is created with the GUC value as its password.
-- On re-runs:    the role's password is re-set to the current GUC value,
--                keeping `.env` and the database in sync.
-- If GUC unset:  the script aborts with a clear error - no silent fallback
--                to a placeholder, no unauthenticatable role left behind.

DO $$
DECLARE
    role_password TEXT;
    role_exists   BOOLEAN;
BEGIN
    -- current_setting(..., true) returns NULL if the GUC is missing
    -- instead of raising an error. We handle the missing case ourselves
    -- so we can give a useful message.
    role_password := current_setting('logger.db_password', true);

    IF role_password IS NULL OR role_password = '' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'invalid_parameter_value',
            MESSAGE = 'Required GUC ''logger.db_password'' is not set.',
            DETAIL  = 'openagent-logger init.sql expects the openagent_logger role''s '
                      'password to be supplied via the PGOPTIONS env var on '
                      'the Postgres container, e.g. '
                      '-e PGOPTIONS="-c logger.db_password=$LOGGER_DB_PASSWORD".',
            HINT    = 'See README §"Prerequisites: shared infrastructure" '
                      'for the docker run command.';
    END IF;

    SELECT EXISTS(
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'openagent_logger'
    ) INTO role_exists;

    IF role_exists THEN
        EXECUTE FORMAT(
            'ALTER ROLE openagent_logger WITH PASSWORD %L',
            role_password
        );
        RAISE NOTICE 'Role openagent_logger already existed; password re-applied from logger.db_password.';
    ELSE
        EXECUTE FORMAT(
            'CREATE ROLE openagent_logger '
            'WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT '
            'PASSWORD %L',
            role_password
        );
        RAISE NOTICE 'Created role openagent_logger with password from logger.db_password.';
    END IF;
END
$$;


-- -----------------------------------------------------------------------------
-- Schema: openagent_logger
-- -----------------------------------------------------------------------------

CREATE SCHEMA IF NOT EXISTS openagent_logger AUTHORIZATION openagent_logger;

COMMENT ON SCHEMA openagent_logger IS
    'Capture layer for the OpenAgent system: operational events, conversation '
    'captures, and audit events. Append-only, monthly-partitioned tables.';


-- =============================================================================
-- Parent table: openagent_logger.ops_events
-- =============================================================================
-- Short-retention operational telemetry (~90 days).
-- Examples: request_received, auth_failure, upstream_call, upstream_error,
-- client_disconnect, stream_complete.
--
-- Partition key: created_at. Primary key includes created_at because
-- PostgreSQL requires the partition key in every PK / UNIQUE constraint
-- on a partitioned table.

CREATE TABLE IF NOT EXISTS openagent_logger.ops_events (
    -- Envelope (common to every event table)
    event_id          UUID         NOT NULL DEFAULT gen_random_uuid(),
    request_id        UUID         NOT NULL,
    source_service    VARCHAR(64)  NOT NULL,
    created_at        TIMESTAMPTZ  NOT NULL,
    client_timestamp  TIMESTAMPTZ  NOT NULL,
    session_id        VARCHAR(64),
    user_id           UUID,
    hmac_signature    VARCHAR(64)  NOT NULL,
    retention_class   VARCHAR(16)  NOT NULL DEFAULT 'short',

    -- Per-type columns
    action            VARCHAR(128) NOT NULL,
    outcome           VARCHAR(32)  NOT NULL,
    details           JSONB        NOT NULL DEFAULT '{}'::jsonb,

    PRIMARY KEY (event_id, created_at)
) PARTITION BY RANGE (created_at);

COMMENT ON TABLE openagent_logger.ops_events IS
    'Short-retention operational telemetry. Monthly partitions; the daily '
    'scheduler in src/scheduler.py drops partitions older than the '
    'configured retention window (default 90 days).';

-- Envelope-column single-column indexes (parent indexes propagate to children)
CREATE INDEX IF NOT EXISTS ix_ops_events_request_id
    ON openagent_logger.ops_events (request_id);
CREATE INDEX IF NOT EXISTS ix_ops_events_source_service
    ON openagent_logger.ops_events (source_service);
CREATE INDEX IF NOT EXISTS ix_ops_events_created_at
    ON openagent_logger.ops_events (created_at);
CREATE INDEX IF NOT EXISTS ix_ops_events_session_id
    ON openagent_logger.ops_events (session_id);
CREATE INDEX IF NOT EXISTS ix_ops_events_user_id
    ON openagent_logger.ops_events (user_id);

-- Composite indexes from src/models.py __table_args__
CREATE INDEX IF NOT EXISTS ix_ops_events_session_created
    ON openagent_logger.ops_events (session_id, created_at);
CREATE INDEX IF NOT EXISTS ix_ops_events_service_created
    ON openagent_logger.ops_events (source_service, created_at);
CREATE INDEX IF NOT EXISTS ix_ops_events_action_created
    ON openagent_logger.ops_events (action, created_at);


-- =============================================================================
-- Parent table: openagent_logger.conversation_captures
-- =============================================================================
-- Full /chat call captures (~180 days), stored for observability and audit.
-- The schema is model-agnostic - the model identifier is recorded per row in
-- the model_used column.

CREATE TABLE IF NOT EXISTS openagent_logger.conversation_captures (
    -- Envelope
    event_id          UUID         NOT NULL DEFAULT gen_random_uuid(),
    request_id        UUID         NOT NULL,
    source_service    VARCHAR(64)  NOT NULL,
    created_at        TIMESTAMPTZ  NOT NULL,
    client_timestamp  TIMESTAMPTZ  NOT NULL,
    session_id        VARCHAR(64),
    user_id           UUID,
    hmac_signature    VARCHAR(64)  NOT NULL,
    retention_class   VARCHAR(16)  NOT NULL DEFAULT 'medium',

    -- Per-type columns
    input_text        TEXT         NOT NULL,
    output_text       TEXT         NOT NULL,
    input_hash        VARCHAR(64)  NOT NULL,
    output_hash       VARCHAR(64)  NOT NULL,
    model_used        VARCHAR(255),
    reasoning_effort  VARCHAR(16),
    latency_ms        INTEGER,
    input_tokens      INTEGER,
    output_tokens     INTEGER,

    PRIMARY KEY (event_id, created_at)
) PARTITION BY RANGE (created_at);

COMMENT ON TABLE openagent_logger.conversation_captures IS
    'Captured /chat conversations for observability and audit. Monthly '
    'partitions; default retention 180 days. PII stripping, if required, '
    'happens downstream, not here.';

-- Envelope-column single-column indexes
CREATE INDEX IF NOT EXISTS ix_capture_request_id
    ON openagent_logger.conversation_captures (request_id);
CREATE INDEX IF NOT EXISTS ix_capture_source_service
    ON openagent_logger.conversation_captures (source_service);
CREATE INDEX IF NOT EXISTS ix_capture_created_at
    ON openagent_logger.conversation_captures (created_at);
CREATE INDEX IF NOT EXISTS ix_capture_session_id
    ON openagent_logger.conversation_captures (session_id);
CREATE INDEX IF NOT EXISTS ix_capture_user_id
    ON openagent_logger.conversation_captures (user_id);

-- Composite indexes from src/models.py __table_args__
CREATE INDEX IF NOT EXISTS ix_capture_session_created
    ON openagent_logger.conversation_captures (session_id, created_at);
CREATE INDEX IF NOT EXISTS ix_capture_user_created
    ON openagent_logger.conversation_captures (user_id, created_at);
CREATE INDEX IF NOT EXISTS ix_capture_input_hash
    ON openagent_logger.conversation_captures (input_hash);


-- =============================================================================
-- Parent table: openagent_logger.audit_events
-- =============================================================================
-- Security-relevant action records (~7 years, compliance-driven).
-- Examples: key_rotation, secret_changed, admin_endpoint_hit,
-- retention_job_run, auth_threshold_crossed.

CREATE TABLE IF NOT EXISTS openagent_logger.audit_events (
    -- Envelope
    event_id          UUID         NOT NULL DEFAULT gen_random_uuid(),
    request_id        UUID         NOT NULL,
    source_service    VARCHAR(64)  NOT NULL,
    created_at        TIMESTAMPTZ  NOT NULL,
    client_timestamp  TIMESTAMPTZ  NOT NULL,
    session_id        VARCHAR(64),
    user_id           UUID,
    hmac_signature    VARCHAR(64)  NOT NULL,
    retention_class   VARCHAR(16)  NOT NULL DEFAULT 'long',

    -- Per-type columns
    actor             VARCHAR(128) NOT NULL,
    action            VARCHAR(128) NOT NULL,
    target            VARCHAR(255),
    outcome           VARCHAR(32)  NOT NULL,
    ip_address        INET,
    details           JSONB        NOT NULL DEFAULT '{}'::jsonb,

    PRIMARY KEY (event_id, created_at)
) PARTITION BY RANGE (created_at);

COMMENT ON TABLE openagent_logger.audit_events IS
    'Compliance-grade audit log. Monthly partitions; default retention '
    '~7 years (2555 days). Append-only - every row is intended to survive '
    'for compliance review.';

-- Envelope-column single-column indexes
CREATE INDEX IF NOT EXISTS ix_audit_request_id
    ON openagent_logger.audit_events (request_id);
CREATE INDEX IF NOT EXISTS ix_audit_source_service
    ON openagent_logger.audit_events (source_service);
CREATE INDEX IF NOT EXISTS ix_audit_created_at
    ON openagent_logger.audit_events (created_at);
CREATE INDEX IF NOT EXISTS ix_audit_session_id
    ON openagent_logger.audit_events (session_id);
CREATE INDEX IF NOT EXISTS ix_audit_user_id
    ON openagent_logger.audit_events (user_id);

-- Composite indexes from src/models.py __table_args__
CREATE INDEX IF NOT EXISTS ix_audit_actor_created
    ON openagent_logger.audit_events (actor, created_at);
CREATE INDEX IF NOT EXISTS ix_audit_action_created
    ON openagent_logger.audit_events (action, created_at);
CREATE INDEX IF NOT EXISTS ix_audit_outcome_created
    ON openagent_logger.audit_events (outcome, created_at);


-- =============================================================================
-- Initial partitions: current calendar month and next calendar month
-- =============================================================================
-- The retention scheduler in src/scheduler.py creates next-month partitions
-- daily, but we still need partitions to exist NOW so the first inbound
-- event after deploy has somewhere to land.
--
-- Partition names follow the convention in src/partitioning.py:
--     <parent_table>_y<YYYY>m<MM>

DO $$
DECLARE
    cur_year      INT;
    cur_month     INT;
    nxt_year      INT;
    nxt_month     INT;

    cur_start     DATE;
    cur_end       DATE;
    nxt_start     DATE;
    nxt_end       DATE;

    cur_suffix    TEXT;
    nxt_suffix    TEXT;

    parent_tables TEXT[] := ARRAY['ops_events', 'conversation_captures', 'audit_events'];
    parent_name   TEXT;
BEGIN
    cur_year  := EXTRACT(YEAR  FROM CURRENT_DATE)::INT;
    cur_month := EXTRACT(MONTH FROM CURRENT_DATE)::INT;

    IF cur_month = 12 THEN
        nxt_year  := cur_year + 1;
        nxt_month := 1;
    ELSE
        nxt_year  := cur_year;
        nxt_month := cur_month + 1;
    END IF;

    -- Half-open ranges: [start, end)
    cur_start := MAKE_DATE(cur_year, cur_month, 1);
    cur_end   := MAKE_DATE(nxt_year, nxt_month, 1);
    nxt_start := cur_end;

    IF nxt_month = 12 THEN
        nxt_end := MAKE_DATE(nxt_year + 1, 1, 1);
    ELSE
        nxt_end := MAKE_DATE(nxt_year, nxt_month + 1, 1);
    END IF;

    cur_suffix := FORMAT(
        'y%sm%s',
        LPAD(cur_year::TEXT,  4, '0'),
        LPAD(cur_month::TEXT, 2, '0')
    );
    nxt_suffix := FORMAT(
        'y%sm%s',
        LPAD(nxt_year::TEXT,  4, '0'),
        LPAD(nxt_month::TEXT, 2, '0')
    );

    RAISE NOTICE 'Creating initial partitions:';
    RAISE NOTICE '  current month: % [% to %)', cur_suffix, cur_start, cur_end;
    RAISE NOTICE '  next month:    % [% to %)', nxt_suffix, nxt_start, nxt_end;

    FOREACH parent_name IN ARRAY parent_tables LOOP
        -- Current month
        EXECUTE FORMAT(
            'CREATE TABLE IF NOT EXISTS %I.%I '
            'PARTITION OF %I.%I '
            'FOR VALUES FROM (%L) TO (%L)',
            'openagent_logger',
            parent_name || '_' || cur_suffix,
            'openagent_logger',
            parent_name,
            cur_start,
            cur_end
        );
        RAISE NOTICE '  ensured: openagent_logger.%_%', parent_name, cur_suffix;

        -- Next month
        EXECUTE FORMAT(
            'CREATE TABLE IF NOT EXISTS %I.%I '
            'PARTITION OF %I.%I '
            'FOR VALUES FROM (%L) TO (%L)',
            'openagent_logger',
            parent_name || '_' || nxt_suffix,
            'openagent_logger',
            parent_name,
            nxt_start,
            nxt_end
        );
        RAISE NOTICE '  ensured: openagent_logger.%_%', parent_name, nxt_suffix;
    END LOOP;
END
$$;


-- =============================================================================
-- Ownership: transfer everything in openagent_logger to the openagent_logger role
-- =============================================================================
-- If init.sql was run by a superuser, the parent tables and the initial
-- partitions are owned by that superuser. We want openagent_logger to own
-- them so the daily scheduler can DROP expired partitions at runtime
-- (DROP TABLE requires being the owner).
--
-- New partitions created at runtime by openagent-logger inherit ownership
-- naturally because the service connects as the openagent_logger role.

DO $$
DECLARE
    rec RECORD;
    owned_count INT := 0;
BEGIN
    FOR rec IN
        SELECT c.relname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'openagent_logger'
          AND c.relkind IN ('r', 'p')  -- regular table OR partitioned (parent) table
    LOOP
        EXECUTE FORMAT(
            'ALTER TABLE %I.%I OWNER TO %I',
            'openagent_logger',
            rec.relname,
            'openagent_logger'
        );
        owned_count := owned_count + 1;
    END LOOP;

    RAISE NOTICE 'Transferred ownership of % object(s) to openagent_logger', owned_count;
END
$$;


-- =============================================================================
-- Grants for the openagent_logger role
-- =============================================================================
-- Append-only by grant: SELECT and INSERT only. No UPDATE, no DELETE.
-- This enforces the append-only design at the database layer - even a
-- compromised service token can not silently rewrite or remove rows.
--
-- DROP TABLE on partitions is permitted because openagent_logger OWNS the
-- partition tables (set by the ownership block above). Ownership rights
-- and DML grants are separate concepts in PostgreSQL.
--
-- CREATE on the schema is required so the runtime scheduler can create
-- next-month partitions on demand.

GRANT USAGE  ON SCHEMA openagent_logger TO openagent_logger;
GRANT CREATE ON SCHEMA openagent_logger TO openagent_logger;

GRANT SELECT, INSERT ON ALL TABLES    IN SCHEMA openagent_logger TO openagent_logger;
GRANT USAGE          ON ALL SEQUENCES IN SCHEMA openagent_logger TO openagent_logger;

-- Future objects in the schema (partitions created by the scheduler,
-- additional tables added later) inherit the same grants automatically.
ALTER DEFAULT PRIVILEGES IN SCHEMA openagent_logger
    GRANT SELECT, INSERT ON TABLES TO openagent_logger;
ALTER DEFAULT PRIVILEGES IN SCHEMA openagent_logger
    GRANT USAGE ON SEQUENCES TO openagent_logger;


-- =============================================================================
-- Completion summary
-- =============================================================================

DO $$
DECLARE
    parent_count    INT;
    partition_count INT;
    index_count     INT;
BEGIN
    SELECT COUNT(*) INTO parent_count
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'openagent_logger' AND c.relkind = 'p';

    SELECT COUNT(*) INTO partition_count
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'openagent_logger' AND c.relkind = 'r';

    SELECT COUNT(*) INTO index_count
    FROM pg_indexes
    WHERE schemaname = 'openagent_logger';

    RAISE NOTICE '';
    RAISE NOTICE '====================================================================';
    RAISE NOTICE 'openagent-logger schema initialization complete.';
    RAISE NOTICE '  Schema:             openagent_logger';
    RAISE NOTICE '  Role:               openagent_logger (password from logger.db_password GUC)';
    RAISE NOTICE '  Parent tables:      %', parent_count;
    RAISE NOTICE '  Initial partitions: %', partition_count;
    RAISE NOTICE '  Indexes (all):      %', index_count;
    RAISE NOTICE '====================================================================';
END
$$;