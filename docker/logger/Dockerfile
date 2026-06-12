# syntax=docker/dockerfile:1.7

# ============================================================================
# openagent-logger - Dockerfile
# ============================================================================
#
# Container image for the openagent-logger HTTP service.
#
#   - Base:        python:3.11-slim
#   - User:        openagent (uid 1000, no shell, no home password)
#   - Listens on:  8003 (extends the OpenAgent port topology: 8000 frontend,
#                  8001 openagent-api, 8002 openagent-infra, 8003 openagent-logger)
#   - Healthcheck: GET /health with the X-API-Key header AND
#                  inspect the JSON body for `"status":"ok"`
#
# Build context is the project root, NOT this directory. The COPY
# instructions below resolve paths from the project root.
#
# Build:
#     docker build -t openagent-logger:latest -f docker/logger/Dockerfile .
#
# The companion docker-compose.yml references this file via
# `build.dockerfile: docker/logger/Dockerfile`.
# ============================================================================


FROM python:3.11-slim


# ----------------------------------------------------------------------------
# Image metadata (OCI standard labels)
# ----------------------------------------------------------------------------

LABEL org.opencontainers.image.title="openagent-logger" \
      org.opencontainers.image.description="Capture layer for the OpenAgent system" \
      org.opencontainers.image.vendor="William McKeon" \
      org.opencontainers.image.licenses="Apache-2.0"


# ----------------------------------------------------------------------------
# Environment
# ----------------------------------------------------------------------------
#
# PYTHONDONTWRITEBYTECODE / PYTHONUNBUFFERED  - standard Python-in-container
# PIP_NO_CACHE_DIR / PIP_DISABLE_PIP_VERSION_CHECK  - smaller, quieter pip
# LOGGER_PORT  - default port; overridable at runtime via env

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    LOGGER_PORT=8003


# ----------------------------------------------------------------------------
# OS dependencies
# ----------------------------------------------------------------------------
#
# - curl: required by HEALTHCHECK below
# - ca-certificates: lets curl/Python verify TLS for outbound calls
#
# Everything else stays out so the image is small. psycopg2-binary in
# requirements.txt ships compiled, so no build-essential needed.

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


# ----------------------------------------------------------------------------
# Non-root user
# ----------------------------------------------------------------------------
#
# UID 1000 is the conventional first non-root uid; keeping it consistent
# across the OpenAgent services means file permissions on any shared volume
# line up.

RUN groupadd --system --gid 1000 openagent \
    && useradd --system \
        --uid 1000 \
        --gid openagent \
        --shell /usr/sbin/nologin \
        --create-home \
        openagent


# ----------------------------------------------------------------------------
# Application
# ----------------------------------------------------------------------------

WORKDIR /app

# Install Python dependencies FIRST (separate layer) so source-code changes
# do not invalidate the pip-install cache.
COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

# Copy source.
COPY src/ /app/src/

# Ownership: everything readable by the runtime user.
RUN chown -R openagent:openagent /app


# ----------------------------------------------------------------------------
# Runtime
# ----------------------------------------------------------------------------

USER openagent

EXPOSE 8003

# Healthcheck calls /health with the X-API-Key the service expects AND
# inspects the response body for `"status":"ok"`. This is stricter than
# checking just the HTTP code because /health returns 200 even when the
# service reports itself as `unhealthy` or `degraded` (e.g. DB
# disconnected) - the nested status field is the real signal.
#
# Pipeline behavior:
#   - curl --fail   -> exits non-zero on HTTP 4xx/5xx (auth failure,
#                      server error). On HTTP success, body goes to stdout.
#   - grep -q       -> exits 0 if `"status":"ok"` is found in the body,
#                      non-zero otherwise.
#   - The pipeline's exit code is the exit code of grep (the last command),
#     so any of {curl fail, body missing "status":"ok"} -> non-zero ->
#     Docker marks the container unhealthy.
#
# --silent / --show-error: keep stdout to the body for grep, but still
# surface the underlying error in `docker inspect` output if it fails.
# start-period 30s: gives lifespan startup (DB probe, scheduler init)
# room to settle before the first probe counts toward failure.
#
# Manual probe from outside the container:
#     docker exec <name> sh -c 'curl -fsS \
#         -H "X-API-Key: ${LOGGER_API_KEY}" \
#         http://localhost:8003/health | grep -q "\"status\":\"ok\""'

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl --fail --silent --show-error \
        --header "X-API-Key: ${LOGGER_API_KEY}" \
        "http://localhost:${LOGGER_PORT}/health" \
        | grep -q '"status":"ok"' \
        || exit 1

# `exec uvicorn` makes uvicorn replace sh as PID 1 so that SIGTERM from
# Docker / Render reaches uvicorn directly and the FastAPI lifespan handler's
# shutdown_scheduler() actually runs.
#
# --workers 1 is REQUIRED, not incidental: the retention scheduler runs
# in-process (src/scheduler.py). With >1 worker each process would start its
# own scheduler and run retention concurrently. Pinning a single worker keeps
# exactly one scheduler. (A DB advisory lock guards the job as a backstop, but
# one worker is the intended topology - scale out with a dedicated instance.)
CMD ["sh", "-c", "exec uvicorn src.api:app --host 0.0.0.0 --port ${LOGGER_PORT} --workers 1"]
