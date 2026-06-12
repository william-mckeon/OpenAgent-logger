#!/usr/bin/env bash
#
# Idempotently create the openagent-network Docker network.
#
# Ensures the openagent-network Docker network exists on this host. Run this
# once per machine BEFORE 'docker compose up' so the compose file's
# external-network reference can resolve.
#
# Safe to run any number of times. If the network already exists the script
# reports "already exists" and exits 0. If anything else goes wrong (Docker not
# installed, daemon not reachable, network-create fails) it exits 1 with a
# clear message.
#
# This is the bash counterpart of scripts/setup-network.ps1.
#
# openagent-logger owns the shared Docker network and the shared Postgres
# instance the other OpenAgent services attach to; this script creates that
# network. See README.
#
# Usage:
#     ./scripts/setup-network.sh

set -euo pipefail

NETWORK_NAME='openagent-network'

# ---------------------------------------------------------------------
# 1. Verify the docker command is on PATH
# ---------------------------------------------------------------------

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: 'docker' command not found." >&2
    echo "  Install Docker and ensure it is on PATH." >&2
    exit 1
fi

# ---------------------------------------------------------------------
# 2. Verify the Docker daemon is reachable
# ---------------------------------------------------------------------

if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker daemon is not reachable." >&2
    echo "  Start Docker, then re-run this script." >&2
    exit 1
fi

# ---------------------------------------------------------------------
# 3. Create the network idempotently
# ---------------------------------------------------------------------
#
# 'docker network inspect' succeeds (exit 0) only if the network exists, so it
# is a clean existence test that avoids name-matching pitfalls.

if docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
    echo "OK: Docker network '$NETWORK_NAME' already exists."
    exit 0
fi

echo "Creating Docker network '$NETWORK_NAME'..."
if ! docker network create "$NETWORK_NAME" >/dev/null; then
    echo "ERROR: 'docker network create $NETWORK_NAME' failed." >&2
    exit 1
fi

echo "OK: Docker network '$NETWORK_NAME' created."
echo "Next: 'docker compose up' will now be able to attach to this network."
exit 0
