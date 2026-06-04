<#
.SYNOPSIS
    Idempotently create the openagent-network Docker network.

.DESCRIPTION
    Ensures the openagent-network Docker network exists on this host. Run
    this once per machine BEFORE 'docker compose up' so the compose
    file's external-network reference can resolve.

    Safe to run any number of times. If the network already exists the
    script reports "already exists" and exits with code 0. If anything
    else goes wrong (Docker not installed, daemon not reachable,
    network-create fails) it exits with code 1 and a clear message.

.NOTES
    openagent-logger owns the shared Docker network and the shared
    Postgres instance the other OpenAgent services attach to; this
    script creates that network. See README.

    Execution-policy note:
        PowerShell may refuse to run this script the first time with an
        "execution policy" error. Either bypass for one invocation:

            powershell -ExecutionPolicy Bypass -File .\scripts\setup-network.ps1

        or relax the policy once for your user account:

            Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

.EXAMPLE
    .\scripts\setup-network.ps1
#>

$ErrorActionPreference = 'Stop'
$NETWORK_NAME = 'openagent-network'


# ---------------------------------------------------------------------
# 1. Verify the docker command is on PATH
# ---------------------------------------------------------------------

try {
    $null = Get-Command docker -ErrorAction Stop
} catch {
    Write-Host "ERROR: 'docker' command not found." -ForegroundColor Red
    Write-Host "  Install Docker Desktop and ensure it is on PATH." -ForegroundColor Red
    exit 1
}


# ---------------------------------------------------------------------
# 2. Verify the Docker daemon is reachable
# ---------------------------------------------------------------------
#
# External commands in PowerShell do NOT throw exceptions on non-zero
# exit. We check $LASTEXITCODE explicitly.

docker info 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Docker daemon is not reachable." -ForegroundColor Red
    Write-Host "  Start Docker Desktop, then re-run this script." -ForegroundColor Red
    exit 1
}


# ---------------------------------------------------------------------
# 3. Check whether the network already exists
# ---------------------------------------------------------------------
#
# Listing all networks and comparing names locally avoids the regex
# quoting issues that come with the --filter 'name=^...$' approach
# across different PowerShell versions.

$networks = @(docker network ls --format '{{.Name}}')
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: 'docker network ls' failed." -ForegroundColor Red
    exit 1
}

if ($networks -contains $NETWORK_NAME) {
    Write-Host "OK: Docker network '$NETWORK_NAME' already exists." -ForegroundColor Green
    exit 0
}


# ---------------------------------------------------------------------
# 4. Create the network
# ---------------------------------------------------------------------

Write-Host "Creating Docker network '$NETWORK_NAME'..." -ForegroundColor Cyan
docker network create $NETWORK_NAME | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: 'docker network create $NETWORK_NAME' failed." -ForegroundColor Red
    exit 1
}

Write-Host "OK: Docker network '$NETWORK_NAME' created." -ForegroundColor Green
Write-Host ""
Write-Host "Next: 'docker compose up' will now be able to attach to this network." -ForegroundColor Gray
exit 0