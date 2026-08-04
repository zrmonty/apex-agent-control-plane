# Phase 0 durable-path E2E: providers + NATS + Postgres + live mTLS tests + Object-Lock.
# Windows: docker writes progress to stderr; do not treat that as a terminating error.
$ErrorActionPreference = 'Continue'
$composeDir = Resolve-Path (Join-Path $PSScriptRoot '..')
$live = Join-Path $composeDir 'live-mtls'
$failed = $false

function Assert-Exit([string]$step) {
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL: $step (exit $LASTEXITCODE)" -ForegroundColor Red
        $script:failed = $true
        return $false
    }
    return $true
}

Set-Location $live

Write-Host '==> Docker'
docker info --format '{{.ServerVersion}}' | Out-Null
if (-not (Assert-Exit 'docker info')) { exit 1 }

Write-Host '==> PKI + configs'
python -m pip install --user --quiet cryptography boto3 2>$null
python .\generate_pki.py --out .\secrets
if (-not (Assert-Exit 'generate_pki')) { exit 1 }
python .\render_configs.py
if (-not (Assert-Exit 'render_configs')) { exit 1 }

Write-Host '==> Start E2E stack (providers, NATS, Postgres, MinIO)'
Set-Location $composeDir
cmd /c "docker compose -f compose.e2e.yaml down --remove-orphans >nul 2>&1"
cmd /c "docker compose -f compose.e2e.yaml up -d"
if (-not (Assert-Exit 'compose.e2e up')) { exit 1 }
Start-Sleep -Seconds 12

Write-Host '==> Live mTLS stack (Valkey + NATS + reference providers for client tests)'
Set-Location $live
cmd /c "docker compose -f compose.yaml up -d"
if (-not (Assert-Exit 'live-mtls up')) {
    Write-Host 'WARN: live-mtls full stack failed; trying valkey only'
    cmd /c "docker compose -f compose.yaml up -d valkey"
}
Start-Sleep -Seconds 8

$env:APEX_LIVE_MTLS = '1'
$env:APEX_LIVE_MTLS_SECRETS = (Resolve-Path .\secrets).Path
$env:APEX_ALLOW_LOOPBACK_SINKS = '1'
$ingest = Resolve-Path (Join-Path $composeDir '..\..\apps\event-ingest')
Push-Location $ingest
try {
    Write-Host '==> Live mTLS client tests'
    cargo test --test live_mtls --features 'test-support,valkey' -- --nocapture
    if (-not (Assert-Exit 'live_mtls tests')) { }
}
finally {
    Pop-Location
}

Write-Host '==> PostgreSQL durability smoke (feature postgres)'
$env:APEX_POSTGRES_URL = 'postgres://apex:apex_e2e_local_only@127.0.0.1:15432/apex'
Push-Location $ingest
try {
    cargo test --lib --features 'postgres,test-support' postgres_ -- --nocapture
    if (-not (Assert-Exit 'postgres_ tests')) {
        cargo test --lib --features 'postgres,test-support' -- --nocapture
        Assert-Exit 'postgres lib tests' | Out-Null
    }
}
finally {
    Pop-Location
}

Write-Host '==> Object-Lock acceptance against MinIO'
$env:MINIO_ENDPOINT = 'http://127.0.0.1:19000'
$env:MINIO_ACCESS_KEY = 'apexminio'
$env:MINIO_SECRET_KEY = 'apexminio_e2e_local_only'
$env:MINIO_BUCKET = 'apex-events'
python (Join-Path $composeDir 'object_lock_acceptance.py')
if (-not (Assert-Exit 'object_lock_acceptance')) { }

Write-Host '==> Azure/GCS archive acceptance (optional without credentials)'
$env:APEX_CLOUD_ACCEPTANCE_OPTIONAL = '1'
python (Join-Path $composeDir 'object_lock_acceptance_azure.py')
if (-not (Assert-Exit 'azure acceptance')) { }
python (Join-Path $composeDir 'object_lock_acceptance_gcs.py')
if (-not (Assert-Exit 'gcs acceptance')) { }

if ($failed) {
    Write-Host 'E2E_PATH_FAILED' -ForegroundColor Red
    exit 1
}

Write-Host 'E2E_PATH_PASSED' -ForegroundColor Green
Write-Host 'Tear down: docker compose -f deploy/compose/compose.e2e.yaml down'
Write-Host '           docker compose -f deploy/compose/live-mtls/compose.yaml down'
exit 0
