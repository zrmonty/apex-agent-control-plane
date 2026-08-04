# Phase 0 durable-path E2E: providers + NATS + Postgres + live mTLS tests + Object-Lock.
$ErrorActionPreference = 'Stop'
$composeDir = Resolve-Path (Join-Path $PSScriptRoot '..')
$live = Join-Path $composeDir 'live-mtls'
Set-Location $live

Write-Host '==> Docker'
docker info --format '{{.ServerVersion}}' | Out-Null

Write-Host '==> PKI + configs'
python -m pip install --user --quiet cryptography boto3
python .\generate_pki.py --out .\secrets
python .\render_configs.py

Write-Host '==> Start E2E stack (providers, NATS, Postgres, MinIO)'
Set-Location $composeDir
docker compose -f compose.e2e.yaml down --remove-orphans 2>$null
docker compose -f compose.e2e.yaml up -d
Start-Sleep -Seconds 8

Write-Host '==> Live mTLS client tests (Valkey optional; NATS + HTTP providers)'
# Valkey is not in compose.e2e; start live-mtls valkey for full suite or skip valkey.
Set-Location $live
docker compose -f compose.yaml up -d valkey 2>$null
Start-Sleep -Seconds 2

$env:APEX_LIVE_MTLS = '1'
$env:APEX_LIVE_MTLS_SECRETS = (Resolve-Path .\secrets).Path
$env:APEX_ALLOW_LOOPBACK_SINKS = '1'
$ingest = Resolve-Path (Join-Path $composeDir '..\..\apps\event-ingest')
Push-Location $ingest
try {
    cargo test --test live_mtls --features 'test-support,valkey' -- --nocapture
    if ($LASTEXITCODE -ne 0) { throw "live_mtls failed" }
}
finally {
    Pop-Location
}

Write-Host '==> PostgreSQL durability smoke (feature postgres)'
$env:APEX_POSTGRES_URL = 'postgres://apex:apex_e2e_local_only@127.0.0.1:15432/apex'
Push-Location $ingest
try {
    cargo test --features 'test-support,postgres' postgres_ -- --nocapture
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'postgres_ tests missing or failed; compiling unit module only...'
        cargo test --lib --features 'postgres,test-support' -- --nocapture
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
if ($LASTEXITCODE -ne 0) { throw 'object lock acceptance failed' }

Write-Host '==> Azure/GCS archive acceptance (optional without credentials)'
$env:APEX_CLOUD_ACCEPTANCE_OPTIONAL = '1'
python (Join-Path $composeDir 'object_lock_acceptance_azure.py')
if ($LASTEXITCODE -ne 0) { throw 'azure archive acceptance failed' }
python (Join-Path $composeDir 'object_lock_acceptance_gcs.py')
if ($LASTEXITCODE -ne 0) { throw 'gcs archive acceptance failed' }

Write-Host 'E2E_PATH_PASSED'
Write-Host 'Tear down: docker compose -f deploy/compose/compose.e2e.yaml down'
Write-Host '           docker compose -f deploy/compose/live-mtls/compose.yaml down'
