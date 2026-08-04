# Bootstrap PKI, start live mTLS stack, run Rust handshake tests, tear down.
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
Set-Location $here

Write-Host "==> Checking Docker daemon"
docker info --format '{{.ServerVersion}}' | Out-Null

Write-Host "==> Installing cryptography for PKI generation (user scope)"
python -m pip install --user --quiet cryptography

Write-Host "==> Generating local-dev PKI"
python .\generate_pki.py --out .\secrets

Write-Host "==> Rendering Valkey/NATS configs"
python .\render_configs.py

Write-Host "==> Starting live mTLS stack"
docker compose -f compose.yaml down --remove-orphans 2>$null
docker compose -f compose.yaml up -d

Write-Host "==> Waiting for services"
$deadline = (Get-Date).AddMinutes(2)
do {
    $valkey = docker compose -f compose.yaml ps --status running --services
    if ($valkey -match 'valkey' -and $valkey -match 'jetstream' -and $valkey -match 'clickhouse' -and $valkey -match 'archive') {
        break
    }
    Start-Sleep -Seconds 2
} while ((Get-Date) -lt $deadline)

# Extra settle time for TLS listeners
Start-Sleep -Seconds 5

Write-Host "==> Running live mTLS tests"
$env:APEX_LIVE_MTLS = '1'
$env:APEX_LIVE_MTLS_SECRETS = (Resolve-Path .\secrets).Path
$env:APEX_ALLOW_LOOPBACK_SINKS = '1'
$ingest = Resolve-Path ..\..\..\apps\event-ingest
Push-Location $ingest
try {
    cargo test --test live_mtls --features "test-support,valkey" -- --nocapture
    if ($LASTEXITCODE -ne 0) { throw "live_mtls tests failed with exit $LASTEXITCODE" }
}
finally {
    Pop-Location
}

Write-Host "==> Live mTLS handshake suite passed"
Write-Host "Stack is still running. Tear down with:"
Write-Host "  docker compose -f $here\compose.yaml down"
