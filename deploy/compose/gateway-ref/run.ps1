# Build and run ingest-gateway against reference providers + NATS (local/CI).
$ErrorActionPreference = 'Stop'
$composeDir = Resolve-Path (Join-Path $PSScriptRoot '..')
$live = Join-Path $composeDir 'live-mtls'
Set-Location $live

Write-Host '==> Docker'
docker info --format '{{.ServerVersion}}' | Out-Null

Write-Host '==> PKI'
python -m pip install --user --quiet cryptography
python .\generate_pki.py --out .\secrets
python .\render_configs.py

# Gateway server identity: reuse NATS server cert for local SAN coverage of hostnames.
# Bearer token for file resolver.
if (-not (Test-Path .\secrets\ingest-bearer-token)) {
    Set-Content -Path .\secrets\ingest-bearer-token -Value "gateway-ref-token" -NoNewline
}

Write-Host '==> Gateway reference stack (build may take several minutes)'
Set-Location $composeDir
docker compose -f compose.gateway-ref.yaml down --remove-orphans 2>$null
docker compose -f compose.gateway-ref.yaml up -d --build
if ($LASTEXITCODE -ne 0) { throw 'gateway-ref compose failed' }

Write-Host '==> Waiting for gateway'
Start-Sleep -Seconds 15
docker compose -f compose.gateway-ref.yaml ps

Write-Host 'GATEWAY_REF_STACK_UP'
Write-Host 'Ingest (host): https://127.0.0.1:18445'
Write-Host 'Tear down: docker compose -f deploy/compose/compose.gateway-ref.yaml down'
