$ErrorActionPreference = 'Stop'

$composeDir = $PSScriptRoot
$envPath = Join-Path $composeDir '.env'
if (-not (Test-Path -LiteralPath $envPath -PathType Leaf)) {
    throw "Compose preflight: missing $envPath. Copy .env.example to .env and replace every placeholder."
}

$values = @{}
foreach ($line in Get-Content -LiteralPath $envPath) {
    if ($line -match '^\s*#' -or $line -match '^\s*$') { continue }
    $parts = $line -split '=', 2
    if ($parts.Count -ne 2) { throw "Compose preflight: malformed .env line; expected KEY=VALUE." }
    $values[$parts[0].Trim()] = $parts[1].Trim()
}

$imageKeys = @('APEX_INGEST_IMAGE', 'APEX_CONTROL_IMAGE', 'NATS_IMAGE', 'CLICKHOUSE_IMAGE', 'MINIO_IMAGE', 'MINIO_MC_IMAGE', 'CLICKHOUSE_API_IMAGE', 'ARCHIVE_API_IMAGE')
foreach ($key in $imageKeys) {
    $value = $values[$key]
    if ([string]::IsNullOrWhiteSpace($value) -or $value -match 'REPLACE_WITH' -or $value -notmatch '@sha256:[0-9a-fA-F]{64}$') {
        throw "Compose preflight: $key must be an approved image pinned by a 64-hex SHA-256 digest."
    }
}

$secretKeys = @(
    'GATEWAY_SERVER_CERT_FILE', 'GATEWAY_SERVER_KEY_FILE', 'GATEWAY_CLIENT_CA_FILE',
    'CONTROL_SERVER_CERT_FILE', 'CONTROL_SERVER_KEY_FILE', 'CONTROL_CLIENT_CA_FILE',
    'CONTROL_OPERATOR_TOKENS_FILE',
    'CONTROL_NATS_CLIENT_CERT_FILE', 'CONTROL_NATS_CLIENT_KEY_FILE',
    'CONTROL_NATS_USERNAME_FILE', 'CONTROL_NATS_PASSWORD_FILE',
    'INGEST_BEARER_TOKEN_FILE', 'NATS_USERNAME_FILE', 'NATS_PASSWORD_FILE',
    'INGEST_NATS_CLIENT_CERT_FILE', 'INGEST_NATS_CLIENT_KEY_FILE',
    'INGEST_CLICKHOUSE_CLIENT_CERT_FILE', 'INGEST_CLICKHOUSE_CLIENT_KEY_FILE',
    'ARCHIVE_CLIENT_CA_FILE', 'INGEST_ARCHIVE_CLIENT_CERT_FILE', 'INGEST_ARCHIVE_CLIENT_KEY_FILE',
    'NATS_CONFIG_FILE', 'CLICKHOUSE_USERS_CONFIG_FILE', 'CLICKHOUSE_TLS_CONFIG_FILE',
    'CLICKHOUSE_SERVER_CERT_FILE', 'CLICKHOUSE_SERVER_KEY_FILE', 'CLICKHOUSE_CLIENT_CA_FILE',
    'MINIO_ROOT_USER_FILE', 'MINIO_ROOT_PASSWORD_FILE', 'MINIO_SERVER_CERT_FILE',
    'MINIO_SERVER_KEY_FILE', 'MINIO_SERVER_CA_FILE', 'NATS_SERVER_CERT_FILE', 'NATS_SERVER_KEY_FILE',
    'CLICKHOUSE_API_SERVER_CERT_FILE', 'CLICKHOUSE_API_SERVER_KEY_FILE', 'CLICKHOUSE_API_CLIENT_CA_FILE',
    'CLICKHOUSE_WRITER_CERT_FILE', 'CLICKHOUSE_WRITER_KEY_FILE',
    'ARCHIVE_API_SERVER_CERT_FILE', 'ARCHIVE_API_SERVER_KEY_FILE', 'ARCHIVE_API_CLIENT_CA_FILE',
    'ARCHIVE_WRITER_CERT_FILE', 'ARCHIVE_WRITER_KEY_FILE',
    'ARCHIVE_BACKEND_ACCESS_KEY_FILE', 'ARCHIVE_BACKEND_SECRET_KEY_FILE'
)
foreach ($key in $secretKeys) {
    $rawPath = $values[$key]
    if ([string]::IsNullOrWhiteSpace($rawPath) -or $rawPath -match 'REPLACE_WITH') {
        throw "Compose preflight: $key is missing or still contains a placeholder."
    }
    $candidate = if ([System.IO.Path]::IsPathRooted($rawPath)) { $rawPath } else { Join-Path $composeDir $rawPath }
    $resolved = [System.IO.Path]::GetFullPath($candidate)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "Compose preflight: secret file for $key does not exist."
    }
}

$agentId = $values['APEX_BEARER_AGENT_ID']
if ([string]::IsNullOrWhiteSpace($agentId) -or $agentId -notmatch '^[A-Za-z0-9._:-]{1,256}$' -or $agentId.Contains('..')) {
    throw 'Compose preflight: APEX_BEARER_AGENT_ID must be a safe 1-256 character workload identifier.'
}
$bearerCertSha256 = $values['APEX_BEARER_CERT_SHA256']
if ([string]::IsNullOrWhiteSpace($bearerCertSha256) -or $bearerCertSha256 -notmatch '^[A-Fa-f0-9]{64}$') {
    throw 'Compose preflight: APEX_BEARER_CERT_SHA256 must be exactly 64 hexadecimal characters.'
}
$providerCertSha256 = $values['APEX_PROVIDER_CLIENT_CERT_SHA256']
if ([string]::IsNullOrWhiteSpace($providerCertSha256) -or $providerCertSha256 -notmatch '^[A-Fa-f0-9]{64}$') {
    throw 'Compose preflight: APEX_PROVIDER_CLIENT_CERT_SHA256 must be exactly 64 hexadecimal characters.'
}

if ($values['APEX_ARCHIVE_REQUIRE_OBJECT_LOCK'] -notin @('true', 'false')) {
    throw 'Compose preflight: APEX_ARCHIVE_REQUIRE_OBJECT_LOCK must be explicitly true or false.'
}
if ($values['APEX_ARCHIVE_BUCKET'] -notmatch '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$') {
    throw 'Compose preflight: APEX_ARCHIVE_BUCKET must be a lowercase DNS-safe bucket name.'
}

$bind = if ([string]::IsNullOrWhiteSpace($values['APEX_INGEST_BIND'])) { '127.0.0.1' } else { $values['APEX_INGEST_BIND'] }
$allowNonLocal = $values['APEX_ALLOW_NONLOCAL_INGEST_BIND'] -eq 'true'
if ($bind -notin @('127.0.0.1', '::1', 'localhost') -and -not $allowNonLocal) {
    throw 'Compose preflight: APEX_INGEST_BIND is non-local; set APEX_ALLOW_NONLOCAL_INGEST_BIND=true only with an approved network policy and client-certificate boundary.'
}
if ($allowNonLocal -and $bind -in @('0.0.0.0', '::')) {
    Write-Warning 'Compose preflight: ingest is exposed on every interface; verify firewalling and mTLS before continuing.'
}

# Separate gate for the OOB control gateway's published port. Acknowledging
# that ingest may be reached off-host is not the same decision as
# acknowledging it for the channel that can stop, pause, or inject into a
# running agent.
$controlBind = if ([string]::IsNullOrWhiteSpace($values['APEX_CONTROL_BIND'])) { '127.0.0.1' } else { $values['APEX_CONTROL_BIND'] }
$allowNonLocalControl = $values['APEX_ALLOW_NONLOCAL_CONTROL_BIND'] -eq 'true'
if ($controlBind -notin @('127.0.0.1', '::1', 'localhost') -and -not $allowNonLocalControl) {
    throw 'Compose preflight: APEX_CONTROL_BIND is non-local; set APEX_ALLOW_NONLOCAL_CONTROL_BIND=true only with an approved network policy and operator client certificates issued.'
}
if ($allowNonLocalControl -and $controlBind -in @('0.0.0.0', '::')) {
    Write-Warning 'Compose preflight: the out-of-band control channel is exposed on every interface; verify firewalling and operator certificate issuance before continuing.'
}

docker info --format '{{.ServerVersion}}' *> $null
if ($LASTEXITCODE -ne 0) {
    throw 'Compose preflight: Docker daemon is unavailable. Start Docker Desktop or the configured daemon.'
}

docker compose --env-file $envPath -f (Join-Path $composeDir 'compose.yaml') config --quiet
if ($LASTEXITCODE -ne 0) { throw 'Compose preflight: rendered Compose configuration is invalid.' }
Write-Output 'Compose preflight passed; no secret values were printed.'
