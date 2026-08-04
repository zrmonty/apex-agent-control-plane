# Apex lab installer entrypoint for Windows (PowerShell).
# Usage:
#   .\deploy\lab\install.ps1
#   .\deploy\lab\install.ps1 -Force -StartLiveMtls
#   .\deploy\lab\install.ps1 enroll -Agent my-bot
#   .\deploy\lab\install.ps1 status

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('install', 'enroll', 'status')]
    [string] $Command = 'install',

    [string] $Out = '',
    [string] $KeyId = 'operator-1',
    [string] $Agent = '',
    [string] $Workspace = 'lab',
    [string] $Namespace = 'demo',
    [ValidateSet('staging', 'production', 'local-development')]
    [string] $Profile = 'staging',
    [string] $IngestEndpoint = 'https://127.0.0.1:18445',
    [int] $ValidityDays = 90,
    [string] $DemoAgent = 'lab-demo',
    [switch] $Force,
    [switch] $SkipServicePki,
    [switch] $SkipDemoEnroll,
    [switch] $StartLiveMtls,
    [switch] $StartGatewayRef
)

$ErrorActionPreference = 'Stop'
$Here = $PSScriptRoot
$RepoRoot = (Resolve-Path (Join-Path $Here '..\..')).Path
$Installer = Join-Path $Here 'install_lab.py'

function Find-Python {
    foreach ($name in @('python', 'python3', 'py')) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        if ($name -eq 'py') {
            try {
                $ver = & py -3 -c "import sys; print(sys.version)" 2>$null
                if ($LASTEXITCODE -eq 0) { return @('py', '-3') }
            } catch { }
            continue
        }
        try {
            $ver = & $name -c "import sys; print(sys.version)" 2>$null
            if ($LASTEXITCODE -eq 0) { return @($name) }
        } catch { }
    }
    throw 'Python 3.11+ is required. Install from https://www.python.org/downloads/ and ensure python is on PATH.'
}

$Python = Find-Python
Write-Host "==> Python: $($Python -join ' ')"

Write-Host '==> Ensuring cryptography is installed'
$cryptoOk = $false
try {
    & @Python -c 'import cryptography' 2>$null
    if ($LASTEXITCODE -eq 0) { $cryptoOk = $true }
} catch { }
if (-not $cryptoOk) {
    & @Python -m pip install --user --quiet 'cryptography>=42' 2>$null
    if ($LASTEXITCODE -ne 0) {
        & @Python -m pip install --quiet 'cryptography>=42'
        if ($LASTEXITCODE -ne 0) { throw 'Failed to install Python package cryptography' }
    }
}

$pyArgs = @($Installer, $Command)
if ($Out) { $pyArgs += @('--out', $Out) }

switch ($Command) {
    'install' {
        $pyArgs += @('--key-id', $KeyId)
        $pyArgs += @('--workspace', $Workspace)
        $pyArgs += @('--namespace', $Namespace)
        $pyArgs += @('--profile', $Profile)
        $pyArgs += @('--ingest-endpoint', $IngestEndpoint)
        $pyArgs += @('--validity-days', "$ValidityDays")
        $pyArgs += @('--demo-agent', $DemoAgent)
        if ($Force) { $pyArgs += '--force' }
        if ($SkipServicePki) { $pyArgs += '--skip-service-pki' }
        if ($SkipDemoEnroll) { $pyArgs += '--skip-demo-enroll' }
        if ($StartLiveMtls) { $pyArgs += '--start-live-mtls' }
        if ($StartGatewayRef) { $pyArgs += '--start-gateway-ref' }
    }
    'enroll' {
        if (-not $Agent) { throw 'enroll requires -Agent <agent_code>' }
        $pyArgs += @('--agent', $Agent)
        $pyArgs += @('--key-id', $KeyId)
        $pyArgs += @('--workspace', $Workspace)
        $pyArgs += @('--namespace', $Namespace)
        $pyArgs += @('--profile', $Profile)
        $pyArgs += @('--ingest-endpoint', $IngestEndpoint)
        $pyArgs += @('--validity-days', "$ValidityDays")
        if ($Force) { $pyArgs += '--force' }
    }
    'status' { }
}

Write-Host "==> $($Python -join ' ') $($pyArgs -join ' ')"
& @Python @pyArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
