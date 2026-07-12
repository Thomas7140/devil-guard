[CmdletBinding()]
param(
    [string]$BinaryPath = '',
    [string]$GatekeeperUrl = '',
    [string]$GatekeeperToken = ''
)

$ErrorActionPreference = 'Stop'
$serviceName = 'DevilGuardSentinel'
$displayName = 'Devil-Guard Sentinel'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}

if ([string]::IsNullOrWhiteSpace($BinaryPath)) {
    $scriptParent = Split-Path -Parent $PSScriptRoot
    $publishRoot = Split-Path -Parent $scriptParent
    $candidates = @(
        (Join-Path $scriptParent 'Sentinel\DevilGuard.Sentinel.exe'),
        (Join-Path $publishRoot 'Sentinel\DevilGuard.Sentinel.exe'),
        (Join-Path $scriptParent 'DevilGuard.Sentinel.exe')
    )
    $BinaryPath = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}

if ([string]::IsNullOrWhiteSpace($BinaryPath)) {
    throw 'Sentinel executable was not found. Supply -BinaryPath explicitly.'
}

$binary = [IO.Path]::GetFullPath($BinaryPath)
if (-not (Test-Path -LiteralPath $binary)) {
    throw "Sentinel executable not found: $binary"
}

if (-not [string]::IsNullOrWhiteSpace($GatekeeperUrl)) {
    if (-not [Uri]::IsWellFormedUriString($GatekeeperUrl, [UriKind]::Absolute)) {
        throw 'GatekeeperUrl must be an absolute URL (for example https://example.com).'
    }
    [Environment]::SetEnvironmentVariable('DEVILGUARD_GATEKEEPER_URL', $GatekeeperUrl.Trim(), 'Machine')
}

if (-not [string]::IsNullOrWhiteSpace($GatekeeperToken)) {
    [Environment]::SetEnvironmentVariable('DEVILGUARD_GATEKEEPER_TOKEN', $GatekeeperToken.Trim(), 'Machine')
}

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force
        $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    & sc.exe delete $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed with exit code $LASTEXITCODE." }
    Start-Sleep -Seconds 1
}

& sc.exe create $serviceName "binPath= `"$binary`"" 'start= auto' "DisplayName= $displayName" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed with exit code $LASTEXITCODE." }

& sc.exe description $serviceName 'Devil-Guard background health and monitoring service.' | Out-Null
& sc.exe failure $serviceName 'reset= 86400' 'actions= restart/5000/restart/15000/none/0' | Out-Null
Start-Service -Name $serviceName

Write-Host "$displayName is installed and running."
if (-not [string]::IsNullOrWhiteSpace($GatekeeperUrl)) {
    Write-Host "Gatekeeper URL configured in machine environment: DEVILGUARD_GATEKEEPER_URL"
}
if (-not [string]::IsNullOrWhiteSpace($GatekeeperToken)) {
    Write-Host "Gatekeeper token configured in machine environment: DEVILGUARD_GATEKEEPER_TOKEN"
}
