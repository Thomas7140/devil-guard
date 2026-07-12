[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$serviceName = 'DevilGuardSentinel'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if (-not $service) {
    Write-Host 'Devil-Guard Sentinel is not installed.'
    exit 0
}

if ($service.Status -ne 'Stopped') {
    Stop-Service -Name $serviceName -Force
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}

& sc.exe delete $serviceName | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed with exit code $LASTEXITCODE." }

Write-Host 'Devil-Guard Sentinel was removed.'
