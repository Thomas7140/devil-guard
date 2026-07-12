[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$forbiddenNames = Get-ChildItem -Path $root -Recurse -File | Where-Object {
    $_.Extension -in @('.pfx', '.snk', '.key', '.exe', '.dll')
}
if ($forbiddenNames) {
    $forbiddenNames | ForEach-Object { Write-Error "Forbidden source artefact: $($_.FullName)" }
    throw 'Forbidden files were found.'
}

$sdkList = & dotnet --list-sdks
if ($LASTEXITCODE -ne 0 -or -not ($sdkList -match '^10\.')) {
    throw 'A .NET 10 SDK is required.'
}

& dotnet restore (Join-Path $root 'Devil-Guard.sln')
if ($LASTEXITCODE -ne 0) { throw 'dotnet restore failed.' }

& dotnet build (Join-Path $root 'Devil-Guard.sln') --configuration Release --no-restore --property:Platform=x86
if ($LASTEXITCODE -ne 0) { throw 'dotnet build failed.' }

Write-Host 'Devil-Guard source verification completed successfully.'
