[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')]
    [string]$Configuration = 'Release',

    [ValidateSet('win-x86')]
    [string]$Runtime = 'win-x86',

    [switch]$FrameworkDependent
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$outputRoot = Join-Path $root 'artifacts\publish'
$selfContained = -not $FrameworkDependent

if (Test-Path -LiteralPath $outputRoot) {
    Remove-Item -LiteralPath $outputRoot -Recurse -Force
}

$projects = @(
    'Sentry\Sentry.csproj',
    'Overseer\Overseer.csproj',
    'Setup\Setup.csproj',
    'Patcher\Patcher.csproj',
    'Sentinel\Sentinel.csproj'
)

foreach ($project in $projects) {
    $projectName = [IO.Path]::GetFileNameWithoutExtension($project)
    $output = Join-Path $outputRoot $projectName
    Write-Host "Publishing $projectName to $output"

    dotnet publish (Join-Path $root $project) `
        --configuration $Configuration `
        --runtime $Runtime `
        --self-contained:$($selfContained.ToString().ToLowerInvariant()) `
        --output $output `
        -p:PublishSingleFile=false `
        -p:DebugType=None `
        -p:DebugSymbols=false

    if ($LASTEXITCODE -ne 0) {
        throw "Publishing $projectName failed with exit code $LASTEXITCODE."
    }
}

$scriptOutput = Join-Path $outputRoot 'Setup\scripts'
New-Item -ItemType Directory -Force -Path $scriptOutput | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'install-service.ps1') $scriptOutput -Force
Copy-Item (Join-Path $PSScriptRoot 'uninstall-service.ps1') $scriptOutput -Force

Write-Host "Publish complete: $outputRoot"
