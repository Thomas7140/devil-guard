# Devil-Guard

Devil-Guard is the cleaned and rebranded successor source tree for the former legacy anti-cheat suite. This edition uses SDK-style projects and targets **.NET 10 for Windows**.

## Platform target

- Target framework: `net10.0-windows10.0.17763.0`
- Language: C# 14
- Desktop UI: WPF
- Supported build architecture: `win-x86`
- Intended operating systems: supported Windows 10 Enterprise/LTSC releases and supported Windows 11 releases
- Default minimum Windows API declaration: Windows 10 version 1809

The x86 target is intentional. Delta Force: Black Hawk Down is a 32-bit application and the current game integration contains fixed 32-bit process-memory addresses. A future x64 build must use architecture-aware address handling before it is considered supported.

## Tooling

Use one of these environments:

- Visual Studio 2026 version 18.0 or later with the **.NET desktop development** workload; or
- the current .NET 10 SDK with the Windows SDK and `dotnet` CLI.

## Build

```powershell
dotnet restore .\Devil-Guard.sln
dotnet build .\Devil-Guard.sln --configuration Release --property:Platform=x86
```

## Verify

On Windows with the .NET 10 SDK installed:

```powershell
.\scripts\verify-source.ps1
```

The script checks for legacy branding, committed binary/key artefacts, restores packages, and builds the release solution.

## Publish

From an ordinary PowerShell prompt:

```powershell
.\scripts\publish.ps1
```

This creates self-contained `win-x86` output under `artifacts\publish`. Use `-FrameworkDependent` only when the target machines already have the matching .NET 10 Desktop Runtime.

## Components

- **Sentry** — desktop client with local runtime and game-process status.
- **Overseer** — local administration and Sentinel service status.
- **Setup** — elevated install/remove controls for the Windows service.
- **Sentinel** — Windows service with health logging and console diagnostic mode.
- **Patcher** — HTTPS-only package downloader with mandatory SHA-256 verification. It stages updates and never automatically executes them.
- **Core** — process, hardware, registry, hashing, and game integration helpers.
- **WebService** — HTTPS JSON client utilities.
- **Logging** — in-memory and file logging helpers.
- **Style** — shared WPF resources.

## Sentinel service

After publishing, run the installation script from an elevated PowerShell prompt or launch Devil-Guard Setup:

```powershell
.\scripts\install-service.ps1 -BinaryPath "C:\path\to\DevilGuard.Sentinel.exe"
```

Optional Gatekeeper configuration during install:

```powershell
.\scripts\install-service.ps1 -BinaryPath "C:\path\to\DevilGuard.Sentinel.exe" -GatekeeperUrl "https://your-domain/api" -GatekeeperToken "your-server-token"
```

This writes machine-level environment variables used by Sentinel:

- `DEVILGUARD_GATEKEEPER_URL`
- `DEVILGUARD_GATEKEEPER_TOKEN`

Service name: `DevilGuardSentinel`

Service logs: `%ProgramData%\DevilGuard\Logs`

Desktop logs: `%LocalAppData%\DevilGuard\Logs`

## Secure updater design

The patcher requires:

1. an HTTPS manifest URL;
2. an HTTPS package URL in that manifest; and
3. an exact SHA-256 package hash.

It downloads to a temporary file, verifies the digest with constant-time comparison, moves the verified package into a staging directory, and stops. Code signing and deployment approval remain separate release steps.

## Migration scope and limitations

The source package intentionally excludes historical build outputs, installers, backup folders, committed PFX files, old compiled binaries, and the Legacy/V2/Concepts trees. Those artefacts contained obsolete branding, outdated networking code, and sensitive signing material.

This is a source-level migration. It has been statically checked, but it still requires restore, compile, code signing, and functional testing on a supported Windows machine. The DFBHD memory offsets are inherited game-version-specific values and must be verified against the exact executable build before production use.
