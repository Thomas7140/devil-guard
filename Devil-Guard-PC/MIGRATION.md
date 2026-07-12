# Devil-Guard .NET 10 migration notes

## Completed

- Replaced product, namespace, assembly, registry, resource, solution, and UI references with Devil-Guard / `DevilGuard`.
- Converted the active projects to SDK-style `net10.0-windows` projects.
- Standardised the supported runtime to `win-x86` for the existing 32-bit game integration.
- Removed generated executables, DLLs, package caches, release output, backup copies, nested archives, and private-key/PFX files.
- Replaced legacy HTTP request code with `HttpClient` and HTTPS enforcement.
- Replaced the legacy third-party JSON serializer with `System.Text.Json`.
- Replaced obsolete UTF-7 and older cryptographic APIs.
- Fixed duplicate empty GUID log identifiers.
- Corrected unsafe process-memory buffer handling and resource disposal.
- Removed unverified legacy cheat/debugger hash signature tables rather than carrying stale detections into the new build.
- Added WPF status interfaces for Sentry, Overseer, and Setup.
- Added a functioning Windows service host with health logging and console diagnostic mode.
- Replaced the unsafe download-and-run updater with a non-executing HTTPS/SHA-256 staging tool.
- Added publish and service installation scripts.

## Production work still required

- Build and test the solution with the current .NET 10 SDK on Windows.
- Replace placeholder update endpoints and establish signed release infrastructure.
- Sign all release executables and packages with a newly issued certificate kept outside source control.
- Verify all DFBHD process-memory offsets against every supported executable hash.
- Define and implement the server-side API contract, authentication, telemetry consent, retention, and privacy controls.
- Complete security review and dynamic testing before enabling anti-debugging or injection-detection features.
