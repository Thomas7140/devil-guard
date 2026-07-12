using DevilGuard.Core.Detection;
using DevilGuard.Logging;
using DevilGuard.WebService.Contracts;
using DevilGuard.WebService.Network;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Threading;

namespace DevilGuard.Sentinel
{
    public sealed class DevilGuardService : ServiceBase
    {
        private Timer _heartbeatTimer;
        private Timer _monitorTimer;
        private readonly object _syncRoot = new object();

        private static readonly string[] SupportedProcessNames = { "dfbhd", "dfbhdlc" };
        private static readonly string[] MonitoredExtensions = { ".exe", ".dll", ".asi" };
        private static readonly string[] DockerProcessNames = { "com.docker.backend", "Docker Desktop", "docker", "dockerd" };
        private static readonly string[] DockerServiceNames = { "com.docker.service", "docker" };

        private int _trackedProcessId;
        private string _trackedGameDirectory = string.Empty;
        private Dictionary<string, string> _baselineFileHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private bool _hookDetected;
        private bool _suspiciousModulesDetected;
        private bool _directoryIntegrityChanged;
        private bool _dockerDetected;
        private bool _virtualizationDetected;
        private string _lastSuspiciousModuleSignature = string.Empty;
        private string _lastModifiedFileSignature = string.Empty;
        private Uri _gatekeeperBaseUri;
        private string _gatekeeperToken = string.Empty;
        private DateTimeOffset _lastAttestationSentAtUtc = DateTimeOffset.MinValue;
        private string _lastAttestationSignature = string.Empty;
        private string _lastDecisionSignature = string.Empty;

        public DevilGuardService()
        {
            ServiceName = "DevilGuardSentinel";
            CanStop = true;
            CanPauseAndContinue = false;
            AutoLog = false;
        }

        protected override void OnStart(string[] args)
        {
            LoadGatekeeperConfiguration();
            FileLog.TryWrite("sentinel", "Sentinel service started.", machineWide: true);
            _heartbeatTimer = new Timer(WriteHeartbeat, null, TimeSpan.Zero, TimeSpan.FromMinutes(5));
            _monitorTimer = new Timer(RunMonitoringPass, null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(20));
        }

        protected override void OnStop()
        {
            _heartbeatTimer?.Dispose();
            _heartbeatTimer = null;

            _monitorTimer?.Dispose();
            _monitorTimer = null;

            FileLog.TryWrite("sentinel", "Sentinel service stopped.", machineWide: true);
        }

        internal void StartInteractive(string[] args) => OnStart(args);

        internal void StopInteractive() => OnStop();

        private static void WriteHeartbeat(object state)
        {
            FileLog.TryWrite("sentinel", "Heartbeat: service is healthy.", machineWide: true);
        }

        private void RunMonitoringPass(object state)
        {
            lock (_syncRoot)
            {
                try
                {
                    if (!TryGetGameProcess(out Process process))
                    {
                        ResetTrackingWhenNoGame();
                        return;
                    }

                    using (process)
                    {
                        if (!TryGetExecutablePath(process, out string executablePath))
                            return;

                        string gameDirectory = Path.GetDirectoryName(executablePath) ?? string.Empty;
                        if (string.IsNullOrWhiteSpace(gameDirectory) || !Directory.Exists(gameDirectory))
                            return;

                        if (process.Id != _trackedProcessId ||
                            !string.Equals(gameDirectory, _trackedGameDirectory, StringComparison.OrdinalIgnoreCase))
                        {
                            CaptureBaseline(process.Id, gameDirectory);
                        }

                        ScanDockerEnvironment();
                        ScanVirtualizationEnvironment();
                        ScanRuntimeMemoryForHooks(process.Id);
                        ScanLoadedModulesForInjectedLibraries(process, gameDirectory);
                        ScanGameDirectoryForModifiedFiles(gameDirectory);
                        PublishAttestationIfNeeded(process, gameDirectory);
                    }
                }
                catch (Exception exception)
                {
                    FileLog.TryWrite("sentinel", "Runtime monitor error: " + exception.Message, exception, machineWide: true);
                }
            }
        }

        private static bool TryGetGameProcess(out Process process)
        {
            process = null;

            foreach (string processName in SupportedProcessNames)
            {
                Process candidate = Process.GetProcessesByName(processName).FirstOrDefault(item => !item.HasExited);
                if (candidate != null)
                {
                    process = candidate;
                    return true;
                }
            }

            return false;
        }

        private static bool TryGetExecutablePath(Process process, out string executablePath)
        {
            executablePath = string.Empty;
            try
            {
                executablePath = process.MainModule?.FileName ?? string.Empty;
                return !string.IsNullOrWhiteSpace(executablePath) && File.Exists(executablePath);
            }
            catch (Win32Exception)
            {
                return false;
            }
            catch (InvalidOperationException)
            {
                return false;
            }
        }

        private void ResetTrackingWhenNoGame()
        {
            if (_trackedProcessId == 0)
                return;

            FileLog.TryWrite("sentinel", "Game process exited. Monitoring baseline reset.", machineWide: true);
            _trackedProcessId = 0;
            _trackedGameDirectory = string.Empty;
            _baselineFileHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            _hookDetected = false;
            _suspiciousModulesDetected = false;
            _directoryIntegrityChanged = false;
            _dockerDetected = false;
            _virtualizationDetected = false;
            _lastSuspiciousModuleSignature = string.Empty;
            _lastModifiedFileSignature = string.Empty;
            _lastAttestationSignature = string.Empty;
            _lastDecisionSignature = string.Empty;
            _lastAttestationSentAtUtc = DateTimeOffset.MinValue;
        }

        private void CaptureBaseline(int processId, string gameDirectory)
        {
            _trackedProcessId = processId;
            _trackedGameDirectory = gameDirectory;
            _baselineFileHashes = BuildFileHashSnapshot(gameDirectory);
            _hookDetected = false;
            _suspiciousModulesDetected = false;
            _directoryIntegrityChanged = false;
            _dockerDetected = false;
            _virtualizationDetected = false;
            _lastSuspiciousModuleSignature = string.Empty;
            _lastModifiedFileSignature = string.Empty;
            _lastAttestationSignature = string.Empty;
            _lastDecisionSignature = string.Empty;
            _lastAttestationSentAtUtc = DateTimeOffset.MinValue;

            FileLog.TryWrite(
                "sentinel",
                "Monitoring game process " + processId + " in " + gameDirectory + " with " + _baselineFileHashes.Count + " baseline files.",
                machineWide: true);
        }

        private static Dictionary<string, string> BuildFileHashSnapshot(string gameDirectory)
        {
            Dictionary<string, string> hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (string path in EnumerateCandidateFiles(gameDirectory))
            {
                try
                {
                    hashes[path] = ComputeSha256(path);
                }
                catch
                {
                    // Skip files that are transient or currently inaccessible.
                }
            }

            return hashes;
        }

        private void ScanRuntimeMemoryForHooks(int processId)
        {
            bool detected = false;
            try
            {
                detected = IsD3DExportPatched(processId, "d3d8.dll", "Direct3DCreate8", 8);
            }
            catch (Exception exception)
            {
                FileLog.TryWrite("sentinel", "Memory hook scan failed: " + exception.Message, exception, machineWide: true);
                return;
            }

            if (detected && !_hookDetected)
            {
                _hookDetected = true;
                FileLog.TryWrite("sentinel", "Alert: potential injection detected (d3d8 Direct3DCreate8 prologue mismatch).", machineWide: true);
            }
            else if (!detected)
            {
                _hookDetected = false;
            }
        }

        private void ScanLoadedModulesForInjectedLibraries(Process process, string gameDirectory)
        {
            string windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string windowsSystemDirectory = Environment.SystemDirectory;
            List<string> suspicious = new List<string>();

            try
            {
                foreach (ProcessModule module in process.Modules)
                {
                    string modulePath = module.FileName;
                    if (string.IsNullOrWhiteSpace(modulePath))
                        continue;

                    if (IsPathInside(modulePath, gameDirectory) ||
                        IsPathInside(modulePath, windowsDirectory) ||
                        IsPathInside(modulePath, windowsSystemDirectory))
                    {
                        continue;
                    }

                    suspicious.Add(Path.GetFileName(modulePath));
                }
            }
            catch (Win32Exception)
            {
                return;
            }
            catch (InvalidOperationException)
            {
                return;
            }

            suspicious.Sort(StringComparer.OrdinalIgnoreCase);
            string signature = string.Join("|", suspicious);
            if (signature.Length == 0)
            {
                _suspiciousModulesDetected = false;
                _lastSuspiciousModuleSignature = string.Empty;
                return;
            }

            _suspiciousModulesDetected = true;
            if (string.Equals(signature, _lastSuspiciousModuleSignature, StringComparison.Ordinal))
                return;

            _lastSuspiciousModuleSignature = signature;
            FileLog.TryWrite(
                "sentinel",
                "Alert: suspicious modules detected in game process: " + string.Join(", ", suspicious.Take(10)) +
                (suspicious.Count > 10 ? " ..." : string.Empty),
                machineWide: true);
        }

        private void ScanGameDirectoryForModifiedFiles(string gameDirectory)
        {
            Dictionary<string, string> current = BuildFileHashSnapshot(gameDirectory);
            List<string> modified = new List<string>();

            foreach (KeyValuePair<string, string> baseline in _baselineFileHashes)
            {
                if (!current.TryGetValue(baseline.Key, out string currentHash))
                {
                    modified.Add("missing:" + Path.GetFileName(baseline.Key));
                    continue;
                }

                if (!string.Equals(currentHash, baseline.Value, StringComparison.OrdinalIgnoreCase))
                    modified.Add("changed:" + Path.GetFileName(baseline.Key));
            }

            foreach (string currentFile in current.Keys)
            {
                if (!_baselineFileHashes.ContainsKey(currentFile))
                    modified.Add("new:" + Path.GetFileName(currentFile));
            }

            modified.Sort(StringComparer.OrdinalIgnoreCase);
            string signature = string.Join("|", modified);
            if (signature.Length == 0)
            {
                _directoryIntegrityChanged = false;
                _lastModifiedFileSignature = string.Empty;
                return;
            }

            _directoryIntegrityChanged = true;
            if (string.Equals(signature, _lastModifiedFileSignature, StringComparison.Ordinal))
                return;

            _lastModifiedFileSignature = signature;
            FileLog.TryWrite(
                "sentinel",
                "Alert: game directory integrity change detected: " + string.Join(", ", modified.Take(15)) +
                (modified.Count > 15 ? " ..." : string.Empty),
                machineWide: true);
        }

        private void ScanVirtualizationEnvironment()
        {
            bool detected;
            try
            {
                detected = VPC.DetectVPC();
            }
            catch (Exception exception)
            {
                FileLog.TryWrite("sentinel", "Virtualization scan failed: " + exception.Message, exception, machineWide: true);
                return;
            }

            if (detected && !_virtualizationDetected)
            {
                _virtualizationDetected = true;
                FileLog.TryWrite("sentinel", "Alert: virtualized/container-like host environment detected.", machineWide: true);
                return;
            }

            if (!detected && _virtualizationDetected)
            {
                _virtualizationDetected = false;
                FileLog.TryWrite("sentinel", "Virtualization scan no longer indicates a virtualized environment.", machineWide: true);
                return;
            }

            _virtualizationDetected = detected;
        }

        private void ScanDockerEnvironment()
        {
            bool detected = IsAnyDockerProcessRunning() || IsAnyDockerServiceRunning();

            if (detected && !_dockerDetected)
            {
                _dockerDetected = true;
                FileLog.TryWrite("sentinel", "Alert: docker runtime detected on host.", machineWide: true);
                return;
            }

            if (!detected && _dockerDetected)
            {
                _dockerDetected = false;
                FileLog.TryWrite("sentinel", "Docker runtime no longer detected on host.", machineWide: true);
                return;
            }

            _dockerDetected = detected;
        }

        private static bool IsAnyDockerProcessRunning()
        {
            foreach (string processName in DockerProcessNames)
            {
                try
                {
                    if (Process.GetProcessesByName(processName).Any(process => !process.HasExited))
                        return true;
                }
                catch
                {
                    // Ignore transient process inspection errors and continue checking.
                }
            }

            return false;
        }

        private static bool IsAnyDockerServiceRunning()
        {
            ServiceController[] services;
            try
            {
                services = ServiceController.GetServices();
            }
            catch
            {
                return false;
            }

            foreach (ServiceController service in services)
            {
                try
                {
                    if (service.Status != ServiceControllerStatus.Running)
                        continue;

                    if (DockerServiceNames.Any(name => string.Equals(name, service.ServiceName, StringComparison.OrdinalIgnoreCase)))
                        return true;
                }
                catch
                {
                    // Ignore per-service access errors and continue scanning.
                }
            }

            return false;
        }

        private static IEnumerable<string> EnumerateCandidateFiles(string gameDirectory)
        {
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(gameDirectory, "*.*", SearchOption.TopDirectoryOnly);
            }
            catch
            {
                yield break;
            }

            foreach (string path in files)
            {
                string extension = Path.GetExtension(path);
                if (MonitoredExtensions.Any(item => string.Equals(item, extension, StringComparison.OrdinalIgnoreCase)))
                    yield return path;
            }
        }

        private static string ComputeSha256(string path)
        {
            using FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(SHA256.HashData(stream));
        }

        private static bool IsPathInside(string candidatePath, string rootPath)
        {
            if (string.IsNullOrWhiteSpace(candidatePath) || string.IsNullOrWhiteSpace(rootPath))
                return false;

            string normalizedCandidate = Path.GetFullPath(candidatePath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string normalizedRoot = Path.GetFullPath(rootPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

            return normalizedCandidate.StartsWith(normalizedRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(normalizedCandidate, normalizedRoot, StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsD3DExportPatched(int processId, string moduleName, string exportName, int bytesToCompare)
        {
            string localModulePath = Path.Combine(Environment.SystemDirectory, moduleName);
            IntPtr localModule = NativeMethods.LoadLibrary(localModulePath);
            if (localModule == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "LoadLibrary failed for " + localModulePath + ".");

            try
            {
                IntPtr localExport = NativeMethods.GetProcAddress(localModule, exportName);
                if (localExport == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetProcAddress failed for " + exportName + ".");

                byte[] expectedBytes = new byte[bytesToCompare];
                Marshal.Copy(localExport, expectedBytes, 0, bytesToCompare);
                long exportOffset = localExport.ToInt64() - localModule.ToInt64();

                using Process process = Process.GetProcessById(processId);
                ProcessModule remoteModule = process.Modules
                    .Cast<ProcessModule>()
                    .FirstOrDefault(module => string.Equals(Path.GetFileName(module.FileName), moduleName, StringComparison.OrdinalIgnoreCase));

                if (remoteModule == null)
                    return false;

                IntPtr remoteAddress = new IntPtr(remoteModule.BaseAddress.ToInt64() + exportOffset);
                IntPtr remoteHandle = NativeMethods.OpenProcess(NativeMethods.ProcessVmRead | NativeMethods.ProcessQueryInformation, false, processId);
                if (remoteHandle == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess failed for PID " + processId + ".");

                try
                {
                    byte[] actualBytes = new byte[bytesToCompare];
                    bool succeeded = NativeMethods.ReadProcessMemory(remoteHandle, remoteAddress, actualBytes, (UIntPtr)bytesToCompare, out UIntPtr bytesRead);
                    if (!succeeded || (ulong)bytesRead.ToUInt64() != (ulong)bytesToCompare)
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "ReadProcessMemory failed while checking Direct3D export.");

                    return !CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
                }
                finally
                {
                    NativeMethods.CloseHandle(remoteHandle);
                }
            }
            finally
            {
                NativeMethods.FreeLibrary(localModule);
            }
        }

        private void LoadGatekeeperConfiguration()
        {
            string configuredEndpoint = Environment.GetEnvironmentVariable("DEVILGUARD_GATEKEEPER_URL") ?? string.Empty;
            _gatekeeperToken = Environment.GetEnvironmentVariable("DEVILGUARD_GATEKEEPER_TOKEN") ?? string.Empty;

            if (!Uri.TryCreate(configuredEndpoint, UriKind.Absolute, out Uri endpoint))
            {
                _gatekeeperBaseUri = null;
                FileLog.TryWrite("sentinel", "Gatekeeper reporting disabled. Set DEVILGUARD_GATEKEEPER_URL to enable server attestation.", machineWide: true);
                return;
            }

            bool isLocal = endpoint.IsLoopback || string.Equals(endpoint.Host, "localhost", StringComparison.OrdinalIgnoreCase);
            HttpOptions.AllowInsecureLocalhost = isLocal && endpoint.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);
            HttpOptions.Timeout = TimeSpan.FromSeconds(10);

            _gatekeeperBaseUri = endpoint;
            FileLog.TryWrite("sentinel", "Gatekeeper reporting enabled: " + endpoint, machineWide: true);
        }

        private void PublishAttestationIfNeeded(Process process, string gameDirectory)
        {
            if (_gatekeeperBaseUri == null)
                return;

            string localSignature = process.Id + "|" + _hookDetected + "|" + _suspiciousModulesDetected + "|" + _directoryIntegrityChanged + "|" + _dockerDetected + "|" + _virtualizationDetected + "|" + _lastSuspiciousModuleSignature + "|" + _lastModifiedFileSignature;
            bool changed = !string.Equals(localSignature, _lastAttestationSignature, StringComparison.Ordinal);
            bool intervalElapsed = (DateTimeOffset.UtcNow - _lastAttestationSentAtUtc) >= TimeSpan.FromSeconds(60);

            if (!changed && !intervalElapsed)
                return;

            AttestationReport report = new AttestationReport
            {
                MachineId = Environment.MachineName,
                PlayerName = Environment.UserName,
                GameName = process.ProcessName,
                GameDirectory = gameDirectory,
                ProcessId = process.Id,
                GameRunning = true,
                HookDetected = _hookDetected,
                SuspiciousModulesDetected = _suspiciousModulesDetected,
                DirectoryIntegrityChanged = _directoryIntegrityChanged,
                ReportedAtUtc = DateTimeOffset.UtcNow,
                Signals = BuildSignalList()
            };

            try
            {
                AttestationDecision decision = AttestationClient.SubmitReport(_gatekeeperBaseUri, report, _gatekeeperToken);
                _lastAttestationSignature = localSignature;
                _lastAttestationSentAtUtc = DateTimeOffset.UtcNow;

                string decisionSignature = decision.AllowJoin + "|" + decision.Reason;
                if (!string.Equals(decisionSignature, _lastDecisionSignature, StringComparison.Ordinal))
                {
                    _lastDecisionSignature = decisionSignature;
                    FileLog.TryWrite("sentinel", "Gatekeeper decision for " + report.MachineId + ": allowJoin=" + decision.AllowJoin + ", reason=" + decision.Reason, machineWide: true);
                }
            }
            catch (Exception exception)
            {
                FileLog.TryWrite("sentinel", "Gatekeeper report failed: " + exception.Message, exception, machineWide: true);
            }
        }

        private List<string> BuildSignalList()
        {
            List<string> signals = new List<string>();

            if (_hookDetected)
                signals.Add("hook:d3d8-export-mismatch");
            if (_suspiciousModulesDetected)
                signals.Add("module:unexpected-origin");
            if (_directoryIntegrityChanged)
                signals.Add("files:baseline-drift");
            if (_dockerDetected)
                signals.Add("environment:docker");
            if (_virtualizationDetected)
                signals.Add("environment:virtualized-host");

            return signals;
        }

        private static class NativeMethods
        {
            internal const uint ProcessVmRead = 0x0010;
            internal const uint ProcessQueryInformation = 0x0400;

            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            internal static extern IntPtr LoadLibrary(string lpLibFileName);

            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
            internal static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool FreeLibrary(IntPtr hModule);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr OpenProcess(uint processAccess, bool inheritHandle, int processId);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CloseHandle(IntPtr hObject);
        }
    }
}
