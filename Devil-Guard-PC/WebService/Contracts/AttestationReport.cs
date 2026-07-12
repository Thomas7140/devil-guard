using System;
using System.Collections.Generic;

namespace DevilGuard.WebService.Contracts
{
    public sealed class AttestationReport
    {
        public string MachineId { get; set; } = string.Empty;
        public string PlayerName { get; set; } = string.Empty;
        public string GameName { get; set; } = string.Empty;
        public string GameDirectory { get; set; } = string.Empty;
        public int ProcessId { get; set; }
        public bool GameRunning { get; set; }
        public bool HookDetected { get; set; }
        public bool SuspiciousModulesDetected { get; set; }
        public bool DirectoryIntegrityChanged { get; set; }
        public List<string> Signals { get; set; } = new List<string>();
        public DateTimeOffset ReportedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    }
}
