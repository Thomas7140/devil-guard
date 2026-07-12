using System;

namespace DevilGuard.WebService.Contracts
{
    public sealed class AttestationDecision
    {
        public string MachineId { get; set; } = string.Empty;
        public bool AllowJoin { get; set; }
        public string Reason { get; set; } = string.Empty;
        public DateTimeOffset DecisionAtUtc { get; set; } = DateTimeOffset.UtcNow;
    }
}
