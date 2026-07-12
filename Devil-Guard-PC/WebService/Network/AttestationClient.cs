using DevilGuard.WebService.Contracts;
using System;

namespace DevilGuard.WebService.Network
{
    public static class AttestationClient
    {
        public static AttestationDecision SubmitReport(Uri serverBaseUri, AttestationReport report, string sharedToken = "")
        {
            ArgumentNullException.ThrowIfNull(serverBaseUri);
            ArgumentNullException.ThrowIfNull(report);

            Uri endpoint = new Uri(serverBaseUri, "/api/attestation/report");
            using Http http = new Http(endpoint.ToString());

            if (!string.IsNullOrWhiteSpace(sharedToken))
                http.AddHeader("X-DevilGuard-Token", sharedToken);

            object response = http.POSTJSON(report, typeof(AttestationDecision));
            return response as AttestationDecision ?? new AttestationDecision
            {
                MachineId = report.MachineId,
                AllowJoin = false,
                Reason = "Server returned an invalid attestation decision.",
                DecisionAtUtc = DateTimeOffset.UtcNow
            };
        }
    }
}
