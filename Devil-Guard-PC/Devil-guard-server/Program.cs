using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using DevilGuard.WebService.Contracts;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

var builder = WebApplication.CreateBuilder(args);

string configuredListenUrl = builder.Configuration["Server:ListenUrl"];
if (string.IsNullOrWhiteSpace(configuredListenUrl))
    configuredListenUrl = Environment.GetEnvironmentVariable("DEVILGUARD_SERVER_LISTEN_URL") ?? string.Empty;

if (!string.IsNullOrWhiteSpace(configuredListenUrl) && Uri.TryCreate(configuredListenUrl, UriKind.Absolute, out Uri listenUri))
{
	if (listenUri.Scheme == Uri.UriSchemeHttp || listenUri.Scheme == Uri.UriSchemeHttps)
		builder.WebHost.UseSetting("urls", listenUri.ToString());
}

var app = builder.Build();

GatekeeperPolicy policy = GatekeeperPolicy.FromConfiguration(builder.Configuration);
ConcurrentDictionary<string, StoredAttestation> reports = new ConcurrentDictionary<string, StoredAttestation>(StringComparer.OrdinalIgnoreCase);

app.MapGet("/", () => Results.Ok(new
{
	service = "Devil-Guard Gatekeeper",
	utc = DateTimeOffset.UtcNow,
	endpoints = new[]
	{
		"POST /api/attestation/report",
		"GET /api/attestation/decision/{machineId}",
		"GET /api/attestation/recent"
	}
}));

app.MapPost("/api/attestation/report", (HttpContext context, AttestationReport report) =>
{
	if (!IsAuthorized(context, policy))
		return Results.Unauthorized();

	if (report == null || string.IsNullOrWhiteSpace(report.MachineId))
		return Results.BadRequest("MachineId is required.");

	AttestationDecision decision = Evaluate(policy, report);
	StoredAttestation snapshot = new StoredAttestation
	{
		Report = report,
		Decision = decision,
		ReceivedAtUtc = DateTimeOffset.UtcNow
	};

	reports.AddOrUpdate(report.MachineId, snapshot, (_, _) => snapshot);
	return Results.Ok(decision);
});

app.MapGet("/api/attestation/decision/{machineId}", (HttpContext context, string machineId) =>
{
	if (!IsAuthorized(context, policy))
		return Results.Unauthorized();

	if (string.IsNullOrWhiteSpace(machineId))
		return Results.BadRequest("machineId is required.");

	if (!reports.TryGetValue(machineId, out StoredAttestation state))
	{
		return Results.NotFound(new AttestationDecision
		{
			MachineId = machineId,
			AllowJoin = false,
			Reason = "No attestation report found for this machine.",
			DecisionAtUtc = DateTimeOffset.UtcNow
		});
	}

	if ((DateTimeOffset.UtcNow - state.ReceivedAtUtc).TotalSeconds > policy.MaxReportAgeSeconds)
	{
		return Results.Ok(new AttestationDecision
		{
			MachineId = machineId,
			AllowJoin = false,
			Reason = "Latest attestation is stale.",
			DecisionAtUtc = DateTimeOffset.UtcNow
		});
	}

	return Results.Ok(state.Decision);
});

app.MapGet("/api/attestation/recent", (HttpContext context) =>
{
	if (!IsAuthorized(context, policy))
		return Results.Unauthorized();

	List<object> payload = reports
		.OrderByDescending(item => item.Value.ReceivedAtUtc)
		.Take(200)
		.Select(item => new
		{
			machineId = item.Key,
			allowJoin = item.Value.Decision.AllowJoin,
			reason = item.Value.Decision.Reason,
			reportedAtUtc = item.Value.Report.ReportedAtUtc,
			receivedAtUtc = item.Value.ReceivedAtUtc,
			signals = item.Value.Report.Signals
		})
		.Cast<object>()
		.ToList();

	return Results.Ok(payload);
});

app.Run();

static bool IsAuthorized(HttpContext context, GatekeeperPolicy policy)
{
	if (string.IsNullOrWhiteSpace(policy.SharedToken))
		return true;

	if (!context.Request.Headers.TryGetValue("X-DevilGuard-Token", out var providedToken))
		return false;

	return string.Equals(providedToken.ToString(), policy.SharedToken, StringComparison.Ordinal);
}

static AttestationDecision Evaluate(GatekeeperPolicy policy, AttestationReport report)
{
	List<string> signals = report.Signals ?? new List<string>();
	bool dockerDetected = signals.Any(signal => string.Equals(signal, "environment:docker", StringComparison.OrdinalIgnoreCase));
	bool hasSignals = report.HookDetected || report.SuspiciousModulesDetected || report.DirectoryIntegrityChanged || signals.Count > 0;

	bool allowJoin = report.GameRunning;
	string reason = "Attestation accepted.";

	if (!report.GameRunning)
	{
		allowJoin = false;
		reason = "Game process is not running on client.";
	}
	else if (dockerDetected)
	{
		allowJoin = false;
		reason = "Docker runtime detected on client.";
	}
	else if (policy.DenyOnAnySignal && hasSignals)
	{
		allowJoin = false;
		reason = "Suspicious anti-cheat signal present.";
	}

	return new AttestationDecision
	{
		MachineId = report.MachineId,
		AllowJoin = allowJoin,
		Reason = reason,
		DecisionAtUtc = DateTimeOffset.UtcNow
	};
}

sealed class StoredAttestation
{
	public AttestationReport Report;
	public AttestationDecision Decision;
	public DateTimeOffset ReceivedAtUtc;
}

sealed class GatekeeperPolicy
{
	public string SharedToken = string.Empty;
	public bool DenyOnAnySignal = true;
	public int MaxReportAgeSeconds = 120;

	public static GatekeeperPolicy FromConfiguration(IConfiguration configuration)
	{
		GatekeeperPolicy policy = new GatekeeperPolicy();

		string configuredToken = configuration["Gatekeeper:SharedToken"];
		if (!string.IsNullOrWhiteSpace(configuredToken))
			policy.SharedToken = configuredToken.Trim();

		if (bool.TryParse(configuration["Gatekeeper:DenyOnAnySignal"], out bool denyOnAnySignal))
			policy.DenyOnAnySignal = denyOnAnySignal;

		if (int.TryParse(configuration["Gatekeeper:MaxReportAgeSeconds"], out int maxAgeSeconds) && maxAgeSeconds >= 10)
			policy.MaxReportAgeSeconds = maxAgeSeconds;

		return policy;
	}
}
