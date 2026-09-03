using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Collections.Generic;
using System;
using System.Threading;
using System.Threading.Tasks;
using System.IO;

namespace Spemcs.Agent.Ipc;

public static class PipeNames
{
    public const string Agent = "spemcs-agent-v1";
    public const string Control = "spemcs-control-v1";
}

public static class MessageTypes
{
    public const string RequestRegistration = "REQUEST_REGISTRATION";
    public const string RegistrationData = "REGISTRATION_DATA";
    public const string ShowPreComplianceLoading = "SHOW_PRE_COMPLIANCE_LOADING";
    public const string UpdatePreComplianceResult = "UPDATE_PRE_COMPLIANCE_RESULT";
    public const string PreComplianceContinued = "PRE_COMPLIANCE_CONTINUED";
    public const string ShowStudentVerification = "SHOW_STUDENT_VERIFICATION";
    public const string StudentVerificationResult = "STUDENT_VERIFICATION_RESULT";
    public const string SessionStart = "SESSION_START";
    public const string SessionStop = "SESSION_STOP";
    public const string StartExam = "START_EXAM";
    public const string StopExam = "STOP_EXAM";
    public const string CommandResult = "COMMAND_RESULT";
}

public sealed record PipeEnvelope(string Type, int Version, string CorrelationId, DateTimeOffset TimestampUtc, JsonElement Payload);
public sealed record RegistrationPayload(string DeviceName, string IpAddress);
public sealed record RegistrationRequestPayload(string IpAddress);
public sealed record StudentVerificationPayload(string RollNumber);
public sealed record CommandResultPayload(bool Accepted, string State, string? Error = null);

public sealed record ProcessDisplayPayload(string Name, string? ExecutablePath, string Category, string? Reason);
public sealed record PreComplianceScanPayload(bool IsLoading, bool IsClean, IReadOnlyList<ProcessDisplayPayload> SuspiciousProcesses, string StatusText);

public static class PipeProtocol
{
    public static async Task WriteAsync(Stream stream, string type, object payload, CancellationToken cancellationToken)
    {
        var envelope = new { Type = type, Version = 1, CorrelationId = Guid.NewGuid().ToString("N"), TimestampUtc = DateTimeOffset.UtcNow, Payload = payload };
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(envelope) + "\n");
        await stream.WriteAsync(bytes, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    public static async Task<PipeEnvelope?> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
        var line = await reader.ReadLineAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(line)) return null;
        try { return JsonSerializer.Deserialize<PipeEnvelope>(line); } catch (JsonException) { return null; }
    }

    public static NamedPipeServerStream CreateServer(string name)
    {
        try
        {
            var security = new PipeSecurity();
            security.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                PipeAccessRights.ReadWrite,
                AccessControlType.Allow));
            security.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                PipeAccessRights.ReadWrite,
                AccessControlType.Allow));

            return NamedPipeServerStreamAcl.Create(
                name,
                PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous,
                0,
                0,
                security);
        }
        catch
        {
            return new NamedPipeServerStream(
                name,
                PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);
        }
    }

    public static NamedPipeClientStream CreateClient(string name) => new(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
}
