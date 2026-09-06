using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading;
using System.Threading.Tasks;
using Spemcs.Agent.Core;

namespace Spemcs.Agent.Service;

/// <summary>
/// Registers this device with the backend and captures the device token the response carries.
/// </summary>
/// <remarks>
/// The request previously sent only <c>deviceName</c> and <c>ipAddress</c>, with no enrolment key,
/// and deserialised the response into a record that had no <c>deviceToken</c> field. Both halves
/// of the credential exchange were therefore dropped on the floor: the agent could not prove it
/// was entitled to enrol, and it threw away the credential it was handed. The backend tolerated
/// the first because its key check was written to skip when unconfigured, and the second because
/// the endpoints that should have demanded the token did not.
/// </remarks>
public class BackendRegistrationService : IRegistrationService
{
    private readonly HttpClient _http;
    private readonly DeviceCredentialStore _credentials;

    public BackendRegistrationService(HttpClient http, DeviceCredentialStore credentials)
    {
        _http = http;
        _credentials = credentials;
    }

    public async Task<DeviceRegistration> RegisterDeviceAsync(string deviceName, string ipAddress, CancellationToken cancellationToken = default)
    {
        var req = new
        {
            deviceName,
            ipAddress,
            // Null when unconfigured. Sent as null rather than omitted so that the resulting 401
            // names a configuration problem instead of looking like a malformed request.
            enrollmentKey = _credentials.EnrollmentKey,
        };
        var res = await _http.PostAsJsonAsync("api/v1/devices/register", req, cancellationToken);
        res.EnsureSuccessStatusCode();
        var data = await res.Content.ReadFromJsonAsync<RegistrationResponse>(cancellationToken: cancellationToken);
        if (data == null) throw new InvalidOperationException("Failed to read registration response.");

        // The token authorises every subsequent agent call. It is never logged: the log file lives
        // on the examination workstation and is readable by whoever sits at it.
        _credentials.SetDeviceToken(data.DeviceToken);

        return new DeviceRegistration(Guid.Parse(data.DeviceId), data.DeviceName, data.IpAddress, DateTimeOffset.Parse(data.RegisteredAtUtc));
    }

    private record RegistrationResponse(string DeviceId, string DeviceName, string IpAddress, string RegisteredAtUtc, string? DeviceToken);
}

/// <summary>
/// Starts exam sessions and binds candidates to them, authenticated as this device.
/// </summary>
public class BackendSessionService : ISessionService
{
    private readonly HttpClient _http;
    private readonly DeviceCredentialStore _credentials;

    public BackendSessionService(HttpClient http, DeviceCredentialStore credentials)
    {
        _http = http;
        _credentials = credentials;
    }

    public async Task<bool> StartExamSessionAsync(string sessionId, ApprovedBrowserFamily approvedBrowser, CancellationToken cancellationToken = default)
    {
        var req = new { sessionId, approvedBrowser = approvedBrowser.ToString() };
        using var message = AgentHttp.CreateJsonPost("api/v1/sessions/start", req, _credentials);
        var res = await _http.SendAsync(message, cancellationToken);
        return res.IsSuccessStatusCode;
    }

    public async Task<bool> RegisterStudentAsync(string sessionId, string rollNumber, CancellationToken cancellationToken = default)
    {
        var req = new { sessionId, rollNumber };
        using var message = AgentHttp.CreateJsonPost("api/v1/sessions/verify-student", req, _credentials);
        var res = await _http.SendAsync(message, cancellationToken);
        return res.IsSuccessStatusCode;
    }
}

/// <summary>
/// Uploads violation events, authenticated as this device.
/// </summary>
public class BackendEventPublisher : IEventPublisher
{
    private readonly HttpClient _http;
    private readonly DeviceCredentialStore _credentials;

    public BackendEventPublisher(HttpClient http, DeviceCredentialStore credentials)
    {
        _http = http;
        _credentials = credentials;
    }

    public async Task PublishEventAsync(ViolationEvent violation, CancellationToken cancellationToken = default)
    {
        var req = new {
            eventId = violation.EventId.ToString(),
            deviceName = violation.DeviceName,
            studentRollNumber = violation.StudentRollNumber,
            eventType = violation.EventType,
            processId = violation.ProcessId,
            processName = violation.ProcessName,
            timestampUtc = violation.TimestampUtc.ToString("o"),
            executablePath = violation.ExecutablePath,
            reason = violation.Reason
        };
        using var message = AgentHttp.CreateJsonPost("api/v1/events", req, _credentials);
        var res = await _http.SendAsync(message, cancellationToken);
        res.EnsureSuccessStatusCode();
    }
}

/// <summary>
/// Builds authenticated agent requests.
/// </summary>
/// <remarks>
/// The device token goes in <c>X-Device-Token</c> on the request rather than on a
/// <see cref="HttpClient"/> default header, because the token is not known when the typed clients
/// are constructed - it arrives at registration, on a different client instance - and because a
/// default header would be attached to every request the client ever makes, including any future
/// call to an endpoint that has no business seeing it.
/// </remarks>
internal static class AgentHttp
{
    internal const string DeviceTokenHeader = "X-Device-Token";

    internal static HttpRequestMessage CreateJsonPost<T>(string requestUri, T body, DeviceCredentialStore credentials)
    {
        var message = new HttpRequestMessage(HttpMethod.Post, requestUri)
        {
            Content = JsonContent.Create(body),
        };

        var token = credentials.DeviceToken;
        if (!string.IsNullOrWhiteSpace(token))
        {
            // Absent rather than blank when unregistered: an empty header value would be a
            // malformed credential, and the backend's uniform 401 would make it indistinguishable
            // from a forged one in the agent's own logs.
            message.Headers.TryAddWithoutValidation(DeviceTokenHeader, token);
        }

        return message;
    }
}
