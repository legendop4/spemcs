using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading;
using System.Threading.Tasks;
using Spemcs.Agent.Core;

namespace Spemcs.Agent.Service;

public class BackendRegistrationService : IRegistrationService
{
    private readonly HttpClient _http;
    public BackendRegistrationService(HttpClient http) => _http = http;

    public async Task<DeviceRegistration> RegisterDeviceAsync(string deviceName, string ipAddress, CancellationToken cancellationToken = default)
    {
        var req = new { deviceName, ipAddress };
        var res = await _http.PostAsJsonAsync("api/v1/devices/register", req, cancellationToken);
        res.EnsureSuccessStatusCode();
        var data = await res.Content.ReadFromJsonAsync<RegistrationResponse>(cancellationToken: cancellationToken);
        if (data == null) throw new InvalidOperationException("Failed to read registration response.");
        return new DeviceRegistration(Guid.Parse(data.DeviceId), data.DeviceName, data.IpAddress, DateTimeOffset.Parse(data.RegisteredAtUtc));
    }
    
    private record RegistrationResponse(string DeviceId, string DeviceName, string IpAddress, string RegisteredAtUtc);
}

public class BackendSessionService : ISessionService
{
    private readonly HttpClient _http;
    public BackendSessionService(HttpClient http) => _http = http;

    public async Task<bool> StartExamSessionAsync(string sessionId, ApprovedBrowserFamily approvedBrowser, CancellationToken cancellationToken = default)
    {
        var req = new { sessionId, approvedBrowser = approvedBrowser.ToString() };
        var res = await _http.PostAsJsonAsync("api/v1/sessions/start", req, cancellationToken);
        return res.IsSuccessStatusCode;
    }

    public async Task<bool> RegisterStudentAsync(string sessionId, string rollNumber, CancellationToken cancellationToken = default)
    {
        var req = new { sessionId, rollNumber };
        var res = await _http.PostAsJsonAsync("api/v1/sessions/verify-student", req, cancellationToken);
        return res.IsSuccessStatusCode;
    }
}

public class BackendEventPublisher : IEventPublisher
{
    private readonly HttpClient _http;
    public BackendEventPublisher(HttpClient http) => _http = http;

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
        var res = await _http.PostAsJsonAsync("api/v1/events", req, cancellationToken);
        res.EnsureSuccessStatusCode();
    }
}
