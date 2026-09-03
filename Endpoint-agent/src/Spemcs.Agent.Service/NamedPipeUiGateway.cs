using Microsoft.Extensions.Logging;
using Spemcs.Agent.Core;
using Spemcs.Agent.Ipc;
using System.Text.Json;
using System.IO.Pipes;

namespace Spemcs.Agent.Service;

public sealed class NamedPipeUiGateway : IExamUiGateway
{
    private readonly ILogger<NamedPipeUiGateway> _log;
    private readonly IUiLauncher _launcher;
    private NamedPipeServerStream? _activeSessionPipe;

    public NamedPipeUiGateway(ILogger<NamedPipeUiGateway> log, IUiLauncher launcher)
    {
        _log = log;
        _launcher = launcher;
    }

    public async Task<DeviceRegistration?> RequestRegistrationAsync(string ipAddress, CancellationToken cancellationToken)
    {
        var response = await RequestAsync(MessageTypes.RequestRegistration, new RegistrationRequestPayload(ipAddress), cancellationToken);
        var result = response?.Payload.Deserialize<RegistrationPayload>();
        if (response?.Type != MessageTypes.RegistrationData || result is null || string.IsNullOrWhiteSpace(result.DeviceName) || result.DeviceName.Length > 100) return null;
        return new DeviceRegistration(Guid.NewGuid(), result.DeviceName.Trim(), ipAddress, DateTimeOffset.UtcNow);
    }

    public async Task ShowPreComplianceLoadingAsync(CancellationToken cancellationToken)
    {
        await CloseActivePipeAsync();
        _activeSessionPipe = PipeProtocol.CreateServer(PipeNames.Agent);
        LaunchUi();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(5));
        await _activeSessionPipe.WaitForConnectionAsync(timeout.Token);

        var payload = new PreComplianceScanPayload(
            IsLoading: true,
            IsClean: false,
            SuspiciousProcesses: [],
            StatusText: "Pre-Compliance Check scanning in progress...");

        await PipeProtocol.WriteAsync(_activeSessionPipe, MessageTypes.ShowPreComplianceLoading, payload, timeout.Token);
    }

    public async Task UpdatePreComplianceResultAsync(PreComplianceScanResult result, CancellationToken cancellationToken)
    {
        if (_activeSessionPipe is null || !_activeSessionPipe.IsConnected) return;

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(5));

        var displayItems = result.SuspiciousProcesses.Select(p => new ProcessDisplayPayload(p.Name, p.ExecutablePath, p.Category, p.Reason)).ToArray();
        var payload = new PreComplianceScanPayload(
            IsLoading: false,
            IsClean: result.IsClean,
            SuspiciousProcesses: displayItems,
            StatusText: result.StatusText);

        await PipeProtocol.WriteAsync(_activeSessionPipe, MessageTypes.UpdatePreComplianceResult, payload, timeout.Token);

        // Await student clicking [ Continue ]
        var response = await PipeProtocol.ReadAsync(_activeSessionPipe, timeout.Token);
        _log.LogInformation("Received pre-compliance acknowledgement from UI: {Type}", response?.Type);
    }

    public async Task<string?> RequestStudentVerificationAsync(CancellationToken cancellationToken)
    {
        if (_activeSessionPipe is null || !_activeSessionPipe.IsConnected)
        {
            _activeSessionPipe = PipeProtocol.CreateServer(PipeNames.Agent);
            LaunchUi();
            await _activeSessionPipe.WaitForConnectionAsync(cancellationToken);
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(5));

        await PipeProtocol.WriteAsync(_activeSessionPipe, MessageTypes.ShowStudentVerification, new { }, timeout.Token);
        var response = await PipeProtocol.ReadAsync(_activeSessionPipe, timeout.Token);
        var result = response?.Payload.Deserialize<StudentVerificationPayload>();

        return result?.RollNumber;
    }

    public async Task NotifySessionStartedAsync(CancellationToken cancellationToken)
    {
        if (_activeSessionPipe is not null && _activeSessionPipe.IsConnected)
        {
            try { await PipeProtocol.WriteAsync(_activeSessionPipe, MessageTypes.SessionStart, new { }, cancellationToken); }
            catch { }
            finally { await CloseActivePipeAsync(); }
        }
    }

    public async Task NotifySessionStoppedAsync(CancellationToken cancellationToken)
    {
        if (_activeSessionPipe is not null && _activeSessionPipe.IsConnected)
        {
            try { await PipeProtocol.WriteAsync(_activeSessionPipe, MessageTypes.SessionStop, new { }, cancellationToken); }
            catch { }
            finally { await CloseActivePipeAsync(); }
        }
    }

    private async Task CloseActivePipeAsync()
    {
        if (_activeSessionPipe is not null)
        {
            await _activeSessionPipe.DisposeAsync();
            _activeSessionPipe = null;
        }
    }

    private async Task<PipeEnvelope?> RequestAsync(string type, object payload, CancellationToken cancellationToken)
    {
        Exception? last = null;
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromMinutes(5));
                await using var server = PipeProtocol.CreateServer(PipeNames.Agent);
                LaunchUi();
                await server.WaitForConnectionAsync(timeout.Token);
                await PipeProtocol.WriteAsync(server, type, payload, timeout.Token);
                return await PipeProtocol.ReadAsync(server, timeout.Token);
            }
            catch (Exception ex) when (ex is IOException or TimeoutException or OperationCanceledException)
            {
                last = ex;
                if (cancellationToken.IsCancellationRequested) throw;
                _log.LogWarning(ex, "UI pipe attempt {Attempt} failed for {MessageType}; retrying.", attempt, type);
                await Task.Delay(TimeSpan.FromMilliseconds(250 * attempt), cancellationToken);
            }
        }
        throw new IOException($"UI pipe request failed after three attempts for {type}.", last);
    }

    private void LaunchUi()
    {
        var activeWorkspaceExe = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "Spemcs.Agent.UI", "bin", "Debug", "net8.0-windows", "Spemcs.Agent.UI.exe"));
        var directSiblingExe = Path.Combine(AppContext.BaseDirectory, "Spemcs.Agent.UI.exe");
        var envPath = Environment.GetEnvironmentVariable("SPEMCS_AGENT_UI_PATH");

        var candidates = new List<string?>
        {
            activeWorkspaceExe,
            directSiblingExe,
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "Spemcs.Agent.UI", "Spemcs.Agent.UI.exe")),
            Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "Endpoint-agent", "src", "Spemcs.Agent.UI", "bin", "Debug", "net8.0-windows", "Spemcs.Agent.UI.exe")),
            envPath
        };

        var path = candidates.FirstOrDefault(p => !string.IsNullOrWhiteSpace(p) && File.Exists(p));
        if (path is null)
        {
            throw new FileNotFoundException("SPEMCS Agent UI executable was not found. Please build the solution with 'dotnet build Endpoint-agent\\Spemcs.Agent.sln'.");
        }

        // Terminate any hanging or orphan UI process from previous runs
        try
        {
            foreach (var p in System.Diagnostics.Process.GetProcessesByName("Spemcs.Agent.UI"))
            {
                try { p.Kill(); } catch { }
            }
        }
        catch { }

        _launcher.Launch(path);
        _log.LogInformation("Launched Agent UI in the active interactive session at {Path}", path);
    }
}
