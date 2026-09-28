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
    private readonly string _pipeName;
    private NamedPipeServerStream? _activeSessionPipe;

    public NamedPipeUiGateway(ILogger<NamedPipeUiGateway> log, IUiLauncher launcher, string pipeName = PipeNames.Agent)
    {
        _log = log;
        _launcher = launcher;
        _pipeName = pipeName;
    }

    public async Task<DeviceRegistration?> RequestRegistrationAsync(string ipAddress, CancellationToken cancellationToken)
    {
        _log.LogInformation("[UI_SETUP_REQUESTED] source=GATEWAY_REQUEST, ip={IpAddress}, pid={Pid}", ipAddress, Environment.ProcessId);
        var response = await RequestAsync(MessageTypes.RequestRegistration, new RegistrationRequestPayload(ipAddress), cancellationToken, arguments: "--setup");
        var result = response?.Payload.Deserialize<RegistrationPayload>();
        if (response?.Type != MessageTypes.RegistrationData || result is null || string.IsNullOrWhiteSpace(result.DeviceName) || result.DeviceName.Length > 100) return null;
        var devId = result.DeviceId.HasValue && result.DeviceId.Value != Guid.Empty ? result.DeviceId.Value : Guid.Empty;
        return new DeviceRegistration(devId, result.DeviceName.Trim(), ipAddress, DateTimeOffset.UtcNow);
    }

    public async Task ShowPreComplianceLoadingAsync(CancellationToken cancellationToken)
    {
        await CloseActivePipeAsync();
        _activeSessionPipe = PipeProtocol.CreateServer(_pipeName);

        bool alreadyRunning = false;
        try
        {
            alreadyRunning = System.Diagnostics.Process.GetProcessesByName("Spemcs.Agent.UI").Length > 0;
        }
        catch { }

        bool connected = false;
        if (alreadyRunning)
        {
            var count = System.Diagnostics.Process.GetProcessesByName("Spemcs.Agent.UI").Length;
            _log.LogInformation("Existing Spemcs.Agent.UI process detected (count={Count}); waiting up to 5s for pipe connection...", count);
            using var quickWait = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            quickWait.CancelAfter(TimeSpan.FromSeconds(5));
            try
            {
                await _activeSessionPipe.WaitForConnectionAsync(quickWait.Token).ConfigureAwait(false);
                connected = true;
                _log.LogInformation("[UI_PIPE_CONNECTED] Connected to existing Spemcs.Agent.UI process.");
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                _log.LogWarning("Existing UI process did not connect within 5s. Terminating stale UI and launching fresh with --exam-mode...");
            }
        }

        if (!connected)
        {
            LaunchUi(arguments: "--exam-mode", forceRestart: true);
            _log.LogInformation("[UI_PIPE_WAIT_BEGIN] Waiting for newly launched UI process to connect on pipe {PipeName}...", _pipeName);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromMinutes(2));
            await _activeSessionPipe.WaitForConnectionAsync(timeout.Token).ConfigureAwait(false);
            _log.LogInformation("[UI_PIPE_CONNECTED] Connected to newly launched UI named pipe.");
        }

        var payload = new PreComplianceScanPayload(
            IsLoading: true,
            IsClean: false,
            SuspiciousProcesses: [],
            StatusText: "Pre-Compliance Check scanning in progress...");

        await PipeProtocol.WriteAsync(_activeSessionPipe, MessageTypes.ShowPreComplianceLoading, payload, cancellationToken).ConfigureAwait(false);
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

        await PipeProtocol.WriteAsync(_activeSessionPipe, MessageTypes.UpdatePreComplianceResult, payload, timeout.Token).ConfigureAwait(false);
        _log.LogInformation("[PRECOMPLIANCE_SHOWN] Pre-compliance scan results sent to UI. IsClean={IsClean}", result.IsClean);

        // Await student clicking [ Continue ]
        var response = await PipeProtocol.ReadAsync(_activeSessionPipe, timeout.Token).ConfigureAwait(false);
        _log.LogInformation("[PRECOMPLIANCE_CONTINUED] Received pre-compliance acknowledgement from UI: {Type}", response?.Type);
    }

    public async Task<string?> RequestStudentVerificationAsync(CancellationToken cancellationToken)
    {
        if (_activeSessionPipe is null || !_activeSessionPipe.IsConnected)
        {
            await ShowPreComplianceLoadingAsync(cancellationToken).ConfigureAwait(false);
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(5));

        await PipeProtocol.WriteAsync(_activeSessionPipe!, MessageTypes.ShowStudentVerification, new { }, timeout.Token).ConfigureAwait(false);
        var response = await PipeProtocol.ReadAsync(_activeSessionPipe!, timeout.Token).ConfigureAwait(false);
        var result = response?.Payload.Deserialize<StudentVerificationPayload>();

        if (result == null || string.IsNullOrWhiteSpace(result.RollNumber)) return null;

        _log.LogInformation("[STUDENT_PASSWORD_VERIFIED] Student verification received for roll: {RollNumber}", result.RollNumber);
        return result.RollNumber;
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

    private async Task<PipeEnvelope?> RequestAsync(string type, object payload, CancellationToken cancellationToken, string? arguments = null)
    {
        Exception? last = null;
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromMinutes(5));
                await using var server = PipeProtocol.CreateServer(_pipeName);

                bool alreadyRunning = false;
                try
                {
                    alreadyRunning = System.Diagnostics.Process.GetProcessesByName("Spemcs.Agent.UI").Length > 0;
                }
                catch { }

                if (!alreadyRunning || attempt > 1)
                {
                    LaunchUi(arguments, forceRestart: attempt > 1);
                }

                _log.LogInformation("[UI_PIPE_WAIT_BEGIN] Waiting for UI to connect for {MessageType} on pipe {PipeName} (attempt {Attempt})...", type, _pipeName, attempt);
                await server.WaitForConnectionAsync(timeout.Token);
                _log.LogInformation("[UI_PIPE_CONNECTED] UI connected for {MessageType}.", type);
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

    private void LaunchUi(string? arguments = null, bool forceRestart = false)
    {
        var activeWorkspaceDebugExe = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "Spemcs.Agent.UI", "bin", "Debug", "net8.0-windows", "Spemcs.Agent.UI.exe"));
        var activeWorkspaceReleaseExe = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "Spemcs.Agent.UI", "bin", "Release", "net8.0-windows", "Spemcs.Agent.UI.exe"));
        var directSiblingExe = Path.Combine(AppContext.BaseDirectory, "Spemcs.Agent.UI.exe");
        var envPath = Environment.GetEnvironmentVariable("SPEMCS_AGENT_UI_PATH");

        var candidates = new List<string?>
        {
            directSiblingExe,
            activeWorkspaceDebugExe,
            activeWorkspaceReleaseExe,
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "Spemcs.Agent.UI", "bin", "Release", "net8.0-windows", "win-x64", "Spemcs.Agent.UI.exe")),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "Spemcs.Agent.UI", "Spemcs.Agent.UI.exe")),
            Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "Endpoint-agent", "src", "Spemcs.Agent.UI", "bin", "Debug", "net8.0-windows", "Spemcs.Agent.UI.exe")),
            Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "Endpoint-agent", "src", "Spemcs.Agent.UI", "bin", "Release", "net8.0-windows", "Spemcs.Agent.UI.exe")),
            Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "Endpoint-agent", "src", "Spemcs.Agent.UI", "bin", "Release", "net8.0-windows", "win-x64", "Spemcs.Agent.UI.exe")),
            envPath
        };

        var path = candidates.FirstOrDefault(p => !string.IsNullOrWhiteSpace(p) && File.Exists(p));
        if (path is null)
        {
            throw new FileNotFoundException("SPEMCS Agent UI executable was not found. Please build the solution with 'dotnet build Endpoint-agent\\Spemcs.Agent.sln'.");
        }

        if (forceRestart)
        {
            // Terminate any hanging or orphan UI process from previous runs on retry
            try
            {
                foreach (var p in System.Diagnostics.Process.GetProcessesByName("Spemcs.Agent.UI"))
                {
                    try
                    {
                        p.Kill();
                        p.WaitForExit(2000);
                    }
                    catch { }
                }
            }
            catch { }
        }

        _log.LogInformation("[UI_LAUNCH_REQUESTED] Requesting UI launch at {Path} with args='{Args}'", path, arguments ?? "");
        bool launched = _launcher.Launch(path, arguments);
        if (launched)
        {
            _log.LogInformation("[UI_LAUNCHED] UI process launched successfully at {Path}", path);
        }
        else
        {
            _log.LogError("[UI_LAUNCH_FAILED] UI launcher failed to start process at {Path}", path);
            throw new InvalidOperationException($"Failed to launch SPEMCS Agent UI at {path}. No active interactive session or CreateProcessAsUser failure.");
        }
    }
}
