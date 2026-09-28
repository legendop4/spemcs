using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Spemcs.Agent.Core;
using Spemcs.Agent.Core.Network;

namespace Spemcs.Agent.Service;

/// <summary>
/// Immutable snapshot of verified workstation enrollment configuration.
/// </summary>
public sealed record EnrolledIdentity(
    string ServerUrl,
    string HardwareUuid,
    string DeviceName,
    string DeviceToken,
    Guid DeviceId);

/// <summary>
/// Service-owned background worker maintaining a persistent 24/7 WebSocket connection to Central Server.
/// Watches config.json for enrollment changes, automatically transitions from pending-enrollment to connected,
/// and reloads/reconnects cleanly with debouncing when identity updates.
/// </summary>
public sealed class CentralWebSocketWorker : BackgroundService, IWebSocketStatusProvider
{
    private readonly ILogger<CentralWebSocketWorker> _log;
    private readonly DeviceCredentialStore _credentials;
    private readonly IKeyringSyncService _keyringSync;
    private readonly ITrustedKeyStore _keyStore;
    private readonly IEnforcementStateMachine _enforcement;
    private readonly IFirewallAdapter _firewall;
    private readonly IRegistrationService _regService;
    private readonly IExamLifecycleCoordinator? _lifecycleCoordinator;
    private readonly IAgentStore? _agentStore;
    private readonly string _defaultBackendUrl;
    private readonly string _configPath;

    private readonly object _identityLock = new();
    private EnrolledIdentity? _activeIdentity;
    private CancellationTokenSource? _currentSocketCts;
    private readonly SemaphoreSlim _reconnectSignal = new(0, 1);
    private readonly System.Threading.Timer _debounceTimer;
    private readonly FileSystemWatcher? _configWatcher;

    private int _backoffSec = 2;

    public bool IsConnected { get; private set; }

    public string? CurrentHardwareUuid
    {
        get
        {
            lock (_identityLock)
            {
                return _activeIdentity?.HardwareUuid;
            }
        }
    }

    public string? CurrentDeviceName
    {
        get
        {
            lock (_identityLock)
            {
                return _activeIdentity?.DeviceName;
            }
        }
    }

    private readonly IRegistrationSynchronizer? _registrationSynchronizer;

    public CentralWebSocketWorker(
        ILogger<CentralWebSocketWorker> log,
        DeviceCredentialStore credentials,
        IKeyringSyncService keyringSync,
        ITrustedKeyStore keyStore,
        IEnforcementStateMachine enforcement,
        IFirewallAdapter firewall,
        IRegistrationService regService,
        ServiceConfigResolver configResolver,
        IExamLifecycleCoordinator? lifecycleCoordinator = null,
        string? customConfigPath = null,
        IAgentStore? agentStore = null,
        IRegistrationSynchronizer? registrationSynchronizer = null)
    {
        _log = log;
        _credentials = credentials;
        _keyringSync = keyringSync;
        _keyStore = keyStore;
        _enforcement = enforcement;
        _firewall = firewall;
        _regService = regService;
        _lifecycleCoordinator = lifecycleCoordinator;
        _agentStore = agentStore;
        _registrationSynchronizer = registrationSynchronizer;
        _defaultBackendUrl = configResolver.ResolvedUrl;

        _configPath = customConfigPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Spemcs", "Endpoint Agent", "config.json");

        _debounceTimer = new System.Threading.Timer(OnDebounceTimerFired, null, Timeout.Infinite, Timeout.Infinite);

        // Try initial load of valid config (if already enrolled)
        _activeIdentity = TryLoadValidConfig(_configPath, _log);
        if (_activeIdentity != null)
        {
            _credentials.SetDeviceToken(_activeIdentity.DeviceToken);
            if (_registrationSynchronizer != null)
            {
                _ = _registrationSynchronizer.SyncRegistrationAsync("ws_startup", allowBackendQuery: false);
            }
            else
            {
                SyncStoreRegistration(_activeIdentity);
            }
            _log.LogInformation("Enrolled identity loaded on startup: '{HardwareUuid}' (Device: '{DeviceName}')",
                _activeIdentity.HardwareUuid, _activeIdentity.DeviceName);
        }
        else
        {
            _log.LogInformation("Workstation is not yet enrolled. Awaiting valid config.json from Setup Wizard...");
        }

        try
        {
            var configDir = Path.GetDirectoryName(_configPath);
            if (!string.IsNullOrWhiteSpace(configDir))
            {
                Directory.CreateDirectory(configDir);
                _configWatcher = new FileSystemWatcher(configDir)
                {
                    Filter = "*.*",
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.CreationTime,
                    EnableRaisingEvents = true
                };
                _configWatcher.Created += OnConfigFileEvent;
                _configWatcher.Changed += OnConfigFileEvent;
                _configWatcher.Renamed += OnConfigFileRenamed;
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to initialize FileSystemWatcher on config directory. Polling fallback will be used.");
        }
    }

    private void OnConfigFileEvent(object sender, FileSystemEventArgs e)
    {
        if (IsConfigRelated(e.Name))
        {
            _debounceTimer.Change(300, Timeout.Infinite);
        }
    }

    private void OnConfigFileRenamed(object sender, RenamedEventArgs e)
    {
        if (IsConfigRelated(e.Name) || IsConfigRelated(e.OldName))
        {
            _debounceTimer.Change(300, Timeout.Infinite);
        }
    }

    private static bool IsConfigRelated(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        return name.Equals("config.json", StringComparison.OrdinalIgnoreCase) ||
               name.StartsWith("config.json.", StringComparison.OrdinalIgnoreCase);
    }

    private void OnDebounceTimerFired(object? state)
    {
        try
        {
            HandleConfigChanged();
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Error while processing configuration change event");
        }
    }

    public void HandleConfigChanged()
    {
        var newIdentity = TryLoadValidConfig(_configPath, _log);
        if (newIdentity == null)
        {
            _log.LogInformation("Configuration changed but is absent, un-enrolled, or invalid. Holding connection.");
            return;
        }

        lock (_identityLock)
        {
            if (_activeIdentity != null &&
                _activeIdentity.HardwareUuid == newIdentity.HardwareUuid &&
                _activeIdentity.DeviceName == newIdentity.DeviceName &&
                _activeIdentity.DeviceToken == newIdentity.DeviceToken &&
                _activeIdentity.ServerUrl == newIdentity.ServerUrl)
            {
                return; // Exact same identity, no-op
            }

            _log.LogInformation("Enrolled identity updated: '{OldHw}' -> '{NewHw}' (Device: '{NewDev}'). Triggering safe reconnect...",
                _activeIdentity?.HardwareUuid ?? "NONE", newIdentity.HardwareUuid, newIdentity.DeviceName);

            _activeIdentity = newIdentity;
            _credentials.SetDeviceToken(newIdentity.DeviceToken);
            if (_registrationSynchronizer != null)
            {
                _ = _registrationSynchronizer.SyncRegistrationAsync("config_watcher", allowBackendQuery: true);
            }
            else
            {
                SyncStoreRegistration(newIdentity);
            }

            // Signal the single execution loop to wake up and cancel the active socket
            if (_reconnectSignal.CurrentCount == 0)
            {
                try { _reconnectSignal.Release(); } catch { }
            }

            try
            {
                _currentSocketCts?.Cancel();
            }
            catch { }
        }
    }

    private void SyncStoreRegistration(EnrolledIdentity identity)
    {
        if (_agentStore == null) return;
        try
        {
            var currentReg = _agentStore.LoadSnapshot().Registration;
            Guid devId = identity.DeviceId != Guid.Empty
                ? identity.DeviceId
                : (currentReg?.DeviceId != null && currentReg.DeviceId != Guid.Empty ? currentReg.DeviceId : Guid.Empty);

            if (devId != Guid.Empty && (currentReg == null || currentReg.DeviceId != devId || currentReg.DeviceName != identity.DeviceName))
            {
                _agentStore.SaveRegistration(new DeviceRegistration(devId, identity.DeviceName, currentReg?.IpAddress ?? "127.0.0.1", DateTimeOffset.UtcNow));
                _log.LogInformation("Synchronized agent store registration with enrolled identity: DeviceName={Name}, DeviceId={Id}", identity.DeviceName, devId);
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to synchronize agent store registration with enrolled identity");
        }
    }

    public static EnrolledIdentity? TryLoadValidConfig(string configPath, ILogger? log = null)
    {
        if (!File.Exists(configPath))
        {
            return null;
        }

        for (int retry = 0; retry < 5; retry++)
        {
            try
            {
                using var stream = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var doc = JsonDocument.Parse(stream);
                var root = doc.RootElement;

                bool registered = false;
                if (root.TryGetProperty("registered", out var regProp))
                {
                    if (regProp.ValueKind == JsonValueKind.True) registered = true;
                    else if (regProp.ValueKind == JsonValueKind.String && bool.TryParse(regProp.GetString(), out var rb)) registered = rb;
                }

                if (!registered)
                {
                    log?.LogDebug("Config file at {Path} has registered=false", configPath);
                    return null;
                }

                string? serverUrl = root.TryGetProperty("serverUrl", out var sProp) ? sProp.GetString()?.Trim() : null;
                string? hwUuid = root.TryGetProperty("hardwareUuid", out var hProp) ? hProp.GetString()?.Trim() : null;
                string? devName = root.TryGetProperty("deviceName", out var dProp) ? dProp.GetString()?.Trim() : null;
                string? devToken = root.TryGetProperty("deviceToken", out var tProp) ? tProp.GetString()?.Trim() : null;
                string? devIdStr = root.TryGetProperty("deviceId", out var diProp) ? diProp.GetString()?.Trim() : null;

                if (string.IsNullOrWhiteSpace(serverUrl) ||
                    string.IsNullOrWhiteSpace(hwUuid) ||
                    string.IsNullOrWhiteSpace(devName) ||
                    string.IsNullOrWhiteSpace(devToken))
                {
                    log?.LogWarning("Config file at {Path} is missing required enrollment fields (serverUrl, hardwareUuid, deviceName, deviceToken)", configPath);
                    return null;
                }

                Guid parsedDevId = Guid.TryParse(devIdStr, out var gid) && gid != Guid.Empty ? gid : Guid.Empty;
                return new EnrolledIdentity(serverUrl, hwUuid, devName, devToken, parsedDevId);
            }
            catch (IOException) when (retry < 4)
            {
                Thread.Sleep(100);
            }
            catch (JsonException) when (retry < 4)
            {
                Thread.Sleep(100);
            }
            catch (Exception ex)
            {
                log?.LogWarning(ex, "Failed to read or parse config file at {Path}", configPath);
                return null;
            }
        }
        return null;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        _log.LogInformation("CentralWebSocketWorker background loop started. Config path: '{ConfigPath}'", _configPath);

        while (!stoppingToken.IsCancellationRequested)
        {
            EnrolledIdentity? identity;
            lock (_identityLock)
            {
                _activeIdentity ??= TryLoadValidConfig(_configPath, _log);
                identity = _activeIdentity;
            }

            if (identity == null)
            {
                _log.LogInformation("CentralWebSocketWorker: Workstation is not enrolled yet. Awaiting valid config.json from Setup Wizard...");
                IsConnected = false;
                try
                {
                    await _reconnectSignal.WaitAsync(TimeSpan.FromSeconds(5), stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                continue;
            }

            _credentials.SetDeviceToken(identity.DeviceToken);

            try
            {
                await _keyringSync.EnsureKeyStoreInitializedAsync(identity.ServerUrl, stoppingToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Keyring sync initialization encountered an error. Proceeding with existing keys.");
            }

            using var socketCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            lock (_identityLock)
            {
                _currentSocketCts = socketCts;
            }

            var wsUri = new Uri(identity.ServerUrl.Replace("http://", "ws://").Replace("https://", "wss://").TrimEnd('/') + "/api/v1/ws/agent");

            try
            {
                using var ws = new ClientWebSocket();
                _log.LogInformation("Connecting to Central WebSocket for '{HardwareUuid}' at {WsUri}...", identity.HardwareUuid, wsUri);

                await ws.ConnectAsync(wsUri, socketCts.Token).ConfigureAwait(false);
                IsConnected = true;
                _log.LogInformation("Central WebSocket connected for '{HardwareUuid}'! State={State}", identity.HardwareUuid, ws.State);
                _backoffSec = 2;

                var registerPayload = JsonSerializer.Serialize(new
                {
                    action = "REGISTER",
                    hardware_uuid = identity.HardwareUuid,
                    device_token = identity.DeviceToken,
                    device_name = identity.DeviceName
                });
                var regBytes = Encoding.UTF8.GetBytes(registerPayload);
                await ws.SendAsync(new ArraySegment<byte>(regBytes), WebSocketMessageType.Text, true, socketCts.Token).ConfigureAwait(false);
                _log.LogInformation("Sent REGISTER payload for '{HardwareUuid}'", identity.HardwareUuid);

                var buffer = new byte[16384];
                while (ws.State == WebSocketState.Open && !socketCts.Token.IsCancellationRequested)
                {
                    var result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), socketCts.Token).ConfigureAwait(false);
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        _log.LogWarning("WebSocket closed by server (Status={Status}, Desc={Desc})", result.CloseStatus, result.CloseStatusDescription);
                        break;
                    }

                    var json = Encoding.UTF8.GetString(buffer, 0, result.Count);
                    await HandleMessageAsync(ws, json, socketCts.Token).ConfigureAwait(false);
                }

                if (ws.State == WebSocketState.Open)
                {
                    try
                    {
                        using var closeCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                        await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Identity changing or shutting down", closeCts.Token).ConfigureAwait(false);
                    }
                    catch { }
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (OperationCanceledException)
            {
                _log.LogInformation("WebSocket disconnected due to identity change or reload request.");
            }
            catch (Exception ex)
            {
                _log.LogWarning("WebSocket connection dropped or failed for '{HardwareUuid}': {Message}. Retrying in {Sec}s...",
                    identity.HardwareUuid, ex.Message, _backoffSec);

                if (ex is WebSocketException wsEx && (wsEx.Message.Contains("401") || wsEx.Message.Contains("403") || wsEx.Message.Contains("Unauthorized") || wsEx.Message.Contains("Forbidden")))
                {
                    _log.LogWarning("Central Server rejected credentials with 401/403. Marking device as Unenrolled.");
                    lock (_identityLock)
                    {
                        _activeIdentity = null;
                    }
                    _credentials.ClearDeviceToken();
                    MarkConfigUnenrolled(_configPath);
                }
            }
            finally
            {
                IsConnected = false;
                lock (_identityLock)
                {
                    if (_currentSocketCts == socketCts)
                    {
                        _currentSocketCts = null;
                    }
                }
            }

            if (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await _reconnectSignal.WaitAsync(TimeSpan.FromSeconds(_backoffSec), stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                _backoffSec = Math.Min(_backoffSec * 2, 30);
            }
        }
    }

    private async Task HandleMessageAsync(ClientWebSocket ws, string json, CancellationToken ct)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            string action = "";
            if (root.TryGetProperty("action", out var actProp))
                action = actProp.GetString() ?? "";
            else if (root.TryGetProperty("message_type", out var msgTypeProp))
                action = msgTypeProp.GetString() ?? "";
            else if (root.TryGetProperty("type", out var typeProp))
                action = typeProp.GetString() ?? "";

            _log.LogInformation("CentralWebSocketWorker received action: '{Action}'", action);

            if (action.Equals("HEARTBEAT_PING", StringComparison.OrdinalIgnoreCase))
            {
                var pong = JsonSerializer.Serialize(new { action = "HEARTBEAT_PONG" });
                var bytes = Encoding.UTF8.GetBytes(pong);
                await ws.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, ct).ConfigureAwait(false);
                return;
            }

            if (action.Equals("REGISTERED", StringComparison.OrdinalIgnoreCase))
            {
                _log.LogInformation("Registration confirmed by Central Server for '{HardwareUuid}'", CurrentHardwareUuid);
                if (root.TryGetProperty("device_id", out var devIdProp) &&
                    Guid.TryParse(devIdProp.GetString(), out var serverDevId) && serverDevId != Guid.Empty)
                {
                    var devName = root.TryGetProperty("device_name", out var dnp) ? dnp.GetString() : CurrentDeviceName;
                    var currentReg = _agentStore?.LoadSnapshot().Registration;
                    if (_agentStore != null && (currentReg == null || currentReg.DeviceId != serverDevId || currentReg.DeviceName != devName))
                    {
                        _agentStore.SaveRegistration(new DeviceRegistration(serverDevId, devName ?? CurrentHardwareUuid ?? "Device", currentReg?.IpAddress ?? "127.0.0.1", DateTimeOffset.UtcNow));
                        _log.LogInformation("[REGISTRATION_SAVED] source=ws_registered, deviceName={Name}, deviceIdPresent=true", devName);
                    }
                }
                return;
            }

            if (action.Equals("LAUNCH_EXAM_MODE", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("START_EXAM", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("START_EXAM_MODE", StringComparison.OrdinalIgnoreCase))
            {
                var examIdStr = root.TryGetProperty("exam_id", out var ep) ? ep.GetString() : null;
                var examName = root.TryGetProperty("exam_name", out var enp) ? enp.GetString() : "Exam";
                var allowedDomain = root.TryGetProperty("allowed_domain", out var adp) ? adp.GetString() : null;
                var approvedBrowser = root.TryGetProperty("approved_browser", out var abp) ? abp.GetString() : null;

                Guid examId = Guid.Empty;
                if (!string.IsNullOrWhiteSpace(examIdStr))
                {
                    Guid.TryParse(examIdStr, out examId);
                }

                _log.LogInformation("[EXAM_ACTIVATION_RECEIVED] Central Server requested {Action}: ExamId={ExamId}, ExamName={ExamName}, Browser={Browser}",
                    action, examId, examName, approvedBrowser);

                if (action.Equals("LAUNCH_EXAM_MODE", StringComparison.OrdinalIgnoreCase))
                {
                    _log.LogInformation("[LAUNCH_EXAM_MODE_RECEIVED] Received LAUNCH_EXAM_MODE command for ExamId={ExamId}", examId);
                }

                var request = new ExamActivationRequest(examId, examName ?? "Exam", allowedDomain, approvedBrowser);

                bool uiLaunchSuccess = false;
                if (_lifecycleCoordinator != null)
                {
                    uiLaunchSuccess = await _lifecycleCoordinator.LaunchExamAsync(request, ct).ConfigureAwait(false);
                }
                else
                {
                    _log.LogWarning("No lifecycle coordinator available to launch exam.");
                }

                if (!uiLaunchSuccess)
                {
                    _log.LogError("[UI_LAUNCH_FAILED] UI launch failed or was rejected for ExamId={ExamId}. Firewall enforcement remains unaffected (fail-closed).", examId);
                }
                else
                {
                    _log.LogInformation("Exam launch initiated: ExamId={ExamId}, Accepted={Accepted}", examId, uiLaunchSuccess);
                }

                return;
            }

            if (action.Equals("SIGNED_NETWORK_POLICY", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("UPDATE_EXAM_POLICY", StringComparison.OrdinalIgnoreCase))
            {
                var rawPolicyJson = root.GetProperty("raw_policy_json").GetString() ?? "";
                var signatureBase64 = root.GetProperty("signature_base64").GetString() ?? "";
                var protocolVersion = root.TryGetProperty("protocol_version", out var pv) ? pv.GetInt32() : 1;

                using var pDoc = JsonDocument.Parse(rawPolicyJson);
                var pRoot = pDoc.RootElement;

                var examId = Guid.Parse(pRoot.GetProperty("exam_id").GetString()!);
                var policyId = Guid.Parse(pRoot.GetProperty("policy_id").GetString()!);
                var version = pRoot.GetProperty("version").GetInt32();
                var keyId = pRoot.TryGetProperty("key_id", out var kProp) ? kProp.GetString() : null;
                var sessionId = (_enforcement.CurrentSession != null && _enforcement.CurrentSession.ExamId == examId)
                    ? _enforcement.CurrentSession.SessionId
                    : Guid.NewGuid();

                // If key is missing from local keystore, attempt on-demand refresh from the connected server
                if (!string.IsNullOrWhiteSpace(keyId) && _keyStore.GetPublicKey(keyId) == null)
                {
                    var serverUrl = _activeIdentity?.ServerUrl ?? ServiceConfigResolver.ResolveCurrentServerUrl(_configPath);
                    _log.LogInformation("Policy key '{KeyId}' not found in local keystore. Performing on-demand refresh from {ServerUrl}...",
                        keyId, serverUrl);
                    try
                    {
                        await _keyringSync.ForceRefreshAsync(serverUrl, ct).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        _log.LogWarning(ex, "On-demand keyring refresh failed for key '{KeyId}'. Proceeding to validation (fail-closed expected).", keyId);
                    }
                }

                var signedMsg = new SignedPolicyMessage(
                    action,
                    protocolVersion,
                    rawPolicyJson,
                    signatureBase64
                );

                _log.LogInformation("Activating enforcement for Exam {ExamId}, Policy {PolicyId}, Version {Version}...",
                    examId, policyId, version);

                var activation = await _enforcement.ActivateAsync(sessionId, signedMsg, examId, FirewallProfiles.All, cancellationToken: ct)
                    .ConfigureAwait(false);

                var rulesInstalled = _firewall.GetRuleNamesByGroup(FirewallRuleModel.SpemcsRuleGroup).Count;
                if (activation.Success)
                {
                    _log.LogInformation("[POLICY_APPLIED] Policy applied successfully for Exam {ExamId}, Policy {PolicyId}, Version {Version}", examId, policyId, version);
                    _log.LogInformation("[ENFORCEMENT_ACTIVE] Windows Firewall lockdown enforcement active: {Rules} rules installed.", rulesInstalled);
                }

                var ackPayload = JsonSerializer.Serialize(new
                {
                    action = "POLICY_VALIDATION_RESULT",
                    exam_id = examId.ToString(),
                    policy_id = policyId.ToString(),
                    version = version,
                    status = activation.Success ? "APPLIED" : "FAILED",
                    rules_installed = activation.Success ? rulesInstalled : 0,
                    details = activation.Success ? "Active network lockdown enforced" : (activation.FailureReason ?? "Activation failed")
                });

                var ackBytes = Encoding.UTF8.GetBytes(ackPayload);
                await ws.SendAsync(new ArraySegment<byte>(ackBytes), WebSocketMessageType.Text, true, ct).ConfigureAwait(false);
                _log.LogInformation("Sent POLICY_VALIDATION_RESULT frame: Status={Status}, Rules={Rules}, Reason={Reason}",
                    activation.Success ? "APPLIED" : "FAILED", rulesInstalled, activation.FailureReason);
                return;
            }

            if (action.Equals("STOP_EXAM_MODE", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("STOP_EXAM", StringComparison.OrdinalIgnoreCase))
            {
                _log.LogInformation("[EXAM_STOP_RECEIVED] Stop exam mode requested by Central Server.");
                var cur = _enforcement.CurrentSession;
                var sessId = cur?.SessionId;
                var examId = cur?.ExamId;
                var policyId = cur?.PolicyId;
                var version = cur?.PolicyVersion ?? 0;

                if (sessId.HasValue)
                {
                    _log.LogInformation("Deactivating enforcement for Session {SessionId}...", sessId.Value);
                    var deact = await _enforcement.DeactivateAsync(sessId.Value, "Exam stopped by Central Server", ct).ConfigureAwait(false);
                    _log.LogInformation("Enforcement deactivated: Success={Success}, State={State}", deact.Success, deact.State);

                    var rulesInstalled = _firewall.GetRuleNamesByGroup(FirewallRuleModel.SpemcsRuleGroup).Count;
                    var ackPayload = JsonSerializer.Serialize(new
                    {
                        action = "POLICY_VALIDATION_RESULT",
                        exam_id = examId?.ToString() ?? "",
                        policy_id = policyId?.ToString() ?? "",
                        version = version,
                        status = deact.Success ? "ROLLED_BACK" : "FAILED",
                        rules_installed = rulesInstalled,
                        details = deact.Success ? "Rules restored to baseline" : (deact.FailureReason ?? "Deactivation failed")
                    });
                    var ackBytes = Encoding.UTF8.GetBytes(ackPayload);
                    await ws.SendAsync(new ArraySegment<byte>(ackBytes), WebSocketMessageType.Text, true, ct).ConfigureAwait(false);
                    _log.LogInformation("Sent POLICY_VALIDATION_RESULT frame for deactivation: Status={Status}", deact.Success ? "ROLLED_BACK" : "FAILED");
                }
                else
                {
                    _log.LogInformation("No active session tracked in memory on STOP_EXAM_MODE. Performing idle state verification.");
                    try
                    {
                        await _enforcement.ReconcileStartupStateAsync(ct).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        _log.LogWarning(ex, "Error reconciling state to Idle on STOP_EXAM_MODE");
                    }
                }

                if (_lifecycleCoordinator != null)
                {
                    await _lifecycleCoordinator.StopExamAsync(ct).ConfigureAwait(false);
                }

                return;
            }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to handle incoming WebSocket message");
        }
    }

    private void MarkConfigUnenrolled(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(path));
                var dict = new Dictionary<string, object?>();
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    if (prop.NameEquals("registered")) dict["registered"] = false;
                    else if (prop.NameEquals("deviceToken")) dict["deviceToken"] = null;
                    else dict[prop.Name] = prop.Value.Clone();
                }
                var json = JsonSerializer.Serialize(dict, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(path, json);
                _log.LogInformation("Marked config.json as unregistered after credentials rejection.");
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to mark config as unenrolled");
        }
    }

    public override void Dispose()
    {
        _configWatcher?.Dispose();
        _debounceTimer?.Dispose();
        _reconnectSignal?.Dispose();
        base.Dispose();
    }
}
