using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Spemcs.Agent.Core;
using Spemcs.Agent.Core.Network;
using Spemcs.Agent.Ipc;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Spemcs.Agent.Service;

public sealed class AgentWorker : BackgroundService
{
    private readonly ILogger<AgentWorker> _log;
    private readonly IAgentStore _store;
    private readonly IExamUiGateway _ui;
    private AgentStateMachine? _machine;
    private ExamPipeline? _pipeline;
    private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly IRegistrationService _regService;
    private readonly ISessionService _sessionService;
    private readonly IEventPublisher _publisher;
    private readonly IEnforcementStateMachine _enforcement;
    private readonly IApprovedBrowserContext _approvedBrowser;
    private readonly IWebSocketStatusProvider? _wsStatus;
    private readonly IExamLifecycleCoordinator? _lifecycleCoordinator;
    private readonly IUiLauncher? _uiLauncher;
    private readonly DeviceCredentialStore? _credentials;
    private readonly IRegistrationSynchronizer? _registrationSynchronizer;

    private EventUploaderWorker? _uploader;
    private NetworkCollector? _networkCollector;
    private ProcessMonitor? _processMonitor;
    private volatile bool _isStopping;

    private DateTimeOffset _lastNetworkRestart = DateTimeOffset.MinValue;
    private DateTimeOffset _lastProcessRestart = DateTimeOffset.MinValue;
    private DateTimeOffset _lastUploaderRestart = DateTimeOffset.MinValue;
    private static readonly TimeSpan RestartCooldown = TimeSpan.FromSeconds(15);

    public ProcessMonitor? ProcessMonitor => _processMonitor;
    public NetworkCollector? NetworkCollector => _networkCollector;
    public EventUploaderWorker? EventUploader => _uploader;

    public bool IsProcessMonitoringRunning => _processMonitor?.IsRunning ?? false;
    public bool IsNetworkMonitoringRunning => _networkCollector?.IsRunning ?? false;
    public bool IsEventUploaderRunning => _uploader?.IsRunning ?? false;
    public bool IsWebSocketConnected => _wsStatus?.IsConnected ?? false;
    public bool IsEnforcementActive => _enforcement.CurrentState == EnforcementState.Active;

    public AgentDiagnosticStatus GetDiagnosticStatus()
    {
        var netRunning = IsNetworkMonitoringRunning;
        var procRunning = IsProcessMonitoringRunning;
        var uploaderRunning = IsEventUploaderRunning;
        var wsConnected = IsWebSocketConnected;
        var enforcementActive = IsEnforcementActive;

        var summary = $"NetworkMonitoring: {(netRunning ? "RUNNING" : "STOPPED")} | " +
                      $"ProcessMonitoring: {(procRunning ? "RUNNING" : "STOPPED")} | " +
                      $"EventUploader: {(uploaderRunning ? "RUNNING" : "STOPPED")} | " +
                      $"WebSocket: {(wsConnected ? "CONNECTED" : "DISCONNECTED")} | " +
                      $"Enforcement: {(enforcementActive ? "ACTIVE" : "INACTIVE")}";

        return new AgentDiagnosticStatus(netRunning, procRunning, uploaderRunning, wsConnected, enforcementActive, summary);
    }

    public static Func<(bool Success, string? Status)>? DnsPolicyEnforcerForTesting { get; set; }

    public AgentWorker(
        ILogger<AgentWorker> log,
        IAgentStore store,
        IExamUiGateway ui,
        IRegistrationService regService,
        ISessionService sessionService,
        IEventPublisher publisher,
        IEnforcementStateMachine enforcement,
        IApprovedBrowserContext approvedBrowser,
        IWebSocketStatusProvider? wsStatus = null,
        IExamLifecycleCoordinator? lifecycleCoordinator = null,
        IUiLauncher? uiLauncher = null,
        DeviceCredentialStore? credentials = null,
        IRegistrationSynchronizer? registrationSynchronizer = null)
    {
        _log = log;
        _store = store;
        _ui = ui;
        _regService = regService;
        _sessionService = sessionService;
        _publisher = publisher;
        _enforcement = enforcement;
        _approvedBrowser = approvedBrowser;
        _wsStatus = wsStatus;
        _lifecycleCoordinator = lifecycleCoordinator;
        _uiLauncher = uiLauncher;
        _credentials = credentials;
        _registrationSynchronizer = registrationSynchronizer;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        _machine = new AgentStateMachine(_store, transition => _log.LogInformation("Agent state transition: from={From} to={To} event={Event} reason={Reason}", transition.From, transition.To, transition.Event, transition.Reason));
        RefreshIpAddress();

        // ---------------------------------------------------------------------
        // P0-C: Crash / restart recovery MUST run before anything can accept a
        // new exam activation, and before the process monitor resumes.
        //
        // Ordering rationale:
        //   * ahead of registration and pipeline construction, so a half-applied
        //     lockdown from a crashed run is reconciled while the agent is still
        //     the only actor touching firewall state;
        //   * ahead of _ready.TrySetResult(), which is what gates START_EXAM -
        //     otherwise an activation could race the recovery pass.
        //
        // ReconcileStartupStateAsync is deliberately used here (not the enforcer's
        // journal-level recovery): it consults the durable enforcement record and
        // PRESERVES a still-valid ACTIVE session whose firewall is genuinely still
        // enforcing BLOCK. A restart of the service - a Windows update reboot, a
        // service crash, an operator restart - must never tear down the network
        // lockdown of an exam that is still in progress.
        // ---------------------------------------------------------------------
        await RunStartupRecoveryAsync(stoppingToken);

        // ---------------------------------------------------------------------
        // The SPEMCS DNS model - what is REQUIRED, what is DENIED, and what is
        // merely watched. Written out here because the absence of any DNS rule in
        // BuildSessionRules reads like an oversight and is not one.
        //
        // REQUIRED. Recursive DNS to the machine's configured resolver has to keep
        // working. Every allowed destination is a NAME resolved by the backend, and
        // the endpoint's own management channel is reached by name in production.
        // Breaking name resolution does not harden the exam, it cancels it.
        //
        // The traffic that carries it is UDP/53 and TCP/53 from svchost.exe hosting
        // the Dnscache service, not from the browser. Under profile-level
        // DefaultOutboundAction=Block that is permitted by the Windows built-in rule
        // "Core Networking - DNS (UDP-Out)", which is scoped to that service. SPEMCS
        // therefore creates NO rule for port 53 and touches no built-in rule: adding
        // one would either duplicate a narrower existing scope or, worse, open :53
        // for every process. The dependency is real but it is on Windows' own
        // baseline, which the requirements take as given.
        //
        // DENIED. Everything that would let a process pick its own resolver:
        //   * DoH from the browser - closed here, by policy, since a browser DoH
        //     request is indistinguishable from ordinary allowed 443 traffic;
        //   * the browser's embedded plain-DNS stub resolver - closed here too,
        //     because DnsOverHttpsMode does not cover it and it skips the ETW
        //     provider entirely;
        //   * DoH or DoT from any other process - closed by default-deny plus the
        //     fact that every allow rule is pinned to the approved browser
        //     executable, so curl.exe cannot reach 853 or a public DoH endpoint;
        //   * a resolver that is not the configured one - closed by the same two
        //     mechanisms, since no allow rule names an off-box resolver address.
        //
        // WATCHED, NOT PREVENTED. Data encoded in query labels sent to the permitted
        // resolver. This is a genuine residual channel; it is low-bandwidth and it is
        // why DisableSecureDns matters at all - forcing resolution through the OS
        // stub makes the queries visible to the Microsoft-Windows-DNS-Client ETW
        // monitor, which is detection and correlation, not enforcement. No claim of
        // DNS exfiltration prevention should be made anywhere on the basis of this
        // call.
        // ---------------------------------------------------------------------
        bool dnsSuccess;
        string? dnsPolicyStatus;
        if (DnsPolicyEnforcerForTesting is not null)
        {
            (dnsSuccess, dnsPolicyStatus) = DnsPolicyEnforcerForTesting();
        }
        else
        {
            dnsSuccess = BrowserPolicyEnforcer.DisableSecureDns(out dnsPolicyStatus);
        }

        if (dnsSuccess)
        {
            _log.LogInformation("Browser Secure DNS policy enforced: {Status}", dnsPolicyStatus);
        }
        else
        {
            _log.LogWarning("Browser Secure DNS policy enforcement warning: {Status}", dnsPolicyStatus);
        }

        try
        {
            var configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Spemcs", "Endpoint Agent", "config.json");
            bool isAuthoritativeEnrolled = TrySyncAuthoritativeRegistrationFromDisk(configPath);

            if (!isAuthoritativeEnrolled)
            {
                _credentials?.ClearDeviceToken();
                _log.LogInformation("Workstation is unenrolled at startup. Awaiting configuration from Setup Wizard or Central enrollment.");

                // Non-blocking background sync attempt: if credentials or backend exist, sync without delaying Windows service startup
                if (_registrationSynchronizer != null)
                {
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await _registrationSynchronizer.SyncRegistrationAsync("startup_bg", allowBackendQuery: true, stoppingToken);
                        }
                        catch (Exception ex)
                        {
                            _log.LogDebug("Background registration sync deferred: {Message}", ex.Message);
                        }
                    }, stoppingToken);
                }
            }
            else
            {
                _log.LogInformation("Authoritative device registration loaded from disk on startup.");
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning("Device registration check deferred: {Message}", ex.Message);
        }

        var source = new WindowsProcessSource();

        // The approved browser comes from the shared context, NOT from a constant here. Startup
        // recovery has already run, so if an exam is still active its signed family is bound and the
        // classifier will agree with the firewall rules that are currently installed.
        var classifier = new ConfigurableProcessClassifier(_approvedBrowser, selfRoot: AppContext.BaseDirectory, parentResolver: source.FindById);
        var compliance = new PreComplianceEngine(source, classifier);
        _processMonitor = new ProcessMonitor(source, classifier, _store, _machine.Snapshot, _publisher, _log);

        _pipeline = new ExamPipeline(_machine, compliance, _processMonitor, _ui, _approvedBrowser, _store, _sessionService, ownsMonitor: false, log: _log);
        _lifecycleCoordinator?.RegisterHandler(
            (req, ct) => StartExamFromCentralAsync(req, ct),
            (ct) => StopExamFromCentralAsync(ct)
        );
        _ready.TrySetResult();

        _log.LogInformation("SPEMCS agent started in state {State}; approved browser {Browser} ({Source})",
            _machine.State, _approvedBrowser.Current.Family, _approvedBrowser.Current.Source);
        if (_store.LoadSnapshot().Registration is null) _log.LogWarning("Device registration is required before exam activation.");

        // Start EventUploaderWorker with isolated error handling
        try
        {
            _uploader = new EventUploaderWorker(_store, _publisher, _log);
            _uploader.Start();
            _log.LogInformation("EventUploaderWorker started.");
            if (_uploader.IsRunning)
            {
                _log.LogInformation("[EVENT_UPLOADER_RUNNING] EventUploaderWorker running.");
            }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "EventUploaderWorker failed: {Message}", ex.Message);
        }

        // Start NetworkCollector with isolated error handling
        try
        {
            _networkCollector = new NetworkCollector(_store, snapshotProvider: _machine.Snapshot, log: _log, approvedBrowser: _approvedBrowser);
            _networkCollector.Start();
            _log.LogInformation("NetworkCollector started.");
            if (_networkCollector.IsRunning)
            {
                _log.LogInformation("[NETWORK_MONITORING_RUNNING] NetworkCollector running.");
            }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "NetworkCollector failed: {Message}", ex.Message);
        }

        // Start ProcessMonitor with isolated error handling
        try
        {
            _processMonitor.Start();
            _log.LogInformation("ProcessMonitor started.");
            if (_processMonitor.IsRunning)
            {
                _log.LogInformation("[PROCESS_MONITORING_RUNNING] ProcessMonitor running.");
            }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "ProcessMonitor failed: {Message}", ex.Message);
        }

        if (_machine.State == AgentState.Monitoring)
        {
            _log.LogInformation("Live continuous process monitor automatically resumed for session {SessionId}", _machine.Session?.SessionId);
        }

        while (!stoppingToken.IsCancellationRequested && !_isStopping)
        {
            await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            if (stoppingToken.IsCancellationRequested || _isStopping) break;

            var now = DateTimeOffset.UtcNow;

            // Supervisor safety: Only unexpectedly stopped long-running workers are restarted,
            // never restart during shutdown, and enforce a 15-second cooldown to prevent tight loops.
            // Invariant: Reuse existing single instance, NEVER allocate duplicate instances.
            if (_networkCollector is not null && !_networkCollector.IsRunning && !_isStopping && !stoppingToken.IsCancellationRequested)
            {
                if (now - _lastNetworkRestart >= RestartCooldown)
                {
                    _lastNetworkRestart = now;
                    _log.LogWarning("NetworkCollector unexpectedly stopped; attempting supervised restart...");
                    try
                    {
                        _networkCollector.Start();
                        _log.LogInformation("NetworkCollector running.");
                    }
                    catch (Exception ex)
                    {
                        _log.LogError(ex, "NetworkCollector failed: {Message}", ex.Message);
                    }
                }
            }

            if (_processMonitor is not null && !_processMonitor.IsRunning && !_isStopping && !stoppingToken.IsCancellationRequested)
            {
                if (now - _lastProcessRestart >= RestartCooldown)
                {
                    _lastProcessRestart = now;
                    _log.LogWarning("ProcessMonitor unexpectedly stopped; attempting supervised restart...");
                    try
                    {
                        _processMonitor.Start();
                        _log.LogInformation("ProcessMonitor running.");
                    }
                    catch (Exception ex)
                    {
                        _log.LogError(ex, "ProcessMonitor failed: {Message}", ex.Message);
                    }
                }
            }

            if (_uploader is not null && !_uploader.IsRunning && !_isStopping && !stoppingToken.IsCancellationRequested)
            {
                if (now - _lastUploaderRestart >= RestartCooldown)
                {
                    _lastUploaderRestart = now;
                    _log.LogWarning("EventUploaderWorker unexpectedly stopped; attempting supervised restart...");
                    try
                    {
                        _uploader.Start();
                        _log.LogInformation("EventUploaderWorker running.");
                    }
                    catch (Exception ex)
                    {
                        _log.LogError(ex, "EventUploaderWorker failed: {Message}", ex.Message);
                    }
                }
            }

            if (_machine.State == AgentState.Monitoring) _log.LogDebug("Monitoring active for session {SessionId}", _machine.Session?.SessionId);

            // Signed-policy expiry watchdog: the policy's not_before/expires_at window is part
            // of the signed payload, so enforcement must end when it lapses even if no STOP_EXAM
            // command ever arrives (backend unreachable, operator forgot, pipe broken).
            // CheckExpiryAsync is a no-op unless an active session is past ExpiresAtUtc.
            try
            {
                await _enforcement.CheckExpiryAsync(cancellationToken: stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Enforcement expiry check failed; lockdown remains in effect (fail-closed).");
            }
        }
    }

    /// <summary>
    /// Runs enforcement startup reconciliation (P0-C). Never throws: a recovery failure must not
    /// prevent the agent from starting, because the agent is the only component able to report the
    /// problem or to later remove a stale lockdown. Any failure is logged loudly and the firewall
    /// is left as-is (fail-closed) rather than being blindly reset.
    /// </summary>
    private async Task RunStartupRecoveryAsync(CancellationToken cancellationToken)
    {
        try
        {
            _log.LogInformation("Running enforcement startup reconciliation (pre-existing state: {State}).",
                _enforcement.CurrentState);

            var recovery = await _enforcement.ReconcileStartupStateAsync(cancellationToken);

            if (!recovery.RecoveryRequired)
            {
                if (recovery.RecoveredSessionId is Guid preserved)
                {
                    _log.LogWarning(
                        "Startup reconciliation PRESERVED in-progress enforcement session {SessionId} (state={State}). Network lockdown remains active. Details: {Details}",
                        preserved, _enforcement.CurrentState, recovery.Details);
                }
                else
                {
                    _log.LogInformation("Startup reconciliation: no recovery required. Details: {Details}", recovery.Details);
                }
            }
            else if (recovery.Success)
            {
                _log.LogWarning(
                    "Startup reconciliation recovered session {SessionId}: orphanRulesCleaned={Orphans} baselineRestored={BaselineRestored} conflict={Conflict}. Details: {Details}",
                    recovery.RecoveredSessionId, recovery.OrphanRulesCleaned, recovery.BaselineRestored,
                    recovery.ConflictDetected, recovery.Details);
            }
            else
            {
                _log.LogError(
                    "Startup reconciliation FAILED for session {SessionId} (conflict={Conflict}). Firewall state left untouched for manual review. Details: {Details}",
                    recovery.RecoveredSessionId, recovery.ConflictDetected, recovery.Details);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Enforcement startup reconciliation threw; continuing startup with firewall state unchanged.");
        }
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        _isStopping = true;
        _log.LogInformation("SPEMCS agent stopping cleanly.");

        try
        {
            _log.LogInformation("NetworkCollector stopping.");
            _networkCollector?.Stop();
            _log.LogInformation("NetworkCollector stopped.");
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "NetworkCollector failed: {Message}", ex.Message);
        }

        try
        {
            _log.LogInformation("ProcessMonitor stopping.");
            _processMonitor?.Stop();
            _log.LogInformation("ProcessMonitor stopped.");
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "ProcessMonitor failed: {Message}", ex.Message);
        }

        try
        {
            _log.LogInformation("EventUploaderWorker stopping.");
            _uploader?.Stop();
            _log.LogInformation("EventUploaderWorker stopped.");
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "EventUploaderWorker failed: {Message}", ex.Message);
        }

        return base.StopAsync(cancellationToken);
    }

    public async Task<bool> StartExamFromCentralAsync(ExamActivationRequest request, CancellationToken cancellationToken)
    {
        await _ready.Task.WaitAsync(cancellationToken);
        if (_pipeline is null) return false;

        _log.LogInformation("[UI_LAUNCH_REQUESTED] Exam launch requested from Central Server: ExamId={ExamId}, ExamName={ExamName}",
            request.ExamId, request.ExamName);

        if (_registrationSynchronizer != null)
        {
            var isSynced = await _registrationSynchronizer.EnsureAuthoritativeRegistrationAsync("pre_exam_activation", TimeSpan.FromSeconds(3), cancellationToken);
            if (!isSynced)
            {
                _log.LogWarning("[REGISTRATION_SYNC_FAILED] reason=NOT_REGISTERED_BEFORE_EXAM Exam launch aborted because device is not authoritatively registered.");
                return false;
            }
        }

        // Idempotency: If machine is already in an active session, do not duplicate UI launch or session
        if (_machine != null && _machine.State == AgentState.Monitoring && _machine.Session != null)
        {
            _log.LogInformation("Exam session already active for session {SessionId}; skipping duplicate UI launch.", _machine.Session.SessionId);
            return true;
        }

        if (!string.IsNullOrWhiteSpace(request.ApprovedBrowser) &&
            ApprovedBrowserFamilies.TryParse(request.ApprovedBrowser, out var fam))
        {
            _approvedBrowser.SetHostRequested(fam, $"Central Server LAUNCH_EXAM_MODE ({request.ApprovedBrowser})");
        }

        _ = Task.Run(async () =>
        {
            try
            {
                var success = await _pipeline.StartAsync(CancellationToken.None);
                _log.LogInformation("Exam pipeline finished: Success={Success}", success);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Error running exam pipeline");
            }
        });
        return true;
    }

    public async Task<bool> StopExamFromCentralAsync(CancellationToken cancellationToken)
    {
        return await StopExamAsync(cancellationToken);
    }

    public async Task<bool> StartExamAsync(CancellationToken cancellationToken)
    {
        await _ready.Task.WaitAsync(cancellationToken);
        if (_pipeline is null) return false;

        _log.LogInformation("[UI_LAUNCH_REQUESTED] Exam launch requested locally via StartExamAsync.");

        if (_registrationSynchronizer != null)
        {
            var isSynced = await _registrationSynchronizer.EnsureAuthoritativeRegistrationAsync("pre_exam_activation_local", TimeSpan.FromSeconds(3), cancellationToken);
            if (!isSynced)
            {
                _log.LogWarning("[REGISTRATION_SYNC_FAILED] reason=NOT_REGISTERED_BEFORE_EXAM Exam launch aborted because device is not authoritatively registered.");
                return false;
            }
        }

        _ = Task.Run(async () =>
        {
            try { await _pipeline.StartAsync(CancellationToken.None); }
            catch (Exception ex) { _log.LogError(ex, "Error running exam pipeline"); }
        });
        return true;
    }

    public async Task<bool> StopExamAsync(CancellationToken cancellationToken)
    {
        await _ready.Task.WaitAsync(cancellationToken);
        try
        {
            await _ui.NotifySessionStoppedAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to notify UI of session stop");
        }

        return _pipeline is not null && await _pipeline.StopAsync(cancellationToken);
    }

    private bool TrySyncAuthoritativeRegistrationFromDisk(string configPath)
    {
        if (_registrationSynchronizer != null && _registrationSynchronizer.TrySyncFromConfig("disk_eval"))
        {
            return true;
        }

        if (!File.Exists(configPath))
        {
            _log.LogInformation("[ENROLLMENT_STATE_EVALUATED] enrolled=false, hasDeviceId=false, hasToken=false, configPath={ConfigPath}, pid={Pid}", configPath, Environment.ProcessId);
            return false;
        }

        try
        {
            using var cDoc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(configPath));
            var cRoot = cDoc.RootElement;

            bool isReg = cRoot.TryGetProperty("registered", out var rProp) &&
                (rProp.ValueKind == System.Text.Json.JsonValueKind.True ||
                 (rProp.ValueKind == System.Text.Json.JsonValueKind.String && bool.TryParse(rProp.GetString(), out var b) && b));

            var devName = cRoot.TryGetProperty("deviceName", out var dnProp) ? dnProp.GetString() : null;
            var devIdStr = cRoot.TryGetProperty("deviceId", out var diProp) ? diProp.GetString() : null;
            var devToken = cRoot.TryGetProperty("deviceToken", out var dtProp) ? dtProp.GetString() : null;

            bool hasDevId = Guid.TryParse(devIdStr, out var parsedId) && parsedId != Guid.Empty;
            bool hasDevToken = !string.IsNullOrWhiteSpace(devToken);
            bool isEnrolled = isReg && !string.IsNullOrWhiteSpace(devName) && hasDevId && hasDevToken;

            _log.LogInformation("[ENROLLMENT_STATE_EVALUATED] enrolled={Enrolled}, hasDeviceId={HasId}, hasToken={HasToken}, configPath={ConfigPath}, pid={Pid}",
                isEnrolled, hasDevId, hasDevToken, configPath, Environment.ProcessId);

            if (isEnrolled)
            {
                var currentReg = _store.LoadSnapshot().Registration;
                if (currentReg == null || currentReg.DeviceId != parsedId || currentReg.DeviceName != devName)
                {
                    _store.SaveRegistration(new DeviceRegistration(parsedId, devName!, GetCurrentIpAddress(), DateTimeOffset.UtcNow));
                    _log.LogInformation("Synchronized authoritative device registration into store from config.json: DeviceName={Name}, DeviceId={Id}", devName, parsedId);
                }
                if (_credentials != null && string.IsNullOrWhiteSpace(_credentials.DeviceToken))
                {
                    _credentials.SetDeviceToken(devToken);
                }
                return true;
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to evaluate config at {Path}", configPath);
        }

        return false;
    }

    public async Task HandleRevocationAsync(string reason, CancellationToken ct = default)
    {
        _log.LogWarning("Registration credential revoked or invalid: {Reason}. Transitioning to Enrollment Required.", reason);
        _credentials?.ClearDeviceToken();
        try
        {
            var configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Spemcs", "Endpoint Agent", "config.json");
            if (File.Exists(configPath))
            {
                var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(configPath));
                var dict = new Dictionary<string, object?>();
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    if (prop.NameEquals("registered")) dict["registered"] = false;
                    else if (prop.NameEquals("deviceToken")) dict["deviceToken"] = null;
                    else dict[prop.Name] = prop.Value.Clone();
                }
                var json = System.Text.Json.JsonSerializer.Serialize(dict, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(configPath, json);
                _log.LogInformation("Marked config.json as unregistered after revocation.");
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to update config.json upon revocation");
        }

        try
        {
            var coordinator = new RegistrationCoordinator(_store, _ui, _regService, isCredentialValid: () => false);
            await coordinator.EnsureRegisteredAsync(GetCurrentIpAddress(), ct);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to re-trigger registration coordinator after revocation");
        }
    }

    private void RefreshIpAddress()
    {
        var current = _store.LoadSnapshot().Registration;
        if (current is null) return;
        var address = GetCurrentIpAddress();
        if (!string.IsNullOrWhiteSpace(address) && address != current.IpAddress)
            _store.SaveRegistration(current with { IpAddress = address });
    }

    private static string GetCurrentIpAddress() => NetworkInterface.GetAllNetworkInterfaces().SelectMany(n => n.GetIPProperties().UnicastAddresses).Select(a => a.Address).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a))?.ToString() ?? "127.0.0.1";
}

public sealed record AgentDiagnosticStatus(
    bool NetworkMonitoringRunning,
    bool ProcessMonitoringRunning,
    bool EventUploaderRunning,
    bool WebSocketConnected,
    bool EnforcementActive,
    string Summary);
