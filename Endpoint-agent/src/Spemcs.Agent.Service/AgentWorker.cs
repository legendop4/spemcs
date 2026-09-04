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

    private EventUploaderWorker? _uploader;
    private NetworkCollector? _networkCollector;

    public AgentWorker(
        ILogger<AgentWorker> log,
        IAgentStore store,
        IExamUiGateway ui,
        IRegistrationService regService,
        ISessionService sessionService,
        IEventPublisher publisher,
        IEnforcementStateMachine enforcement,
        IApprovedBrowserContext approvedBrowser)
    {
        _log = log;
        _store = store;
        _ui = ui;
        _regService = regService;
        _sessionService = sessionService;
        _publisher = publisher;
        _enforcement = enforcement;
        _approvedBrowser = approvedBrowser;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
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

        // Enforce browser policies so DNS queries route through Windows OS resolver (ETW monitoring)
        if (BrowserPolicyEnforcer.DisableSecureDns(out var dnsPolicyStatus))
        {
            _log.LogInformation("Browser Secure DNS policy enforced: {Status}", dnsPolicyStatus);
        }
        else
        {
            _log.LogWarning("Browser Secure DNS policy enforcement warning: {Status}", dnsPolicyStatus);
        }

        try
        {
            if (!await new RegistrationCoordinator(_store, _ui, _regService).EnsureRegisteredAsync(GetCurrentIpAddress(), stoppingToken))
                _log.LogWarning("Device registration was not completed; START_EXAM will be rejected.");
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
        var monitor = new ProcessMonitor(source, classifier, _store, _machine.Snapshot, _publisher, _log);

        _pipeline = new ExamPipeline(_machine, compliance, monitor, _ui, _approvedBrowser, _store, _sessionService);
        _ready.TrySetResult();

        _log.LogInformation("SPEMCS agent started in state {State}; approved browser {Browser} ({Source})",
            _machine.State, _approvedBrowser.Current.Family, _approvedBrowser.Current.Source);
        if (_store.LoadSnapshot().Registration is null) _log.LogWarning("Device registration is required before exam activation.");

        _uploader = new EventUploaderWorker(_store, _publisher, _log);
        _uploader.Start();

        _networkCollector = new NetworkCollector(_store, snapshotProvider: _machine.Snapshot, log: _log, approvedBrowser: _approvedBrowser);
        _networkCollector.Start();

        if (_machine.State == AgentState.Monitoring)
        {
            monitor.Start();
            _log.LogInformation("Live continuous process monitor automatically resumed for session {SessionId}", _machine.Session?.SessionId);
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
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
        _log.LogInformation("SPEMCS agent stopping cleanly.");
        _networkCollector?.Stop();
        _uploader?.Stop();
        return base.StopAsync(cancellationToken);
    }

    public async Task<bool> StartExamAsync(CancellationToken cancellationToken)
    {
        await _ready.Task.WaitAsync(cancellationToken);
        if (_pipeline is null) return false;
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
        return _pipeline is not null && await _pipeline.StopAsync(cancellationToken);
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
