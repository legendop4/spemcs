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
