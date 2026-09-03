using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Spemcs.Agent.Core;
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

    private EventUploaderWorker? _uploader;
    private NetworkCollector? _networkCollector;

    public AgentWorker(ILogger<AgentWorker> log, IAgentStore store, IExamUiGateway ui, IRegistrationService regService, ISessionService sessionService, IEventPublisher publisher)
    {
        _log = log;
        _store = store;
        _ui = ui;
        _regService = regService;
        _sessionService = sessionService;
        _publisher = publisher;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _machine = new AgentStateMachine(_store, transition => _log.LogInformation("Agent state transition: from={From} to={To} event={Event} reason={Reason}", transition.From, transition.To, transition.Event, transition.Reason));
        RefreshIpAddress();

        // Enforce browser policies so DNS queries route through Windows OS resolver (ETW monitoring)
        if (BrowserPolicyEnforcer.DisableSecureDns(out var dnsPolicyStatus))
        {
            _log.LogInformation("Browser Secure DNS policy enforced: {Status}", dnsPolicyStatus);
        }
        else
        {
            _log.LogWarning("Browser Secure DNS policy enforcement warning: {Status}", dnsPolicyStatus);
        }

        if (!await new RegistrationCoordinator(_store, _ui, _regService).EnsureRegisteredAsync(GetCurrentIpAddress(), stoppingToken))
            _log.LogWarning("Device registration was not completed; START_EXAM will be rejected.");

        var source = new WindowsProcessSource();
        var approvedBrowser = ApprovedBrowserFamily.Chrome;
        var classifier = new ConfigurableProcessClassifier(approvedBrowser, selfRoot: AppContext.BaseDirectory, parentResolver: source.FindById);
        var compliance = new PreComplianceEngine(source, classifier);
        var monitor = new ProcessMonitor(source, classifier, _store, _machine.Snapshot, _publisher, _log);

        _pipeline = new ExamPipeline(_machine, compliance, monitor, _ui, _store, _sessionService, approvedBrowser);
        _ready.TrySetResult();

        _log.LogInformation("SPEMCS agent started in state {State}", _machine.State);
        if (_store.LoadSnapshot().Registration is null) _log.LogWarning("Device registration is required before exam activation.");

        _uploader = new EventUploaderWorker(_store, _publisher, _log);
        _uploader.Start();

        _networkCollector = new NetworkCollector(_store, snapshotProvider: _machine.Snapshot, log: _log);
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
