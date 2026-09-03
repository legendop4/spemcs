using Microsoft.Extensions.Logging;

namespace Spemcs.Agent.Core;

public sealed class ProcessMonitor
{
    private readonly IProcessSource _source;
    private readonly IProcessClassifier _classifier;
    private readonly IAgentStore _store;
    private readonly IEventPublisher _publisher;
    private readonly Func<AgentSnapshot> _snapshot;
    private readonly ILogger? _log;
    private readonly Dictionary<int, (string Name, string? Path, ClassificationResult Classification)> _seen = [];
    private CancellationTokenSource? _monitorCancellation;
    private Task? _monitorTask;

    public ProcessMonitor(
        IProcessSource source,
        IProcessClassifier classifier,
        IAgentStore store,
        Func<AgentSnapshot> snapshot,
        IEventPublisher? publisher = null,
        ILogger? log = null)
    {
        _source = source;
        _classifier = classifier;
        _store = store;
        _snapshot = snapshot;
        _publisher = publisher ?? new LocalMockEventPublisher();
        _log = log;
    }

    public int Reconcile()
    {
        try
        {
            var count = 0;
            var current = _source.GetProcesses();
            var currentPids = current.Select(p => p.ProcessId).ToHashSet();

            // 1. Detect new process launches & existing suspicious processes
            foreach (var process in current)
            {
                if (_seen.ContainsKey(process.ProcessId)) continue;
                var result = _classifier.Classify(process);
                _seen[process.ProcessId] = (process.Name, process.ExecutablePath, result);

                if (result.IsSuspicious)
                {
                    var state = _snapshot();
                    var registration = state.Registration;
                    var deviceName = registration?.DeviceName ?? Environment.MachineName;

                    var violation = new ViolationEvent(
                        Guid.NewGuid(),
                        deviceName,
                        state.Session?.StudentRollNumber,
                        EventTypes.ApplicationOpened,
                        process.ProcessId,
                        process.Name,
                        DateTimeOffset.UtcNow,
                        process.ExecutablePath,
                        result.Reason ?? $"Unauthorized process detected: {process.Name}");

                    _store.Enqueue(violation);
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await _publisher.PublishEventAsync(violation);
                        }
                        catch (Exception ex)
                        {
                            _log?.LogError(ex, "Failed to publish violation event for {ProcessName} (PID {Pid}) to backend", process.Name, process.ProcessId);
                        }
                    });

                    _log?.LogWarning("LIVE DETECTION: {EventType} roll={RollNumber} pid={Pid} name={Name} path={Path} reason={Reason}",
                        violation.EventType, violation.StudentRollNumber ?? "N/A", process.ProcessId, process.Name, process.ExecutablePath, result.Reason);
                    count++;
                }
            }

            // 2. Detect closed suspicious processes
            var exitedPids = _seen.Keys.Where(pid => !currentPids.Contains(pid)).ToList();
            foreach (var pid in exitedPids)
            {
                if (_seen.TryGetValue(pid, out var info))
                {
                    _seen.Remove(pid);
                    if (info.Classification.IsSuspicious)
                    {
                        var state = _snapshot();
                        var registration = state.Registration;
                        var deviceName = registration?.DeviceName ?? Environment.MachineName;

                        var closeEvent = new ViolationEvent(
                            Guid.NewGuid(),
                            deviceName,
                            state.Session?.StudentRollNumber,
                            EventTypes.ApplicationClosed,
                            pid,
                            info.Name,
                            DateTimeOffset.UtcNow,
                            info.Path,
                            "Suspicious process exited");

                        _store.Enqueue(closeEvent);
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                await _publisher.PublishEventAsync(closeEvent);
                            }
                            catch (Exception ex)
                            {
                                _log?.LogError(ex, "Failed to publish close event for {ProcessName} to backend", info.Name);
                            }
                        });

                        _log?.LogInformation("LIVE DETECTION: {EventType} roll={RollNumber} pid={Pid} name={Name}",
                            closeEvent.EventType, closeEvent.StudentRollNumber ?? "N/A", pid, info.Name);
                    }
                }
            }

            return count;
        }
        catch (Exception ex)
        {
            _log?.LogError(ex, "Error during process reconciliation");
            return 0;
        }
    }

    public void Start()
    {
        Stop();
        _seen.Clear();
        _monitorCancellation = new CancellationTokenSource();
        _monitorTask = Task.Run(() => RunAsync(_monitorCancellation.Token));
        _log?.LogInformation("Live continuous process monitor started.");

        // Immediately reconcile all running processes so background/pre-existing tools are captured
        Reconcile();
    }

    public void Stop()
    {
        _monitorCancellation?.Cancel();
        try { _monitorTask?.Wait(TimeSpan.FromSeconds(2)); } catch (AggregateException) { }
        _monitorCancellation?.Dispose();
        _monitorCancellation = null;
        _monitorTask = null;
        _seen.Clear();
        _log?.LogInformation("Live continuous process monitor stopped.");
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        while (!cancellationToken.IsCancellationRequested)
        {
            try 
            { 
                if (await timer.WaitForNextTickAsync(cancellationToken))
                {
                    Reconcile(); 
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) 
            {
                break;
            }
            catch (Exception ex)
            {
                _log?.LogError(ex, "Exception in live process monitor reconciliation loop");
            }
        }
    }
}

public sealed class LocalNoOpUploader : IEventUploader
{
    public Task UploadAsync(IReadOnlyList<ViolationEvent> events, CancellationToken cancellationToken) => Task.CompletedTask;
}
