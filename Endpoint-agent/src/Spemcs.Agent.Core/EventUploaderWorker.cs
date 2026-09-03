using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Spemcs.Agent.Core;

/// <summary>
/// Background worker responsible for reliably uploading persisted events from SqliteAgentStore
/// to the SPEMCS backend with exponential backoff and crash recovery.
/// </summary>
public sealed class EventUploaderWorker
{
    private readonly IAgentStore _store;
    private readonly IEventPublisher _publisher;
    private readonly ILogger? _log;
    private readonly TimeSpan _pollInterval;
    private readonly int _batchSize;
    private CancellationTokenSource? _cts;
    private Task? _workerTask;
    private readonly object _lock = new();

    public bool IsRunning { get; private set; }

    public EventUploaderWorker(
        IAgentStore store,
        IEventPublisher publisher,
        ILogger? log = null,
        TimeSpan? pollInterval = null,
        int batchSize = 25)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _publisher = publisher ?? throw new ArgumentNullException(nameof(publisher));
        _log = log;
        _pollInterval = pollInterval ?? TimeSpan.FromSeconds(1);
        _batchSize = batchSize > 0 ? batchSize : 25;
    }

    public void Start()
    {
        lock (_lock)
        {
            if (IsRunning) return;
            _cts = new CancellationTokenSource();
            IsRunning = true;
            _workerTask = Task.Run(() => RunLoopAsync(_cts.Token));
            _log?.LogInformation("EventUploaderWorker background loop started.");
        }
    }

    public void Stop()
    {
        lock (_lock)
        {
            if (!IsRunning) return;
            _cts?.Cancel();
            try { _workerTask?.Wait(TimeSpan.FromSeconds(3)); } catch { }
            _cts?.Dispose();
            _cts = null;
            _workerTask = null;
            IsRunning = false;
            _log?.LogInformation("EventUploaderWorker background loop stopped.");
        }
    }

    public async Task<int> ProcessBatchAsync(CancellationToken cancellationToken = default)
    {
        var claimed = _store.ClaimPendingEvents(_batchSize, DateTimeOffset.UtcNow);
        if (claimed.Count == 0) return 0;

        int processed = 0;
        foreach (var eventItem in claimed)
        {
            if (cancellationToken.IsCancellationRequested) break;

            try
            {
                await _publisher.PublishEventAsync(eventItem, cancellationToken);
                _store.MarkUploaded(eventItem.EventId);
                _log?.LogInformation("Successfully uploaded event {EventId} ({EventType})", eventItem.EventId, eventItem.EventType);
                processed++;
            }
            catch (Exception ex)
            {
                if (IsPermanentError(ex))
                {
                    _log?.LogError(ex, "Permanent payload error for event {EventId}. Marking failed far-future to prevent queue stall.", eventItem.EventId);
                    // Permanent payload error (e.g. 400/422 schema error): mark failed with 1-year offset so queue moves forward
                    _store.MarkUploadFailed(eventItem.EventId, DateTimeOffset.UtcNow.AddDays(365));
                }
                else
                {
                    int attempts = 1;
                    if (_store is SqliteAgentStore sqliteStore)
                    {
                        attempts = sqliteStore.GetAttemptCount(eventItem.EventId);
                    }
                    var delay = CalculateBackoff(attempts);
                    var retryAt = DateTimeOffset.UtcNow.Add(delay);

                    _store.MarkUploadFailed(eventItem.EventId, retryAt);
                    _log?.LogWarning(ex, "Transient error uploading event {EventId} (Attempt {Attempt}). Scheduling retry at {RetryAt} ({DelaySeconds}s backoff)",
                        eventItem.EventId, attempts, retryAt.ToString("HH:mm:ss"), delay.TotalSeconds);
                }
            }
        }

        return processed;
    }

    private async Task RunLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await ProcessBatchAsync(cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _log?.LogError(ex, "Unexpected error in EventUploaderWorker loop");
            }

            try
            {
                await Task.Delay(_pollInterval, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    public static TimeSpan CalculateBackoff(int attemptCount)
    {
        if (attemptCount <= 1) return TimeSpan.FromSeconds(2);
        int seconds = (int)(2 * Math.Pow(2, Math.Min(attemptCount - 1, 5)));
        return TimeSpan.FromSeconds(Math.Min(seconds, 60));
    }

    public static bool IsPermanentError(Exception ex)
    {
        if (ex is HttpRequestException httpEx && httpEx.StatusCode.HasValue)
        {
            var code = (int)httpEx.StatusCode.Value;
            if (code == 400 || code == 422) return true;
        }
        return false;
    }
}
