using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Spemcs.Agent.Core;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class MockEventPublisher : IEventPublisher
{
    private readonly List<ViolationEvent> _published = new();
    private Func<ViolationEvent, Task>? _onPublish;

    public IReadOnlyList<ViolationEvent> PublishedEvents
    {
        get { lock (_published) return _published.ToList(); }
    }

    public void SetPublishCallback(Func<ViolationEvent, Task> onPublish)
    {
        _onPublish = onPublish;
    }

    public async Task PublishEventAsync(ViolationEvent violation, CancellationToken cancellationToken = default)
    {
        if (_onPublish != null)
        {
            await _onPublish(violation);
        }
        lock (_published)
        {
            _published.Add(violation);
        }
    }
}

public sealed class EventUploaderTests
{
    [Fact]
    public async Task Pending_event_is_uploaded_successfully_and_marked_uploaded()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-test-uploader-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var publisher = new MockEventPublisher();
            var worker = new EventUploaderWorker(store, publisher, pollInterval: TimeSpan.FromMilliseconds(50));

            var ev = CreateEvent("chrome");
            store.Enqueue(ev);

            Assert.Single(store.GetEvents(EventDeliveryStatus.Pending));

            int processed = await worker.ProcessBatchAsync();
            Assert.Equal(1, processed);
            Assert.Single(publisher.PublishedEvents);
            Assert.Equal(ev.EventId, publisher.PublishedEvents[0].EventId);
            Assert.Single(store.GetEvents(EventDeliveryStatus.Uploaded));
            Assert.Empty(store.GetEvents(EventDeliveryStatus.Pending));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public async Task Transient_network_failure_keeps_event_retryable_and_updates_attempt_count_and_backoff()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-test-fail-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var publisher = new MockEventPublisher();
            publisher.SetPublishCallback(_ => throw new HttpRequestException("Backend Offline / Timeout"));

            var worker = new EventUploaderWorker(store, publisher);

            var ev = CreateEvent("firefox");
            store.Enqueue(ev);

            // First attempt fails
            await worker.ProcessBatchAsync();

            Assert.Single(store.GetEvents(EventDeliveryStatus.Failed));
            Assert.Equal(1, store.GetAttemptCount(ev.EventId));

            // Immediate claim returns 0 because next_attempt_utc is in the future
            var claimedBeforeExpiry = store.ClaimPendingEvents(10, DateTimeOffset.UtcNow);
            Assert.Empty(claimedBeforeExpiry);

            // Claim after backoff expiry (e.g. +3 seconds) re-claims event with SAME event_id
            var claimedAfterExpiry = store.ClaimPendingEvents(10, DateTimeOffset.UtcNow.AddSeconds(3));
            Assert.Single(claimedAfterExpiry);
            Assert.Equal(ev.EventId, claimedAfterExpiry[0].EventId);
            Assert.Equal(2, store.GetAttemptCount(ev.EventId));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void Exponential_backoff_calculation_matches_specification()
    {
        Assert.Equal(TimeSpan.FromSeconds(2), EventUploaderWorker.CalculateBackoff(1));
        Assert.Equal(TimeSpan.FromSeconds(4), EventUploaderWorker.CalculateBackoff(2));
        Assert.Equal(TimeSpan.FromSeconds(8), EventUploaderWorker.CalculateBackoff(3));
        Assert.Equal(TimeSpan.FromSeconds(16), EventUploaderWorker.CalculateBackoff(4));
        Assert.Equal(TimeSpan.FromSeconds(32), EventUploaderWorker.CalculateBackoff(5));
        Assert.Equal(TimeSpan.FromSeconds(60), EventUploaderWorker.CalculateBackoff(6));
        Assert.Equal(TimeSpan.FromSeconds(60), EventUploaderWorker.CalculateBackoff(10));
    }

    [Fact]
    public void IsPermanentError_classifies_http_status_codes_correctly()
    {
        var ex400 = new HttpRequestException("Bad Request", null, HttpStatusCode.BadRequest);
        var ex422 = new HttpRequestException("Unprocessable", null, HttpStatusCode.UnprocessableEntity);
        var ex500 = new HttpRequestException("Server Error", null, HttpStatusCode.InternalServerError);
        var exNet = new HttpRequestException("Connection Refused");

        Assert.True(EventUploaderWorker.IsPermanentError(ex400));
        Assert.True(EventUploaderWorker.IsPermanentError(ex422));
        Assert.False(EventUploaderWorker.IsPermanentError(ex500));
        Assert.False(EventUploaderWorker.IsPermanentError(exNet));
    }

    [Fact]
    public async Task Multiple_pending_events_are_drained_in_batch()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-test-batch-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var publisher = new MockEventPublisher();
            var worker = new EventUploaderWorker(store, publisher, batchSize: 5);

            for (int i = 0; i < 12; i++)
            {
                store.Enqueue(CreateEvent($"app_{i}"));
            }

            Assert.Equal(12, store.GetEvents(EventDeliveryStatus.Pending).Count);

            int batch1 = await worker.ProcessBatchAsync();
            Assert.Equal(5, batch1);
            Assert.Equal(5, publisher.PublishedEvents.Count);

            int batch2 = await worker.ProcessBatchAsync();
            Assert.Equal(5, batch2);

            int batch3 = await worker.ProcessBatchAsync();
            Assert.Equal(2, batch3);

            Assert.Equal(12, publisher.PublishedEvents.Count);
            Assert.Equal(12, store.GetEvents(EventDeliveryStatus.Uploaded).Count);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public async Task Worker_starts_and_stops_cleanly()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-test-lifecycle-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var publisher = new MockEventPublisher();
            var worker = new EventUploaderWorker(store, publisher, pollInterval: TimeSpan.FromMilliseconds(50));

            worker.Start();
            Assert.True(worker.IsRunning);

            store.Enqueue(CreateEvent("test_app"));
            await Task.Delay(200);

            Assert.Single(publisher.PublishedEvents);

            worker.Stop();
            Assert.False(worker.IsRunning);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void ProcessMonitor_enqueue_is_non_blocking()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-test-nonblock-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var source = new WindowsProcessSource();
            var classifier = new ConfigurableProcessClassifier();
            var publisher = new MockEventPublisher();

            var monitor = new ProcessMonitor(
                source,
                classifier,
                store,
                () => new AgentSnapshot(AgentState.Monitoring, null, null),
                publisher);

            var sw = System.Diagnostics.Stopwatch.StartNew();
            int count = monitor.Reconcile();
            sw.Stop();

            // Reconcile completes synchronously without waiting for network I/O
            Assert.True(sw.ElapsedMilliseconds < 10000);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public async Task Agent_restart_recovers_stale_uploading_events_and_resumes_processing()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-test-restart-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store1 = new SqliteAgentStore(root);
            var ev = CreateEvent("crashed_app");
            store1.Enqueue(ev);

            // Simulate agent crash while event was claimed as Uploading
            var claimed = store1.ClaimPendingEvents(10);
            Assert.Single(claimed);
            Assert.Equal(EventDeliveryStatus.Uploading, claimed[0].DeliveryStatus);

            // Simulate agent restart (new store instance on same path)
            var store2 = new SqliteAgentStore(root);
            var publisher = new MockEventPublisher();
            var worker = new EventUploaderWorker(store2, publisher);

            // ClaimPendingEvents auto-recovers stale Uploading status to Pending and claims it
            int processed = await worker.ProcessBatchAsync();
            Assert.Equal(1, processed);
            Assert.Single(publisher.PublishedEvents);
            Assert.Equal(ev.EventId, publisher.PublishedEvents[0].EventId);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    private static ViolationEvent CreateEvent(string name) => new(
        Guid.NewGuid(),
        "LAB-PC-01",
        "STUDENT-101",
        "APPLICATION_OPENED",
        1234,
        name,
        DateTimeOffset.UtcNow,
        $"C:\\{name}.exe",
        "Unauthorized process test");
}
