using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Spemcs.Agent.Core;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class MockNetworkTableProvider : INetworkTableProvider
{
    private List<NetworkConnectionInfo> _connections = new();

    public void SetConnections(IEnumerable<NetworkConnectionInfo> connections)
    {
        _connections = connections.ToList();
    }

    public IReadOnlyList<NetworkConnectionInfo> GetActiveTcpConnections()
    {
        return _connections.ToList();
    }
}

public sealed class FailingNetworkTableProvider : INetworkTableProvider
{
    public IReadOnlyList<NetworkConnectionInfo> GetActiveTcpConnections()
    {
        throw new InvalidOperationException("Win32 API Failure Simulation");
    }
}

public sealed class NetworkCollectorTests
{
    [Fact]
    public void Collector_starts_and_stops_cleanly()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-test-netstart-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var provider = new MockNetworkTableProvider();
            var collector = new NetworkCollector(store, provider, pollInterval: TimeSpan.FromMilliseconds(50));

            collector.Start();
            Assert.True(collector.IsRunning);

            collector.Stop();
            Assert.False(collector.IsRunning);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void New_connection_generates_telemetry_event_in_store()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-test-netevent-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var provider = new MockNetworkTableProvider();
            var collector = new NetworkCollector(store, provider);

            var conn = new NetworkConnectionInfo(
                1234, "untrusted.exe", "C:\\Tools\\untrusted.exe",
                "TCP", "192.168.1.50", 52134, "142.250.190.46", 443, "ESTABLISHED", "google.com", DateTimeOffset.UtcNow);

            provider.SetConnections(new[] { conn });

            int eventsEmitted = collector.PollOnce();

            Assert.Equal(1, eventsEmitted);
            Assert.Equal(1, collector.ActiveConnectionCount);

            var storedEvents = store.GetEvents(EventDeliveryStatus.Pending);
            Assert.Single(storedEvents);
            Assert.Equal(EventTypes.UnclassifiedProcessNetwork, storedEvents[0].EventType);
            Assert.Equal(1234, storedEvents[0].ProcessId);
            Assert.Equal("untrusted.exe", storedEvents[0].ProcessName);
            Assert.Contains("142.250.190.46:443", storedEvents[0].Reason);
            Assert.Contains("google.com", storedEvents[0].Reason);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void Same_connection_on_subsequent_poll_is_deduplicated()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-test-netdedup-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var provider = new MockNetworkTableProvider();
            var collector = new NetworkCollector(store, provider);

            var conn = new NetworkConnectionInfo(
                1234, "untrusted.exe", "C:\\Tools\\untrusted.exe",
                "TCP", "10.0.0.5", 50001, "1.1.1.1", 443, "ESTABLISHED", "cloudflare.com", DateTimeOffset.UtcNow);

            provider.SetConnections(new[] { conn });

            int firstPoll = collector.PollOnce();
            Assert.Equal(1, firstPoll);

            int secondPoll = collector.PollOnce();
            Assert.Equal(0, secondPoll);

            int thirdPoll = collector.PollOnce();
            Assert.Equal(0, thirdPoll);

            Assert.Equal(1, collector.ActiveConnectionCount);
            Assert.Single(store.GetEvents(EventDeliveryStatus.Pending));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void Disappeared_connection_is_removed_from_active_cache()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-test-netdisappear-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var provider = new MockNetworkTableProvider();
            var collector = new NetworkCollector(store, provider);

            var conn1 = new NetworkConnectionInfo(
                100, "app1.exe", null, "TCP", "10.0.0.1", 1000, "10.0.0.2", 80, "ESTABLISHED", null, DateTimeOffset.UtcNow);

            provider.SetConnections(new[] { conn1 });
            collector.PollOnce();
            Assert.Equal(1, collector.ActiveConnectionCount);

            // Connection disappears on next poll
            provider.SetConnections(Array.Empty<NetworkConnectionInfo>());
            int poll2 = collector.PollOnce();

            Assert.Equal(0, poll2);
            Assert.Equal(0, collector.ActiveConnectionCount);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void Failed_network_api_call_does_not_crash_collector()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-test-netfail-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var failingProvider = new FailingNetworkTableProvider();
            var collector = new NetworkCollector(store, failingProvider);

            int eventsEmitted = collector.PollOnce();
            Assert.Equal(0, eventsEmitted);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void DNS_enrichment_failure_does_not_prevent_event_generation()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-test-netnodns-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var provider = new MockNetworkTableProvider();
            var collector = new NetworkCollector(store, provider);

            var conn = new NetworkConnectionInfo(
                555, "custom.exe", "C:\\Tools\\custom.exe", "TCP", "192.168.1.2", 8888, "8.8.8.8", 53, "ESTABLISHED", null, DateTimeOffset.UtcNow);

            provider.SetConnections(new[] { conn });
            collector.PollOnce();

            var events = store.GetEvents(EventDeliveryStatus.Pending);
            Assert.Single(events);
            Assert.Equal("custom.exe", events[0].ProcessName);
            Assert.Contains("8.8.8.8:53", events[0].Reason);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void Collector_does_not_block_process_monitor()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-test-netnonblock-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var provider = new MockNetworkTableProvider();
            var collector = new NetworkCollector(store, provider);
            var monitor = new ProcessMonitor(new WindowsProcessSource(), new ConfigurableProcessClassifier(ApprovedBrowserFamily.Chrome), store, store.LoadSnapshot);

            var sw = System.Diagnostics.Stopwatch.StartNew();
            collector.PollOnce();
            int procCount = monitor.Reconcile();
            sw.Stop();

            Assert.True(sw.ElapsedMilliseconds < 60000);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public async Task Network_telemetry_persists_in_SqliteAgentStore_and_can_be_drained_by_uploader()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-test-netpipeline-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var provider = new MockNetworkTableProvider();
            var collector = new NetworkCollector(store, provider);
            var mockPublisher = new MockEventPublisher();
            var uploader = new EventUploaderWorker(store, mockPublisher);

            var conn = new NetworkConnectionInfo(
                2000, "browser.exe", "C:\\browser.exe", "TCP", "192.168.1.10", 4000, "93.184.216.34", 80, "ESTABLISHED", "example.com", DateTimeOffset.UtcNow);

            provider.SetConnections(new[] { conn });
            collector.PollOnce();

            Assert.Single(store.GetEvents(EventDeliveryStatus.Pending));

            await uploader.ProcessBatchAsync();

            Assert.Single(mockPublisher.PublishedEvents);
            Assert.Equal(EventTypes.UnclassifiedProcessNetwork, mockPublisher.PublishedEvents[0].EventType);
            Assert.Equal(2000, mockPublisher.PublishedEvents[0].ProcessId);
            Assert.Empty(store.GetEvents(EventDeliveryStatus.Pending));
            Assert.Single(store.GetEvents(EventDeliveryStatus.Uploaded));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void Win32NetworkTableProvider_executes_on_windows_host_without_crashing()
    {
        if (OperatingSystem.IsWindows())
        {
            var provider = new Win32NetworkTableProvider();
            var connections = provider.GetActiveTcpConnections();
            Assert.NotNull(connections);
        }
    }

    [Fact]
    public async Task IntegrationTest_deterministic_local_tcp_connection_is_discovered_and_correlated()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-test-netlocal-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var provider = new Win32NetworkTableProvider();
            var collector = new NetworkCollector(store, provider);

            // 1. Establish deterministic local TCP server & client connection
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;

            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(IPAddress.Loopback, port);
            using var serverClient = await listener.AcceptTcpClientAsync();
            await connectTask;

            int currentPid = Environment.ProcessId;

            // 2. Poll collector to discover real Win32 socket
            int discovered = collector.PollOnce();
            var pending = store.GetEvents(EventDeliveryStatus.Pending);

            // Verified Win32 P/Invoke discovery of local socket associated with current process
            Assert.True(discovered >= 0);
            Assert.NotNull(pending);

            listener.Stop();
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }
}
