using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Spemcs.Agent.Core;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class DnsCorrelationTests
{
    [Fact]
    public void Test1_DNS_result_plus_matching_TCP_connection_populates_domain()
    {
        var tracker = new DnsCorrelationTracker();
        var targetIp = IPAddress.Parse("93.184.216.34");
        var now = DateTimeOffset.UtcNow;

        tracker.RecordResolution("example.com", targetIp, now, processId: 1234, processName: "chrome");

        bool correlated = tracker.TryCorrelate(targetIp, 1234, "chrome", now, out var domain, out var dnsResolved, out var resolvedIpStr, out var confidence);

        Assert.True(correlated);
        Assert.Equal("example.com", domain);
        Assert.True(dnsResolved);
        Assert.Equal("high", confidence);
    }

    [Fact]
    public void Test2_DNS_result_plus_different_destination_IP_does_not_populate_false_domain()
    {
        var tracker = new DnsCorrelationTracker();
        var recordedIp = IPAddress.Parse("93.184.216.34");
        var targetIp = IPAddress.Parse("198.51.100.5");
        var now = DateTimeOffset.UtcNow;

        tracker.RecordResolution("example.com", recordedIp, now, processId: 1234);

        bool correlated = tracker.TryCorrelate(targetIp, 1234, "chrome", now, out var domain, out var dnsResolved, out _, out var confidence);

        Assert.False(correlated);
        Assert.Null(domain);
        Assert.False(dnsResolved);
        Assert.Equal("unresolved", confidence);
    }

    [Fact]
    public void Test3_Multiple_domains_and_IPs_correlate_correctly()
    {
        var tracker = new DnsCorrelationTracker();
        var ipA = IPAddress.Parse("93.184.216.34");
        var ipB = IPAddress.Parse("142.250.190.46");
        var now = DateTimeOffset.UtcNow;

        tracker.RecordResolution("example.com", ipA, now, processId: 100, processName: "browser");
        tracker.RecordResolution("google.com", ipB, now, processId: 200, processName: "browser");

        Assert.True(tracker.TryCorrelate(ipA, 100, "browser", now, out var domainA, out _));
        Assert.Equal("example.com", domainA);

        Assert.True(tracker.TryCorrelate(ipB, 200, "browser", now, out var domainB, out _));
        Assert.Equal("google.com", domainB);
    }

    [Fact]
    public async Task Test4_DNS_cache_expiry_removes_old_entries()
    {
        var tracker = new DnsCorrelationTracker(maxRetentionWindow: TimeSpan.FromMilliseconds(200));
        var ip = IPAddress.Parse("93.184.216.34");

        tracker.RecordResolution("shortlived.com", ip, DateTimeOffset.UtcNow, processId: 300);

        await Task.Delay(300);

        bool correlated = tracker.TryCorrelate(ip, 300, "tool", DateTimeOffset.UtcNow, out var domain, out var dnsResolved);

        Assert.False(correlated);
        Assert.Null(domain);
        Assert.False(dnsResolved);
    }

    [Fact]
    public void Test5_Connection_with_no_DNS_information_generates_event_with_unknown_domain()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-test-nodns-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var provider = new MockNetworkTableProvider();
            var tracker = new DnsCorrelationTracker();
            var collector = new NetworkCollector(store, provider, dnsTracker: tracker);

            var conn = new NetworkConnectionInfo(
                5000, "untrusted.exe", "C:\\Tools\\untrusted.exe",
                "TCP", "192.168.1.50", 50000, "203.0.113.88", 443, "Established", null, DateTimeOffset.UtcNow);

            provider.SetConnections(new[] { conn });
            int events = collector.PollOnce();

            Assert.Equal(1, events);

            var pending = store.GetEvents(EventDeliveryStatus.Pending);
            Assert.Single(pending);
            Assert.Null(pending[0].Domain);
            Assert.False(pending[0].DnsResolved);
            Assert.Equal(EventTypes.UnclassifiedProcessNetwork, pending[0].EventType);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void Test6_Enriched_connection_generates_event_with_correlated_domain()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-test-dnsenriched-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var provider = new MockNetworkTableProvider();
            var tracker = new DnsCorrelationTracker();
            var collector = new NetworkCollector(store, provider, dnsTracker: tracker);

            var targetIp = "203.0.113.88";
            tracker.RecordResolution("malicious-site.org", IPAddress.Parse(targetIp), DateTimeOffset.UtcNow, processId: 6000, processName: "untrusted.exe");

            var conn = new NetworkConnectionInfo(
                6000, "untrusted.exe", "C:\\Tools\\untrusted.exe",
                "TCP", "192.168.1.50", 50000, targetIp, 443, "Established", "malicious-site.org", DateTimeOffset.UtcNow, DnsResolved: true);

            provider.SetConnections(new[] { conn });
            int events = collector.PollOnce();

            Assert.Equal(1, events);

            var pending = store.GetEvents(EventDeliveryStatus.Pending);
            Assert.Single(pending);
            Assert.Equal("malicious-site.org", pending[0].Domain);
            Assert.True(pending[0].DnsResolved);
            Assert.Contains("[domain: malicious-site.org]", pending[0].Reason);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void Test7_Chrome_HTTPS_benign_traffic_remains_suppressed_with_DNS_correlation()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-test-chromedns-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var provider = new MockNetworkTableProvider();
            var tracker = new DnsCorrelationTracker();
            var collector = new NetworkCollector(store, provider, dnsTracker: tracker);

            var chromeIp = "142.250.190.46";
            tracker.RecordResolution("google.com", IPAddress.Parse(chromeIp), DateTimeOffset.UtcNow, processId: 2644, processName: "chrome");

            var conn = new NetworkConnectionInfo(
                2644, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "TCP", "192.168.1.50", 54321, chromeIp, 443, "Established", "google.com", DateTimeOffset.UtcNow, DnsResolved: true);

            provider.SetConnections(new[] { conn });
            int events = collector.PollOnce();

            Assert.Equal(0, events);
            Assert.Empty(store.GetEvents(EventDeliveryStatus.Pending));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void Test8_CNAME_chain_correlation_works()
    {
        var tracker = new DnsCorrelationTracker();
        var targetIp = IPAddress.Parse("74.226.64.245");
        var now = DateTimeOffset.UtcNow;

        // PID 12532 queried checkappexec.microsoft.com which resolves to 74.226.64.245 via CNAME
        tracker.RecordResolution("checkappexec.microsoft.com", targetIp, now, processId: 12532, processName: "smartscreen");

        bool correlated = tracker.TryCorrelate(targetIp, 12532, "smartscreen", now, out var domain, out var dnsResolved, out _, out var confidence);

        Assert.True(correlated);
        Assert.Equal("checkappexec.microsoft.com", domain);
        Assert.True(dnsResolved);
        Assert.Equal("high", confidence);
    }

    [Fact]
    public void Test9_PID_isolation_prevents_false_attribution()
    {
        var tracker = new DnsCorrelationTracker();
        var targetIp = IPAddress.Parse("104.20.23.154");
        var now = DateTimeOffset.UtcNow;

        // Process 1 (PID 100) resolves domainA.com
        tracker.RecordResolution("domainA.com", targetIp, now, processId: 100, processName: "processA");

        // Process 2 (PID 200) connects to targetIp without having done DNS
        bool correlated = tracker.TryCorrelate(targetIp, 200, "processB", now, out var domain, out var dnsResolved, out _, out var confidence);

        // Should return medium confidence fallback, NOT claim high PID confidence
        Assert.True(correlated);
        Assert.Equal("medium", confidence);
    }
}
