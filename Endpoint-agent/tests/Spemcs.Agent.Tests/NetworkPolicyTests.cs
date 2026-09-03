using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Spemcs.Agent.Core;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class NetworkPolicyTests
{
    private readonly NetworkPolicyEvaluator _evaluator = new();

    [Fact]
    public void Test1_Prohibited_process_plus_socket_promotes_to_CRITICAL()
    {
        var conn = new NetworkConnectionInfo(
            123, "anydesk.exe", "C:\\Program Files\\AnyDesk\\anydesk.exe",
            "TCP", "192.168.1.10", 50000, "1.2.3.4", 443, "Established", null, DateTimeOffset.UtcNow);

        var result = _evaluator.Evaluate(conn);

        Assert.True(result.IsPromoted);
        Assert.Equal(EventTypes.ProhibitedProcessNetwork, result.EventType);
        Assert.Equal("CRITICAL", result.Severity);
    }

    [Fact]
    public void Test2_Suspicious_AppData_executable_plus_external_socket_promotes_to_HIGH()
    {
        var conn = new NetworkConnectionInfo(
            456, "untrusted.exe", "C:\\Users\\Student\\AppData\\Local\\TempApp\\untrusted.exe",
            "TCP", "192.168.1.10", 50001, "93.184.216.34", 443, "Established", null, DateTimeOffset.UtcNow);

        var result = _evaluator.Evaluate(conn);

        Assert.True(result.IsPromoted);
        Assert.Equal(EventTypes.SuspiciousPathNetwork, result.EventType);
        Assert.Equal("HIGH", result.Severity);
    }

    [Fact]
    public void Test3_Suspicious_Temp_executable_plus_external_socket_promotes_to_HIGH()
    {
        var conn = new NetworkConnectionInfo(
            789, "payload.exe", "C:\\Windows\\Temp\\payload.exe",
            "TCP", "192.168.1.10", 50002, "198.51.100.25", 80, "Established", null, DateTimeOffset.UtcNow);

        var result = _evaluator.Evaluate(conn);

        Assert.True(result.IsPromoted);
        Assert.Equal(EventTypes.SuspiciousPathNetwork, result.EventType);
        Assert.Equal("HIGH", result.Severity);
    }

    [Fact]
    public void Test4_Unknown_process_plus_external_socket_promotes_to_MEDIUM()
    {
        var conn = new NetworkConnectionInfo(
            1001, "mycustomtool.exe", "C:\\Tools\\mycustomtool.exe",
            "TCP", "192.168.1.10", 50003, "203.0.113.5", 443, "Established", null, DateTimeOffset.UtcNow);

        var result = _evaluator.Evaluate(conn);

        Assert.True(result.IsPromoted);
        Assert.Equal(EventTypes.UnclassifiedProcessNetwork, result.EventType);
        Assert.Equal("MEDIUM", result.Severity);
    }

    [Fact]
    public void Test5_Chrome_plus_HTTPS_is_suppressed()
    {
        var conn = new NetworkConnectionInfo(
            2000, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "TCP", "192.168.1.10", 50004, "142.250.190.46", 443, "Established", "google.com", DateTimeOffset.UtcNow);

        var result = _evaluator.Evaluate(conn);

        Assert.False(result.IsPromoted);
    }

    [Fact]
    public void Test6_Chrome_plus_localhost_is_suppressed()
    {
        var conn = new NetworkConnectionInfo(
            2000, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "TCP", "127.0.0.1", 50005, "127.0.0.1", 8000, "Established", null, DateTimeOffset.UtcNow);

        var result = _evaluator.Evaluate(conn);

        Assert.False(result.IsPromoted);
    }

    [Fact]
    public void Test7_SPEMCS_process_plus_localhost_is_suppressed()
    {
        var conn = new NetworkConnectionInfo(
            3000, "Spemcs.Agent.UI.exe", "C:\\Program Files\\SPEMCS\\Endpoint Agent\\Spemcs.Agent.UI.exe",
            "TCP", "127.0.0.1", 50006, "127.0.0.1", 8000, "Established", null, DateTimeOffset.UtcNow);

        var result = _evaluator.Evaluate(conn);

        Assert.False(result.IsPromoted);
    }

    [Fact]
    public void Test8_Non_standard_port_alone_on_benign_system_process_is_suppressed()
    {
        var conn = new NetworkConnectionInfo(
            4, "System", null,
            "TCP", "0.0.0.0", 10243, "0.0.0.0", 0, "Listen", null, DateTimeOffset.UtcNow);

        var result = _evaluator.Evaluate(conn);

        Assert.False(result.IsPromoted);
    }

    [Fact]
    public void Test9_Direct_IP_alone_on_benign_process_is_suppressed()
    {
        var conn = new NetworkConnectionInfo(
            5000, "svchost.exe", "C:\\Windows\\System32\\svchost.exe",
            "TCP", "192.168.1.10", 50007, "13.107.21.200", 443, "Established", null, DateTimeOffset.UtcNow);

        var result = _evaluator.Evaluate(conn);

        Assert.False(result.IsPromoted);
    }

    [Fact]
    public void Test10_Suspicious_process_plus_non_standard_port_promotes_to_HIGH()
    {
        var classification = new ClassificationResult(Classification.Suspicious, "Suspicious User App", "UserApp", null, null, null);
        var conn = new NetworkConnectionInfo(
            6000, "proxytool.exe", "C:\\Tools\\proxytool.exe",
            "TCP", "192.168.1.10", 50008, "198.51.100.88", 8080, "Established", null, DateTimeOffset.UtcNow);

        var options = new NetworkPolicyOptions { EnableUnclassifiedRule = false };
        var evaluator = new NetworkPolicyEvaluator(options);

        var result = evaluator.Evaluate(conn, classification);

        Assert.True(result.IsPromoted);
        Assert.Equal(EventTypes.AnomalousPortViolation, result.EventType);
        Assert.Equal("HIGH", result.Severity);
    }

    [Fact]
    public void Test11_Repeated_anomalous_connections_crossing_threshold_promotes_to_HIGH()
    {
        var options = new NetworkPolicyOptions
        {
            EnableUnclassifiedRule = false,
            BurstThresholdCount = 3,
            BurstWindow = TimeSpan.FromSeconds(5)
        };
        var evaluator = new NetworkPolicyEvaluator(options);

        int pid = 7000;
        var conn1 = new NetworkConnectionInfo(pid, "testproc", null, "TCP", "10.0.0.1", 1001, "1.1.1.1", 443, "Established", null, DateTimeOffset.UtcNow);
        var conn2 = new NetworkConnectionInfo(pid, "testproc", null, "TCP", "10.0.0.1", 1002, "2.2.2.2", 443, "Established", null, DateTimeOffset.UtcNow);
        var conn3 = new NetworkConnectionInfo(pid, "testproc", null, "TCP", "10.0.0.1", 1003, "3.3.3.3", 443, "Established", null, DateTimeOffset.UtcNow);

        Assert.False(evaluator.Evaluate(conn1).IsPromoted);
        Assert.False(evaluator.Evaluate(conn2).IsPromoted);

        var res3 = evaluator.Evaluate(conn3);
        Assert.True(res3.IsPromoted);
        Assert.Equal(EventTypes.BurstConnectionAnomaly, res3.EventType);
        Assert.Equal("HIGH", res3.Severity);
    }

    [Fact]
    public async Task Test12_Burst_state_expires_correctly()
    {
        var options = new NetworkPolicyOptions
        {
            EnableUnclassifiedRule = false,
            BurstThresholdCount = 2,
            BurstWindow = TimeSpan.FromMilliseconds(200)
        };
        var evaluator = new NetworkPolicyEvaluator(options);

        int pid = 8000;
        var conn1 = new NetworkConnectionInfo(pid, "testproc", null, "TCP", "10.0.0.1", 1001, "1.1.1.1", 443, "Established", null, DateTimeOffset.UtcNow);

        evaluator.Evaluate(conn1);

        await Task.Delay(300);

        var conn2 = new NetworkConnectionInfo(pid, "testproc", null, "TCP", "10.0.0.1", 1002, "2.2.2.2", 443, "Established", null, DateTimeOffset.UtcNow);
        var res2 = evaluator.Evaluate(conn2);

        Assert.False(res2.IsPromoted);
    }

    [Fact]
    public void Regression_Same_connection_appearing_in_3_consecutive_polls_produces_exactly_1_event()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-reg-poll3-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var provider = new MockNetworkTableProvider();
            var collector = new NetworkCollector(store, provider);

            var conn = new NetworkConnectionInfo(
                3708, "dotnet.exe", "C:\\Program Files\\dotnet\\dotnet.exe",
                "TCP", "192.168.1.50", 52100, "20.50.88.234", 443, "Established", null, DateTimeOffset.UtcNow);

            provider.SetConnections(new[] { conn });

            int poll1 = collector.PollOnce();
            int poll2 = collector.PollOnce();
            int poll3 = collector.PollOnce();

            Assert.Equal(1, poll1);
            Assert.Equal(0, poll2);
            Assert.Equal(0, poll3);

            var pending = store.GetEvents(EventDeliveryStatus.Pending);
            Assert.Single(pending);
            Assert.Equal(EventTypes.UnclassifiedProcessNetwork, pending[0].EventType);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void Regression_Same_connection_with_different_local_ephemeral_port_produces_new_event()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-reg-diffport-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var provider = new MockNetworkTableProvider();
            var collector = new NetworkCollector(store, provider);

            var conn1 = new NetworkConnectionInfo(
                3708, "dotnet.exe", "C:\\Program Files\\dotnet\\dotnet.exe",
                "TCP", "192.168.1.50", 52100, "20.50.88.234", 443, "Established", null, DateTimeOffset.UtcNow);

            var conn2 = new NetworkConnectionInfo(
                3708, "dotnet.exe", "C:\\Program Files\\dotnet\\dotnet.exe",
                "TCP", "192.168.1.50", 52101, "20.50.88.234", 443, "Established", null, DateTimeOffset.UtcNow);

            provider.SetConnections(new[] { conn1 });
            int poll1 = collector.PollOnce();

            provider.SetConnections(new[] { conn1, conn2 });
            int poll2 = collector.PollOnce();

            Assert.Equal(1, poll1);
            Assert.Equal(1, poll2);

            var pending = store.GetEvents(EventDeliveryStatus.Pending);
            Assert.Equal(2, pending.Count);
            Assert.Contains(":52100", pending[0].Reason);
            Assert.Contains(":52101", pending[1].Reason);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void Regression_Connection_disappears_and_later_reappears_with_same_tuple()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-reg-reappear-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var provider = new MockNetworkTableProvider();
            var collector = new NetworkCollector(store, provider);

            var conn = new NetworkConnectionInfo(
                3708, "dotnet.exe", "C:\\Program Files\\dotnet\\dotnet.exe",
                "TCP", "192.168.1.50", 52100, "20.50.88.234", 443, "Established", null, DateTimeOffset.UtcNow);

            provider.SetConnections(new[] { conn });
            collector.PollOnce();

            // Connection disappears on poll 2
            provider.SetConnections(Array.Empty<NetworkConnectionInfo>());
            collector.PollOnce();

            // Connection reappears with same 6-tuple on poll 3
            provider.SetConnections(new[] { conn });
            int poll3 = collector.PollOnce();

            Assert.Equal(1, poll3);

            var pending = store.GetEvents(EventDeliveryStatus.Pending);
            Assert.Equal(2, pending.Count);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void Regression_Multiple_NetworkCollector_Start_calls_cannot_create_duplicate_workers()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-reg-multistart-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var provider = new MockNetworkTableProvider();
            var collector = new NetworkCollector(store, provider);

            collector.Start();
            collector.Start();
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
    public void Regression_Normal_Chrome_443_traffic_remains_suppressed()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-reg-chromesuppress-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var provider = new MockNetworkTableProvider();
            var collector = new NetworkCollector(store, provider);

            var conn = new NetworkConnectionInfo(
                2644, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "TCP", "192.168.1.50", 54321, "142.251.150.119", 443, "Established", "google.com", DateTimeOffset.UtcNow);

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
    public void Regression_Suspicious_unclassified_external_traffic_produces_exactly_one_event()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-reg-unclassified1-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var provider = new MockNetworkTableProvider();
            var collector = new NetworkCollector(store, provider);

            var conn = new NetworkConnectionInfo(
                5000, "untrusted.exe", "C:\\Tools\\untrusted.exe",
                "TCP", "192.168.1.50", 50000, "93.184.216.34", 443, "Established", null, DateTimeOffset.UtcNow);

            provider.SetConnections(new[] { conn });

            int poll1 = collector.PollOnce();
            int poll2 = collector.PollOnce();

            Assert.Equal(1, poll1);
            Assert.Equal(0, poll2);

            var pending = store.GetEvents(EventDeliveryStatus.Pending);
            Assert.Single(pending);
            Assert.Equal(EventTypes.UnclassifiedProcessNetwork, pending[0].EventType);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void Test_Browser_MsEdge_To_ChatGPT_Promotes_To_CRITICAL_Prohibited_Domain_Access()
    {
        var conn = new NetworkConnectionInfo(
            7356, "msedge.exe", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            "TCP", "192.168.1.10", 54321, "104.20.23.154", 443, "Established", "chatgpt.com", DateTimeOffset.UtcNow);

        var result = _evaluator.Evaluate(conn);

        Assert.True(result.IsPromoted);
        Assert.Equal("PROHIBITED_DOMAIN_ACCESS", result.EventType);
        Assert.Equal("CRITICAL", result.Severity);
    }

    [Fact]
    public void Test_Browser_MsEdge_To_Normal_Domain_Suppresses()
    {
        var conn = new NetworkConnectionInfo(
            7356, "msedge.exe", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            "TCP", "192.168.1.10", 54322, "93.184.216.34", 443, "Established", "example.com", DateTimeOffset.UtcNow);

        var result = _evaluator.Evaluate(conn);

        Assert.False(result.IsPromoted);
    }

    [Fact]
    public void Test_Domain_Matching_Boundaries()
    {
        var prohibited = new[] { "chatgpt.com", "openai.com" };

        // Should match
        Assert.True(NetworkPolicyEvaluator.IsProhibitedDomain("chatgpt.com", prohibited));
        Assert.True(NetworkPolicyEvaluator.IsProhibitedDomain("www.chatgpt.com", prohibited));
        Assert.True(NetworkPolicyEvaluator.IsProhibitedDomain("api.chatgpt.com", prohibited));
        Assert.True(NetworkPolicyEvaluator.IsProhibitedDomain("chatgpt.com.", prohibited));

        // Should NOT match
        Assert.False(NetworkPolicyEvaluator.IsProhibitedDomain("notchatgpt.com", prohibited));
        Assert.False(NetworkPolicyEvaluator.IsProhibitedDomain("chatgpt.com.evil.example", prohibited));
        Assert.False(NetworkPolicyEvaluator.IsProhibitedDomain("examplechatgpt.com", prohibited));
    }
}
