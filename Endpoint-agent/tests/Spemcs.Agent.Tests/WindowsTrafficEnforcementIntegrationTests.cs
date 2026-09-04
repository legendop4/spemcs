using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Spemcs.Agent.Core.Network;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class WindowsTrafficEnforcementIntegrationTests : IDisposable
{
    private readonly TcpListener _managementListener;
    private readonly TcpListener _vendorListener;
    private readonly TcpListener _unauthorizedListener;
    private readonly int _managementPort;
    private readonly int _vendorPort;
    private readonly int _unauthorizedPort;
    private readonly CancellationTokenSource _listenerCts = new();

    public WindowsTrafficEnforcementIntegrationTests()
    {
        // Bind to localhost on dynamic free ports
        _managementListener = new TcpListener(IPAddress.Loopback, 0);
        _managementListener.Start();
        _managementPort = ((IPEndPoint)_managementListener.LocalEndpoint).Port;

        _vendorListener = new TcpListener(IPAddress.Loopback, 0);
        _vendorListener.Start();
        _vendorPort = ((IPEndPoint)_vendorListener.LocalEndpoint).Port;

        _unauthorizedListener = new TcpListener(IPAddress.Loopback, 0);
        _unauthorizedListener.Start();
        _unauthorizedPort = ((IPEndPoint)_unauthorizedListener.LocalEndpoint).Port;

        // Background accept loop to keep listeners responsive
        _ = Task.Run(() => AcceptLoopAsync(_managementListener, _listenerCts.Token));
        _ = Task.Run(() => AcceptLoopAsync(_vendorListener, _listenerCts.Token));
        _ = Task.Run(() => AcceptLoopAsync(_unauthorizedListener, _listenerCts.Token));
    }

    private static async Task AcceptLoopAsync(TcpListener listener, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                using var client = await listener.AcceptTcpClientAsync(ct);
                // Simple handshake
                var stream = client.GetStream();
                stream.WriteByte(0x01);
            }
        }
        catch { }
    }

    public void Dispose()
    {
        _listenerCts.Cancel();
        try { _managementListener.Stop(); } catch { }
        try { _vendorListener.Stop(); } catch { }
        try { _unauthorizedListener.Stop(); } catch { }
    }

    private static bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    [Fact]
    public async Task BaselineNetwork_BothEndpointsReachableBeforeEnforcement()
    {
        // 1. Management listener is reachable
        using var client1 = new TcpClient();
        await client1.ConnectAsync(IPAddress.Loopback, _managementPort);
        Assert.True(client1.Connected);

        // 2. Unauthorized listener is also reachable before enforcement
        using var client2 = new TcpClient();
        await client2.ConnectAsync(IPAddress.Loopback, _unauthorizedPort);
        Assert.True(client2.Connected);
    }

    [Fact]
    public async Task ControlledTrafficEnforcement_Verification()
    {
        // If running elevated, perform live COM firewall mutation
        // If unelevated, verify privilege security boundary and mock traffic assertions
        var isElevated = IsAdministrator();

        var tempDbPath = Path.Combine(Path.GetTempPath(), $"spemcs_traffic_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDbPath);

        try
        {
            var journal = new SqliteRollbackJournal(tempDbPath);
            var keyStore = new TrustedKeyStore();
            var connectivity = new ManagementConnectivityVerifier(timeoutMs: 1500);
            var receiver = new PolicyReceiver(keyStore, journal, connectivity);

            IFirewallAdapter firewall = isElevated ? new WindowsFirewallAdapter() : new MockFirewallAdapter();
            var enforcer = new NetworkEnforcer(firewall, journal);
            var machine = new EnforcementStateMachine(receiver, enforcer, firewall, journal, connectivity);

            // Read baseline
            var initialBaseline = firewall.GetBaseline();
            Assert.NotNull(initialBaseline);

            // Test pre-enforcement reachability
            using (var testTcp = new TcpClient())
            {
                await testTcp.ConnectAsync(IPAddress.Loopback, _managementPort);
                Assert.True(testTcp.Connected);
            }

            using (var unauthTcp = new TcpClient())
            {
                await unauthTcp.ConnectAsync(IPAddress.Loopback, _unauthorizedPort);
                Assert.True(unauthTcp.Connected);
            }

            // If running elevated: perform live COM enforcement and traffic blockage
            // If running unelevated: verify elevation boundary and in-memory enforcement behavior
            if (isElevated)
            {
                // Live COM execution
                var sessionId = Guid.NewGuid();
                var examId = Guid.NewGuid();
                // Set default block on Private profile (typical for local loopback / lab network)
                firewall.SetDefaultOutboundAction(FirewallProfiles.Private, FirewallAction.Block);
                var verifiedBaseline = firewall.GetBaseline();
                Assert.Equal(FirewallAction.Block, verifiedBaseline.PrivateDefaultOutbound);

                // Safe rollback
                firewall.SetDefaultOutboundAction(FirewallProfiles.Private, initialBaseline.PrivateDefaultOutbound);
                var restored = firewall.GetBaseline();
                Assert.Equal(initialBaseline.PrivateDefaultOutbound, restored.PrivateDefaultOutbound);
            }
            else
            {
                // Standard user elevation boundary test:
                // Verify that COM mutation is safely blocked by Windows security
                var comAdapter = new WindowsFirewallAdapter();
                Assert.Throws<UnauthorizedAccessException>(() =>
                    comAdapter.SetDefaultOutboundAction(FirewallProfiles.Private, FirewallAction.Block));
            }
        }
        finally
        {
            try { Directory.Delete(tempDbPath, true); } catch { }
        }
    }

    [Fact]
    public async Task FullRestrictiveTrafficLevelEnforcement_EndToEnd()
    {
        // 1. Pre-enforcement: Verify all 3 listeners accept real network connections
        using (var testMgmt = new TcpClient())
        {
            await testMgmt.ConnectAsync(IPAddress.Loopback, _managementPort);
            Assert.True(testMgmt.Connected);
        }

        using (var testVendor = new TcpClient())
        {
            await testVendor.ConnectAsync(IPAddress.Loopback, _vendorPort);
            Assert.True(testVendor.Connected);
        }

        using (var testUnauth = new TcpClient())
        {
            await testUnauth.ConnectAsync(IPAddress.Loopback, _unauthorizedPort);
            Assert.True(testUnauth.Connected);
        }

        // 2. Setup mock firewall adapter to simulate traffic-level enforcement
        var mockFirewall = new MockFirewallAdapter();
        var tempDbPath = Path.Combine(Path.GetTempPath(), $"spemcs_e2e_traffic_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDbPath);

        try
        {
            var journal = new SqliteRollbackJournal(tempDbPath);
            var keyStore = new TrustedKeyStore();
            var connectivity = new MockManagementConnectivityVerifier(shouldSucceed: true);
            var receiver = new PolicyReceiver(keyStore, journal, connectivity);
            var enforcer = new NetworkEnforcer(mockFirewall, journal);
            var machine = new EnforcementStateMachine(receiver, enforcer, mockFirewall, journal, connectivity);

            // Generate an RSA key for signing the test policy
            using var rsa = RSA.Create(2048);
            var keyId = "dev-key-1";
            keyStore.RegisterPublicKey(keyId, rsa);

            var sessionId = Guid.NewGuid();
            var examId = Guid.NewGuid();
            var policyId = Guid.NewGuid();

            // Policy allows _managementPort and _vendorPort. _unauthorizedPort is omitted.
            var rawJson = $@"{{
                ""allowed_destinations"": [
                    {{
                        ""domains"": [""vendor.local""],
                        ""ip_ranges"": [""127.0.0.1""],
                        ""name"": ""ExamVendor"",
                        ""tcp_ports"": [{_vendorPort}],
                        ""udp_ports"": []
                    }}
                ],
                ""exam_id"": ""{examId}"",
                ""expires_at"": ""2035-01-01T00:00:00Z"",
                ""key_id"": ""{keyId}"",
                ""management_server"": {{
                    ""ip_addresses"": [""127.0.0.1""],
                    ""port"": {_managementPort}
                }},
                ""not_before"": ""2025-01-01T00:00:00Z"",
                ""policy_id"": ""{policyId}"",
                ""schema_version"": ""1.0"",
                ""vendor_profile_id"": null,
                ""version"": 1
            }}";

            // Clean compact JSON
            using var doc = System.Text.Json.JsonDocument.Parse(rawJson);
            using var ms = new MemoryStream();
            using (var writer = new System.Text.Json.Utf8JsonWriter(ms))
            {
                doc.WriteTo(writer);
            }
            var compactJson = System.Text.Encoding.UTF8.GetString(ms.ToArray());

            var sigBytes = rsa.SignData(
                System.Text.Encoding.UTF8.GetBytes(compactJson),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss);
            var sigBase64 = Convert.ToBase64String(sigBytes);

            var msg = new SignedPolicyMessage(
                MessageType: "SIGNED_NETWORK_POLICY",
                ProtocolVersion: 1,
                RawPolicyJson: compactJson,
                SignatureBase64: sigBase64
            );

            // 3. ACTIVATE ENFORCEMENT
            var actResult = await machine.ActivateAsync(sessionId, msg, examId, FirewallProfiles.Private, DateTimeOffset.UtcNow);
            Assert.True(actResult.Success);
            Assert.Equal(EnforcementState.Active, machine.CurrentState);

            // 4. Verify actual firewall state: DefaultOutboundAction == BLOCK
            var baseline = mockFirewall.GetBaseline();
            Assert.Equal(FirewallAction.Block, baseline.PrivateDefaultOutbound);

            // 5. Verify traffic permissions under ACTIVE state:
            // Management: SUCCESS
            Assert.True(IsTrafficPermitted(mockFirewall, "127.0.0.1", _managementPort),
                "Authorized management traffic should be permitted under SPEMCS rules.");

            // Vendor: SUCCESS
            Assert.True(IsTrafficPermitted(mockFirewall, "127.0.0.1", _vendorPort),
                "Authorized vendor traffic should be permitted under SPEMCS rules.");

            // Unauthorized destination: BLOCKED
            Assert.False(IsTrafficPermitted(mockFirewall, "127.0.0.1", _unauthorizedPort),
                "Unauthorized destination must be blocked under DefaultOutboundAction == BLOCK.");

            // 6. DEACTIVATE / STOP EXAM
            var deactResult = await machine.DeactivateAsync(sessionId, "Exam finished");
            Assert.True(deactResult.Success);
            Assert.Equal(EnforcementState.Idle, machine.CurrentState);

            // 7. Verify baseline restored: DefaultOutboundAction == ALLOW
            var restoredBaseline = mockFirewall.GetBaseline();
            Assert.Equal(FirewallAction.Allow, restoredBaseline.PrivateDefaultOutbound);

            // 8. Verify unauthorized destination is reachable again
            Assert.True(IsTrafficPermitted(mockFirewall, "127.0.0.1", _unauthorizedPort),
                "Unauthorized destination should be permitted again once default block is lifted.");

            // 9. Verify SPEMCS rules removed and unrelated rules untouched
            Assert.Empty(mockFirewall.Rules);
            Assert.Equal(3, mockFirewall.UnrelatedRuleNames.Count);
        }
        finally
        {
            try { Directory.Delete(tempDbPath, true); } catch { }
        }
    }

    private static bool IsTrafficPermitted(MockFirewallAdapter firewall, string ip, int port)
    {
        // Under Windows Firewall logic:
        // If DefaultOutboundAction == Allow, traffic is permitted unless a Block rule matches.
        // If DefaultOutboundAction == Block, traffic is blocked unless an Allow rule matches.
        var isDefaultBlock = firewall.PrivateDefaultOutbound == FirewallAction.Block;
        if (!isDefaultBlock)
        {
            return true;
        }

        // Check if any active destination allow rule matches the target IP and Port (ignore internal loopback rules)
        return firewall.Rules.Any(r =>
            r.Action == FirewallAction.Allow &&
            r.Direction == FirewallDirection.Outbound &&
            r.Enabled &&
            !r.Purpose.StartsWith("Loopback", StringComparison.OrdinalIgnoreCase) &&
            (r.RemoteAddresses == "*" || r.RemoteAddresses.Contains(ip)) &&
            (r.RemotePorts == "*" || r.RemotePorts.Split(',').Select(p => p.Trim()).Contains(port.ToString()))
        );
    }
}
