using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Spemcs.Agent.Core.Network;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class DynamicPolicyUpdateIntegrationTests : IDisposable
{
    private readonly TcpListener _mgmtListener;
    private readonly TcpListener _vendorListenerA;
    private readonly TcpListener _vendorListenerB;
    private readonly int _mgmtPort;
    private readonly int _vendorPortA;
    private readonly int _vendorPortB;
    private readonly CancellationTokenSource _listenerCts = new();

    public DynamicPolicyUpdateIntegrationTests()
    {
        _mgmtListener = new TcpListener(IPAddress.Loopback, 0);
        _mgmtListener.Start();
        _mgmtPort = ((IPEndPoint)_mgmtListener.LocalEndpoint).Port;

        _vendorListenerA = new TcpListener(IPAddress.Loopback, 0);
        _vendorListenerA.Start();
        _vendorPortA = ((IPEndPoint)_vendorListenerA.LocalEndpoint).Port;

        _vendorListenerB = new TcpListener(IPAddress.Loopback, 0);
        _vendorListenerB.Start();
        _vendorPortB = ((IPEndPoint)_vendorListenerB.LocalEndpoint).Port;

        _ = Task.Run(() => AcceptLoopAsync(_mgmtListener, _listenerCts.Token));
        _ = Task.Run(() => AcceptLoopAsync(_vendorListenerA, _listenerCts.Token));
        _ = Task.Run(() => AcceptLoopAsync(_vendorListenerB, _listenerCts.Token));
    }

    private static async Task AcceptLoopAsync(TcpListener listener, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                using var client = await listener.AcceptTcpClientAsync(ct);
                var stream = client.GetStream();
                stream.WriteByte(0x01);
            }
        }
        catch { }
    }

    public void Dispose()
    {
        _listenerCts.Cancel();
        try { _mgmtListener.Stop(); } catch { }
        try { _vendorListenerA.Stop(); } catch { }
        try { _vendorListenerB.Stop(); } catch { }
    }

    private SignedPolicyMessage CreateSignedMessage(
        RSA rsa,
        string keyId,
        Guid examId,
        int version,
        int vendorPort,
        string msgType = "SIGNED_NETWORK_POLICY")
    {
        var policyId = Guid.NewGuid();
        var payloadObj = new Dictionary<string, object?>
        {
            ["schema_version"] = "1.0",
            ["key_id"] = keyId,
            ["exam_id"] = examId.ToString(),
            ["policy_id"] = policyId.ToString(),
            ["version"] = version,
            ["vendor_profile_id"] = null,
            ["allowed_destinations"] = new List<object>
            {
                new Dictionary<string, object>
                {
                    ["name"] = "VendorApp",
                    ["domains"] = new List<string> { "vendor.local" },
                    ["ip_ranges"] = new List<string> { "127.0.0.1" },
                    ["tcp_ports"] = new List<int> { vendorPort },
                    ["udp_ports"] = new List<int>()
                }
            },
            ["management_server"] = new Dictionary<string, object>
            {
                ["ip_addresses"] = new List<string> { "127.0.0.1" },
                ["port"] = _mgmtPort
            },
            ["not_before"] = DateTimeOffset.UtcNow.AddMinutes(-5).ToString("O"),
            ["expires_at"] = DateTimeOffset.UtcNow.AddHours(2).ToString("O")
        };

        var rawJson = JsonSerializer.Serialize(payloadObj);
        var rawBytes = System.Text.Encoding.UTF8.GetBytes(rawJson);
        var sigBytes = rsa.SignData(rawBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        return new SignedPolicyMessage(
            MessageType: msgType,
            ProtocolVersion: 1,
            RawPolicyJson: rawJson,
            SignatureBase64: Convert.ToBase64String(sigBytes)
        );
    }

    [Fact]
    public async Task DynamicIpRotation_FullTrafficVerification_EndToEnd()
    {
        // 1. Pre-Enforcement: Verify all 3 sockets accept traffic before lockdown
        using (var testMgmt = new TcpClient())
        {
            await testMgmt.ConnectAsync(IPAddress.Loopback, _mgmtPort);
            Assert.True(testMgmt.Connected);
        }
        using (var testA = new TcpClient())
        {
            await testA.ConnectAsync(IPAddress.Loopback, _vendorPortA);
            Assert.True(testA.Connected);
        }
        using (var testB = new TcpClient())
        {
            await testB.ConnectAsync(IPAddress.Loopback, _vendorPortB);
            Assert.True(testB.Connected);
        }

        // 2. Setup Environment
        var tempDbPath = Path.Combine(Path.GetTempPath(), $"spemcs_m7_e2e_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDbPath);

        try
        {
            var journal = new SqliteRollbackJournal(tempDbPath);
            var keyStore = new TrustedKeyStore();
            var connectivity = new MockManagementConnectivityVerifier(shouldSucceed: true);
            var receiver = new PolicyReceiver(keyStore, journal, connectivity);
            var mockFirewall = new MockFirewallAdapter();
            var enforcer = new NetworkEnforcer(mockFirewall, journal);
            var machine = new EnforcementStateMachine(receiver, enforcer, mockFirewall, journal, connectivity);

            using var rsa = RSA.Create(2048);
            var keyId = "dev-key-1";
            keyStore.RegisterPublicKey(keyId, rsa);

            var sessionId = Guid.NewGuid();
            var examId = Guid.NewGuid();

            // -----------------------------------------------------------------
            // 3. Activate Policy v1 (Allowed: Management + VendorPortA)
            // -----------------------------------------------------------------
            var msgV1 = CreateSignedMessage(rsa, keyId, examId, version: 1, vendorPort: _vendorPortA);
            var act = await machine.ActivateAsync(sessionId, msgV1, examId, FirewallProfiles.Private);

            Assert.True(act.Success);
            Assert.Equal(EnforcementState.Active, machine.CurrentState);
            Assert.Equal(FirewallAction.Block, mockFirewall.GetBaseline().PrivateDefaultOutbound);

            // Traffic Under Policy v1:
            Assert.True(IsTrafficPermitted(mockFirewall, "127.0.0.1", _mgmtPort), "Management must be permitted");
            Assert.True(IsTrafficPermitted(mockFirewall, "127.0.0.1", _vendorPortA), "Vendor Port A must be permitted");
            Assert.False(IsTrafficPermitted(mockFirewall, "127.0.0.1", _vendorPortB), "Vendor Port B must be BLOCKED under v1");

            // -----------------------------------------------------------------
            // 4. Dynamic Policy Update to v2 (Rotated: Management + VendorPortB)
            // -----------------------------------------------------------------
            var msgV2 = CreateSignedMessage(rsa, keyId, examId, version: 2, vendorPort: _vendorPortB, msgType: "UPDATE_EXAM_POLICY");
            var update = await machine.UpdatePolicyAsync(msgV2);

            Assert.True(update.Success);
            Assert.Equal(2, update.NewVersion);
            Assert.Equal(2, machine.CurrentSession?.PolicyVersion);
            Assert.Equal(EnforcementState.Active, machine.CurrentState); // Remained ACTIVE!

            // Verify DefaultOutboundAction remained BLOCK throughout
            Assert.Equal(FirewallAction.Block, mockFirewall.GetBaseline().PrivateDefaultOutbound);

            // Traffic Under Policy v2 (Rotated!):
            Assert.True(IsTrafficPermitted(mockFirewall, "127.0.0.1", _mgmtPort), "Management remains permitted");
            Assert.True(IsTrafficPermitted(mockFirewall, "127.0.0.1", _vendorPortB), "Rotated Vendor Port B is now PERMITTED");
            Assert.False(IsTrafficPermitted(mockFirewall, "127.0.0.1", _vendorPortA), "Retired Vendor Port A is now BLOCKED");

            // -----------------------------------------------------------------
            // 5. Deactivate / Stop Exam
            // -----------------------------------------------------------------
            var deact = await machine.DeactivateAsync(sessionId, "Exam completed");
            Assert.True(deact.Success);
            Assert.Equal(EnforcementState.Idle, machine.CurrentState);

            // Baseline restored to ALLOW
            Assert.Equal(FirewallAction.Allow, mockFirewall.GetBaseline().PrivateDefaultOutbound);
            Assert.True(IsTrafficPermitted(mockFirewall, "127.0.0.1", _vendorPortA), "Port A restored after exam");
            Assert.True(IsTrafficPermitted(mockFirewall, "127.0.0.1", _vendorPortB), "Port B restored after exam");

            // SPEMCS rules purged; unrelated rules intact
            Assert.Empty(mockFirewall.Rules);
            Assert.Equal(3, mockFirewall.UnrelatedRuleNames.Count);
        }
        finally
        {
            try { Directory.Delete(tempDbPath, true); } catch { }
        }
    }

    [Fact]
    public async Task FailedUpdate_FullTrafficVerification_EndToEnd()
    {
        var tempDbPath = Path.Combine(Path.GetTempPath(), $"spemcs_m7_fail_traffic_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDbPath);

        try
        {
            var journal = new SqliteRollbackJournal(tempDbPath);
            var keyStore = new TrustedKeyStore();
            var connectivity = new MockManagementConnectivityVerifier(shouldSucceed: true);
            var receiver = new PolicyReceiver(keyStore, journal, connectivity);
            var mockFirewall = new MockFirewallAdapter();
            var enforcer = new NetworkEnforcer(mockFirewall, journal);
            var machine = new EnforcementStateMachine(receiver, enforcer, mockFirewall, journal, connectivity);

            using var rsa = RSA.Create(2048);
            var keyId = "dev-key-1";
            keyStore.RegisterPublicKey(keyId, rsa);

            var sessionId = Guid.NewGuid();
            var examId = Guid.NewGuid();

            // 1. Activate Policy v1 (Allowed: Management + VendorPortA)
            var msgV1 = CreateSignedMessage(rsa, keyId, examId, version: 1, vendorPort: _vendorPortA);
            var act = await machine.ActivateAsync(sessionId, msgV1, examId, FirewallProfiles.Private);
            Assert.True(act.Success);
            Assert.Equal(EnforcementState.Active, machine.CurrentState);

            // 2. Candidate B arrives attempting to rotate to _vendorPortB, but management probe fails
            connectivity.ShouldSucceed = false;

            var msgV2 = CreateSignedMessage(rsa, keyId, examId, version: 2, vendorPort: _vendorPortB, msgType: "UPDATE_EXAM_POLICY");
            var update = await machine.UpdatePolicyAsync(msgV2);

            // Update failed!
            Assert.False(update.Success);
            Assert.Equal(EnforcementState.Active, machine.CurrentState); // Stays ACTIVE on Policy v1!
            Assert.Equal(1, machine.CurrentSession?.PolicyVersion);

            // 3. Traffic Verification Under Preserved Policy A:
            // Management: SUCCESS
            Assert.True(IsTrafficPermitted(mockFirewall, "127.0.0.1", _mgmtPort), "Management remains permitted");

            // Old Vendor Port A: SUCCESS (Policy A still active!)
            Assert.True(IsTrafficPermitted(mockFirewall, "127.0.0.1", _vendorPortA), "Vendor Port A remains permitted");

            // Candidate-only Vendor Port B: BLOCKED (Rolled back!)
            Assert.False(IsTrafficPermitted(mockFirewall, "127.0.0.1", _vendorPortB), "Candidate-only Port B must be BLOCKED");

            // Unauthorized port: BLOCKED
            Assert.False(IsTrafficPermitted(mockFirewall, "127.0.0.1", 9999), "Unauthorized traffic remains BLOCKED");

            // DefaultOutboundAction: BLOCK
            Assert.Equal(FirewallAction.Block, mockFirewall.GetBaseline().PrivateDefaultOutbound);

            // Unrelated rules preserved:
            Assert.Equal(3, mockFirewall.UnrelatedRuleNames.Count);
        }
        finally
        {
            try { Directory.Delete(tempDbPath, true); } catch { }
        }
    }

    private static bool IsTrafficPermitted(MockFirewallAdapter firewall, string ip, int port)
    {
        var isDefaultBlock = firewall.PrivateDefaultOutbound == FirewallAction.Block;
        if (!isDefaultBlock) return true;

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
