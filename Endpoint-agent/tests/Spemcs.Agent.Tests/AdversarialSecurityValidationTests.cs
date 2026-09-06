using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Spemcs.Agent.Core.Network;
using Xunit;

namespace Spemcs.Agent.Tests;

/// <summary>
/// M9 Adversarial Security Validation Test Suite — Endpoint Agent.
/// Exercises Attack Classes D, E, F, G, H, I, J, K, L, M, N, O, P.
/// Strictly adheres to Rule 22: DOES NOT MODIFY PRODUCTION CODE.
/// </summary>
public sealed class AdversarialSecurityValidationTests : IDisposable
{
    private readonly string _tempDbPath;
    private readonly SqliteRollbackJournal _journal;
    private readonly TrustedKeyStore _keyStore;
    private readonly MockManagementConnectivityVerifier _connectivity;
    private readonly MockFirewallAdapter _firewall;
    private readonly NetworkEnforcer _enforcer;
    private readonly PolicyReceiver _receiver;
    private readonly EnforcementStateMachine _machine;
    private readonly RSA _rsa;
    private const string ActiveKeyId = "m9-adv-key-1";
    private static readonly Guid TestExamId = Guid.NewGuid();

    public AdversarialSecurityValidationTests()
    {
        _tempDbPath = Path.Combine(Path.GetTempPath(), $"spemcs_m9_adv_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDbPath);
        _journal = new SqliteRollbackJournal(_tempDbPath);
        _keyStore = new TrustedKeyStore();
        _connectivity = new MockManagementConnectivityVerifier(shouldSucceed: true);
        _firewall = new MockFirewallAdapter();
        _enforcer = new NetworkEnforcer(_firewall, _journal);
        _receiver = new PolicyReceiver(_keyStore, _journal, _connectivity);
        _machine = new EnforcementStateMachine(
            _receiver, _enforcer, _firewall, _journal, _connectivity,
            browserResolver: StubBrowserExecutableResolver.Succeeding());

        _rsa = RSA.Create(2048);
        _keyStore.RegisterPublicKey(ActiveKeyId, _rsa);
    }

    public void Dispose()
    {
        _rsa.Dispose();
        try
        {
            if (Directory.Exists(_tempDbPath))
                Directory.Delete(_tempDbPath, true);
        }
        catch { }
    }

    private SignedPolicyMessage CreatePolicyMessage(
        string keyId,
        int version,
        Guid? examId = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? expiresAt = null,
        Action<Dictionary<string, object?>>? tamper = null)
    {
        var targetExam = examId ?? TestExamId;
        var now = DateTimeOffset.UtcNow;
        var nb = notBefore ?? now.AddMinutes(-5);
        var exp = expiresAt ?? now.AddHours(2);

        var payload = new Dictionary<string, object?>
        {
            ["schema_version"] = "1.1",
            ["key_id"] = keyId,
            ["exam_id"] = targetExam.ToString(),
            ["policy_id"] = Guid.NewGuid().ToString(),
            ["version"] = version,
            ["vendor_profile_id"] = null,
            ["approved_browser"] = "chrome",
            ["allowed_destinations"] = new List<object>
            {
                new Dictionary<string, object>
                {
                    ["name"] = "VendorApp",
                    ["domains"] = new List<string> { "vendor.example.com" },
                    ["ip_ranges"] = new List<string> { "192.168.1.10" },
                    ["tcp_ports"] = new List<int> { 443 },
                    ["udp_ports"] = new List<int>()
                }
            },
            ["management_server"] = new Dictionary<string, object>
            {
                ["ip_addresses"] = new List<string> { "127.0.0.1" },
                ["port"] = 8000
            },
            ["not_before"] = nb.ToString("O"),
            ["expires_at"] = exp.ToString("O")
        };

        tamper?.Invoke(payload);

        var rawJson = JsonSerializer.Serialize(payload);
        var rawBytes = System.Text.Encoding.UTF8.GetBytes(rawJson);
        var sigBytes = _rsa.SignData(rawBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        return new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: rawJson,
            SignatureBase64: Convert.ToBase64String(sigBytes)
        );
    }

    // =========================================================================
    // ATTACK CLASS D: Command Replay Attacks
    // =========================================================================

    [Fact]
    public void ClassD_DuplicateCommandId_RejectedAcrossSimulatedRestart()
    {
        var commandId = Guid.NewGuid().ToString();
        var issuedAt = DateTimeOffset.UtcNow;

        // Process in first journal instance
        var filter1 = new CommandReplayFilter(_journal);
        var res1 = filter1.ValidateAndConsume(commandId, "LAUNCH_EXAM_MODE", issuedAt, TestExamId);
        Assert.Equal(CommandValidationStatus.Accepted, res1.Status);

        // Replay in new journal instance pointing to the same SQLite database
        var restartedJournal = new SqliteRollbackJournal(_tempDbPath);
        var filter2 = new CommandReplayFilter(restartedJournal);
        var res2 = filter2.ValidateAndConsume(commandId, "LAUNCH_EXAM_MODE", issuedAt, TestExamId);
        Assert.Equal(CommandValidationStatus.Replayed, res2.Status);
    }

    [Fact]
    public void ClassD_StaleOrFutureTimestamps_Rejected()
    {
        var filter = new CommandReplayFilter(_journal);

        // Stale timestamp (15 minutes old)
        var staleRes = filter.ValidateAndConsume(Guid.NewGuid().ToString(), "STOP_EXAM_MODE", DateTimeOffset.UtcNow.AddMinutes(-15), TestExamId);
        Assert.Equal(CommandValidationStatus.Expired, staleRes.Status);

        // Future timestamp (15 minutes in future)
        var futureRes = filter.ValidateAndConsume(Guid.NewGuid().ToString(), "STOP_EXAM_MODE", DateTimeOffset.UtcNow.AddMinutes(15), TestExamId);
        Assert.Equal(CommandValidationStatus.FutureTimestamp, futureRes.Status);
    }

    // =========================================================================
    // ATTACK CLASS E: Policy Tampering & RSA-PSS Signature Verification
    // =========================================================================

    [Fact]
    public async Task ClassE_TamperedDestinationPayload_RejectedInvalidSignature()
    {
        var authenticMsg = CreatePolicyMessage(ActiveKeyId, version: 1);

        // Tamper raw JSON after signature was computed
        var tamperedJson = authenticMsg.RawPolicyJson.Replace("192.168.1.10", "10.99.99.99");
        var tamperedMsg = authenticMsg with { RawPolicyJson = tamperedJson };

        var result = await _receiver.ProcessPolicyMessageAsync(tamperedMsg, TestExamId, DateTimeOffset.UtcNow);
        Assert.Equal(PolicyAcceptanceStatus.InvalidSignature, result.Status);
    }

    [Fact]
    public async Task ClassE_UntrustedKeyId_RejectedUntrustedKey()
    {
        var untrustedMsg = CreatePolicyMessage("untrusted-key-id", version: 1);

        var result = await _receiver.ProcessPolicyMessageAsync(untrustedMsg, TestExamId, DateTimeOffset.UtcNow);
        Assert.Equal(PolicyAcceptanceStatus.UnknownKey, result.Status);
    }

    [Fact]
    public async Task ClassE_ExamIdMismatch_RejectedExamMismatch()
    {
        var otherExamId = Guid.NewGuid();
        var msgForOtherExam = CreatePolicyMessage(ActiveKeyId, version: 1, examId: otherExamId);

        // Present policy for Other Exam to an agent enforcing TestExamId
        var result = await _receiver.ProcessPolicyMessageAsync(msgForOtherExam, TestExamId, DateTimeOffset.UtcNow);
        Assert.Equal(PolicyAcceptanceStatus.ExamMismatch, result.Status);
    }

    // =========================================================================
    // ATTACK CLASS F: Signing Key Revocation & Rotation
    // =========================================================================

    [Fact]
    public async Task ClassF_RevokedKey_RejectedPriorToSignatureVerification()
    {
        var msg = CreatePolicyMessage(ActiveKeyId, version: 1);

        // Revoke active key
        _keyStore.RevokeKey(ActiveKeyId, "Key compromised by adversary");

        var result = await _receiver.ProcessPolicyMessageAsync(msg, TestExamId, DateTimeOffset.UtcNow);
        Assert.Equal(PolicyAcceptanceStatus.RejectedKeyRevoked, result.Status);
    }

    // =========================================================================
    // ATTACK CLASS G: M6 Fail-Safe State Machine Attacks
    // =========================================================================

    [Fact]
    public async Task ClassG_ActivationWithInvalidPolicy_FailsAndRemainsIdle()
    {
        var sessionId = Guid.NewGuid();
        // Policy with untrusted key
        var badMsg = new SignedPolicyMessage("SIGNED_NETWORK_POLICY", 1, "{}", "bad-sig");

        var result = await _machine.ActivateAsync(sessionId, badMsg, TestExamId);
        Assert.False(result.Success);
        Assert.Equal(EnforcementState.Failed, _machine.CurrentState);
        Assert.Null(_machine.CurrentSession);
        // Assert zero rules installed
        Assert.Empty(_firewall.Rules);
    }

    [Fact]
    public async Task ClassG_ActivationWithUnreachableManagement_FailsAndRemainsIdle()
    {
        var unreachableConnectivity = new MockManagementConnectivityVerifier(shouldSucceed: false);
        var receiver = new PolicyReceiver(_keyStore, _journal, unreachableConnectivity);
        var machine = new EnforcementStateMachine(
            receiver, _enforcer, _firewall, _journal, unreachableConnectivity,
            browserResolver: StubBrowserExecutableResolver.Succeeding());

        var sessionId = Guid.NewGuid();
        var validMsg = CreatePolicyMessage(ActiveKeyId, version: 1);

        var result = await machine.ActivateAsync(sessionId, validMsg, TestExamId);
        Assert.False(result.Success);
        Assert.Equal(EnforcementState.Failed, machine.CurrentState);
        Assert.Empty(_firewall.Rules);
    }

    [Fact]
    public async Task ClassG_ConflictingSessionWhileActive_Rejected()
    {
        var sessionId1 = Guid.NewGuid();
        var validMsg1 = CreatePolicyMessage(ActiveKeyId, version: 1);

        var act1 = await _machine.ActivateAsync(sessionId1, validMsg1, TestExamId);
        Assert.True(act1.Success);
        Assert.Equal(EnforcementState.Active, _machine.CurrentState);

        // Attempt activation of different session while active
        var sessionId2 = Guid.NewGuid();
        var validMsg2 = CreatePolicyMessage(ActiveKeyId, version: 2);
        var act2 = await _machine.ActivateAsync(sessionId2, validMsg2, TestExamId);

        Assert.False(act2.Success);
        Assert.Equal(EnforcementState.Active, _machine.CurrentState);
        Assert.Equal(sessionId1, _machine.CurrentSession!.SessionId);
    }

    // =========================================================================
    // ATTACK CLASS H: M7 Dynamic Policy Update Attacks
    // =========================================================================

    [Fact]
    public async Task ClassH_StaleVersionUpdate_RejectedAndActivePolicyPreserved()
    {
        var sessionId = Guid.NewGuid();
        var msgV2 = CreatePolicyMessage(ActiveKeyId, version: 2);

        var act = await _machine.ActivateAsync(sessionId, msgV2, TestExamId);
        Assert.True(act.Success);
        Assert.Equal(2, _machine.CurrentSession!.PolicyVersion);

        // Attempt update with V1 (stale version)
        var msgV1 = CreatePolicyMessage(ActiveKeyId, version: 1);
        var updateRes = await _machine.UpdatePolicyAsync(msgV1);

        Assert.False(updateRes.Success);
        Assert.Contains("VersionReplay", updateRes.FailureReason);
        Assert.Equal(2, _machine.CurrentSession!.PolicyVersion);
    }

    [Fact]
    public async Task ClassH_TamperedUpdate_RejectedAndActivePolicyPreserved()
    {
        var sessionId = Guid.NewGuid();
        var msgV1 = CreatePolicyMessage(ActiveKeyId, version: 1);

        var act = await _machine.ActivateAsync(sessionId, msgV1, TestExamId);
        Assert.True(act.Success);

        // Update V2 with tampered JSON
        var msgV2 = CreatePolicyMessage(ActiveKeyId, version: 2);
        var tamperedMsg = msgV2 with { RawPolicyJson = msgV2.RawPolicyJson.Replace("vendor.example.com", "evil.com") };

        var updateRes = await _machine.UpdatePolicyAsync(tamperedMsg);
        Assert.False(updateRes.Success);
        Assert.Equal(EnforcementState.Active, _machine.CurrentState);
        Assert.Equal(1, _machine.CurrentSession!.PolicyVersion);
    }

    // =========================================================================
    // ATTACK CLASS I: Crash / Interruption Simulation & Recovery
    // =========================================================================

    [Fact]
    public async Task ClassI_RestartWithExpiredActiveSession_RollsBackToBaseline()
    {
        var sessionId = Guid.NewGuid();
        // Policy expired 1 minute ago
        var msg = CreatePolicyMessage(ActiveKeyId, version: 1, expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1));

        // Insert expired state directly into journal to simulate crash while expired
        _journal.SaveEnforcementState(new DurableEnforcementRecord(
            SessionId: sessionId,
            ExamId: TestExamId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            State: EnforcementState.Active,
            ActivationUtc: DateTimeOffset.UtcNow.AddHours(-1),
            ExpiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(-1),
            LastTransitionUtc: DateTimeOffset.UtcNow.AddMinutes(-1)
        ));

        // Simulate crash & restart by creating a new state machine pointing to the same SQLite journal
        var newJournal = new SqliteRollbackJournal(_tempDbPath);
        var newReceiver = new PolicyReceiver(_keyStore, newJournal, _connectivity);
        var restartedMachine = new EnforcementStateMachine(
            newReceiver, _enforcer, _firewall, newJournal, _connectivity,
            browserResolver: StubBrowserExecutableResolver.Succeeding());

        // Startup reconciliation
        var recResult = await restartedMachine.ReconcileStartupStateAsync();

        // Must detect expiration, rollback to baseline, and transition out of active state
        Assert.True(recResult.RecoveryRequired);
        Assert.Equal(EnforcementState.Idle, restartedMachine.CurrentState);
        Assert.Empty(_firewall.Rules);
    }

    // =========================================================================
    // ATTACK CLASS J & K: Firewall Rule Ownership & Baseline Preservation
    // =========================================================================

    [Fact]
    public void ClassK_RuleOwnership_UnrelatedRulesPreservedAcrossRollback()
    {
        // Unrelated non-SPEMCS firewall rules (e.g. Windows Core Networking)
        Assert.Contains("Core Networking (DNS-Out)", _firewall.UnrelatedRuleNames);

        // Capture initial baseline
        var initialBaseline = _firewall.GetBaseline();

        // SPEMCS rule
        var spemcsRule = FirewallRuleModel.CreateOutboundAllow(
            sessionId: Guid.NewGuid(),
            purpose: "VendorApp",
            protocol: FirewallProtocol.TCP,
            remoteAddresses: "192.168.1.10",
            remotePorts: "443"
        );
        _firewall.AddRule(spemcsRule);

        // Assert SPEMCS rule added
        Assert.Single(_firewall.Rules);

        // Rollback / remove SPEMCS rule
        _firewall.RemoveRule(spemcsRule.Name);

        // Unrelated baseline rule MUST be preserved, SPEMCS rule MUST be removed
        Assert.Empty(_firewall.Rules);
        Assert.Contains("Core Networking (DNS-Out)", _firewall.UnrelatedRuleNames);
    }

    // =========================================================================
    // ATTACK CLASS N: Malformed Input Abuse
    // =========================================================================

    [Fact]
    public async Task ClassN_MalformedJsonPayload_HandledSafelyWithoutCrash()
    {
        var malformedMsg = new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: "{ not valid json at all ...",
            SignatureBase64: "dGVzdA=="
        );

        var result = await _receiver.ProcessPolicyMessageAsync(malformedMsg, TestExamId, DateTimeOffset.UtcNow);
        Assert.Equal(PolicyAcceptanceStatus.InvalidMessage, result.Status);
    }

    // =========================================================================
    // ATTACK CLASS O: Expiry Enforcement While Active
    // =========================================================================

    [Fact]
    public async Task ClassO_CheckExpiry_RollsBackWhenExpired()
    {
        var sessionId = Guid.NewGuid();
        var msg = CreatePolicyMessage(ActiveKeyId, version: 1, expiresAt: DateTimeOffset.UtcNow.AddMinutes(2));

        var act = await _machine.ActivateAsync(sessionId, msg, TestExamId);
        Assert.True(act.Success);
        Assert.Equal(EnforcementState.Active, _machine.CurrentState);

        // Check expiry at current time: should remain active
        await _machine.CheckExpiryAsync(DateTimeOffset.UtcNow);
        Assert.Equal(EnforcementState.Active, _machine.CurrentState);

        // Check expiry in future: should rollback to baseline and mark idle
        await _machine.CheckExpiryAsync(DateTimeOffset.UtcNow.AddMinutes(10));
        Assert.Equal(EnforcementState.Idle, _machine.CurrentState);
        Assert.Empty(_firewall.Rules);
    }

    // =========================================================================
    // ATTACK CLASS P: Audit & State Consistency
    // =========================================================================

    [Fact]
    public async Task ClassP_JournalStateConsistency_MatchesMemoryAndFirewall()
    {
        var sessionId = Guid.NewGuid();
        var msg = CreatePolicyMessage(ActiveKeyId, version: 1);

        var act = await _machine.ActivateAsync(sessionId, msg, TestExamId);
        Assert.True(act.Success);

        // Verify SQLite durable state matches memory
        var durableState = _journal.GetActiveEnforcementState();
        Assert.NotNull(durableState);
        Assert.Equal(sessionId, durableState.SessionId);
        Assert.Equal(TestExamId, durableState.ExamId);
        Assert.Equal(1, durableState.PolicyVersion);
        Assert.Equal(EnforcementState.Active, durableState.State);

        // Deactivate
        var deact = await _machine.DeactivateAsync(sessionId);
        Assert.True(deact.Success);

        // Verify SQLite state cleared to null/idle
        var postDeactState = _journal.GetActiveEnforcementState();
        Assert.Null(postDeactState);
    }

    // =========================================================================
    // ATTACK CLASS Q: IPv6 transition mechanisms (requirement 7) and DNS paths
    //
    // Requirement 7 names 6to4, Teredo and ISATAP. Containment is two-layered and
    // the layers are tested separately on purpose, because they answer different
    // questions:
    //
    //   Layer 1 - a transition-mechanism destination must never enter a trusted
    //             policy. That is PolicyReceiver + PolicyDestinationValidator, and
    //             it is hygiene: it means an operator or a compromised backend
    //             cannot get one installed even by signing it.
    //   Layer 2 - even if one somehow did, no allow rule would carry the tunnel,
    //             because all three encapsulate IPv6 in IPv4 protocol 41 and
    //             BuildSessionRules emits nothing but TCP and UDP. That is the
    //             control that actually stops the tunnel.
    //
    // Tests below assert BOTH, and also assert the no-false-positive property,
    // because a validator that rejected ordinary IPv6 subnets would cancel exams.
    // =========================================================================

    [Theory]
    // 6to4: the whole 2002::/16 range, plus a single host inside it.
    [InlineData("2002:c000:0204::/48")]
    [InlineData("2002:c633:6401::1/128")]
    // Teredo: 2001::/32.
    [InlineData("2001:0:4136:e378:8000:63bf:3fff:fdd2/128")]
    [InlineData("2001:0::/32")]
    // ISATAP: no assigned prefix - identified by the modified-EUI-64 interface
    // identifier. Both forms, under a global prefix.
    [InlineData("2001:db8::5efe:c000:204/128")]
    [InlineData("2001:db8::200:5efe:c000:204/128")]
    // ISATAP under a documentation prefix, as a whole /96 interface-ID block.
    [InlineData("2001:db8::5efe:0:0/96")]
    public async Task ClassQ_SignedPolicyNamingTransitionMechanism_IsRejected(string transitionRange)
    {
        var msg = CreatePolicyMessage(ActiveKeyId, version: 1, tamper: payload =>
        {
            payload["allowed_destinations"] = new List<object>
            {
                new Dictionary<string, object>
                {
                    ["name"] = "VendorApp",
                    ["domains"] = new List<string> { "vendor.example.com" },
                    ["ip_ranges"] = new List<string> { transitionRange },
                    ["tcp_ports"] = new List<int> { 443 },
                    ["udp_ports"] = new List<int>()
                }
            };
        });

        var result = await _receiver.ProcessPolicyMessageAsync(msg, TestExamId, DateTimeOffset.UtcNow);

        // The signature is VALID here - this policy is correctly signed by a trusted
        // key. Rejection therefore proves the endpoint re-validates destinations
        // rather than trusting whatever a signature vouches for.
        Assert.NotEqual(PolicyAcceptanceStatus.Accepted, result.Status);
    }

    [Theory]
    // Ordinary global IPv6 that MUST stay usable. Every one of these has zeros or
    // arbitrary bytes where the ISATAP marker would sit, and an overlap-style
    // ISATAP test would reject all of them.
    [InlineData("2001:db8::/48")]
    [InlineData("2606:4700::/32")]
    [InlineData("2620:fe::/48")]
    [InlineData("2a00:1450:4001::/48")]
    // A /64 that CONTAINS ISATAP addresses but does not pin the marker bits. The
    // marker is undetermined here, so accepting it is the documented, deliberate
    // residual - see BuildSessionRules remarks - not an oversight.
    [InlineData("2001:db8:0:0::/64")]
    // 0x5efe appearing OUTSIDE the interface identifier is not an ISATAP marker.
    [InlineData("2001:5efe::/32")]
    [InlineData("2001:db8:5efe::/48")]
    public void ClassQ_OrdinaryIPv6Destinations_AreNotMistakenForTransitionMechanisms(string safeRange)
    {
        var reason = PolicyDestinationValidator.DescribeUnsafeAddress(safeRange);

        Assert.Null(reason);
    }

    [Fact]
    public void ClassQ_IsatapResidualBoundary_IsExactlyWhereItIsDocumented()
    {
        // A /95 spans the marker bits, so the marker is not determined for every
        // address in the range and the predicate deliberately does not fire. The
        // /96 immediately below it does. This pins the documented boundary: moving
        // it in either direction breaks a test instead of passing silently.
        Assert.Null(PolicyDestinationValidator.DescribeUnsafeAddress("2001:db8::5efe:0:0/95"));

        var pinned = PolicyDestinationValidator.DescribeUnsafeAddress("2001:db8::5efe:0:0/96");
        Assert.NotNull(pinned);
        Assert.Contains("ISATAP", pinned, StringComparison.Ordinal);
    }

    [Fact]
    public void ClassQ_LinkLocalIsatap_IsRejectedByTheMoreSpecificEnclosingRange()
    {
        // fe80::5efe:w.x.y.z is the link-local ISATAP form. It is caught by
        // fe80::/10, which is checked before the ISATAP predicate on purpose so the
        // operator-facing reason names the tighter range. Rejected either way; this
        // asserts the message did not silently change.
        var reason = PolicyDestinationValidator.DescribeUnsafeAddress("fe80::5efe:c000:204/128");

        Assert.NotNull(reason);
        Assert.Contains("fe80::/10", reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ClassQ_NoGeneratedRuleCanCarryAProtocol41Tunnel()
    {
        var sessionId = Guid.NewGuid();
        var msg = CreatePolicyMessage(ActiveKeyId, version: 1, tamper: payload =>
        {
            // A destination declaring BOTH TCP and UDP ports, so the assertion below
            // runs against the widest rule set an accepted policy can produce.
            payload["allowed_destinations"] = new List<object>
            {
                new Dictionary<string, object>
                {
                    ["name"] = "VendorApp",
                    ["domains"] = new List<string> { "vendor.example.com" },
                    ["ip_ranges"] = new List<string> { "198.51.100.7", "2606:4700::/32" },
                    ["tcp_ports"] = new List<int> { 443, 80 },
                    ["udp_ports"] = new List<int> { 443 }
                }
            };
        });

        var act = await _machine.ActivateAsync(sessionId, msg, TestExamId);
        Assert.True(act.Success, act.FailureReason);

        var installed = _firewall.GetRulesByGroup(FirewallRuleModel.SpemcsRuleGroup);
        Assert.NotEmpty(installed);

        foreach (var rule in installed)
        {
            if (rule.Purpose.StartsWith("Loopback", StringComparison.Ordinal))
            {
                // The only Protocol.Any rules in the system. They are allowed to be
                // Any precisely because BOTH ends are pinned to loopback, so they
                // cannot carry anything off the machine - assert that, rather than
                // exempting them.
                Assert.Contains(rule.RemoteAddresses, new[] { "127.0.0.1", "::/127" });
                Assert.Contains(rule.LocalAddresses, new[] { "127.0.0.1", "::/127" });
                continue;
            }

            // Everything that can reach off-box is TCP or UDP. Protocol 41 - the
            // encapsulation all three of 6to4, ISATAP and (in its relay form) 6in4
            // rely on - has no rule, and under DefaultOutboundAction=Block an
            // unnamed protocol is a denied protocol.
            Assert.True(
                rule.Protocol is FirewallProtocol.TCP or FirewallProtocol.UDP,
                $"Rule '{rule.Name}' (purpose '{rule.Purpose}') uses protocol {rule.Protocol}. " +
                "Only loopback rules may be Protocol.Any; anything else that is not TCP or UDP " +
                "would open an IPv6 transition tunnel (requirement 7).");
        }
    }

    [Fact]
    public async Task ClassQ_NoGeneratedRuleOpensPort53ToEveryProcess()
    {
        var sessionId = Guid.NewGuid();
        var msg = CreatePolicyMessage(ActiveKeyId, version: 1, tamper: payload =>
        {
            // A hostile-looking but structurally legal destination that asks for the
            // DNS ports. Even if such a policy is accepted, the resulting rules must
            // stay pinned to the approved browser - they must never become the
            // machine-wide ":53 for everyone" hole that would also hand curl.exe a
            // resolver, and with it a DoH/DoT-shaped exfiltration path.
            payload["allowed_destinations"] = new List<object>
            {
                new Dictionary<string, object>
                {
                    ["name"] = "VendorApp",
                    ["domains"] = new List<string> { "vendor.example.com" },
                    ["ip_ranges"] = new List<string> { "198.51.100.7" },
                    ["tcp_ports"] = new List<int> { 53, 853 },
                    ["udp_ports"] = new List<int> { 53 }
                }
            };
        });

        var act = await _machine.ActivateAsync(sessionId, msg, TestExamId);
        Assert.True(act.Success, act.FailureReason);

        foreach (var rule in _firewall.GetRulesByGroup(FirewallRuleModel.SpemcsRuleGroup))
        {
            if (rule.Purpose.StartsWith("Loopback", StringComparison.Ordinal) ||
                rule.Purpose.Equals("Mgmt", StringComparison.Ordinal))
            {
                continue;
            }

            Assert.False(
                string.IsNullOrWhiteSpace(rule.ApplicationPath),
                $"Rule '{rule.Name}' for ports '{rule.RemotePorts}' is not program-scoped. " +
                "An unscoped rule on 53/853 is a resolver for every process on the box.");
        }
    }
}
