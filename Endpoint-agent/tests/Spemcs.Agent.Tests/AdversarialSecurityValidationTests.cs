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
}
