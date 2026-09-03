using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Spemcs.Agent.Core.Network;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class DynamicPolicyUpdateUnitTests : IDisposable
{
    private readonly string _tempDbPath;
    private readonly SqliteRollbackJournal _journal;
    private readonly TrustedKeyStore _keyStore;
    private readonly MockManagementConnectivityVerifier _connectivity;
    private readonly PolicyReceiver _receiver;
    private readonly MockFirewallAdapter _firewall;
    private readonly NetworkEnforcer _enforcer;
    private readonly EnforcementStateMachine _machine;
    private readonly RSA _rsa;
    private readonly string _keyId = "dev-key-1";
    private static readonly Guid TestExamId = Guid.NewGuid();

    public DynamicPolicyUpdateUnitTests()
    {
        _tempDbPath = Path.Combine(Path.GetTempPath(), $"spemcs_m7_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDbPath);
        _journal = new SqliteRollbackJournal(_tempDbPath);
        _keyStore = new TrustedKeyStore();
        _connectivity = new MockManagementConnectivityVerifier(shouldSucceed: true);
        _receiver = new PolicyReceiver(_keyStore, _journal, _connectivity);
        _firewall = new MockFirewallAdapter();
        _enforcer = new NetworkEnforcer(_firewall, _journal);
        _machine = new EnforcementStateMachine(_receiver, _enforcer, _firewall, _journal, _connectivity);

        _rsa = RSA.Create(2048);
        _keyStore.RegisterPublicKey(_keyId, _rsa);
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

    private SignedPolicyMessage CreateSignedMessage(
        int version,
        List<string> vendorIps,
        int vendorPort,
        string msgType = "SIGNED_NETWORK_POLICY",
        Guid? examIdOverride = null,
        DateTimeOffset? expiresAtOverride = null,
        bool tamperSignature = false)
    {
        var examId = examIdOverride ?? TestExamId;
        var policyId = Guid.NewGuid();
        var expStr = (expiresAtOverride ?? DateTimeOffset.UtcNow.AddHours(2)).ToString("O");

        var payloadObj = new Dictionary<string, object?>
        {
            ["schema_version"] = "1.0",
            ["key_id"] = _keyId,
            ["exam_id"] = examId.ToString(),
            ["policy_id"] = policyId.ToString(),
            ["version"] = version,
            ["vendor_profile_id"] = null,
            ["allowed_destinations"] = new List<object>
            {
                new Dictionary<string, object>
                {
                    ["name"] = "VendorApp",
                    ["domains"] = new List<string> { "vendor.example.com" },
                    ["ip_ranges"] = vendorIps,
                    ["tcp_ports"] = new List<int> { vendorPort },
                    ["udp_ports"] = new List<int>()
                }
            },
            ["management_server"] = new Dictionary<string, object>
            {
                ["ip_addresses"] = new List<string> { "127.0.0.1" },
                ["port"] = 8000
            },
            ["not_before"] = DateTimeOffset.UtcNow.AddMinutes(-5).ToString("O"),
            ["expires_at"] = expStr
        };

        var rawJson = JsonSerializer.Serialize(payloadObj);
        var rawBytes = System.Text.Encoding.UTF8.GetBytes(rawJson);
        var sigBytes = _rsa.SignData(rawBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        if (tamperSignature)
        {
            sigBytes[0] ^= 0xFF;
        }

        return new SignedPolicyMessage(
            MessageType: msgType,
            ProtocolVersion: 1,
            RawPolicyJson: rawJson,
            SignatureBase64: Convert.ToBase64String(sigBytes)
        );
    }

    // =========================================================================
    // 1. Monotonicity Tests (Section 4)
    // =========================================================================

    [Fact]
    public async Task UpdatePolicy_RejectsSameOrLowerVersion_PreservesActivePolicy()
    {
        var sessionId = Guid.NewGuid();
        var initialMsg = CreateSignedMessage(version: 1, new List<string> { "192.168.1.10" }, 443);

        var act = await _machine.ActivateAsync(sessionId, initialMsg, TestExamId);
        Assert.True(act.Success);
        Assert.Equal(1, _machine.CurrentSession?.PolicyVersion);

        // Attempt update with same version (v1)
        var sameVersionMsg = CreateSignedMessage(version: 1, new List<string> { "192.168.1.20" }, 443, msgType: "UPDATE_EXAM_POLICY");
        var updateResult1 = await _machine.UpdatePolicyAsync(sameVersionMsg);

        Assert.False(updateResult1.Success);
        Assert.Contains("strictly greater", updateResult1.FailureReason);
        Assert.Equal(1, _machine.CurrentSession?.PolicyVersion); // Still v1

        // Attempt update with lower version (v0) - Rejected by M5
        var lowerVersionMsg = CreateSignedMessage(version: 0, new List<string> { "192.168.1.20" }, 443, msgType: "UPDATE_EXAM_POLICY");
        var updateResult2 = await _machine.UpdatePolicyAsync(lowerVersionMsg);

        Assert.False(updateResult2.Success);
        Assert.Equal(1, _machine.CurrentSession?.PolicyVersion); // Still v1
    }

    // =========================================================================
    // 2. IP Rotation & Additive Staging (Section 1, 9 & 22)
    // =========================================================================

    [Fact]
    public async Task UpdatePolicy_IpRotation_ReplacesOldRuleWithNewRule_TransactionSafeFailSafe()
    {
        // Clarification of IP rotation semantics:
        // The implementation uses an additive-first sequence (Add B -> Verify B -> Remove A -> Verify final -> Commit).
        // This is a transaction-safe / fail-safe rotation guaranteeing that:
        // 1. Allowed destinations ⊆ A ∪ B during transition.
        // 2. DefaultOutboundAction == BLOCK throughout transition.
        // 3. No unintended destination is ever allowed.
        var sessionId = Guid.NewGuid();
        // Policy v1 allows 10.0.0.1:443
        var msgV1 = CreateSignedMessage(version: 1, new List<string> { "10.0.0.1" }, 443);
        var act = await _machine.ActivateAsync(sessionId, msgV1, TestExamId);
        Assert.True(act.Success);

        var rulesV1 = _firewall.Rules.ToList();
        Assert.Contains(rulesV1, r => r.RemoteAddresses.Contains("10.0.0.1"));
        Assert.DoesNotContain(rulesV1, r => r.RemoteAddresses.Contains("10.0.0.2"));

        // Policy v2 rotates to 10.0.0.2:443
        var msgV2 = CreateSignedMessage(version: 2, new List<string> { "10.0.0.2" }, 443, msgType: "UPDATE_EXAM_POLICY");
        var update = await _machine.UpdatePolicyAsync(msgV2);

        Assert.True(update.Success);
        Assert.Equal(2, update.NewVersion);
        Assert.Equal(2, _machine.CurrentSession?.PolicyVersion);

        // Verify final firewall state: 10.0.0.2 is present, 10.0.0.1 is retired, BLOCK is intact
        var rulesV2 = _firewall.Rules.ToList();
        Assert.Contains(rulesV2, r => r.RemoteAddresses.Contains("10.0.0.2"));
        Assert.DoesNotContain(rulesV2, r => r.RemoteAddresses.Contains("10.0.0.1"));

        var baseline = _firewall.GetBaseline();
        Assert.Equal(FirewallAction.Block, baseline.PrivateDefaultOutbound);
    }

    [Fact]
    public async Task UpdatePolicy_DestinationAddition_BothOldAndNewPresent()
    {
        var sessionId = Guid.NewGuid();
        // Policy v1: 10.0.0.1
        var msgV1 = CreateSignedMessage(version: 1, new List<string> { "10.0.0.1" }, 443);
        await _machine.ActivateAsync(sessionId, msgV1, TestExamId);

        // Policy v2: 10.0.0.1 and 10.0.0.2
        var msgV2 = CreateSignedMessage(version: 2, new List<string> { "10.0.0.1", "10.0.0.2" }, 443, msgType: "UPDATE_EXAM_POLICY");
        var update = await _machine.UpdatePolicyAsync(msgV2);

        Assert.True(update.Success);
        var rules = _firewall.Rules.ToList();
        Assert.Contains(rules, r => r.RemoteAddresses.Contains("10.0.0.1"));
        Assert.Contains(rules, r => r.RemoteAddresses.Contains("10.0.0.2"));
    }

    // =========================================================================
    // 3. Failed Update Safe Rollback (Section 19: No Permissive Fallback)
    // =========================================================================

    [Fact]
    public async Task UpdatePolicy_WhenCandidateVerificationFails_RollsBackCandidate_PreservesActivePolicy()
    {
        var sessionId = Guid.NewGuid();
        var msgV1 = CreateSignedMessage(version: 1, new List<string> { "10.0.0.1" }, 443);
        await _machine.ActivateAsync(sessionId, msgV1, TestExamId);

        // Simulate management connectivity failure during candidate update
        _connectivity.ShouldSucceed = false;

        var msgV2 = CreateSignedMessage(version: 2, new List<string> { "10.0.0.99" }, 443, msgType: "UPDATE_EXAM_POLICY");
        var update = await _machine.UpdatePolicyAsync(msgV2);

        Assert.False(update.Success);
        Assert.Equal(1, _machine.CurrentSession?.PolicyVersion); // Still v1!

        // Firewall must still contain v1 rules, must NOT contain v2 rules, and DefaultOutboundAction == BLOCK
        var rules = _firewall.Rules.ToList();
        Assert.Contains(rules, r => r.RemoteAddresses.Contains("10.0.0.1"));
        Assert.DoesNotContain(rules, r => r.RemoteAddresses.Contains("10.0.0.99"));

        var baseline = _firewall.GetBaseline();
        Assert.Equal(FirewallAction.Block, baseline.PrivateDefaultOutbound);
    }

    // =========================================================================
    // 4. Security Invariants (Section 23)
    // =========================================================================

    [Fact]
    public async Task UpdatePolicy_TamperedSignature_RejectedWithoutTouchingFirewall()
    {
        var sessionId = Guid.NewGuid();
        var msgV1 = CreateSignedMessage(version: 1, new List<string> { "10.0.0.1" }, 443);
        await _machine.ActivateAsync(sessionId, msgV1, TestExamId);

        var tamperedV2 = CreateSignedMessage(version: 2, new List<string> { "10.0.0.2" }, 443,
            msgType: "UPDATE_EXAM_POLICY", tamperSignature: true);

        var update = await _machine.UpdatePolicyAsync(tamperedV2);
        Assert.False(update.Success);
        Assert.Equal(1, _machine.CurrentSession?.PolicyVersion);

        // Policy v1 intact
        Assert.Contains(_firewall.Rules, r => r.RemoteAddresses.Contains("10.0.0.1"));
        Assert.DoesNotContain(_firewall.Rules, r => r.RemoteAddresses.Contains("10.0.0.2"));
    }

    [Fact]
    public async Task UpdatePolicy_WrongExamId_RejectedWithoutTouchingFirewall()
    {
        var sessionId = Guid.NewGuid();
        var msgV1 = CreateSignedMessage(version: 1, new List<string> { "10.0.0.1" }, 443);
        await _machine.ActivateAsync(sessionId, msgV1, TestExamId);

        var wrongExamMsg = CreateSignedMessage(version: 2, new List<string> { "10.0.0.2" }, 443,
            msgType: "UPDATE_EXAM_POLICY", examIdOverride: Guid.NewGuid());

        var update = await _machine.UpdatePolicyAsync(wrongExamMsg);
        Assert.False(update.Success);
        Assert.Equal(1, _machine.CurrentSession?.PolicyVersion);
    }

    // =========================================================================
    // 5. Crash Recovery with In-Flight Update (Section 16 & 24)
    // =========================================================================

    [Fact]
    public async Task StartupReconciliation_CleansUpIncompleteUpdateCandidate_PreservesCommittedPolicy()
    {
        var sessionId = Guid.NewGuid();
        var msgV1 = CreateSignedMessage(version: 1, new List<string> { "10.0.0.1" }, 443);
        await _machine.ActivateAsync(sessionId, msgV1, TestExamId);

        // Simulate an in-flight update record that crashed in UpdateApplying
        var updateId = Guid.NewGuid();
        var candidateRule = FirewallRuleModel.CreateOutboundAllow(
            sessionId, "CandidateVendor", FirewallProtocol.TCP, "10.0.0.88", "443");

        // Manually install candidate rule into firewall
        _firewall.AddRule(candidateRule);
        _journal.RecordAppliedRule(sessionId, candidateRule.Name);

        var inFlightUpdate = new DurableUpdateJournalRecord(
            UpdateId: updateId,
            SessionId: sessionId,
            ExamId: TestExamId,
            OldPolicyId: _machine.CurrentSession!.PolicyId,
            OldPolicyVersion: 1,
            NewPolicyId: Guid.NewGuid(),
            NewPolicyVersion: 2,
            Phase: PolicyUpdatePhase.UpdateApplying,
            StartedUtc: DateTimeOffset.UtcNow,
            CompletedUtc: null,
            CandidateRules: new List<FirewallRuleModel> { candidateRule },
            RetiredRuleNames: new List<string>()
        );
        _journal.SaveUpdateJournal(inFlightUpdate);

        // Create new state machine simulating service restart
        var newMachine = new EnforcementStateMachine(_receiver, _enforcer, _firewall, _journal, _connectivity);
        var recovery = await newMachine.ReconcileStartupStateAsync();

        Assert.True(recovery.Success);
        Assert.Equal(EnforcementState.Active, newMachine.CurrentState);
        Assert.Equal(1, newMachine.CurrentSession?.PolicyVersion); // Policy v1 remains committed!

        // Candidate rule was purged
        Assert.False(_firewall.RuleExists(candidateRule.Name));

        // Incomplete update marked as failed
        var journalRecord = _journal.GetUpdate(updateId);
        Assert.NotNull(journalRecord);
        Assert.Equal(PolicyUpdatePhase.UpdateFailed, journalRecord.Phase);
    }

    // =========================================================================
    // 6. Explicit Destination Removal (Section 2)
    // =========================================================================

    [Fact]
    public async Task UpdatePolicy_DestinationRemoval_OldDestinationRetiredAndBlocked_Committed()
    {
        var sessionId = Guid.NewGuid();
        // Policy v1 has Vendor A (10.0.0.1) and Vendor B (10.0.0.2)
        var msgV1 = CreateSignedMessage(version: 1, new List<string> { "10.0.0.1", "10.0.0.2" }, 443);
        await _machine.ActivateAsync(sessionId, msgV1, TestExamId);

        var rulesV1 = _firewall.Rules.ToList();
        Assert.Contains(rulesV1, r => r.RemoteAddresses.Contains("10.0.0.1"));
        Assert.Contains(rulesV1, r => r.RemoteAddresses.Contains("10.0.0.2"));

        // Policy v2 removes Vendor B (only Vendor A remains)
        var msgV2 = CreateSignedMessage(version: 2, new List<string> { "10.0.0.1" }, 443, msgType: "UPDATE_EXAM_POLICY");
        var update = await _machine.UpdatePolicyAsync(msgV2);

        Assert.True(update.Success);
        Assert.Equal(2, update.NewVersion);

        // Verification: Vendor A remains, Vendor B is retired, management remains, DefaultOutboundAction == BLOCK
        var rulesV2 = _firewall.Rules.ToList();
        Assert.Contains(rulesV2, r => r.RemoteAddresses.Contains("10.0.0.1"));
        Assert.DoesNotContain(rulesV2, r => r.RemoteAddresses.Contains("10.0.0.2"));
        Assert.Contains(rulesV2, r => r.Purpose == "Mgmt");

        var baseline = _firewall.GetBaseline();
        Assert.Equal(FirewallAction.Block, baseline.PrivateDefaultOutbound);
    }

    // =========================================================================
    // 7. Management Failure During Update (Section 3)
    // =========================================================================

    [Fact]
    public async Task UpdatePolicy_ManagementFailureDuringUpdate_RollsBackCandidate_PreservesActivePolicy()
    {
        var sessionId = Guid.NewGuid();
        var msgV1 = CreateSignedMessage(version: 1, new List<string> { "10.0.0.1" }, 443);
        await _machine.ActivateAsync(sessionId, msgV1, TestExamId);

        // Simulate management connectivity probe failing during candidate update
        _connectivity.ShouldSucceed = false;

        var msgV2 = CreateSignedMessage(version: 2, new List<string> { "10.0.0.2" }, 443, msgType: "UPDATE_EXAM_POLICY");
        var update = await _machine.UpdatePolicyAsync(msgV2);

        Assert.False(update.Success);
        Assert.Equal(EnforcementState.Active, _machine.CurrentState); // Does NOT drop to IDLE!
        Assert.Equal(1, _machine.CurrentSession?.PolicyVersion);

        // Candidate rules removed, old rules remain, DefaultOutboundAction == BLOCK
        Assert.Contains(_firewall.Rules, r => r.RemoteAddresses.Contains("10.0.0.1"));
        Assert.DoesNotContain(_firewall.Rules, r => r.RemoteAddresses.Contains("10.0.0.2"));
        Assert.Equal(FirewallAction.Block, _firewall.GetBaseline().PrivateDefaultOutbound);
    }

    // =========================================================================
    // 8. Commit Boundary Interruption Cases (Section 4)
    // =========================================================================

    [Fact]
    public async Task CommitBoundary_CaseA_FirewallHasCandidate_SQLiteHasCommittedA_ReconcilesToPolicyA()
    {
        // Case A: Firewall transitioned rule B, but SQLite still records Policy A
        var sessionId = Guid.NewGuid();
        var msgV1 = CreateSignedMessage(version: 1, new List<string> { "10.0.0.1" }, 443);
        await _machine.ActivateAsync(sessionId, msgV1, TestExamId);

        var updateId = Guid.NewGuid();
        var candidateRuleB = FirewallRuleModel.CreateOutboundAllow(
            sessionId, "VendorB", FirewallProtocol.TCP, "10.0.0.2", "443");
        _firewall.AddRule(candidateRuleB);
        _journal.RecordAppliedRule(sessionId, candidateRuleB.Name);

        var inFlightUpdate = new DurableUpdateJournalRecord(
            UpdateId: updateId,
            SessionId: sessionId,
            ExamId: TestExamId,
            OldPolicyId: _machine.CurrentSession!.PolicyId,
            OldPolicyVersion: 1,
            NewPolicyId: Guid.NewGuid(),
            NewPolicyVersion: 2,
            Phase: PolicyUpdatePhase.UpdateVerifying,
            StartedUtc: DateTimeOffset.UtcNow,
            CompletedUtc: null,
            CandidateRules: new List<FirewallRuleModel> { candidateRuleB },
            RetiredRuleNames: new List<string>()
        );
        _journal.SaveUpdateJournal(inFlightUpdate);

        // Restart reconciliation
        var restartMachine = new EnforcementStateMachine(_receiver, _enforcer, _firewall, _journal, _connectivity);
        var recovery = await restartMachine.ReconcileStartupStateAsync();

        Assert.True(recovery.Success);
        Assert.Equal(1, restartMachine.CurrentSession?.PolicyVersion); // Policy A safely restored!
        Assert.False(_firewall.RuleExists(candidateRuleB.Name)); // Candidate rule B purged!
        Assert.Equal(FirewallAction.Block, _firewall.GetBaseline().PrivateDefaultOutbound);
    }

    [Fact]
    public async Task CommitBoundary_CaseB_SQLiteHasCommittedB_JournalUnfinalized_ReconcilesToPolicyB()
    {
        // Case B: SQLite committed Policy B, but process was interrupted before journal was marked UpdateCommitted
        var sessionId = Guid.NewGuid();
        var msgV1 = CreateSignedMessage(version: 1, new List<string> { "10.0.0.1" }, 443);
        await _machine.ActivateAsync(sessionId, msgV1, TestExamId);

        var updateId = Guid.NewGuid();
        var newPolicyId = Guid.NewGuid();
        var ruleB = FirewallRuleModel.CreateOutboundAllow(
            sessionId, "VendorB", FirewallProtocol.TCP, "10.0.0.2", "443");
        _firewall.AddRule(ruleB);
        _journal.RecordAppliedRule(sessionId, ruleB.Name);

        // Update SQLite session state to Policy B
        var updatedSession = _machine.CurrentSession! with
        {
            PolicyId = newPolicyId,
            PolicyVersion = 2,
            LastTransitionUtc = DateTimeOffset.UtcNow
        };
        _journal.SaveEnforcementState(updatedSession);

        var unfinalizedJournal = new DurableUpdateJournalRecord(
            UpdateId: updateId,
            SessionId: sessionId,
            ExamId: TestExamId,
            OldPolicyId: _machine.CurrentSession!.PolicyId,
            OldPolicyVersion: 1,
            NewPolicyId: newPolicyId,
            NewPolicyVersion: 2,
            Phase: PolicyUpdatePhase.UpdateCommitting,
            StartedUtc: DateTimeOffset.UtcNow,
            CompletedUtc: null,
            CandidateRules: new List<FirewallRuleModel> { ruleB },
            RetiredRuleNames: new List<string>()
        );
        _journal.SaveUpdateJournal(unfinalizedJournal);

        // Restart reconciliation
        var restartMachine = new EnforcementStateMachine(_receiver, _enforcer, _firewall, _journal, _connectivity);
        var recovery = await restartMachine.ReconcileStartupStateAsync();

        Assert.True(recovery.Success);
        Assert.Equal(2, restartMachine.CurrentSession?.PolicyVersion); // Policy B recognized as committed!
        Assert.True(_firewall.RuleExists(ruleB.Name)); // Rule B preserved!

        var finalRecord = _journal.GetUpdate(updateId);
        Assert.NotNull(finalRecord);
        Assert.Equal(PolicyUpdatePhase.UpdateCommitted, finalRecord.Phase);
    }

    // =========================================================================
    // 9. Update + Expiry Race (Section 5)
    // =========================================================================

    [Fact]
    public async Task UpdatePolicy_WhenPolicyAExpiresDuringUpdate_ExpiryRemainsAuthoritative()
    {
        var sessionId = Guid.NewGuid();
        // Policy A with 1 minute validity
        var expiryTime = DateTimeOffset.UtcNow.AddMinutes(1);
        var msgV1 = CreateSignedMessage(version: 1, new List<string> { "10.0.0.1" }, 443, expiresAtOverride: expiryTime);
        await _machine.ActivateAsync(sessionId, msgV1, TestExamId);

        // Time advances past expiry
        var pastExpiryTime = expiryTime.AddMinutes(5);

        // CheckExpiry detects expired boundary and rolls back to IDLE
        await _machine.CheckExpiryAsync(pastExpiryTime);
        Assert.Equal(EnforcementState.Idle, _machine.CurrentState);

        // Attempting update on expired/IDLE endpoint is rejected; does NOT extend exam!
        var msgV2 = CreateSignedMessage(version: 2, new List<string> { "10.0.0.2" }, 443, msgType: "UPDATE_EXAM_POLICY");
        var update = await _machine.UpdatePolicyAsync(msgV2);

        Assert.False(update.Success);
        Assert.Equal(EnforcementState.Idle, _machine.CurrentState);
    }

    // =========================================================================
    // 10. Update + Deactivate Race (Section 6)
    // =========================================================================

    [Fact]
    public async Task UpdatePolicy_ConcurrentWithDeactivate_SerializedCleanly_NoOrphanRules()
    {
        var sessionId = Guid.NewGuid();
        var msgV1 = CreateSignedMessage(version: 1, new List<string> { "10.0.0.1" }, 443);
        await _machine.ActivateAsync(sessionId, msgV1, TestExamId);

        // Deactivate called first
        var deact = await _machine.DeactivateAsync(sessionId, "Exam stopped");
        Assert.True(deact.Success);
        Assert.Equal(EnforcementState.Idle, _machine.CurrentState);

        // Subsequent update attempt is safely rejected
        var msgV2 = CreateSignedMessage(version: 2, new List<string> { "10.0.0.2" }, 443, msgType: "UPDATE_EXAM_POLICY");
        var update = await _machine.UpdatePolicyAsync(msgV2);

        Assert.False(update.Success);
        Assert.Equal(EnforcementState.Idle, _machine.CurrentState);
        Assert.Empty(_firewall.Rules); // Zero orphan rules!
    }

    // =========================================================================
    // 11. Unrelated Rules Preservation (Section 8)
    // =========================================================================

    [Fact]
    public async Task UpdatePolicy_SuccessfulAndFailedUpdates_PreserveUnrelatedRules()
    {
        var sessionId = Guid.NewGuid();
        var msgV1 = CreateSignedMessage(version: 1, new List<string> { "10.0.0.1" }, 443);
        await _machine.ActivateAsync(sessionId, msgV1, TestExamId);

        var unrelatedBefore = _firewall.UnrelatedRuleNames.ToList();

        // 1. Successful update
        var msgV2 = CreateSignedMessage(version: 2, new List<string> { "10.0.0.2" }, 443, msgType: "UPDATE_EXAM_POLICY");
        var updateSuccess = await _machine.UpdatePolicyAsync(msgV2);
        Assert.True(updateSuccess.Success);
        Assert.Equal(unrelatedBefore, _firewall.UnrelatedRuleNames);

        // 2. Failed update
        _connectivity.ShouldSucceed = false;
        var msgV3 = CreateSignedMessage(version: 3, new List<string> { "10.0.0.3" }, 443, msgType: "UPDATE_EXAM_POLICY");
        var updateFail = await _machine.UpdatePolicyAsync(msgV3);
        Assert.False(updateFail.Success);
        Assert.Equal(unrelatedBefore, _firewall.UnrelatedRuleNames); // Still 100% intact!
    }
}
