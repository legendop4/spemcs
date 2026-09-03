using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Spemcs.Agent.Core.Network;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class EnforcementStateMachineUnitTests : IDisposable
{
    private readonly string _tempDbPath;
    private readonly SqliteRollbackJournal _journal;
    private readonly TrustedKeyStore _keyStore;
    private readonly MockManagementConnectivityVerifier _connectivity;
    private readonly PolicyReceiver _receiver;
    private readonly MockFirewallAdapter _firewall;
    private readonly NetworkEnforcer _enforcer;
    private readonly EnforcementStateMachine _machine;

    private const string PythonPublicKeyPem = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzJ6JteFg33KWaPABNb3/
f0jwRyJJL1jcwxMemlyUfMrH1W/rczxVw2dCJ0ou318qPYBtTMumzuGmASlZnpMw
VgjTIdS6EMyxX2fhFHf8CyCw1DRuKARKEXBA44dCu/umKhYTLCDQQ20Z3G2ApPGL
1tP5qPhIAFIafu1duWa7BIYT+17TofFjN4Zb1rvwA60mmqIdjMXbZbONrqnMDIK7
m6GErjzhnJNoxXyuIKJ/A99dJHTLCRr/SG59p/UgKG+VBpwdfrPUFJlEOXbiYi3y
fqRMwZnP7hsEKQQT42YZ6W1A8ySqrcfPmw+3hQZiCBIP0wL0mF3I7G3XLIYEv5qJ
NwIDAQAB
-----END PUBLIC KEY-----
";

    private const string PythonRawJson = "{\"allowed_destinations\":[{\"domains\":[\"test.example.com\"],\"ip_ranges\":[\"192.168.1.0/24\"],\"name\":\"TestVendor\",\"tcp_ports\":[443],\"udp_ports\":[]}],\"exam_id\":\"11111111-2222-3333-4444-555555555555\",\"expires_at\":\"2030-01-01T00:00:00Z\",\"key_id\":\"dev-key-1\",\"management_server\":{\"ip_addresses\":[\"127.0.0.1\"],\"port\":8000},\"not_before\":\"2026-01-01T00:00:00Z\",\"policy_id\":\"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\",\"schema_version\":\"1.0\",\"vendor_profile_id\":null,\"version\":1}";
    private const string PythonSignatureBase64 = "hSuzYgf7vtIpk8uE7HwtPlP3j/jd+Xi67HHEBVxnxE1t6DJ5qLzWIE92gcCVdyXUhkwpcNa/DjtPYfhU584F3C/MZGB9nxyPCxCEbVAQokhjndaGYhDbsKsmRLPm7d5MIRXcqgvWzYuyGEmJvcc7PIjVRb0OqqtQxMClALOaz4aW/Ht9DWTZr/YgGdOHEVRIpyyhByTs0+xNSKDKTX+8J4QUGj4Di093lzBN8hie7KIPL8WmwXtT1h5KO4ZpyTLekgL/70loJ11maEpd3vCnyAlHjJ0aUKMGj3vwQcq3gQ4WppBNQcLpO0ihQizZ7DfGXxPDO93HBpv0HUBNsfXsIQ==";
    private static readonly Guid PythonExamId = Guid.Parse("11111111-2222-3333-4444-555555555555");
    private static readonly DateTimeOffset ValidEvalTime = new(2026, 9, 3, 12, 0, 0, TimeSpan.Zero);

    public EnforcementStateMachineUnitTests()
    {
        _tempDbPath = Path.Combine(Path.GetTempPath(), $"spemcs_m6_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDbPath);
        _journal = new SqliteRollbackJournal(_tempDbPath);
        _keyStore = new TrustedKeyStore();
        _connectivity = new MockManagementConnectivityVerifier(shouldSucceed: true);
        _receiver = new PolicyReceiver(_keyStore, _journal, _connectivity);
        _firewall = new MockFirewallAdapter();
        _enforcer = new NetworkEnforcer(_firewall, _journal);
        _machine = new EnforcementStateMachine(_receiver, _enforcer, _firewall, _journal, _connectivity);

        _keyStore.RegisterPublicKeyPem("dev-key-1", PythonPublicKeyPem);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDbPath))
                Directory.Delete(_tempDbPath, true);
        }
        catch { }
    }

    private SignedPolicyMessage CreateValidMessage() => new(
        MessageType: "SIGNED_NETWORK_POLICY",
        ProtocolVersion: 1,
        RawPolicyJson: PythonRawJson,
        SignatureBase64: PythonSignatureBase64
    );

    // =========================================================================
    // 1. Happy Path: Activation -> Enforcement -> Deactivation (Section 5, 14)
    // =========================================================================

    [Fact]
    public async Task HappyPath_ActivationReachesActive_ThenDeactivatesToIdle()
    {
        var sessionId = Guid.NewGuid();
        var msg = CreateValidMessage();

        // 1. Activate
        var actResult = await _machine.ActivateAsync(sessionId, msg, PythonExamId, FirewallProfiles.Private | FirewallProfiles.Public, ValidEvalTime);

        Assert.True(actResult.Success);
        Assert.Equal(EnforcementState.Active, actResult.State);
        Assert.Equal(EnforcementState.Active, _machine.CurrentState);
        Assert.NotNull(_machine.CurrentSession);
        Assert.Equal(sessionId, _machine.CurrentSession.SessionId);

        // Verify Firewall state: default outbound is BLOCK and rules were added
        var baseline = _firewall.GetBaseline();
        Assert.Equal(FirewallAction.Block, baseline.PrivateDefaultOutbound);
        Assert.Equal(FirewallAction.Block, baseline.PublicDefaultOutbound);
        Assert.NotEmpty(_firewall.Rules);

        // Verify durable journal record
        var record = _journal.GetEnforcementState(sessionId);
        Assert.NotNull(record);
        Assert.Equal(EnforcementState.Active, record.State);

        // 2. Deactivate
        var deactResult = await _machine.DeactivateAsync(sessionId, "Exam completed");
        Assert.True(deactResult.Success);
        Assert.Equal(EnforcementState.Idle, deactResult.State);
        Assert.Equal(EnforcementState.Idle, _machine.CurrentState);

        // Verify firewall restored to ALLOW and rules removed
        var restoredBaseline = _firewall.GetBaseline();
        Assert.Equal(FirewallAction.Allow, restoredBaseline.PrivateDefaultOutbound);
        Assert.Equal(FirewallAction.Allow, restoredBaseline.PublicDefaultOutbound);
        Assert.Empty(_firewall.Rules);
    }

    // =========================================================================
    // 2. Policy Failure Preconditions (Section 4 & 6: Fail-Safe)
    // =========================================================================

    [Fact]
    public async Task InvalidSignature_AbortsActivation_WithoutTouchingFirewall()
    {
        var sessionId = Guid.NewGuid();
        var tamperedMsg = new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: PythonRawJson.Replace("192.168.1.0/24", "192.168.99.0/24"), // tampered
            SignatureBase64: PythonSignatureBase64
        );

        var result = await _machine.ActivateAsync(sessionId, tamperedMsg, PythonExamId, currentTimeUtc: ValidEvalTime);

        Assert.False(result.Success);
        Assert.Equal(EnforcementState.Failed, result.State);
        Assert.Equal(EnforcementState.Failed, _machine.CurrentState);

        // Verify ZERO firewall mutations
        Assert.Empty(_firewall.Rules);
        var baseline = _firewall.GetBaseline();
        Assert.Equal(FirewallAction.Allow, baseline.PrivateDefaultOutbound);
    }

    [Fact]
    public async Task ExpiredPolicy_AbortsActivation_WithoutTouchingFirewall()
    {
        var sessionId = Guid.NewGuid();
        var msg = CreateValidMessage();
        var expiredTime = new DateTimeOffset(2035, 1, 1, 0, 0, 0, TimeSpan.Zero); // Expired

        var result = await _machine.ActivateAsync(sessionId, msg, PythonExamId, currentTimeUtc: expiredTime);

        Assert.False(result.Success);
        Assert.Equal(EnforcementState.Failed, result.State);
        Assert.Empty(_firewall.Rules);
    }

    [Fact]
    public async Task UnreachableManagement_AbortsActivation_WithoutTouchingFirewall()
    {
        var sessionId = Guid.NewGuid();
        var msg = CreateValidMessage();

        _connectivity.ShouldSucceed = false; // Management is down

        var result = await _machine.ActivateAsync(sessionId, msg, PythonExamId, currentTimeUtc: ValidEvalTime);

        Assert.False(result.Success);
        Assert.Equal(EnforcementState.Failed, result.State);
        Assert.Empty(_firewall.Rules);
    }

    // =========================================================================
    // 3. Duplicate and Conflicting Activation (Section 13)
    // =========================================================================

    [Fact]
    public async Task DuplicateActivation_IsIdempotent_WithoutDuplicateRules()
    {
        var sessionId = Guid.NewGuid();
        var msg = CreateValidMessage();

        var first = await _machine.ActivateAsync(sessionId, msg, PythonExamId, currentTimeUtc: ValidEvalTime);
        Assert.True(first.Success);
        var initialRuleCount = _firewall.Rules.Count;

        // Duplicate call with same session ID
        var second = await _machine.ActivateAsync(sessionId, msg, PythonExamId, currentTimeUtc: ValidEvalTime);
        Assert.True(second.Success);
        Assert.Equal(EnforcementState.Active, second.State);
        Assert.Equal(initialRuleCount, _firewall.Rules.Count); // No duplicate rules
    }

    [Fact]
    public async Task ConflictingSession_WhileActive_IsRejected()
    {
        var session1 = Guid.NewGuid();
        var session2 = Guid.NewGuid();
        var msg = CreateValidMessage();

        var first = await _machine.ActivateAsync(session1, msg, PythonExamId, currentTimeUtc: ValidEvalTime);
        Assert.True(first.Success);

        // Attempt second different session while session1 is ACTIVE
        var second = await _machine.ActivateAsync(session2, msg, PythonExamId, currentTimeUtc: ValidEvalTime);
        Assert.False(second.Success);
        Assert.Contains("already active", second.FailureReason);
        Assert.Equal(session1, _machine.CurrentSession?.SessionId);
    }

    // =========================================================================
    // 4. Policy Signed Expiry (Section 11)
    // =========================================================================

    [Fact]
    public async Task PolicyExpiry_AutomaticallyRollsBack_WhenExpiryTimeReached()
    {
        var sessionId = Guid.NewGuid();
        var msg = CreateValidMessage();

        var actResult = await _machine.ActivateAsync(sessionId, msg, PythonExamId, currentTimeUtc: ValidEvalTime);
        Assert.True(actResult.Success);
        Assert.NotEmpty(_firewall.Rules);

        // Simulate clock advancing past expires_at (2030-01-01)
        var futureTime = new DateTimeOffset(2030, 1, 2, 0, 0, 0, TimeSpan.Zero);
        await _machine.CheckExpiryAsync(futureTime);

        // Verify state transitioned to IDLE and firewall rules cleaned up
        Assert.Equal(EnforcementState.Idle, _machine.CurrentState);
        Assert.Empty(_firewall.Rules);
        var baseline = _firewall.GetBaseline();
        Assert.Equal(FirewallAction.Allow, baseline.PrivateDefaultOutbound);
    }

    // =========================================================================
    // 5. Startup Crash Reconciliation (Section 12, 21)
    // =========================================================================

    [Fact]
    public async Task StartupReconciliation_RollsBackIncompleteSession()
    {
        var sessionId = Guid.NewGuid();
        // Record a session that crashed while in ApplyingRules
        var record = new DurableEnforcementRecord(
            SessionId: sessionId,
            ExamId: PythonExamId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            State: EnforcementState.ApplyingRules,
            ActivationUtc: DateTimeOffset.UtcNow,
            ExpiresAtUtc: DateTimeOffset.UtcNow.AddHours(2),
            LastTransitionUtc: DateTimeOffset.UtcNow,
            FailureReason: null
        );
        _journal.SaveEnforcementState(record);

        // Simulate crash recovery on new service instance
        var newMachine = new EnforcementStateMachine(_receiver, _enforcer, _firewall, _journal, _connectivity);
        var recovery = await newMachine.ReconcileStartupStateAsync();

        Assert.True(recovery.Success);
        Assert.Equal(sessionId, recovery.RecoveredSessionId);
        Assert.Equal(EnforcementState.Idle, newMachine.CurrentState);

        var updatedRecord = _journal.GetEnforcementState(sessionId);
        Assert.NotNull(updatedRecord);
        Assert.Equal(EnforcementState.RolledBack, updatedRecord.State);
    }

    [Fact]
    public async Task StartupReconciliation_CleansUpSessionExpiredWhileOffline()
    {
        var sessionId = Guid.NewGuid();
        // Record a session that was Active but expired while PC was powered down
        var record = new DurableEnforcementRecord(
            SessionId: sessionId,
            ExamId: PythonExamId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            State: EnforcementState.Active,
            ActivationUtc: DateTimeOffset.UtcNow.AddDays(-2),
            ExpiresAtUtc: DateTimeOffset.UtcNow.AddDays(-1), // Expired yesterday
            LastTransitionUtc: DateTimeOffset.UtcNow.AddDays(-2)
        );
        _journal.SaveEnforcementState(record);

        var newMachine = new EnforcementStateMachine(_receiver, _enforcer, _firewall, _journal, _connectivity);
        var recovery = await newMachine.ReconcileStartupStateAsync();

        Assert.True(recovery.Success);
        Assert.Equal(EnforcementState.Idle, newMachine.CurrentState);
    }
}
