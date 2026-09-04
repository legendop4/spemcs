using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Spemcs.Agent.Core;
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
    private readonly StubBrowserExecutableResolver _browserResolver;
    private readonly EnforcementStateMachine _machine;

    // Cross-language interop payloads (Python signer -> C# verifier) live in one place so the
    // two test classes that consume them cannot drift apart. See PythonInteropFixtures.
    private static readonly Guid PythonExamId = PythonInteropFixtures.ExamId;
    private static readonly DateTimeOffset ValidEvalTime = PythonInteropFixtures.ValidEvalTime;

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
        _browserResolver = StubBrowserExecutableResolver.Succeeding();
        _machine = new EnforcementStateMachine(
            _receiver, _enforcer, _firewall, _journal, _connectivity,
            browserResolver: _browserResolver);

        _keyStore.RegisterPublicKeyPem(
            PythonInteropFixtures.KeyId, PythonInteropFixtures.PublicKeyPem);
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

    private static SignedPolicyMessage CreateValidMessage() => PythonInteropFixtures.ValidMessage();

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
            RawPolicyJson: PythonInteropFixtures.ValidRawJson.Replace("192.168.1.0/24", "192.168.99.0/24"), // tampered
            SignatureBase64: PythonInteropFixtures.ValidSignatureBase64
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
        var newMachine = new EnforcementStateMachine(
            _receiver, _enforcer, _firewall, _journal, _connectivity,
            browserResolver: StubBrowserExecutableResolver.Succeeding());
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

        var newMachine = new EnforcementStateMachine(
            _receiver, _enforcer, _firewall, _journal, _connectivity,
            browserResolver: StubBrowserExecutableResolver.Succeeding());
        var recovery = await newMachine.ReconcileStartupStateAsync();

        Assert.True(recovery.Success);
        Assert.Equal(EnforcementState.Idle, newMachine.CurrentState);
    }

    // =========================================================================
    // 6. Requirements 4 & 5: vendor allow rules are scoped to the approved browser
    //    named in the SIGNED policy, and nothing else can reach the allowlist.
    // =========================================================================

    [Fact]
    public async Task PythonSignedPolicy_ScopesEveryVendorRuleToTheApprovedBrowser()
    {
        var sessionId = Guid.NewGuid();

        var actResult = await _machine.ActivateAsync(
            sessionId, CreateValidMessage(), PythonExamId,
            FirewallProfiles.Private, ValidEvalTime);

        Assert.True(actResult.Success, actResult.FailureReason ?? "activation failed");

        // The signed payload says "chrome" - the state machine must have asked for exactly that,
        // rather than falling back to a hardcoded default. Compared with lifted equality so the
        // nullable "never asked at all" case fails loudly rather than being coerced.
        Assert.True(
            _browserResolver.LastRequestedFamily == ApprovedBrowserFamily.Chrome,
            $"expected the SIGNED browser family Chrome, got {_browserResolver.LastRequestedFamily}");
        Assert.Equal(1, _browserResolver.ResolveCallCount);

        var vendorRules = _firewall.Rules
            .Where(r => !r.Purpose.StartsWith("Loopback", StringComparison.OrdinalIgnoreCase)
                     && !r.Purpose.StartsWith("Mgmt", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.NotEmpty(vendorRules);

        // Requirement 4: no destination allow rule may be program-unscoped.
        // Requirement 5: the program must be the approved browser, so curl.exe / python.exe
        // inherit nothing from the allowlist.
        Assert.All(vendorRules, r => Assert.Equal(
            StubBrowserExecutableResolver.DefaultChromePath, r.ApplicationPath));

        // Requirement 10: SPEMCS only ever installs ALLOW rules; default-deny comes from
        // DefaultOutboundAction, never from a blanket explicit BLOCK rule.
        Assert.All(_firewall.Rules, r => Assert.Equal(FirewallAction.Allow, r.Action));
        Assert.Equal(FirewallAction.Block, _firewall.GetBaseline().PrivateDefaultOutbound);
    }

    [Fact]
    public async Task LegacySchema10Policy_RejectedFailClosed_DespiteValidSignature()
    {
        var sessionId = Guid.NewGuid();

        // This payload is correctly signed by a trusted key. It is refused purely because it
        // predates the mandatory approved_browser field - accepting it would mean installing a
        // vendor allow rule with no program scope at all.
        var legacyMsg = PythonInteropFixtures.LegacySchema10Message();

        var validation = await _receiver.ProcessPolicyMessageAsync(legacyMsg, PythonExamId, ValidEvalTime);
        Assert.NotEqual(PolicyAcceptanceStatus.Accepted, validation.Status);
        Assert.True(
            validation.Status is PolicyAcceptanceStatus.MissingFields
                              or PolicyAcceptanceStatus.UnsupportedSchema,
            $"expected a schema/mandatory-field rejection, got {validation.Status}: {validation.Details}");

        // And the state machine must leave the firewall completely untouched.
        var result = await _machine.ActivateAsync(sessionId, legacyMsg, PythonExamId, currentTimeUtc: ValidEvalTime);

        Assert.False(result.Success);
        Assert.Equal(EnforcementState.Failed, result.State);
        Assert.Empty(_firewall.Rules);
        Assert.Equal(FirewallAction.Allow, _firewall.GetBaseline().PrivateDefaultOutbound);
    }

    [Fact]
    public async Task UnscopableApprovedBrowser_RejectedAfterSignatureVerifies_FirewallUntouched()
    {
        var sessionId = Guid.NewGuid();

        var msg = PythonInteropFixtures.UnscopableBrowserMessage();

        var validation = await _receiver.ProcessPolicyMessageAsync(msg, PythonExamId, ValidEvalTime);

        // UnsupportedApprovedBrowser - NOT InvalidSignature. The distinction matters: it proves
        // the signature verified and the policy was then refused on its own terms, so a valid
        // signature is never sufficient to obtain a firewall rule the agent cannot scope.
        Assert.Equal(PolicyAcceptanceStatus.UnsupportedApprovedBrowser, validation.Status);

        var result = await _machine.ActivateAsync(sessionId, msg, PythonExamId, currentTimeUtc: ValidEvalTime);

        Assert.False(result.Success);
        Assert.Equal(EnforcementState.Failed, result.State);
        Assert.Empty(_firewall.Rules);
        Assert.Equal(FirewallAction.Allow, _firewall.GetBaseline().PrivateDefaultOutbound);
    }

    [Fact]
    public async Task ActivationAbortsWithoutTouchingFirewall_WhenNoTrustedBrowserIsInstalled()
    {
        // A machine where the approved browser is absent or fails Authenticode. Resolution
        // happens before any durable record or firewall mutation, so there is nothing to roll
        // back - the candidate keeps normal connectivity instead of being stranded.
        var failingResolver = StubBrowserExecutableResolver.Failing();
        var machine = new EnforcementStateMachine(
            _receiver, _enforcer, _firewall, _journal, _connectivity,
            browserResolver: failingResolver);

        var result = await machine.ActivateAsync(
            Guid.NewGuid(), CreateValidMessage(), PythonExamId,
            FirewallProfiles.Private, ValidEvalTime);

        Assert.False(result.Success);
        Assert.Equal(EnforcementState.Failed, result.State);
        Assert.Contains("could not be resolved", result.FailureReason);
        Assert.Empty(_firewall.Rules);
        Assert.Equal(FirewallAction.Allow, _firewall.GetBaseline().PrivateDefaultOutbound);
        Assert.Equal(FirewallAction.Allow, _firewall.GetBaseline().PublicDefaultOutbound);
        Assert.Equal(FirewallAction.Allow, _firewall.GetBaseline().DomainDefaultOutbound);
    }
}
