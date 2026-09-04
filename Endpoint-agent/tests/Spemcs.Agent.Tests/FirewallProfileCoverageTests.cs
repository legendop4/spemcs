using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Spemcs.Agent.Core.Network;
using Xunit;

namespace Spemcs.Agent.Tests;

/// <summary>
/// Requirement 6: the lockdown must cover the Domain, Private AND Public firewall profiles.
/// </summary>
/// <remarks>
/// <para>
/// The bug these tests exist to prevent was not a crash - it was a silent no-op. The wire default
/// for the target profile mask was <c>6</c> (Private|Public), which omits Domain. A university lab
/// PC is domain-joined, so Domain is the profile it actually runs under: SPEMCS reported a
/// successful lockdown, installed its allow rules against two profiles nobody was using, and left
/// the live profile's <c>DefaultOutboundAction</c> at ALLOW. The candidate had unrestricted internet
/// access for the whole exam and nothing in the logs said so.
/// </para>
/// <para>
/// Three separate defects made that possible, and each has its own section below: the default value
/// itself, the fact that the mask arrives unauthenticated from the control pipe, and readback checks
/// that OR-ed Private and Public together so one BLOCK profile vouched for the rest.
/// </para>
/// </remarks>
public sealed class FirewallProfileCoverageTests : IDisposable
{
    private readonly string _tempDbPath;
    private readonly SqliteRollbackJournal _journal;
    private readonly TrustedKeyStore _keyStore;
    private readonly MockManagementConnectivityVerifier _connectivity;
    private readonly PolicyReceiver _receiver;
    private readonly MockFirewallAdapter _firewall;
    private readonly NetworkEnforcer _enforcer;
    private readonly EnforcementStateMachine _machine;

    public FirewallProfileCoverageTests()
    {
        _tempDbPath = Path.Combine(Path.GetTempPath(), $"spemcs_req6_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDbPath);
        _journal = new SqliteRollbackJournal(_tempDbPath);
        _keyStore = new TrustedKeyStore();
        _connectivity = new MockManagementConnectivityVerifier(shouldSucceed: true);
        _receiver = new PolicyReceiver(_keyStore, _journal, _connectivity);
        _firewall = new MockFirewallAdapter();
        _enforcer = new NetworkEnforcer(_firewall, _journal);
        _machine = NewMachine();

        _keyStore.RegisterPublicKeyPem(PythonInteropFixtures.KeyId, PythonInteropFixtures.PublicKeyPem);
    }

    /// <summary>A state machine over the SAME journal and firewall: models a service restart.</summary>
    private EnforcementStateMachine NewMachine() => new(
        _receiver, _enforcer, _firewall, _journal, _connectivity,
        browserResolver: StubBrowserExecutableResolver.Succeeding());

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDbPath)) Directory.Delete(_tempDbPath, true);
        }
        catch { }
    }

    // =========================================================================
    // 1. The untrusted wire value cannot narrow the profile set
    // =========================================================================
    // The mask is NOT inside the signed policy bytes, and the control pipe is writable by any
    // authenticated user, so it is attacker-controlled input on a machine where the attacker is the
    // candidate. Requirement 6 removes the need to trust it: all three profiles are always in scope,
    // so the field carries no legitimate variation and any other value is normalized upward.

    [Fact]
    public void The_complete_profile_mask_is_accepted_without_complaint()
    {
        var result = FirewallProfileSet.FromUntrustedWireValue((int)FirewallProfiles.All, out var anomaly);

        Assert.Equal(FirewallProfiles.All, result);
        Assert.Null(anomaly);
    }

    [Fact]
    public void The_legacy_default_of_six_is_widened_and_names_the_missing_domain_profile()
    {
        // 6 is the specific historical value; it deserves its own named test rather than being one
        // row of a theory, because the whole class of bug is traceable to it.
        var result = FirewallProfileSet.FromUntrustedWireValue(6, out var anomaly);

        Assert.Equal(FirewallProfiles.All, result);
        Assert.NotNull(anomaly);
        Assert.Contains("Domain", anomaly);
    }

    [Theory]
    [InlineData(0)]   // None: would lock down nothing at all
    [InlineData(1)]   // Domain only
    [InlineData(2)]   // Private only
    [InlineData(3)]
    [InlineData(4)]   // Public only
    [InlineData(5)]
    [InlineData(6)]   // the legacy default
    public void Any_incomplete_profile_mask_is_widened_to_all_and_reported(int wireValue)
    {
        var result = FirewallProfileSet.FromUntrustedWireValue(wireValue, out var anomaly);

        Assert.Equal(FirewallProfiles.All, result);
        Assert.NotNull(anomaly);
    }

    [Theory]
    [InlineData(8)]           // a bit Windows has no profile for
    [InlineData(255)]
    [InlineData(int.MaxValue)]
    [InlineData(-1)]          // all bits set, including the sign bit
    [InlineData(int.MinValue)]
    public void Undefined_profile_bits_are_discarded_rather_than_cast_through(int wireValue)
    {
        var result = FirewallProfileSet.FromUntrustedWireValue(wireValue, out var anomaly);

        // A raw cast would have produced a FirewallProfiles value with meaningless bits set, which
        // then flows into HasFlag checks, the journal, and rollback scoping.
        Assert.Equal(FirewallProfiles.All, result);
        Assert.NotNull(anomaly);
        Assert.Contains("no Windows firewall profile", anomaly);
    }

    [Fact]
    public void Normalization_never_returns_a_set_missing_any_profile()
    {
        // Exhaustive over every value the field can hold in one byte, plus the extremes. The point
        // is the absence of an escape hatch: there is no input that yields a narrower set.
        var probes = Enumerable.Range(-1, 260).Append(int.MinValue).Append(int.MaxValue);

        foreach (var wireValue in probes)
        {
            var result = FirewallProfileSet.FromUntrustedWireValue(wireValue, out _);

            Assert.True(result.HasFlag(FirewallProfiles.Domain), $"Domain missing for {wireValue}");
            Assert.True(result.HasFlag(FirewallProfiles.Private), $"Private missing for {wireValue}");
            Assert.True(result.HasFlag(FirewallProfiles.Public), $"Public missing for {wireValue}");
        }
    }

    // =========================================================================
    // 2. Activation actually reaches all three profiles
    // =========================================================================

    [Fact]
    public async Task Activation_blocks_outbound_on_every_profile_and_scopes_rules_to_all_three()
    {
        var sessionId = Guid.NewGuid();

        var result = await _machine.ActivateAsync(
            sessionId, PythonInteropFixtures.ValidMessage(), PythonInteropFixtures.ExamId,
            FirewallProfiles.All, PythonInteropFixtures.ValidEvalTime);

        Assert.True(result.Success, result.FailureReason);

        // Requirement 1 + 6 together: default-deny, on every profile.
        var baseline = _firewall.GetBaseline();
        Assert.Equal(FirewallAction.Block, baseline.DomainDefaultOutbound);
        Assert.Equal(FirewallAction.Block, baseline.PrivateDefaultOutbound);
        Assert.Equal(FirewallAction.Block, baseline.PublicDefaultOutbound);

        // Blocking every profile while scoping the allow rules to only some would lock the candidate
        // out of the exam itself, so the rules must carry the same profile set.
        var sessionRules = _firewall.Rules.Where(r => r.SessionId == sessionId).ToList();
        Assert.NotEmpty(sessionRules);
        foreach (var rule in sessionRules)
        {
            Assert.True(rule.Profiles.HasFlag(FirewallProfiles.Domain), $"{rule.Name} omits Domain");
            Assert.True(rule.Profiles.HasFlag(FirewallProfiles.Private), $"{rule.Name} omits Private");
            Assert.True(rule.Profiles.HasFlag(FirewallProfiles.Public), $"{rule.Name} omits Public");
        }

        // The mask must be durable: rollback and any later update read it back from here, so a
        // session that is not recorded as All would restore or re-scope the wrong profiles.
        Assert.Equal(FirewallProfiles.All, _journal.GetSession(sessionId)?.TargetProfiles);
    }

    [Fact]
    public async Task Deactivation_restores_the_baseline_on_every_profile()
    {
        var sessionId = Guid.NewGuid();
        await _machine.ActivateAsync(
            sessionId, PythonInteropFixtures.ValidMessage(), PythonInteropFixtures.ExamId,
            FirewallProfiles.All, PythonInteropFixtures.ValidEvalTime);

        var deact = await _machine.DeactivateAsync(sessionId, "Exam completed");

        Assert.True(deact.Success);

        // Requirement 9: the pre-exam baseline was ALLOW on all three (MockFirewallAdapter's
        // defaults). Leaving Domain on BLOCK would strand a domain-joined machine offline after the
        // exam - the most visible possible rollback failure.
        var baseline = _firewall.GetBaseline();
        Assert.Equal(FirewallAction.Allow, baseline.DomainDefaultOutbound);
        Assert.Equal(FirewallAction.Allow, baseline.PrivateDefaultOutbound);
        Assert.Equal(FirewallAction.Allow, baseline.PublicDefaultOutbound);
    }

    [Fact]
    public async Task A_profile_that_refuses_to_hold_block_fails_the_activation()
    {
        // Models a GPO that re-asserts its own outbound default on the Domain profile. The COM call
        // does not throw; the profile simply does not change. Reporting success here is the failure
        // mode that matters, because it produces an exam that everyone believes is locked down.
        _firewall.ProfilesIgnoringBlock = FirewallProfiles.Domain;
        var sessionId = Guid.NewGuid();

        var result = await _machine.ActivateAsync(
            sessionId, PythonInteropFixtures.ValidMessage(), PythonInteropFixtures.ExamId,
            FirewallProfiles.All, PythonInteropFixtures.ValidEvalTime);

        Assert.False(result.Success);
        Assert.NotEqual(EnforcementState.Active, result.State);
        Assert.Equal(FirewallAction.Allow, _firewall.GetBaseline().DomainDefaultOutbound);

        // Fail-closed must also mean fail-clean: a half-applied lockdown left behind would deny the
        // candidate's traffic on the profiles that DID take, with no session owning the rules.
        Assert.DoesNotContain(_firewall.Rules, r => r.SessionId == sessionId);
    }

    [Fact]
    public async Task A_profile_outside_the_target_set_is_not_required_to_be_blocking()
    {
        // The mirror image of the previous test, and the reason the check is HasFlag-based rather
        // than a blanket "all three must be BLOCK". Without this case, a stricter implementation
        // could pass every other test in this file by simply demanding BLOCK everywhere, which would
        // break the narrower profile sets the unit tests and integration tests legitimately use.
        _firewall.ProfilesIgnoringBlock = FirewallProfiles.Domain;
        var sessionId = Guid.NewGuid();

        var result = await _machine.ActivateAsync(
            sessionId, PythonInteropFixtures.ValidMessage(), PythonInteropFixtures.ExamId,
            FirewallProfiles.Private | FirewallProfiles.Public, PythonInteropFixtures.ValidEvalTime);

        Assert.True(result.Success, result.FailureReason);
        Assert.Equal(FirewallAction.Block, _firewall.GetBaseline().PrivateDefaultOutbound);
        Assert.Equal(FirewallAction.Block, _firewall.GetBaseline().PublicDefaultOutbound);
    }

    // =========================================================================
    // 3. Startup reconciliation honours the whole profile set
    // =========================================================================
    // The readback here used to be `Private == Block || Public == Block`. Because it was an OR, a
    // single BLOCK profile vouched for the others, and because Domain was absent, the profile most
    // likely to be in use was never consulted at all.

    [Fact]
    public async Task Restart_records_a_conflict_when_the_domain_profile_stopped_blocking()
    {
        var sessionId = Guid.NewGuid();
        var activation = await _machine.ActivateAsync(
            sessionId, PythonInteropFixtures.ValidMessage(), PythonInteropFixtures.ExamId,
            FirewallProfiles.All, PythonInteropFixtures.ValidEvalTime);
        Assert.True(activation.Success, activation.FailureReason);

        // A GPO refresh reverted Domain while the service was down. Private and Public are still
        // BLOCK, which is exactly the state the old OR-based check reported as healthy.
        _firewall.DomainDefaultOutbound = FirewallAction.Allow;

        var restarted = NewMachine();
        var recovery = await restarted.ReconcileStartupStateAsync();

        Assert.True(recovery.ConflictDetected);
        Assert.Equal(EnforcementState.Conflict, restarted.CurrentState);
        Assert.Equal(sessionId, recovery.RecoveredSessionId);

        var record = _journal.GetEnforcementState(sessionId);
        Assert.NotNull(record);
        Assert.Equal(EnforcementState.Conflict, record.State);
    }

    [Fact]
    public async Task Restart_records_a_conflict_when_only_one_profile_is_still_blocking()
    {
        // The OR also meant that Private alone holding BLOCK excused Public. Two profiles wide open
        // was indistinguishable from a healthy lockdown.
        var sessionId = Guid.NewGuid();
        await _machine.ActivateAsync(
            sessionId, PythonInteropFixtures.ValidMessage(), PythonInteropFixtures.ExamId,
            FirewallProfiles.All, PythonInteropFixtures.ValidEvalTime);

        _firewall.DomainDefaultOutbound = FirewallAction.Allow;
        _firewall.PublicDefaultOutbound = FirewallAction.Allow;

        var recovery = await NewMachine().ReconcileStartupStateAsync();

        Assert.True(recovery.ConflictDetected);
    }

    [Fact]
    public async Task Restart_resumes_a_healthy_session_untouched()
    {
        // The stricter check must not turn every restart into a conflict: an exam in progress that
        // is genuinely still enforced has to survive a service restart (requirement: never destroy a
        // valid running exam).
        var sessionId = Guid.NewGuid();
        await _machine.ActivateAsync(
            sessionId, PythonInteropFixtures.ValidMessage(), PythonInteropFixtures.ExamId,
            FirewallProfiles.All, PythonInteropFixtures.ValidEvalTime);

        var restarted = NewMachine();
        var recovery = await restarted.ReconcileStartupStateAsync();

        Assert.False(recovery.ConflictDetected);
        Assert.False(recovery.RecoveryRequired);
        Assert.Equal(EnforcementState.Active, restarted.CurrentState);
        Assert.Equal(sessionId, restarted.CurrentSession?.SessionId);
        Assert.Contains(_firewall.Rules, r => r.SessionId == sessionId);
    }

    [Fact]
    public async Task Restart_ignores_an_untargeted_profile_that_is_not_blocking()
    {
        // A session activated for Private|Public has no claim on Domain, so Domain sitting at ALLOW
        // is the correct pre-exam state and not a conflict. This is what makes the reconciliation
        // check read the session's recorded mask instead of assuming All.
        var sessionId = Guid.NewGuid();
        await _machine.ActivateAsync(
            sessionId, PythonInteropFixtures.ValidMessage(), PythonInteropFixtures.ExamId,
            FirewallProfiles.Private | FirewallProfiles.Public, PythonInteropFixtures.ValidEvalTime);

        Assert.Equal(FirewallAction.Allow, _firewall.GetBaseline().DomainDefaultOutbound);

        var restarted = NewMachine();
        var recovery = await restarted.ReconcileStartupStateAsync();

        Assert.False(recovery.ConflictDetected);
        Assert.Equal(EnforcementState.Active, restarted.CurrentState);
    }

    [Fact]
    public async Task Restart_assumes_all_profiles_when_the_journal_has_no_session_row()
    {
        // DurableEnforcementRecord does not carry the profile mask, so a record whose companion
        // session row is missing - a torn write, or a journal trimmed by hand - has to fall back to
        // something. FirewallProfiles.All is the strict reading: it can only ever raise a conflict a
        // human then investigates, never wave through a machine that is not actually enforcing.
        var sessionId = Guid.NewGuid();
        _journal.SaveEnforcementState(new DurableEnforcementRecord(
            SessionId: sessionId,
            ExamId: PythonInteropFixtures.ExamId,
            PolicyId: PythonInteropFixtures.PolicyId,
            PolicyVersion: 1,
            State: EnforcementState.Active,
            ActivationUtc: DateTimeOffset.UtcNow.AddMinutes(-10),
            ExpiresAtUtc: DateTimeOffset.UtcNow.AddHours(2),
            LastTransitionUtc: DateTimeOffset.UtcNow.AddMinutes(-10)));

        Assert.Null(_journal.GetSession(sessionId));

        // Private and Public ARE blocking; only Domain is open. The old check passed this exact
        // state, which is what makes it the right probe for the fallback.
        _firewall.PrivateDefaultOutbound = FirewallAction.Block;
        _firewall.PublicDefaultOutbound = FirewallAction.Block;
        _firewall.DomainDefaultOutbound = FirewallAction.Allow;

        var recovery = await NewMachine().ReconcileStartupStateAsync();

        Assert.True(recovery.ConflictDetected);
    }
}
