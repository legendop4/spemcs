using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Spemcs.Agent.Core.Network;
using Xunit;

namespace Spemcs.Agent.Tests;

/// <summary>
/// Phase 18 / requirement 9: when an exam ends - normally, by expiry, or by a crash - SPEMCS must put
/// the endpoint back in EXACTLY the state it found it, and must not disturb anything it does not own.
/// </summary>
/// <remarks>
/// <para>
/// Two habits distinguish these tests from the rollback assertions that came before them, and both
/// come straight from the acceptance brief.
/// </para>
/// <para>
/// FIRST: state, not calls. Every claim about restoration is checked by reading
/// <see cref="MockFirewallAdapter"/> back and comparing it against a snapshot taken BEFORE the exam.
/// "Rollback called <c>SetDefaultOutboundAction</c>" is not evidence that the machine is at its
/// baseline - a write can be silently refused by a GPO, and a write of the wrong value is still a
/// write. <see cref="FirewallSnapshot"/> exists so the property can be stated as an equality between
/// two observed states, and <see cref="Property_TheSnapshotComparisonCanActuallyFail"/> exists so the
/// equality cannot quietly become a tautology.
/// </para>
/// <para>
/// SECOND: preservation is falsifiable. Until Phase 18, <c>MockFirewallAdapter.RemoveRule</c> only
/// touched its own SPEMCS rule list, so <c>UnrelatedRuleNames</c> was physically undeletable and every
/// "unrelated rules preserved" assertion in the suite passed unconditionally. It can now be deleted
/// from, exactly as the real COM API can, which is what makes these tests capable of catching the
/// failure they describe. The list includes a rule named
/// <see cref="MockFirewallAdapter.OffLimitsUnrelatedRuleName"/> so the project owner's standing
/// instruction about it is enforced by assertion rather than by good intentions - it is a string in a
/// test double, and nothing reachable from this file talks to the live Windows Firewall.
/// </para>
/// </remarks>
public sealed class RollbackScopeTests : IDisposable
{
    private readonly string _tempDir;
    private readonly SqliteRollbackJournal _journal;
    private readonly TrustedKeyStore _keyStore;
    private readonly MockManagementConnectivityVerifier _connectivity;
    private readonly PolicyReceiver _receiver;
    private readonly MockFirewallAdapter _firewall;
    private readonly NetworkEnforcer _enforcer;
    private readonly EnforcementStateMachine _machine;

    public RollbackScopeTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"spemcs_rollback_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _journal = new SqliteRollbackJournal(_tempDir);
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

    /// <summary>An enforcer over the SAME journal and firewall: models a service restart.</summary>
    private NetworkEnforcer NewEnforcer() => new(_firewall, _journal);

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir)) Directory.Delete(_tempDir, true);
        }
        catch
        {
            // Temp-dir cleanup failures are not test failures.
        }
    }

    // =========================================================================
    // Test infrastructure
    // =========================================================================

    /// <summary>
    /// Everything about the firewall that SPEMCS could conceivably have changed, in a form two
    /// snapshots can be compared for equality.
    /// </summary>
    /// <remarks>
    /// Rule names are sorted, because rule ORDER is not part of the state SPEMCS controls and a
    /// reordering is not a change; a name appearing or disappearing is.
    /// </remarks>
    private sealed record FirewallSnapshot(
        FirewallAction Domain,
        FirewallAction Private,
        FirewallAction Public,
        string SpemcsRules,
        string UnrelatedRules);

    private FirewallSnapshot Snapshot() => new(
        Domain: _firewall.DomainDefaultOutbound,
        Private: _firewall.PrivateDefaultOutbound,
        Public: _firewall.PublicDefaultOutbound,
        SpemcsRules: string.Join("|", _firewall.Rules.Select(r => r.Name).OrderBy(n => n, StringComparer.Ordinal)),
        UnrelatedRules: string.Join("|", _firewall.UnrelatedRuleNames.OrderBy(n => n, StringComparer.Ordinal)));

    private static FirewallRuleModel Rule(Guid sessionId, string purpose, string remote = "203.0.113.5", string port = "443")
        => FirewallRuleModel.CreateOutboundAllow(sessionId, purpose, FirewallProtocol.TCP, remote, port);

    private static EnforcementSession Session(
        Guid sessionId,
        FirewallProfiles targetProfiles,
        params FirewallRuleModel[] rules) => new(
            SessionId: sessionId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            Rules: rules,
            TargetProfiles: targetProfiles,
            CreatedUtc: DateTimeOffset.UtcNow);

    /// <summary>
    /// Writes a journal row directly, so a test can put the system in the state a crash would have
    /// left it in without needing to actually crash a process.
    /// </summary>
    /// <param name="updatedUtc">
    /// Overrides the row's update timestamp. <c>GetLatestActiveOrIncompleteSession</c> orders by it, so
    /// a test that needs a specific row chosen out of several must pin this rather than rely on wall
    /// clock resolution between two statements.
    /// </param>
    private JournalRecord SeedSession(
        Guid sessionId,
        EnforcementPhase phase,
        FirewallProfiles targetProfiles,
        FirewallProfileBaseline baseline,
        IReadOnlyList<FirewallRuleModel> intendedRules,
        IReadOnlyList<string> appliedRuleNames,
        DateTimeOffset? updatedUtc = null)
    {
        var record = new JournalRecord(
            SessionId: sessionId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            Phase: phase,
            StartUtc: DateTimeOffset.UtcNow,
            UpdatedUtc: updatedUtc ?? DateTimeOffset.UtcNow,
            Baseline: baseline,
            TargetProfiles: targetProfiles,
            IntendedRules: intendedRules,
            AppliedRuleNames: appliedRuleNames,
            LastError: null,
            ConflictDetails: null);

        _journal.SaveSession(record);
        return record;
    }

    private static FirewallProfileBaseline BaselineOf(
        FirewallAction domain,
        FirewallAction priv,
        FirewallAction pub,
        FirewallProfiles activeProfiles = FirewallProfiles.All)
        => new(domain, priv, pub, activeProfiles, DateTimeOffset.UtcNow);

    private static FirewallProfileBaseline AllAllow => BaselineOf(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow);

    private void SetLiveProfiles(FirewallAction domain, FirewallAction priv, FirewallAction pub)
    {
        _firewall.DomainDefaultOutbound = domain;
        _firewall.PrivateDefaultOutbound = priv;
        _firewall.PublicDefaultOutbound = pub;
    }

    /// <summary>
    /// Puts the system in the state a live, verified lockdown leaves behind: the session's rules
    /// installed, an <see cref="EnforcementPhase.Active"/> journal row carrying the pre-exam baseline,
    /// and the targeted profile defaults on <see cref="FirewallAction.Block"/>.
    /// </summary>
    /// <remarks>
    /// Setting the live profiles to BLOCK is load-bearing, not decoration. Active is the one phase in
    /// which read-back confirmed BLOCK, so it is the one phase that licenses an
    /// external-modification report. A fixture that seeds Active while leaving the defaults at their
    /// pre-exam values is describing a machine somebody has ALREADY tampered with, and every test built
    /// on it would carry a conflict verdict it never meant to assert.
    /// </remarks>
    private void SeedActiveLockdown(
        Guid sessionId,
        FirewallProfileBaseline preExamBaseline,
        IReadOnlyList<FirewallRuleModel> installedRules,
        IReadOnlyList<string>? journaledRuleNames = null,
        FirewallProfiles targetProfiles = FirewallProfiles.All,
        DateTimeOffset? updatedUtc = null)
    {
        foreach (var rule in installedRules)
        {
            _firewall.AddRule(rule);
        }

        SeedSession(sessionId, EnforcementPhase.Active, targetProfiles, preExamBaseline,
            installedRules,
            journaledRuleNames ?? installedRules.Select(r => r.Name).ToList(),
            updatedUtc);

        SetLiveProfiles(FirewallAction.Block, FirewallAction.Block, FirewallAction.Block);
    }

    /// <summary>
    /// Asserts that no rule SPEMCS does not own was even OFFERED to <c>RemoveRule</c>. Stronger than
    /// asserting survival: a rule can survive a delete attempt by accident (wrong name, already gone),
    /// and a rollback that tries to delete other products' rules is a defect even when it misses.
    /// </summary>
    private void AssertNoAttemptOnUnrelatedRules()
    {
        foreach (var name in MockFirewallAdapter.DefaultUnrelatedRuleNames)
        {
            Assert.DoesNotContain(name, _firewall.RemovalAttempts);
        }
    }

    // =========================================================================
    // STEP 6 - the exact scope of what SPEMCS captures and restores
    // =========================================================================
    // The audit noted that FirewallProfileBaseline "does not completely capture inbound baseline
    // state even though documentation previously implied broader restoration". Inspecting the current
    // code settled it the other way: SPEMCS mutates NO inbound state, so the baseline is complete for
    // what it owns and adding inbound fields would create a value rollback must either ignore (dead
    // weight) or write back - a change SPEMCS has no mandate to make. The brief's instruction for that
    // outcome was to document the scope rather than add restoration complexity. These three tests are
    // that documentation made executable: if SPEMCS ever DOES start touching inbound state, they fail,
    // and the baseline must grow at that point.

    [Fact]
    public void Scope_TheFirewallAdapterExposesNoWayToMutateInboundState()
    {
        var inboundMembers = typeof(IFirewallAdapter)
            .GetMembers(BindingFlags.Public | BindingFlags.Instance)
            .Where(m => m.Name.Contains("Inbound", StringComparison.OrdinalIgnoreCase))
            .Select(m => m.Name)
            .ToList();

        Assert.Empty(inboundMembers);

        // Positive control: the reflection is actually looking at the right type and would notice.
        Assert.Contains(
            typeof(IFirewallAdapter).GetMembers(BindingFlags.Public | BindingFlags.Instance).Select(m => m.Name),
            n => n.Equals(nameof(IFirewallAdapter.SetDefaultOutboundAction), StringComparison.Ordinal));
    }

    [Fact]
    public void Scope_TheBaselineCarriesTheThreeOutboundDefaultsAndNothingInbound()
    {
        var properties = typeof(FirewallProfileBaseline)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        // An exact set, so adding or removing a captured value forces a decision here about whether
        // rollback restores it.
        Assert.Equal(
            new[]
            {
                nameof(FirewallProfileBaseline.ActiveProfiles),
                nameof(FirewallProfileBaseline.CapturedUtc),
                nameof(FirewallProfileBaseline.DomainDefaultOutbound),
                nameof(FirewallProfileBaseline.PrivateDefaultOutbound),
                nameof(FirewallProfileBaseline.PublicDefaultOutbound),
            },
            properties);
    }

    [Fact]
    public async Task Scope_EveryRuleARealSessionInstallsIsOutboundAndInTheSpemcsGroup()
    {
        var sessionId = Guid.NewGuid();
        var result = await _machine.ActivateAsync(
            sessionId, PythonInteropFixtures.ValidMessage(), PythonInteropFixtures.ExamId,
            FirewallProfiles.All, PythonInteropFixtures.ValidEvalTime);

        Assert.True(result.Success, result.FailureReason);
        Assert.NotEmpty(_firewall.Rules);

        foreach (var rule in _firewall.Rules)
        {
            Assert.Equal(FirewallDirection.Outbound, rule.Direction);
            Assert.Equal(FirewallRuleModel.SpemcsRuleGroup, rule.Group);
        }
    }

    // =========================================================================
    // STEP 2 + STEP 9 - session-safe rule ownership
    // =========================================================================

    [Fact]
    public async Task Ownership_RollbackOfOneSessionLeavesAnotherLiveSessionsRulesIntact()
    {
        // The scenario the brief specifies: an unrelated rule, a rule belonging to session A, and a
        // rule belonging to session B. Roll back B only.
        var sessionA = Guid.NewGuid();
        var sessionB = Guid.NewGuid();

        var ruleA = Rule(sessionA, "VendorA", "203.0.113.10");
        _firewall.AddRule(ruleA);
        SeedSession(sessionA, EnforcementPhase.Active, FirewallProfiles.All, AllAllow,
            new[] { ruleA }, new[] { ruleA.Name });

        var applyB = await _enforcer.ApplyEnforcementAsync(
            Session(sessionB, FirewallProfiles.Private, Rule(sessionB, "VendorB", "203.0.113.20")));
        Assert.True(applyB.Success);

        var unrelatedBefore = _firewall.UnrelatedRuleNames.ToList();

        var rollback = await _enforcer.RemoveEnforcementAsync(sessionB);

        Assert.True(rollback.Success, rollback.ErrorMessage);
        Assert.Equal(1, rollback.RulesRemovedCount);

        // Session A survives untouched - rule still installed, and never even offered for removal.
        Assert.True(_firewall.RuleExists(ruleA.Name));
        Assert.DoesNotContain(ruleA.Name, _firewall.RemovalAttempts);

        // Session B is gone.
        Assert.DoesNotContain(_firewall.Rules, r => r.SessionId == sessionB);

        // Unrelated rules survive untouched.
        Assert.Equal(unrelatedBefore, _firewall.UnrelatedRuleNames);
        AssertNoAttemptOnUnrelatedRules();
    }

    [Fact]
    public async Task Ownership_ACorruptJournalEntryCannotMakeRollbackDeleteAnArbitraryRule()
    {
        // Attack: the journal is a file on disk. If rollback deletes every name it finds in
        // AppliedRuleNames, then editing that row - or a corruption that scrambles it - turns rollback
        // into an arbitrary rule-deletion primitive, aimed at a name of the attacker's choosing. Here
        // the chosen name is the one rule the project owner has explicitly placed off-limits.
        var sessionId = Guid.NewGuid();
        var ownRule = Rule(sessionId, "Vendor");

        SeedActiveLockdown(sessionId, AllAllow, new[] { ownRule },
            journaledRuleNames: new[]
            {
                ownRule.Name,
                MockFirewallAdapter.OffLimitsUnrelatedRuleName,
                "Core Networking (DNS-Out)",
                FirewallRuleModel.NamePrefix + "not-a-session-id-Vendor",
            });

        var rollback = await _enforcer.RemoveEnforcementAsync(sessionId);

        // Only the rule that carries this session's prefix is removed.
        Assert.Equal(1, rollback.RulesRemovedCount);
        Assert.False(_firewall.RuleExists(ownRule.Name));

        // The injected names are refused, not merely missed: they were never offered for removal.
        Assert.True(_firewall.RuleExists(MockFirewallAdapter.OffLimitsUnrelatedRuleName));
        Assert.Equal(MockFirewallAdapter.DefaultUnrelatedRuleNames, _firewall.UnrelatedRuleNames);
        AssertNoAttemptOnUnrelatedRules();
        Assert.DoesNotContain(FirewallRuleModel.NamePrefix + "not-a-session-id-Vendor", _firewall.RemovalAttempts);
    }

    [Fact]
    public async Task Ownership_ARuleReachingTheFirewallButNotTheJournalIsStillRemoved()
    {
        // The crash window between AddRule and RecordAppliedRule. The journal never learned about the
        // rule, so the group scan is the only thing that can find it - which is why ownership is a
        // UNION of the journal and a prefix scan rather than either one alone.
        var sessionId = Guid.NewGuid();
        var journaled = Rule(sessionId, "Journaled", "203.0.113.30");
        var unjournaled = Rule(sessionId, "Unjournaled", "203.0.113.31");

        SeedActiveLockdown(sessionId, AllAllow, new[] { journaled, unjournaled },
            journaledRuleNames: new[] { journaled.Name });

        var rollback = await _enforcer.RemoveEnforcementAsync(sessionId);

        Assert.Equal(2, rollback.RulesRemovedCount);
        Assert.Empty(_firewall.Rules);
    }

    [Fact]
    public async Task Ownership_AJournaledRuleThatIsAlreadyGoneIsNotAFailure()
    {
        // The mirror crash window: the COM delete succeeded, the journal write did not. A retried
        // rollback must treat the absence as done, not as an error.
        var sessionId = Guid.NewGuid();
        var vanished = Rule(sessionId, "Vanished");

        SeedActiveLockdown(sessionId, AllAllow,
            installedRules: Array.Empty<FirewallRuleModel>(),
            journaledRuleNames: new[] { vanished.Name });

        var rollback = await _enforcer.RemoveEnforcementAsync(sessionId);

        Assert.True(rollback.Success, rollback.ErrorMessage);
        Assert.False(rollback.ConflictDetected);
        Assert.Equal(0, rollback.RulesRemovedCount);
    }

    [Fact]
    public async Task Ownership_ARuleNamedLikeSpemcsButOutsideTheGroupIsNeverACandidate()
    {
        // A third-party or hand-made rule that merely LOOKS like ours. Containment by group is what
        // makes this safe: the enumeration rollback works from is GetRuleNamesByGroup, so a rule
        // outside the group cannot be reached no matter what it is called - not even one carrying a
        // real session's prefix.
        var sessionId = Guid.NewGuid();
        var apply = await _enforcer.ApplyEnforcementAsync(
            Session(sessionId, FirewallProfiles.All, Rule(sessionId, "Vendor")));
        Assert.True(apply.Success);

        var impostor = Rule(sessionId, "Vendor", "198.51.100.9") with { Group = "SOME_OTHER_PRODUCT" };
        _firewall.AddRule(impostor);

        await _enforcer.RemoveEnforcementAsync(sessionId);

        Assert.True(_firewall.RuleExists(impostor.Name));
        Assert.DoesNotContain(impostor.Name, _firewall.RemovalAttempts);
    }

    [Fact]
    public async Task Ownership_EveryRuleNameARealSessionGeneratesIsAttributableToThatSession()
    {
        // Ownership is decided by parsing the rule NAME, because GetRulesByGroup reads back from
        // Windows and Windows stores no session field. That only works if every name the generator
        // produces round-trips - including the deliberately human-readable management rule and the two
        // loopback rules, which do not go through the hashed branch.
        var sessionId = Guid.NewGuid();
        var result = await _machine.ActivateAsync(
            sessionId, PythonInteropFixtures.ValidMessage(), PythonInteropFixtures.ExamId,
            FirewallProfiles.All, PythonInteropFixtures.ValidEvalTime);
        Assert.True(result.Success, result.FailureReason);

        var purposes = _firewall.Rules.Select(r => r.Purpose).ToList();
        Assert.Contains("Mgmt", purposes);
        Assert.Contains(purposes, p => p.StartsWith("Loopback", StringComparison.Ordinal));

        foreach (var rule in _firewall.Rules)
        {
            Assert.True(FirewallRuleModel.TryParseSessionId(rule.Name, out var owner),
                $"Generated rule name '{rule.Name}' (purpose {rule.Purpose}) is not attributable to a session.");
            Assert.Equal(sessionId, owner);
            Assert.StartsWith(FirewallRuleModel.SessionNamePrefix(sessionId), rule.Name, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("Codex")]
    [InlineData("Core Networking (DNS-Out)")]
    [InlineData("SPEMCS")]
    [InlineData("SPEMCS-")]
    [InlineData("SPEMCS-Vendor-AABBCCDD")]
    // Prefix plus a well-formed GUID but no purpose segment: not a name the generator can produce,
    // so attributing it would be a guess.
    [InlineData("SPEMCS-0123456789abcdef0123456789abcdef")]
    [InlineData("SPEMCS-0123456789abcdef0123456789abcdef-")]
    // 31 hex digits, then a dash: length-based parsing that did not check the separator would read
    // the dash as part of the GUID.
    [InlineData("SPEMCS-0123456789abcdef0123456789abcde-Vendor")]
    // Non-hex character inside the GUID field.
    [InlineData("SPEMCS-0123456789abcdef0123456789abcdeg-Vendor")]
    // GUID in dashed form, which is not what "N" produces.
    [InlineData("SPEMCS-01234567-89ab-cdef-0123-456789abcdef-Vendor")]
    public void Ownership_TryParseSessionId_RefusesToGuessAtMalformedNames(string? ruleName)
    {
        Assert.False(FirewallRuleModel.TryParseSessionId(ruleName, out var sessionId));
        Assert.Equal(Guid.Empty, sessionId);
    }

    [Fact]
    public void Ownership_TryParseSessionId_AcceptsTheNamesTheGeneratorProduces()
    {
        var sessionId = Guid.NewGuid();

        foreach (var name in new[]
        {
            FirewallRuleModel.GenerateRuleName(sessionId, "Mgmt", "127.0.0.1", "8002"),
            FirewallRuleModel.GenerateRuleName(sessionId, "Vendor", "203.0.113.0/24", "443", FirewallProtocol.TCP, @"C:\browser.exe"),
            FirewallRuleModel.CreateLoopbackIPv4Allow(sessionId).Name,
            FirewallRuleModel.CreateLoopbackIPv6Allow(sessionId).Name,
        })
        {
            Assert.True(FirewallRuleModel.TryParseSessionId(name, out var parsed), name);
            Assert.Equal(sessionId, parsed);
        }

        // Windows rule names are case-insensitive, so attribution must be too.
        var upper = FirewallRuleModel.GenerateRuleName(sessionId, "Vendor", "203.0.113.1", "443").ToUpperInvariant();
        Assert.True(FirewallRuleModel.TryParseSessionId(upper, out var upperParsed));
        Assert.Equal(sessionId, upperParsed);
    }

    // =========================================================================
    // STEP 3 - exact profile baseline restoration
    // =========================================================================
    // "Do not blindly restore defaults such as Block / Allow / NotConfigured. Restore the actual
    // captured value." With only two FirewallAction values, a hardcoded restore-to-Allow is right
    // half the time by accident, which is exactly the kind of bug a single-combination test misses.

    [Theory]
    [InlineData(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow)]
    [InlineData(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Block)]
    [InlineData(FirewallAction.Allow, FirewallAction.Block, FirewallAction.Allow)]
    [InlineData(FirewallAction.Allow, FirewallAction.Block, FirewallAction.Block)]
    [InlineData(FirewallAction.Block, FirewallAction.Allow, FirewallAction.Allow)]
    [InlineData(FirewallAction.Block, FirewallAction.Allow, FirewallAction.Block)]
    [InlineData(FirewallAction.Block, FirewallAction.Block, FirewallAction.Allow)]
    [InlineData(FirewallAction.Block, FirewallAction.Block, FirewallAction.Block)]
    public async Task Restoration_RestoresTheExactCapturedActionForEveryProfileCombination(
        FirewallAction domain, FirewallAction priv, FirewallAction pub)
    {
        SetLiveProfiles(domain, priv, pub);
        var before = Snapshot();

        var sessionId = Guid.NewGuid();
        var apply = await _enforcer.ApplyEnforcementAsync(
            Session(sessionId, FirewallProfiles.All, Rule(sessionId, "Vendor")));
        Assert.True(apply.Success, apply.ErrorMessage);

        // During the exam every targeted profile is BLOCK, whatever it was before.
        Assert.Equal(FirewallAction.Block, _firewall.DomainDefaultOutbound);
        Assert.Equal(FirewallAction.Block, _firewall.PrivateDefaultOutbound);
        Assert.Equal(FirewallAction.Block, _firewall.PublicDefaultOutbound);

        var rollback = await _enforcer.RemoveEnforcementAsync(sessionId);

        Assert.True(rollback.Success, rollback.ErrorMessage);
        Assert.True(rollback.BaselineRestored);
        Assert.False(rollback.ConflictDetected);

        // Exactly, on every profile - not "back to Allow".
        Assert.Equal(before, Snapshot());
    }

    [Fact]
    public async Task Restoration_ABlockBaselineIsRestoredToBlockNotDowngradedToAllow()
    {
        // Called out separately from the theory above because it is the case a
        // restore-the-obvious-default implementation gets wrong, and getting it wrong leaves the host
        // MORE open after the exam than it was before - a security regression caused by a monitoring
        // product's cleanup.
        SetLiveProfiles(FirewallAction.Block, FirewallAction.Block, FirewallAction.Block);

        var sessionId = Guid.NewGuid();
        await _enforcer.ApplyEnforcementAsync(Session(sessionId, FirewallProfiles.All, Rule(sessionId, "Vendor")));
        await _enforcer.RemoveEnforcementAsync(sessionId);

        Assert.Equal(FirewallAction.Block, _firewall.DomainDefaultOutbound);
        Assert.Equal(FirewallAction.Block, _firewall.PrivateDefaultOutbound);
        Assert.Equal(FirewallAction.Block, _firewall.PublicDefaultOutbound);
    }

    [Fact]
    public async Task Restoration_AProfileOutsideTheTargetSetIsNeverWrittenAtAll()
    {
        // Asserted on the write log rather than on the final value, because a final-state assertion
        // cannot tell "left alone" apart from "written back to the value it already had" - and writing
        // to an untargeted profile is out of scope even when the value happens to match.
        SetLiveProfiles(FirewallAction.Block, FirewallAction.Allow, FirewallAction.Block);

        var sessionId = Guid.NewGuid();
        await _enforcer.ApplyEnforcementAsync(Session(sessionId, FirewallProfiles.Private, Rule(sessionId, "Vendor")));
        await _enforcer.RemoveEnforcementAsync(sessionId);

        Assert.Equal(FirewallAction.Block, _firewall.DomainDefaultOutbound);
        Assert.Equal(FirewallAction.Allow, _firewall.PrivateDefaultOutbound);
        Assert.Equal(FirewallAction.Block, _firewall.PublicDefaultOutbound);

        // Every write names Private and only Private.
        Assert.NotEmpty(_firewall.DefaultActionWrites);
        foreach (var (profiles, _) in _firewall.DefaultActionWrites)
        {
            Assert.False(profiles.HasFlag(FirewallProfiles.Domain), $"Untargeted Domain profile was written: {profiles}");
            Assert.False(profiles.HasFlag(FirewallProfiles.Public), $"Untargeted Public profile was written: {profiles}");
        }
    }

    [Fact]
    public async Task Restoration_AProfileAlreadyAtItsBaselineIsNotWrittenAgain()
    {
        // Rollback should be a convergence, not an unconditional re-write. A no-op write is not
        // harmless: on a real host every SetDefaultOutboundAction is a policy change event, and
        // re-writing a value an administrator has since re-asserted is exactly the kind of
        // interference requirement 9 is meant to avoid.
        SetLiveProfiles(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow);

        var sessionId = Guid.NewGuid();
        await _enforcer.ApplyEnforcementAsync(Session(sessionId, FirewallProfiles.Private, Rule(sessionId, "Vendor")));
        await _enforcer.RemoveEnforcementAsync(sessionId);

        _firewall.DefaultActionWrites.Clear();

        // Second rollback: everything already matches the captured baseline.
        var again = await _enforcer.RemoveEnforcementAsync(sessionId);

        Assert.True(again.Success, again.ErrorMessage);
        Assert.True(again.BaselineRestored);
        Assert.Empty(_firewall.DefaultActionWrites);
    }

    // =========================================================================
    // STEP 4 - rollback must not depend on the current action
    // =========================================================================

    [Fact]
    public async Task CurrentActionIndependence_AnExternallyClearedBlockOnABlockBaselineIsStillRestored()
    {
        // THE FAIL-OPEN THIS STEP EXISTS FOR, and the reason "if current == Block then restore else
        // return" cannot be kept. FirewallAction has two values, so "not Block" meant "Allow", and the
        // old code responded by yielding: it returned without restoring and reported
        // BaselineRestored=false as though that were a safe outcome.
        //
        // Here the host was ALREADY deny-by-default before the exam. SPEMCS set Block (a no-op),
        // something later cleared it to Allow, and rollback ran. Yielding leaves the machine
        // permanently more permissive than SPEMCS found it, and the exam session gets the blame.
        SetLiveProfiles(FirewallAction.Block, FirewallAction.Block, FirewallAction.Block);
        var before = Snapshot();

        var sessionId = Guid.NewGuid();
        await _enforcer.ApplyEnforcementAsync(Session(sessionId, FirewallProfiles.All, Rule(sessionId, "Vendor")));

        // External administrator / GPO / another product clears the outbound default mid-exam.
        _firewall.PrivateDefaultOutbound = FirewallAction.Allow;

        var rollback = await _enforcer.RemoveEnforcementAsync(sessionId);

        // The pre-exam posture is restored...
        Assert.Equal(FirewallAction.Block, _firewall.PrivateDefaultOutbound);
        Assert.True(rollback.BaselineRestored);
        Assert.Equal(before, Snapshot());

        // ...and the external change is still reported and journaled, so re-asserting the baseline is
        // not the same as hiding the event.
        Assert.True(rollback.ConflictDetected);
        Assert.NotNull(_journal.GetSession(sessionId)!.ConflictDetails);
        Assert.Equal(EnforcementPhase.Conflict, _journal.GetSession(sessionId)!.Phase);
    }

    [Theory]
    [InlineData(EnforcementPhase.Prepared)]
    [InlineData(EnforcementPhase.ApplyingRules)]
    [InlineData(EnforcementPhase.EnforcingDefaultBlock)]
    [InlineData(EnforcementPhase.RollingBackDefault)]
    [InlineData(EnforcementPhase.RollingBackRules)]
    [InlineData(EnforcementPhase.RolledBack)]
    [InlineData(EnforcementPhase.Failed)]
    [InlineData(EnforcementPhase.Conflict)]
    public async Task CurrentActionIndependence_NoIntermediatePhaseIsReportedAsAnExternalConflict(
        EnforcementPhase phase)
    {
        // Only the Active phase means read-back CONFIRMED Block was in force, so only Active can
        // license the claim that a third party changed it. The old whitelist reported a conflict for
        // every phase in which the profile was not currently Block, which turned four ordinary
        // situations - partial enforcement, a repeated rollback, a crash mid-rollback, and a failed
        // activation - into unresolved operator-visible incidents.
        //
        // Failed and Conflict are in this list for a second reason: the old code did not converge in
        // those phases at all, so a session that died in Failed left its profiles on BLOCK with no
        // code path that would ever put them back.
        SetLiveProfiles(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow);
        var before = Snapshot();

        var sessionId = Guid.NewGuid();
        var rule = Rule(sessionId, "Vendor");
        _firewall.AddRule(rule);

        // Mid-flight state: profiles are on BLOCK because SPEMCS put them there and never finished.
        SetLiveProfiles(FirewallAction.Block, FirewallAction.Block, FirewallAction.Block);

        SeedSession(sessionId, phase, FirewallProfiles.All,
            BaselineOf(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow),
            new[] { rule }, new[] { rule.Name });

        var rollback = await _enforcer.RemoveEnforcementAsync(sessionId);

        Assert.False(rollback.ConflictDetected, $"Phase {phase} produced a false external-conflict report.");
        Assert.True(rollback.Success, rollback.ErrorMessage);

        if (phase is EnforcementPhase.Prepared or EnforcementPhase.ApplyingRules)
        {
            // BLOCK is written only after every allow rule is installed and verified, so in these two
            // phases SPEMCS provably had not written it. The BLOCK observed here therefore belongs to
            // somebody else and must be left alone; only the rules are cleaned up.
            Assert.False(rollback.BaselineRestored);
            Assert.Equal(FirewallAction.Block, _firewall.PrivateDefaultOutbound);
            Assert.Empty(_firewall.DefaultActionWrites);
        }
        else
        {
            Assert.True(rollback.BaselineRestored);
            Assert.Equal(before, Snapshot());
        }

        Assert.Empty(_firewall.Rules);
        AssertNoAttemptOnUnrelatedRules();
    }

    [Fact]
    public async Task CurrentActionIndependence_RollbackIsIdempotent()
    {
        SetLiveProfiles(FirewallAction.Allow, FirewallAction.Block, FirewallAction.Allow);
        var before = Snapshot();

        var sessionId = Guid.NewGuid();
        await _enforcer.ApplyEnforcementAsync(Session(sessionId, FirewallProfiles.All, Rule(sessionId, "Vendor")));

        var first = await _enforcer.RemoveEnforcementAsync(sessionId);
        var afterFirst = Snapshot();

        var second = await _enforcer.RemoveEnforcementAsync(sessionId);
        var third = await _enforcer.RemoveEnforcementAsync(sessionId);

        Assert.True(first.Success);
        Assert.Equal(1, first.RulesRemovedCount);

        foreach (var repeat in new[] { second, third })
        {
            Assert.True(repeat.Success, repeat.ErrorMessage);
            Assert.False(repeat.ConflictDetected);
            Assert.True(repeat.BaselineRestored);
            Assert.Equal(0, repeat.RulesRemovedCount);
        }

        Assert.Equal(before, afterFirst);
        Assert.Equal(before, Snapshot());
        Assert.Equal(EnforcementPhase.RolledBack, _journal.GetSession(sessionId)!.Phase);
    }

    [Fact]
    public async Task CurrentActionIndependence_PartialEnforcementRollsBackCleanlyWithoutAConflict()
    {
        // Activation fails at the default-block step because one profile silently refuses to hold
        // BLOCK - the GPO failure mode read-back verification exists to catch. The profiles that DID
        // take must be restored, the rules removed, and none of it reported as tampering.
        SetLiveProfiles(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow);
        var before = Snapshot();

        _firewall.ProfilesIgnoringBlock = FirewallProfiles.Domain;

        var sessionId = Guid.NewGuid();
        var apply = await _enforcer.ApplyEnforcementAsync(
            Session(sessionId, FirewallProfiles.All, Rule(sessionId, "Vendor")));

        Assert.False(apply.Success);

        // ApplyEnforcementAsync rolls back internally on failure; the machine must already be clean.
        Assert.Equal(before, Snapshot());
        Assert.Equal(EnforcementPhase.RolledBack, _journal.GetSession(sessionId)!.Phase);
        Assert.Null(_journal.GetSession(sessionId)!.ConflictDetails);
    }

    [Fact]
    public async Task CurrentActionIndependence_RestoreBaselineAsyncUsesTargetProfilesAndConverges()
    {
        // RestoreBaselineAsync is a separate entry point on INetworkEnforcer, so it needs its own
        // coverage: the audit's third finding was specifically that it passed
        // Baseline.ActiveProfiles instead of TargetProfiles. Inspecting the current source showed that
        // had already been corrected; this pins it so it cannot silently regress.
        SetLiveProfiles(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow);

        var sessionId = Guid.NewGuid();
        var rule = Rule(sessionId, "Vendor");
        _firewall.AddRule(rule);

        // Targets all three profiles, but the captured ActiveProfiles names only Private. If
        // restoration were keyed off ActiveProfiles, Domain and Public would stay on BLOCK.
        SeedSession(sessionId, EnforcementPhase.Active, FirewallProfiles.All,
            BaselineOf(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow, FirewallProfiles.Private),
            new[] { rule }, new[] { rule.Name });

        SetLiveProfiles(FirewallAction.Block, FirewallAction.Block, FirewallAction.Block);

        var result = await _enforcer.RestoreBaselineAsync(sessionId);

        Assert.True(result.Success, result.ErrorMessage);
        Assert.True(result.BaselineRestored);
        Assert.Equal(FirewallAction.Allow, _firewall.DomainDefaultOutbound);
        Assert.Equal(FirewallAction.Allow, _firewall.PrivateDefaultOutbound);
        Assert.Equal(FirewallAction.Allow, _firewall.PublicDefaultOutbound);

        // It restores the baseline only - rules are RemoveEnforcementAsync's job.
        Assert.Equal(0, result.RulesRemovedCount);
        Assert.True(_firewall.RuleExists(rule.Name));
    }

    // =========================================================================
    // STEP 5 - TargetProfiles versus ActiveProfiles
    // =========================================================================
    // The two are not interchangeable and neither replaces the other:
    //
    //   TargetProfiles  - the profiles SPEMCS INTENDED to mutate and did mutate. Durable in the
    //                     journal. The correct restoration key.
    //   ActiveProfiles  - an OBSERVATION of which profiles Windows reported as current at capture
    //                     time. Used for diagnostics and for the loopback-coverage check during rule
    //                     verification. Never a restoration key, because the active set can change
    //                     mid-exam while what SPEMCS wrote does not.

    [Fact]
    public async Task Profiles_RestorationIsKeyedOffTargetProfilesNotTheObservedActiveSet()
    {
        SetLiveProfiles(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow);

        // Windows reports only Private as active - a machine on a home network.
        _firewall.ActiveProfiles = FirewallProfiles.Private;
        var before = Snapshot();

        var sessionId = Guid.NewGuid();
        var apply = await _enforcer.ApplyEnforcementAsync(
            Session(sessionId, FirewallProfiles.All, Rule(sessionId, "Vendor")));
        Assert.True(apply.Success, apply.ErrorMessage);

        Assert.Equal(FirewallProfiles.All, _journal.GetSession(sessionId)!.TargetProfiles);
        Assert.Equal(FirewallProfiles.Private, _journal.GetSession(sessionId)!.Baseline.ActiveProfiles);

        var rollback = await _enforcer.RemoveEnforcementAsync(sessionId);

        Assert.True(rollback.BaselineRestored);
        Assert.Equal(before, Snapshot());
    }

    [Fact]
    public async Task Profiles_AProfileSwitchMidExamDoesNotChangeWhatGetsRestored()
    {
        // A laptop undocked from a Domain network onto Public halfway through the exam. Rollback must
        // undo what SPEMCS WROTE, not what happens to be live at the moment it runs.
        SetLiveProfiles(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow);
        _firewall.ActiveProfiles = FirewallProfiles.Domain;
        var before = Snapshot();

        var sessionId = Guid.NewGuid();
        await _enforcer.ApplyEnforcementAsync(Session(sessionId, FirewallProfiles.All, Rule(sessionId, "Vendor")));

        _firewall.ActiveProfiles = FirewallProfiles.Public;

        var rollback = await _enforcer.RemoveEnforcementAsync(sessionId);

        Assert.True(rollback.BaselineRestored);
        Assert.Equal(before with { }, Snapshot() with { });
        Assert.Equal(FirewallAction.Allow, _firewall.DomainDefaultOutbound);
        Assert.Equal(FirewallAction.Allow, _firewall.PublicDefaultOutbound);
    }

    [Fact]
    public async Task Profiles_TargetProfilesSurviveARestartBecauseTheyLiveInTheJournal()
    {
        SetLiveProfiles(FirewallAction.Allow, FirewallAction.Block, FirewallAction.Allow);
        var before = Snapshot();

        var sessionId = Guid.NewGuid();
        await _enforcer.ApplyEnforcementAsync(
            Session(sessionId, FirewallProfiles.Domain | FirewallProfiles.Public, Rule(sessionId, "Vendor")));

        // A fresh enforcer with no in-memory knowledge of the session at all.
        var rollback = await NewEnforcer().RemoveEnforcementAsync(sessionId);

        Assert.True(rollback.BaselineRestored);
        Assert.Equal(before, Snapshot());
    }

    // =========================================================================
    // STEP 7 - crash and failure scenarios
    // =========================================================================

    [Fact]
    public async Task Crash_A_ImmediatelyAfterBaselineCapture_TouchesNothing()
    {
        SetLiveProfiles(FirewallAction.Allow, FirewallAction.Block, FirewallAction.Allow);
        var before = Snapshot();

        var sessionId = Guid.NewGuid();
        SeedSession(sessionId, EnforcementPhase.Prepared, FirewallProfiles.All,
            _firewall.GetBaseline(), Array.Empty<FirewallRuleModel>(), Array.Empty<string>());

        var recovery = await NewEnforcer().RecoverIncompleteSessionAsync();

        Assert.True(recovery.RecoveryRequired);
        Assert.True(recovery.Success);
        Assert.Equal(sessionId, recovery.RecoveredSessionId);
        Assert.Equal(0, recovery.OrphanRulesCleaned);
        Assert.Equal(before, Snapshot());
        Assert.Empty(_firewall.DefaultActionWrites);
    }

    [Fact]
    public async Task Crash_C_AfterSomeButNotAllRules_RemovesThemAndLeavesTheDefaultAlone()
    {
        SetLiveProfiles(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow);
        var before = Snapshot();

        var sessionId = Guid.NewGuid();
        var rule1 = Rule(sessionId, "VendorA", "203.0.113.41");
        var rule2 = Rule(sessionId, "VendorB", "203.0.113.42");
        var rule3 = Rule(sessionId, "VendorC", "203.0.113.43");

        _firewall.AddRule(rule1);
        _firewall.AddRule(rule2);
        SeedSession(sessionId, EnforcementPhase.ApplyingRules, FirewallProfiles.All,
            _firewall.GetBaseline(), new[] { rule1, rule2, rule3 }, new[] { rule1.Name, rule2.Name });

        var recovery = await NewEnforcer().RecoverIncompleteSessionAsync();

        Assert.True(recovery.Success);
        Assert.Equal(2, recovery.OrphanRulesCleaned);
        Assert.Equal(before, Snapshot());
        // Default block had not been written yet, so there is nothing to restore and nothing was written.
        Assert.False(recovery.BaselineRestored);
        Assert.Empty(_firewall.DefaultActionWrites);
    }

    [Fact]
    public async Task Crash_B_AndD_AfterTheProfileMutation_RestoresTheBaselineAndRemovesTheRules()
    {
        // In SPEMCS's ordering the profile mutation comes AFTER every rule is installed and verified,
        // so "crash after profile mutation" and "crash after creating all rules" are the same window
        // seen from either side. Both are represented by EnforcingDefaultBlock (block written, not yet
        // verified) and Active (written and verified).
        foreach (var phase in new[] { EnforcementPhase.EnforcingDefaultBlock, EnforcementPhase.Active })
        {
            _firewall.Rules.Clear();
            _firewall.DefaultActionWrites.Clear();
            SetLiveProfiles(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow);
            var before = Snapshot();

            var sessionId = Guid.NewGuid();
            var rule = Rule(sessionId, "Vendor");
            _firewall.AddRule(rule);
            var baseline = BaselineOf(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow);

            // The lockdown is in force but no session owns it any more: the exam's signed window has
            // lapsed, so recovery must tear it down rather than preserve it.
            SetLiveProfiles(FirewallAction.Block, FirewallAction.Block, FirewallAction.Block);
            SeedSession(sessionId, phase, FirewallProfiles.All, baseline, new[] { rule }, new[] { rule.Name });

            var recovery = await NewEnforcer().RemoveEnforcementAsync(sessionId);

            Assert.True(recovery.Success, $"[{phase}] {recovery.ErrorMessage}");
            Assert.True(recovery.BaselineRestored, $"[{phase}] baseline was not restored");
            Assert.False(recovery.ConflictDetected, $"[{phase}] false conflict");
            Assert.Equal(1, recovery.RulesRemovedCount);
            Assert.Equal(before, Snapshot());
        }
    }

    [Fact]
    public async Task Crash_E_DuringRollback_CanBeRetriedAndFinishesTheJob()
    {
        // The process died between restoring the profile defaults and removing the rules. On restart
        // the profiles already match the baseline; the old code read that as tampering and refused to
        // finish, stranding the rules.
        SetLiveProfiles(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow);
        var before = Snapshot();

        var sessionId = Guid.NewGuid();
        var rule = Rule(sessionId, "Vendor");
        _firewall.AddRule(rule);

        SeedSession(sessionId, EnforcementPhase.RollingBackRules, FirewallProfiles.All,
            BaselineOf(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow),
            new[] { rule }, new[] { rule.Name });

        var recovery = await NewEnforcer().RecoverIncompleteSessionAsync();

        Assert.True(recovery.Success);
        Assert.False(recovery.ConflictDetected);
        Assert.Equal(1, recovery.OrphanRulesCleaned);
        Assert.Equal(before, Snapshot());
    }

    [Fact]
    public async Task Crash_F_ServiceRestartWhileLockdownIsActive_PreservesTheLiveExam()
    {
        // The most damaging false positive available to recovery code: tearing down a lockdown that is
        // still valid and still running. The candidate loses the examination browser mid-exam and the
        // log records a successful cleanup.
        var sessionId = Guid.NewGuid();
        var activation = await _machine.ActivateAsync(
            sessionId, PythonInteropFixtures.ValidMessage(), PythonInteropFixtures.ExamId,
            FirewallProfiles.All, PythonInteropFixtures.ValidEvalTime);
        Assert.True(activation.Success, activation.FailureReason);

        var duringExam = Snapshot();
        var removalAttemptsBeforeRestart = _firewall.RemovalAttempts.Count;

        var recovery = await NewMachine().ReconcileStartupStateAsync();

        Assert.False(recovery.RecoveryRequired);
        Assert.True(recovery.Success);
        Assert.Equal(sessionId, recovery.RecoveredSessionId);
        Assert.Equal(duringExam, Snapshot());
        Assert.Equal(FirewallAction.Block, _firewall.PrivateDefaultOutbound);

        // Recovery deleted nothing at all - not even attempted a delete.
        Assert.Equal(removalAttemptsBeforeRestart, _firewall.RemovalAttempts.Count);
    }

    [Fact]
    public async Task Crash_G_RecoveryRunTwiceIsSafe()
    {
        SetLiveProfiles(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow);
        var before = Snapshot();

        var sessionId = Guid.NewGuid();
        var rule = Rule(sessionId, "Vendor");
        _firewall.AddRule(rule);
        SetLiveProfiles(FirewallAction.Block, FirewallAction.Block, FirewallAction.Block);
        SeedSession(sessionId, EnforcementPhase.RollingBackDefault, FirewallProfiles.All,
            BaselineOf(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow),
            new[] { rule }, new[] { rule.Name });

        var first = await NewEnforcer().RecoverIncompleteSessionAsync();
        var afterFirst = Snapshot();
        var second = await NewEnforcer().RecoverIncompleteSessionAsync();

        Assert.True(first.Success);
        Assert.Equal(before, afterFirst);

        // The second pass finds nothing to do and says so, rather than finding "orphans".
        Assert.False(second.RecoveryRequired);
        Assert.True(second.Success);
        Assert.Equal(0, second.OrphanRulesCleaned);
        Assert.Equal(before, Snapshot());
    }

    [Fact]
    public async Task Crash_H_MissingJournalRecord_IsANoOpNotAFirewallCleanup()
    {
        // A rollback request for a session the journal has never heard of. Without a baseline there is
        // nothing to restore and no ownership to establish, so the only safe response is to do
        // nothing - certainly not to clean up whatever SPEMCS-ish rules happen to be present.
        var strangerRule = Rule(Guid.NewGuid(), "Stranger");
        _firewall.AddRule(strangerRule);
        var before = Snapshot();

        var rollback = await _enforcer.RemoveEnforcementAsync(Guid.NewGuid());

        Assert.True(rollback.Success);
        Assert.False(rollback.ConflictDetected);
        Assert.False(rollback.BaselineRestored);
        Assert.Equal(0, rollback.RulesRemovedCount);
        Assert.Equal(before, Snapshot());
        Assert.Empty(_firewall.RemovalAttempts);
    }

    [Fact]
    public async Task Crash_I_PartialJournalPersistence_IsReconciledFromTheFirewallItself()
    {
        // The journal row exists but its applied-rule list is empty, because the crash landed between
        // the first AddRule and the first RecordAppliedRule. Recovery has to find the installed rules
        // by scanning the group for this session's prefix; a journal-only implementation leaves them.
        SetLiveProfiles(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow);
        var before = Snapshot();

        var sessionId = Guid.NewGuid();
        var rule1 = Rule(sessionId, "VendorA", "203.0.113.51");
        var rule2 = Rule(sessionId, "VendorB", "203.0.113.52");
        _firewall.AddRule(rule1);
        _firewall.AddRule(rule2);

        SeedSession(sessionId, EnforcementPhase.ApplyingRules, FirewallProfiles.All,
            _firewall.GetBaseline(), new[] { rule1, rule2 }, Array.Empty<string>());

        var recovery = await NewEnforcer().RecoverIncompleteSessionAsync();

        Assert.True(recovery.Success);
        Assert.Equal(2, recovery.OrphanRulesCleaned);
        Assert.Equal(before, Snapshot());
    }

    [Fact]
    public async Task Crash_J_AnotherSessionExistsDuringRecovery_AndKeepsItsRules()
    {
        // Recovery reconciles ONE crashed session per pass, and its rule cleanup must not treat the
        // other session's rules as orphans just because they are in the SPEMCS group.
        var liveSessionId = Guid.NewGuid();
        var activation = await _machine.ActivateAsync(
            liveSessionId, PythonInteropFixtures.ValidMessage(), PythonInteropFixtures.ExamId,
            FirewallProfiles.All, PythonInteropFixtures.ValidEvalTime);
        Assert.True(activation.Success, activation.FailureReason);

        var liveRuleNames = _firewall.Rules.Select(r => r.Name).OrderBy(n => n, StringComparer.Ordinal).ToList();

        // A crashed session whose journal row is pinned to a LATER update time, so it is the row
        // GetLatestActiveOrIncompleteSession returns (that query is ORDER BY updated_utc DESC LIMIT 1).
        // Pinned rather than left to the wall clock, because two statements can land on the same tick.
        var crashedId = Guid.NewGuid();
        var crashedRule = Rule(crashedId, "Crashed", "198.51.100.77");
        _firewall.AddRule(crashedRule);
        SeedSession(crashedId, EnforcementPhase.ApplyingRules, FirewallProfiles.All, AllAllow,
            new[] { crashedRule }, new[] { crashedRule.Name },
            updatedUtc: DateTimeOffset.UtcNow.AddMinutes(1));

        var recovery = await NewEnforcer().RecoverIncompleteSessionAsync();

        Assert.True(recovery.Success);
        Assert.Equal(crashedId, recovery.RecoveredSessionId);

        // The crashed session's rule is gone; every one of the live session's rules is still there.
        Assert.False(_firewall.RuleExists(crashedRule.Name));
        Assert.Equal(liveRuleNames, _firewall.Rules.Select(r => r.Name).OrderBy(n => n, StringComparer.Ordinal));

        // And the live session's lockdown is untouched.
        Assert.Equal(FirewallAction.Block, _firewall.DomainDefaultOutbound);
        Assert.Equal(FirewallAction.Block, _firewall.PrivateDefaultOutbound);
        Assert.Equal(FirewallAction.Block, _firewall.PublicDefaultOutbound);
        AssertNoAttemptOnUnrelatedRules();
    }

    // =========================================================================
    // STEP 8 - property-style before/after comparison
    // =========================================================================

    [Fact]
    public async Task Property_AFullExamLifecycleLeavesTheFirewallExactlyAsItFoundIt()
    {
        // The end-to-end statement of requirement 9, driven through the state machine rather than the
        // enforcer, so policy verification, browser scoping, rule generation, the default-block
        // transition and deactivation are all in the path.
        SetLiveProfiles(FirewallAction.Block, FirewallAction.Allow, FirewallAction.Block);
        var beforeExam = Snapshot();

        var sessionId = Guid.NewGuid();
        var activation = await _machine.ActivateAsync(
            sessionId, PythonInteropFixtures.ValidMessage(), PythonInteropFixtures.ExamId,
            FirewallProfiles.All, PythonInteropFixtures.ValidEvalTime);
        Assert.True(activation.Success, activation.FailureReason);

        // Sanity: the exam actually changed something, so the comparison below is not vacuous.
        Assert.NotEqual(beforeExam, Snapshot());

        var deactivation = await _machine.DeactivateAsync(sessionId);

        Assert.True(deactivation.Success, deactivation.FailureReason);
        Assert.True(deactivation.RollbackCompleted);
        Assert.False(deactivation.ConflictDetected);
        Assert.Equal(beforeExam, Snapshot());
    }

    [Theory]
    [InlineData(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow)]
    [InlineData(FirewallAction.Block, FirewallAction.Allow, FirewallAction.Allow)]
    [InlineData(FirewallAction.Allow, FirewallAction.Block, FirewallAction.Allow)]
    [InlineData(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Block)]
    [InlineData(FirewallAction.Block, FirewallAction.Block, FirewallAction.Block)]
    public async Task Property_UnrelatedAndOtherSessionRulesAreIdenticalBeforeAndAfter(
        FirewallAction domain, FirewallAction priv, FirewallAction pub)
    {
        SetLiveProfiles(domain, priv, pub);

        // A second session that stays live throughout.
        var otherSessionId = Guid.NewGuid();
        var otherRule = Rule(otherSessionId, "OtherVendor", "198.51.100.60");
        _firewall.AddRule(otherRule);
        SeedSession(otherSessionId, EnforcementPhase.Active, FirewallProfiles.All,
            BaselineOf(domain, priv, pub), new[] { otherRule }, new[] { otherRule.Name });

        var unrelatedBefore = _firewall.UnrelatedRuleNames.OrderBy(n => n, StringComparer.Ordinal).ToList();
        var otherSessionBefore = _firewall.Rules
            .Where(r => r.SessionId == otherSessionId)
            .Select(r => r.Name).OrderBy(n => n, StringComparer.Ordinal).ToList();
        var beforeExam = Snapshot();

        var sessionId = Guid.NewGuid();
        var activation = await _machine.ActivateAsync(
            sessionId, PythonInteropFixtures.ValidMessage(), PythonInteropFixtures.ExamId,
            FirewallProfiles.All, PythonInteropFixtures.ValidEvalTime);
        Assert.True(activation.Success, activation.FailureReason);

        var deactivation = await _machine.DeactivateAsync(sessionId);
        Assert.True(deactivation.Success, deactivation.FailureReason);

        Assert.Equal(unrelatedBefore, _firewall.UnrelatedRuleNames.OrderBy(n => n, StringComparer.Ordinal));
        Assert.Equal(otherSessionBefore, _firewall.Rules
            .Where(r => r.SessionId == otherSessionId)
            .Select(r => r.Name).OrderBy(n => n, StringComparer.Ordinal));
        Assert.Equal(beforeExam, Snapshot());
        AssertNoAttemptOnUnrelatedRules();
    }

    [Fact]
    public void Property_TheSnapshotComparisonCanActuallyFail()
    {
        // A meta-test, and the reason it is here is concrete: before Phase 18 the mock could not
        // delete an unrelated rule at all, so every "unrelated rules preserved" assertion in the suite
        // was guaranteed to pass. This asserts that each field of the snapshot is genuinely sensitive
        // to the thing it claims to measure, so the equality checks above cannot become tautologies.
        SetLiveProfiles(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow);
        var reference = Snapshot();

        _firewall.DomainDefaultOutbound = FirewallAction.Block;
        Assert.NotEqual(reference, Snapshot());
        _firewall.DomainDefaultOutbound = FirewallAction.Allow;

        _firewall.PrivateDefaultOutbound = FirewallAction.Block;
        Assert.NotEqual(reference, Snapshot());
        _firewall.PrivateDefaultOutbound = FirewallAction.Allow;

        _firewall.PublicDefaultOutbound = FirewallAction.Block;
        Assert.NotEqual(reference, Snapshot());
        _firewall.PublicDefaultOutbound = FirewallAction.Allow;
        Assert.Equal(reference, Snapshot());

        var rule = Rule(Guid.NewGuid(), "Vendor");
        _firewall.AddRule(rule);
        Assert.NotEqual(reference, Snapshot());
        Assert.True(_firewall.RemoveRule(rule.Name));
        Assert.Equal(reference, Snapshot());

        // The one that used to be impossible: an unrelated rule really can be deleted through the
        // adapter, so its survival is a property the tests can fail on.
        Assert.True(_firewall.RemoveRule(MockFirewallAdapter.OffLimitsUnrelatedRuleName));
        Assert.NotEqual(reference, Snapshot());
    }

    // =========================================================================
    // STEP 9 - adversarial cases
    // =========================================================================

    [Fact]
    public async Task Adversarial_TwoOverlappingSessions_EachRollbackTouchesOnlyItsOwnRules()
    {
        SetLiveProfiles(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow);

        var sessionA = Guid.NewGuid();
        var sessionB = Guid.NewGuid();
        var ruleA1 = Rule(sessionA, "A1", "203.0.113.61");
        var ruleA2 = Rule(sessionA, "A2", "203.0.113.62");
        var ruleB1 = Rule(sessionB, "B1", "203.0.113.63");

        foreach (var r in new[] { ruleA1, ruleA2, ruleB1 }) _firewall.AddRule(r);

        SeedSession(sessionA, EnforcementPhase.Active, FirewallProfiles.All, AllAllow,
            new[] { ruleA1, ruleA2 }, new[] { ruleA1.Name, ruleA2.Name });
        SeedSession(sessionB, EnforcementPhase.Active, FirewallProfiles.All, AllAllow,
            new[] { ruleB1 }, new[] { ruleB1.Name });
        SetLiveProfiles(FirewallAction.Block, FirewallAction.Block, FirewallAction.Block);

        var rollbackA = await _enforcer.RemoveEnforcementAsync(sessionA);
        Assert.Equal(2, rollbackA.RulesRemovedCount);
        Assert.True(_firewall.RuleExists(ruleB1.Name));

        var rollbackB = await _enforcer.RemoveEnforcementAsync(sessionB);
        Assert.Equal(1, rollbackB.RulesRemovedCount);
        Assert.Empty(_firewall.Rules);

        AssertNoAttemptOnUnrelatedRules();
    }

    [Fact]
    public async Task Adversarial_ASimilarlyNamedThirdPartyRuleIsNeverTouched()
    {
        SetLiveProfiles(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow);

        // Names chosen to sit as close to the ownership boundary as possible without being inside it.
        var lookalikes = new[]
        {
            "SPEMCS Monitor (Out)",
            "SPEMCS-Legacy-Vendor",
            "spemcs-exam-helper",
            MockFirewallAdapter.OffLimitsUnrelatedRuleName,
        };
        foreach (var name in lookalikes)
        {
            if (!_firewall.UnrelatedRuleNames.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                _firewall.UnrelatedRuleNames.Add(name);
            }
        }

        var unrelatedBefore = _firewall.UnrelatedRuleNames.OrderBy(n => n, StringComparer.Ordinal).ToList();

        var sessionId = Guid.NewGuid();
        await _enforcer.ApplyEnforcementAsync(Session(sessionId, FirewallProfiles.All, Rule(sessionId, "Vendor")));
        await _enforcer.RemoveEnforcementAsync(sessionId);
        await NewEnforcer().RecoverIncompleteSessionAsync();

        Assert.Equal(unrelatedBefore, _firewall.UnrelatedRuleNames.OrderBy(n => n, StringComparer.Ordinal));
        foreach (var name in lookalikes)
        {
            Assert.DoesNotContain(name, _firewall.RemovalAttempts);
        }
    }

    [Fact]
    public async Task Adversarial_AnUnattributableRuleInsideTheGroupIsTreatedAsAnOrphan()
    {
        // A rule sitting in SPEMCS's own group whose name SPEMCS could not have generated: an older
        // naming scheme, or something planted to look like ours. It cannot belong to a live session,
        // and leaving an ALLOW rule installed is a standing hole on a host whose own baseline may be
        // deny-by-default - so it is cleaned, and logged distinctly from an attributable orphan.
        var impostor = Rule(Guid.NewGuid(), "Vendor") with { Name = "SPEMCS_LEGACY_VENDOR_RULE" };
        _firewall.AddRule(impostor);
        Assert.False(FirewallRuleModel.TryParseSessionId(impostor.Name, out _));

        var recovery = await NewEnforcer().RecoverIncompleteSessionAsync();

        Assert.True(recovery.RecoveryRequired);
        Assert.True(recovery.Success);
        Assert.Equal(1, recovery.OrphanRulesCleaned);
        Assert.False(_firewall.RuleExists(impostor.Name));

        // Containment: the sweep never reached outside the group.
        Assert.Equal(MockFirewallAdapter.DefaultUnrelatedRuleNames, _firewall.UnrelatedRuleNames);
        AssertNoAttemptOnUnrelatedRules();
    }

    [Fact]
    public async Task Adversarial_AnUnattributableRuleIsNotAttributedToTheLiveSession()
    {
        // The dangerous inverse of the previous test: a malformed name must not be coerced to some
        // nearby GUID and thereby inherit a live session's protection - nor, conversely, cause the live
        // session's own rules to be swept.
        var liveSessionId = Guid.NewGuid();
        var activation = await _machine.ActivateAsync(
            liveSessionId, PythonInteropFixtures.ValidMessage(), PythonInteropFixtures.ExamId,
            FirewallProfiles.All, PythonInteropFixtures.ValidEvalTime);
        Assert.True(activation.Success, activation.FailureReason);

        var liveRuleNames = _firewall.Rules.Select(r => r.Name).OrderBy(n => n, StringComparer.Ordinal).ToList();

        // Prefix + a GUID that is one character short of the live session's, then a purpose segment.
        var malformed = FirewallRuleModel.NamePrefix + liveSessionId.ToString("N")[..31] + "-Vendor";
        Assert.False(FirewallRuleModel.TryParseSessionId(malformed, out _));
        _firewall.AddRule(Rule(liveSessionId, "Vendor") with { Name = malformed });

        var recovery = await NewEnforcer().RecoverIncompleteSessionAsync();

        Assert.True(recovery.Success);
        Assert.Equal(1, recovery.OrphanRulesCleaned);
        Assert.False(_firewall.RuleExists(malformed));

        // The live session kept every rule, and its lockdown is intact.
        Assert.Equal(liveRuleNames, _firewall.Rules.Select(r => r.Name).OrderBy(n => n, StringComparer.Ordinal));
        Assert.Equal(FirewallAction.Block, _firewall.PrivateDefaultOutbound);
    }

    [Fact]
    public async Task Adversarial_AStaleRolledBackJournalRecordDoesNotResurrectEnforcement()
    {
        SetLiveProfiles(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow);
        var before = Snapshot();

        var sessionId = Guid.NewGuid();
        var rule = Rule(sessionId, "Vendor");
        SeedSession(sessionId, EnforcementPhase.RolledBack, FirewallProfiles.All,
            BaselineOf(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow),
            new[] { rule }, new[] { rule.Name });

        var recovery = await NewEnforcer().RecoverIncompleteSessionAsync();

        // Nothing to recover: the row is terminal, the firewall is clean.
        Assert.False(recovery.RecoveryRequired);
        Assert.True(recovery.Success);
        Assert.Equal(before, Snapshot());
        Assert.Empty(_firewall.RemovalAttempts);
        Assert.Empty(_firewall.DefaultActionWrites);
    }

    [Fact]
    public async Task Adversarial_ADisabledSpemcsRuleIsStillRemovedByItsOwner()
    {
        // A candidate with local admin who disables an allow rule instead of deleting it: rollback
        // matches on name and group, not on Enabled, so a disabled rule is not left behind as a
        // permanent fixture in the SPEMCS group.
        var sessionId = Guid.NewGuid();
        var disabled = Rule(sessionId, "Vendor") with { Enabled = false };

        SeedActiveLockdown(sessionId, AllAllow, new[] { disabled });

        var rollback = await _enforcer.RemoveEnforcementAsync(sessionId);

        Assert.Equal(1, rollback.RulesRemovedCount);
        Assert.Empty(_firewall.Rules);
    }

    [Fact]
    public async Task Adversarial_RollbackIsNotABroadFirewallCleanupOperation()
    {
        // The summary statement of Step 9: with unrelated rules, a live session, an orphan from a dead
        // session and an unattributable rule all present at once, rolling back ONE session must change
        // exactly that session's rules and nothing else.
        SetLiveProfiles(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow);

        var liveId = Guid.NewGuid();
        var liveRule = Rule(liveId, "Live", "198.51.100.81");
        _firewall.AddRule(liveRule);
        SeedSession(liveId, EnforcementPhase.Active, FirewallProfiles.All,
            BaselineOf(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow),
            new[] { liveRule }, new[] { liveRule.Name });

        var deadId = Guid.NewGuid();
        var orphanRule = Rule(deadId, "Orphan", "198.51.100.82");
        _firewall.AddRule(orphanRule);

        var unattributable = Rule(Guid.NewGuid(), "Weird") with { Name = "SPEMCS_NO_SESSION_HERE" };
        _firewall.AddRule(unattributable);

        var victimId = Guid.NewGuid();
        var apply = await _enforcer.ApplyEnforcementAsync(
            Session(victimId, FirewallProfiles.All, Rule(victimId, "Victim", "198.51.100.83")));
        Assert.True(apply.Success, apply.ErrorMessage);

        var namesBefore = _firewall.Rules.Select(r => r.Name).OrderBy(n => n, StringComparer.Ordinal).ToList();
        var unrelatedBefore = _firewall.UnrelatedRuleNames.OrderBy(n => n, StringComparer.Ordinal).ToList();

        var rollback = await _enforcer.RemoveEnforcementAsync(victimId);

        Assert.True(rollback.Success, rollback.ErrorMessage);
        Assert.Equal(1, rollback.RulesRemovedCount);

        // Exactly one name disappeared, and it was the victim's.
        var namesAfter = _firewall.Rules.Select(r => r.Name).OrderBy(n => n, StringComparer.Ordinal).ToList();
        var removed = namesBefore.Except(namesAfter, StringComparer.Ordinal).ToList();
        Assert.Single(removed);
        Assert.StartsWith(FirewallRuleModel.SessionNamePrefix(victimId), removed[0], StringComparison.Ordinal);

        // Everything else - live session, another session's orphan, the unattributable rule, and every
        // unrelated rule - is exactly as it was. Rollback is not a cleanup pass.
        Assert.True(_firewall.RuleExists(liveRule.Name));
        Assert.True(_firewall.RuleExists(orphanRule.Name));
        Assert.True(_firewall.RuleExists(unattributable.Name));
        Assert.Equal(unrelatedBefore, _firewall.UnrelatedRuleNames.OrderBy(n => n, StringComparer.Ordinal));
        AssertNoAttemptOnUnrelatedRules();
    }
}
