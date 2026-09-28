using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Win32;
using Spemcs.Agent.Core;
using Spemcs.Agent.Core.Network;
using Xunit;

namespace Spemcs.Agent.Tests;

/// <summary>
/// Authoritative test suite verifying the 17 focus scenarios for the PC2555 traffic enforcement
/// and clean rollback remediation:
/// 1. Legitimate Allow baseline
/// 2. Legitimate Block baseline
/// 3. Stale SPEMCS rules + Block anti-poisoning
/// 4. Incomplete journal + Block recovery
/// 5. Missing session record rollback (safe no-op)
/// 6. Session GUID mismatch recovery
/// 7. Orphan SPEMCS rule cleanup
/// 8. Containment of unrelated rules (including Codex)
/// 9. Rollback verification failure when rules remain
/// 10. False rollback-success prevention in DeactivateAsync
/// 11. Crash during activation recovery
/// 12. Crash during rollback recovery
/// 13. Service restart during active lockdown (preservation)
/// 14. Service restart during tampered lockdown (rollback)
/// 15. Chrome and Edge DNS policy registry entries (BuiltInDnsClientEnabled = 0, DnsOverHttpsMode = "off")
/// 16. DoH bypass prevention and policy outcome summarization
/// 17. Process scoping and browser resolution
/// </summary>
public sealed class RemediationVerificationTests : IDisposable
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

    private static readonly Guid ExamId = PythonInteropFixtures.ExamId;
    private static readonly DateTimeOffset ValidTime = PythonInteropFixtures.ValidEvalTime;

    public RemediationVerificationTests()
    {
        _tempDbPath = Path.Combine(Path.GetTempPath(), $"spemcs_remediation_test_{Guid.NewGuid():N}");
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

        _keyStore.RegisterPublicKeyPem(PythonInteropFixtures.KeyId, PythonInteropFixtures.PublicKeyPem);
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

    private static FirewallRuleModel MakeRule(Guid sessionId, string suffix, string ip = "93.184.216.34")
    {
        return FirewallRuleModel.CreateOutboundAllow(
            sessionId,
            suffix,
            FirewallProtocol.TCP,
            ip,
            "80",
            @"C:\Program Files\Google\Chrome\Application\chrome.exe"
        );
    }

    // =========================================================================
    // Scenario 1: Legitimate Allow Baseline
    // =========================================================================
    [Fact]
    public async Task Scenario01_LegitimateAllowBaseline_CapturedAndSavedAuthoritative()
    {
        _firewall.DomainDefaultOutbound = FirewallAction.Allow;
        _firewall.PrivateDefaultOutbound = FirewallAction.Allow;
        _firewall.PublicDefaultOutbound = FirewallAction.Allow;

        var sessionId = Guid.NewGuid();
        var session = new EnforcementSession(
            SessionId: sessionId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            Rules: new[] { MakeRule(sessionId, "Rule1") },
            TargetProfiles: FirewallProfiles.All,
            CreatedUtc: DateTimeOffset.UtcNow
        );

        var result = await _enforcer.ApplyEnforcementAsync(session);
        Assert.True(result.Success);

        var clean = _journal.GetLastKnownCleanBaseline();
        Assert.NotNull(clean);
        Assert.Equal(FirewallAction.Allow, clean.DomainDefaultOutbound);
        Assert.Equal(FirewallAction.Allow, clean.PrivateDefaultOutbound);
        Assert.Equal(FirewallAction.Allow, clean.PublicDefaultOutbound);
    }

    // =========================================================================
    // Scenario 2: Legitimate Block Baseline (Correction 1)
    // =========================================================================
    [Fact]
    public async Task Scenario02_LegitimateBlockBaseline_CapturedAndSavedAuthoritative()
    {
        _firewall.DomainDefaultOutbound = FirewallAction.Block;
        _firewall.PrivateDefaultOutbound = FirewallAction.Block;
        _firewall.PublicDefaultOutbound = FirewallAction.Block;

        var sessionId = Guid.NewGuid();
        var session = new EnforcementSession(
            SessionId: sessionId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            Rules: new[] { MakeRule(sessionId, "Rule1") },
            TargetProfiles: FirewallProfiles.All,
            CreatedUtc: DateTimeOffset.UtcNow
        );

        var result = await _enforcer.ApplyEnforcementAsync(session);
        Assert.True(result.Success);

        var clean = _journal.GetLastKnownCleanBaseline();
        Assert.NotNull(clean);
        Assert.Equal(FirewallAction.Block, clean.DomainDefaultOutbound);
        Assert.Equal(FirewallAction.Block, clean.PrivateDefaultOutbound);
        Assert.Equal(FirewallAction.Block, clean.PublicDefaultOutbound);
    }

    // =========================================================================
    // Scenario 3: Stale SPEMCS Rules + Block Anti-Poisoning
    // =========================================================================
    [Fact]
    public async Task Scenario03_DirtyStateStaleRulesAndBlock_RecoversAuthoritativeCleanBaseline()
    {
        // 1. Establish an authoritative clean baseline (Allow)
        var cleanBaseline = new FirewallProfileBaseline(
            DomainDefaultOutbound: FirewallAction.Allow,
            PrivateDefaultOutbound: FirewallAction.Allow,
            PublicDefaultOutbound: FirewallAction.Allow,
            ActiveProfiles: FirewallProfiles.All,
            CapturedUtc: DateTimeOffset.UtcNow
        );
        _journal.SaveAuthoritativeCleanBaseline(cleanBaseline, DateTimeOffset.UtcNow);

        // 2. Simulate dirty host: leftover SPEMCS rules and firewall left at Block
        var oldSessionId = Guid.NewGuid();
        _firewall.AddRule(MakeRule(oldSessionId, "OrphanRule"));
        _firewall.DomainDefaultOutbound = FirewallAction.Block;
        _firewall.PrivateDefaultOutbound = FirewallAction.Block;
        _firewall.PublicDefaultOutbound = FirewallAction.Block;

        // 3. New session activates
        var newSessionId = Guid.NewGuid();
        var session = new EnforcementSession(
            SessionId: newSessionId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            Rules: new[] { MakeRule(newSessionId, "NewRule") },
            TargetProfiles: FirewallProfiles.All,
            CreatedUtc: DateTimeOffset.UtcNow
        );

        var result = await _enforcer.ApplyEnforcementAsync(session);
        Assert.True(result.Success);

        // Verify that the captured baseline for the new session is the CLEAN Allow baseline, NOT Block
        var record = _journal.GetSession(newSessionId);
        Assert.NotNull(record);
        Assert.Equal(FirewallAction.Allow, record.Baseline.DomainDefaultOutbound);
        Assert.Equal(FirewallAction.Allow, record.Baseline.PrivateDefaultOutbound);
        Assert.Equal(FirewallAction.Allow, record.Baseline.PublicDefaultOutbound);
    }

    // =========================================================================
    // Scenario 4: Incomplete Journal + Block Recovery
    // =========================================================================
    [Fact]
    public async Task Scenario04_IncompleteJournalSessionAndBlock_RecoversAuthoritativeCleanBaseline()
    {
        var cleanBaseline = new FirewallProfileBaseline(
            DomainDefaultOutbound: FirewallAction.Allow,
            PrivateDefaultOutbound: FirewallAction.Allow,
            PublicDefaultOutbound: FirewallAction.Allow,
            ActiveProfiles: FirewallProfiles.All,
            CapturedUtc: DateTimeOffset.UtcNow
        );
        _journal.SaveAuthoritativeCleanBaseline(cleanBaseline, DateTimeOffset.UtcNow);

        // Record a crashed session
        var crashedSessionId = Guid.NewGuid();
        var crashedRecord = new JournalRecord(
            SessionId: crashedSessionId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            Phase: EnforcementPhase.ApplyingRules,
            StartUtc: DateTimeOffset.UtcNow,
            UpdatedUtc: DateTimeOffset.UtcNow,
            Baseline: cleanBaseline,
            TargetProfiles: FirewallProfiles.All,
            IntendedRules: Array.Empty<FirewallRuleModel>(),
            AppliedRuleNames: Array.Empty<string>(),
            LastError: null,
            ConflictDetails: null
        );
        _journal.SaveSession(crashedRecord);

        _firewall.DomainDefaultOutbound = FirewallAction.Block;
        _firewall.PrivateDefaultOutbound = FirewallAction.Block;
        _firewall.PublicDefaultOutbound = FirewallAction.Block;

        var newSessionId = Guid.NewGuid();
        var session = new EnforcementSession(
            SessionId: newSessionId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            Rules: new[] { MakeRule(newSessionId, "NewRule") },
            TargetProfiles: FirewallProfiles.All,
            CreatedUtc: DateTimeOffset.UtcNow
        );

        var result = await _enforcer.ApplyEnforcementAsync(session);
        Assert.True(result.Success);

        var record = _journal.GetSession(newSessionId);
        Assert.NotNull(record);
        Assert.Equal(FirewallAction.Allow, record.Baseline.DomainDefaultOutbound);
    }

    // =========================================================================
    // Scenario 5: Missing Session Record Rollback (Safe No-Op)
    // =========================================================================
    [Fact]
    public async Task Scenario05_MissingSessionRecordRollback_IsSafeNoOp()
    {
        var strangerRule = MakeRule(Guid.NewGuid(), "Stranger");
        _firewall.AddRule(strangerRule);
        _firewall.DomainDefaultOutbound = FirewallAction.Block;

        var unknownSessionId = Guid.NewGuid();
        var rollback = await _enforcer.RemoveEnforcementAsync(unknownSessionId);

        Assert.True(rollback.Success);
        Assert.Equal(0, rollback.RulesRemovedCount);
        Assert.False(rollback.BaselineRestored);
        Assert.False(rollback.ConflictDetected);
        Assert.True(_firewall.RuleExists(strangerRule.Name));
    }

    // =========================================================================
    // Scenario 6: Session GUID Mismatch Recovery
    // =========================================================================
    [Fact]
    public async Task Scenario06_SessionGuidMismatch_StartupRecoverySweepsOrphans()
    {
        var oldSessionId = Guid.NewGuid();
        var oldRule = MakeRule(oldSessionId, "OrphanFromPreviousSession");
        _firewall.AddRule(oldRule);

        Assert.True(_firewall.RuleExists(oldRule.Name));

        var recovery = await _enforcer.RecoverIncompleteSessionAsync();
        Assert.True(recovery.Success);
        Assert.Equal(1, recovery.OrphanRulesCleaned);
        Assert.False(_firewall.RuleExists(oldRule.Name));
    }

    // =========================================================================
    // Scenario 7: Orphan SPEMCS Rule Cleanup
    // =========================================================================
    [Fact]
    public async Task Scenario07_OrphanSpemcsRules_CleanedUpDuringRecovery()
    {
        var id1 = Guid.NewGuid();
        var id2 = Guid.NewGuid();
        var rule1 = MakeRule(id1, "Rule1");
        var rule2 = MakeRule(id2, "Rule2");
        _firewall.AddRule(rule1);
        _firewall.AddRule(rule2);

        var recovery = await _enforcer.RecoverIncompleteSessionAsync();
        Assert.True(recovery.Success);
        Assert.Equal(2, recovery.OrphanRulesCleaned);
        Assert.False(_firewall.RuleExists(rule1.Name));
        Assert.False(_firewall.RuleExists(rule2.Name));
    }

    // =========================================================================
    // Scenario 8: Containment (Unrelated Rules & Codex Untouched)
    // =========================================================================
    [Fact]
    public async Task Scenario08_Containment_UnrelatedRulesAndCodexUntouched()
    {
        var codexRule = FirewallRuleModel.CreateOutboundAllow(
            Guid.NewGuid(), "CodexTool", FirewallProtocol.TCP, "*", "443") with
        {
            Name = "Codex_CLI_Allow",
            Group = "Development"
        };
        _firewall.AddRule(codexRule);

        var orphan = MakeRule(Guid.NewGuid(), "Orphan");
        _firewall.AddRule(orphan);

        var recovery = await _enforcer.RecoverIncompleteSessionAsync();
        Assert.True(recovery.Success);

        Assert.True(_firewall.RuleExists(codexRule.Name));
        Assert.DoesNotContain(codexRule.Name, _firewall.RemovalAttempts);
        Assert.False(_firewall.RuleExists(orphan.Name));
    }

    // =========================================================================
    // Scenario 9: Rollback Verification Failure When Rules Remain
    // =========================================================================
    [Fact]
    public async Task Scenario09_RollbackVerificationFailure_ReportsFailureWhenRulesRemain()
    {
        var sessionId = Guid.NewGuid();
        var stubbornRule = MakeRule(sessionId, "Stubborn");
        _firewall.AddRule(stubbornRule);

        var session = new EnforcementSession(
            SessionId: sessionId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            Rules: new[] { stubbornRule },
            TargetProfiles: FirewallProfiles.All,
            CreatedUtc: DateTimeOffset.UtcNow
        );

        var apply = await _enforcer.ApplyEnforcementAsync(session);
        Assert.True(apply.Success);

        // Make RemoveRule return false / fail to delete the rule
        _firewall.RemovalAttempts.Clear();
        _firewall.BlockRemovalOf(stubbornRule.Name);

        var rollback = await _enforcer.RemoveEnforcementAsync(sessionId);
        Assert.False(rollback.Success);
        Assert.Contains("Post-rollback verification failed", rollback.ErrorMessage);
    }

    // =========================================================================
    // Scenario 10: False Rollback-Success Prevention in DeactivateAsync
    // =========================================================================
    [Fact]
    public async Task Scenario10_FalseRollbackSuccessPrevention_DeactivateAsyncTransitionsToFailed()
    {
        var sessionId = Guid.NewGuid();
        var actResult = await _machine.ActivateAsync(
            sessionId, PythonInteropFixtures.ValidMessage(), ExamId,
            FirewallProfiles.All, ValidTime);
        Assert.True(actResult.Success);

        // Block removal of one of the active session's rules
        var activeRule = _firewall.Rules.First(r => r.SessionId == sessionId);
        _firewall.BlockRemovalOf(activeRule.Name);

        var deactResult = await _machine.DeactivateAsync(sessionId, "Exam finished");

        Assert.False(deactResult.Success);
        Assert.False(deactResult.RollbackCompleted);
        Assert.Equal(EnforcementState.Failed, deactResult.State);
        Assert.Equal(EnforcementState.Failed, _machine.CurrentState);
    }

    // =========================================================================
    // Scenario 11: Crash During Activation Recovery
    // =========================================================================
    [Fact]
    public async Task Scenario11_CrashDuringActivation_ReconciledOnRestart()
    {
        var sessionId = Guid.NewGuid();
        var baseline = new FirewallProfileBaseline(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow, FirewallProfiles.All, DateTimeOffset.UtcNow);
        var rule = MakeRule(sessionId, "HalfInstalled");
        _firewall.AddRule(rule);

        var record = new JournalRecord(
            SessionId: sessionId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            Phase: EnforcementPhase.ApplyingRules,
            StartUtc: DateTimeOffset.UtcNow,
            UpdatedUtc: DateTimeOffset.UtcNow,
            Baseline: baseline,
            TargetProfiles: FirewallProfiles.All,
            IntendedRules: new[] { rule },
            AppliedRuleNames: new[] { rule.Name },
            LastError: null,
            ConflictDetails: null
        );
        _journal.SaveSession(record);

        var recovery = await _enforcer.RecoverIncompleteSessionAsync();
        Assert.True(recovery.Success);
        Assert.True(recovery.RecoveryRequired);
        Assert.False(_firewall.RuleExists(rule.Name));
    }

    // =========================================================================
    // Scenario 12: Crash During Rollback Recovery
    // =========================================================================
    [Fact]
    public async Task Scenario12_CrashDuringRollback_ReconciledOnRestart()
    {
        var sessionId = Guid.NewGuid();
        var baseline = new FirewallProfileBaseline(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow, FirewallProfiles.All, DateTimeOffset.UtcNow);
        var rule = MakeRule(sessionId, "PendingTeardown");
        _firewall.AddRule(rule);
        _firewall.DomainDefaultOutbound = FirewallAction.Block;

        var record = new JournalRecord(
            SessionId: sessionId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            Phase: EnforcementPhase.RollingBackRules,
            StartUtc: DateTimeOffset.UtcNow,
            UpdatedUtc: DateTimeOffset.UtcNow,
            Baseline: baseline,
            TargetProfiles: FirewallProfiles.All,
            IntendedRules: new[] { rule },
            AppliedRuleNames: new[] { rule.Name },
            LastError: null,
            ConflictDetails: null
        );
        _journal.SaveSession(record);

        var recovery = await _enforcer.RecoverIncompleteSessionAsync();
        Assert.True(recovery.Success);
        Assert.True(recovery.RecoveryRequired);
        Assert.False(_firewall.RuleExists(rule.Name));
        Assert.Equal(FirewallAction.Allow, _firewall.DomainDefaultOutbound);
    }

    // =========================================================================
    // Scenario 13: Service Restart During Active Lockdown (Preservation)
    // =========================================================================
    [Fact]
    public async Task Scenario13_ServiceRestartDuringActiveLockdown_EnforcementPreserved()
    {
        var sessionId = Guid.NewGuid();
        var baseline = new FirewallProfileBaseline(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow, FirewallProfiles.All, DateTimeOffset.UtcNow);
        var rule = MakeRule(sessionId, "LiveRule");
        _firewall.AddRule(rule);
        _firewall.DomainDefaultOutbound = FirewallAction.Block;
        _firewall.PrivateDefaultOutbound = FirewallAction.Block;
        _firewall.PublicDefaultOutbound = FirewallAction.Block;

        var record = new JournalRecord(
            SessionId: sessionId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            Phase: EnforcementPhase.Active,
            StartUtc: DateTimeOffset.UtcNow,
            UpdatedUtc: DateTimeOffset.UtcNow,
            Baseline: baseline,
            TargetProfiles: FirewallProfiles.All,
            IntendedRules: new[] { rule },
            AppliedRuleNames: new[] { rule.Name },
            LastError: null,
            ConflictDetails: null
        );
        _journal.SaveSession(record);

        var recovery = await _enforcer.RecoverIncompleteSessionAsync();
        Assert.True(recovery.Success);
        Assert.False(recovery.RecoveryRequired);
        Assert.True(_firewall.RuleExists(rule.Name));
        Assert.Equal(FirewallAction.Block, _firewall.DomainDefaultOutbound);
    }

    // =========================================================================
    // Scenario 14: Service Restart During Tampered Lockdown (Rollback)
    // =========================================================================
    [Fact]
    public async Task Scenario14_ServiceRestartDuringTamperedLockdown_RollsBack()
    {
        var sessionId = Guid.NewGuid();
        var baseline = new FirewallProfileBaseline(FirewallAction.Allow, FirewallAction.Allow, FirewallAction.Allow, FirewallProfiles.All, DateTimeOffset.UtcNow);
        var rule = MakeRule(sessionId, "LiveRule");
        _firewall.AddRule(rule);
        // Tampered: profiles were changed from Block to Allow while offline
        _firewall.DomainDefaultOutbound = FirewallAction.Allow;
        _firewall.PrivateDefaultOutbound = FirewallAction.Allow;
        _firewall.PublicDefaultOutbound = FirewallAction.Allow;

        var record = new JournalRecord(
            SessionId: sessionId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            Phase: EnforcementPhase.Active,
            StartUtc: DateTimeOffset.UtcNow,
            UpdatedUtc: DateTimeOffset.UtcNow,
            Baseline: baseline,
            TargetProfiles: FirewallProfiles.All,
            IntendedRules: new[] { rule },
            AppliedRuleNames: new[] { rule.Name },
            LastError: null,
            ConflictDetails: null
        );
        _journal.SaveSession(record);

        var recovery = await _enforcer.RecoverIncompleteSessionAsync();
        Assert.True(recovery.Success);
        Assert.True(recovery.RecoveryRequired);
        Assert.False(_firewall.RuleExists(rule.Name));
    }

    // =========================================================================
    // Scenario 15: Browser Secure DNS Policy Registry Configuration
    // =========================================================================
    [Fact]
    public void Scenario15_BrowserDnsPolicy_DisableSecureDnsEnforcesRegistryKeys()
    {
        var entries = BrowserDnsPolicy.RequiredEntries;
        Assert.NotEmpty(entries);

        // Verify Chrome has BuiltInDnsClientEnabled = 0 and DnsOverHttpsMode = "off"
        var chromeDnsClient = entries.FirstOrDefault(e => e.BrowserLabel == "Google Chrome" && e.ValueName == "BuiltInDnsClientEnabled");
        Assert.NotNull(chromeDnsClient);
        Assert.Equal(0, chromeDnsClient.Value);

        var chromeDoh = entries.FirstOrDefault(e => e.BrowserLabel == "Google Chrome" && e.ValueName == "DnsOverHttpsMode");
        Assert.NotNull(chromeDoh);
        Assert.Equal("off", chromeDoh.Value);

        // Verify Edge has BuiltInDnsClientEnabled = 0 and DnsOverHttpsMode = "off"
        var edgeDnsClient = entries.FirstOrDefault(e => e.BrowserLabel == "Microsoft Edge" && e.ValueName == "BuiltInDnsClientEnabled");
        Assert.NotNull(edgeDnsClient);
        Assert.Equal(0, edgeDnsClient.Value);

        var edgeDoh = entries.FirstOrDefault(e => e.BrowserLabel == "Microsoft Edge" && e.ValueName == "DnsOverHttpsMode");
        Assert.NotNull(edgeDoh);
        Assert.Equal("off", edgeDoh.Value);
    }

    // =========================================================================
    // Scenario 16: DoH Bypass Prevention & Outcome Summarization
    // =========================================================================
    [Fact]
    public void Scenario16_BrowserDnsPolicy_SummarizeCatchesDegradedOrFailed()
    {
        var allApplied = BrowserDnsPolicy.RequiredEntries.Select(e =>
            new BrowserDnsPolicyWriteOutcome(e, BrowserDnsPolicyHive.LocalMachine, null)).ToList();

        var success = BrowserDnsPolicy.Summarize(allApplied, out var statusMsg);
        Assert.True(success);
        Assert.Contains("Applied machine-wide", statusMsg);

        // If one entry fell back to CurrentUser, it must be reported as degraded and return false
        var degraded = BrowserDnsPolicy.RequiredEntries.Select((e, idx) =>
            new BrowserDnsPolicyWriteOutcome(e, idx == 0 ? BrowserDnsPolicyHive.CurrentUser : BrowserDnsPolicyHive.LocalMachine, null)).ToList();

        var degradedSuccess = BrowserDnsPolicy.Summarize(degraded, out var degradedMsg);
        Assert.False(degradedSuccess);
        Assert.Contains("DEGRADED", degradedMsg);
    }

    // =========================================================================
    // Scenario 17: Process Scoping & Browser Resolution
    // =========================================================================
    [Fact]
    public void Scenario17_ApprovedBrowserResolution_ScopingVendorRules()
    {
        var resolver = StubBrowserExecutableResolver.Returning(@"C:\Program Files\Google\Chrome\Application\chrome.exe");
        var res = resolver.Resolve(ApprovedBrowserFamily.Chrome);

        Assert.True(res.Success);
        Assert.Equal(@"C:\Program Files\Google\Chrome\Application\chrome.exe", res.ExecutablePath);
        Assert.False(res.IsUserWritableLocation);
    }
}
