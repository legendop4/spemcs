using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Spemcs.Agent.Core.Network;
using Xunit;

namespace Spemcs.Agent.Tests;

public class NetworkEnforcementUnitTests : IDisposable
{
    private readonly string _testDir;
    private readonly SqliteRollbackJournal _journal;
    private readonly MockFirewallAdapter _firewall;
    private readonly NetworkEnforcer _enforcer;

    public NetworkEnforcementUnitTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "Spemcs_Test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDir);
        _journal = new SqliteRollbackJournal(_testDir);
        _firewall = new MockFirewallAdapter();
        _enforcer = new NetworkEnforcer(_firewall, _journal);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testDir))
            {
                Directory.Delete(_testDir, recursive: true);
            }
        }
        catch
        {
            // Ignore cleanup errors on temp dirs
        }
    }

    [Fact]
    public void RuleName_IsDeterministic_AndContainsSessionAndHash()
    {
        var sessionId = Guid.NewGuid();
        var name1 = FirewallRuleModel.GenerateRuleName(sessionId, "Mgmt", "192.168.1.1", "8000");
        var name2 = FirewallRuleModel.GenerateRuleName(sessionId, "Mgmt", "192.168.1.1", "8000");

        Assert.Equal(name1, name2);
        Assert.StartsWith($"SPEMCS-{sessionId:N}-Mgmt-", name1);
    }

    [Fact]
    public void Journal_PersistsAndRetrievesSessionRecords()
    {
        var sessionId = Guid.NewGuid();
        var baseline = new FirewallProfileBaseline(
            DomainDefaultOutbound: FirewallAction.Allow,
            PrivateDefaultOutbound: FirewallAction.Allow,
            PublicDefaultOutbound: FirewallAction.Allow,
            ActiveProfiles: FirewallProfiles.Private | FirewallProfiles.Public,
            CapturedUtc: DateTimeOffset.UtcNow
        );

        var rule = FirewallRuleModel.CreateOutboundAllow(sessionId, "Mgmt", FirewallProtocol.TCP, "10.0.0.1", "8000");

        var record = new JournalRecord(
            SessionId: sessionId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            Phase: EnforcementPhase.Prepared,
            StartUtc: DateTimeOffset.UtcNow,
            UpdatedUtc: DateTimeOffset.UtcNow,
            Baseline: baseline,
            TargetProfiles: FirewallProfiles.Private | FirewallProfiles.Public,
            IntendedRules: new[] { rule },
            AppliedRuleNames: Array.Empty<string>(),
            LastError: null,
            ConflictDetails: null
        );

        _journal.SaveSession(record);

        var retrieved = _journal.GetSession(sessionId);
        Assert.NotNull(retrieved);
        Assert.Equal(sessionId, retrieved.SessionId);
        Assert.Equal(EnforcementPhase.Prepared, retrieved.Phase);
        Assert.Single(retrieved.IntendedRules);

        // Update phase & applied rule
        _journal.RecordAppliedRule(sessionId, rule.Name);
        _journal.UpdatePhase(sessionId, EnforcementPhase.Active);

        var updated = _journal.GetSession(sessionId);
        Assert.NotNull(updated);
        Assert.Equal(EnforcementPhase.Active, updated.Phase);
        Assert.Single(updated.AppliedRuleNames);
        Assert.Equal(rule.Name, updated.AppliedRuleNames[0]);
    }

    [Fact]
    public async Task ApplyEnforcement_InstallsRules_ThenSetsDefaultBlock()
    {
        var sessionId = Guid.NewGuid();
        var rule1 = FirewallRuleModel.CreateOutboundAllow(sessionId, "Mgmt", FirewallProtocol.TCP, "10.0.0.1", "8000");
        var rule2 = FirewallRuleModel.CreateOutboundAllow(sessionId, "Vendor", FirewallProtocol.TCP, "192.168.1.0/24", "443");

        var session = new EnforcementSession(
            SessionId: sessionId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            Rules: new[] { rule1, rule2 },
            TargetProfiles: FirewallProfiles.Private | FirewallProfiles.Public,
            CreatedUtc: DateTimeOffset.UtcNow
        );

        var result = await _enforcer.ApplyEnforcementAsync(session);

        Assert.True(result.Success);
        Assert.Equal(2, result.RulesInstalledCount);
        Assert.Equal(EnforcementPhase.Active, result.Phase);

        // Verify firewall state
        Assert.Equal(2, _firewall.Rules.Count);
        Assert.Equal(FirewallAction.Block, _firewall.PrivateDefaultOutbound);
        Assert.Equal(FirewallAction.Block, _firewall.PublicDefaultOutbound);
        Assert.Equal(FirewallAction.Allow, _firewall.DomainDefaultOutbound); // domain was not targeted

        // Verify journal state
        var snapshot = await _enforcer.GetCurrentStateAsync();
        Assert.True(snapshot.IsEnforcing);
        Assert.Equal(sessionId, snapshot.ActiveSessionId);
        Assert.Equal(2, snapshot.ActiveRuleCount);
    }

    [Fact]
    public async Task RemoveEnforcement_RestoresBaseline_AndDeletesRules()
    {
        var sessionId = Guid.NewGuid();
        var rule = FirewallRuleModel.CreateOutboundAllow(sessionId, "Mgmt", FirewallProtocol.TCP, "10.0.0.1", "8000");
        var session = new EnforcementSession(
            SessionId: sessionId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            Rules: new[] { rule },
            TargetProfiles: FirewallProfiles.Private | FirewallProfiles.Public,
            CreatedUtc: DateTimeOffset.UtcNow
        );

        await _enforcer.ApplyEnforcementAsync(session);
        Assert.Equal(FirewallAction.Block, _firewall.PrivateDefaultOutbound);

        // Remove
        var rollback = await _enforcer.RemoveEnforcementAsync(sessionId);
        Assert.True(rollback.Success);
        Assert.True(rollback.BaselineRestored);
        Assert.Equal(1, rollback.RulesRemovedCount);

        // Outbound default restored
        Assert.Equal(FirewallAction.Allow, _firewall.PrivateDefaultOutbound);
        Assert.Equal(FirewallAction.Allow, _firewall.PublicDefaultOutbound);
        Assert.Empty(_firewall.Rules);
    }

    [Fact]
    public async Task CrashSimulation_CrashDuringRuleApplication_StartupRecoveryRollsBack()
    {
        var sessionId = Guid.NewGuid();
        var rule1 = FirewallRuleModel.CreateOutboundAllow(sessionId, "Mgmt", FirewallProtocol.TCP, "10.0.0.1", "8000");
        var rule2 = FirewallRuleModel.CreateOutboundAllow(sessionId, "Vendor", FirewallProtocol.TCP, "192.168.1.0/24", "443");

        // Simulate crash right after rule1 is installed (phase: ApplyingRules)
        var baseline = _firewall.GetBaseline();
        var record = new JournalRecord(
            SessionId: sessionId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            Phase: EnforcementPhase.ApplyingRules,
            StartUtc: DateTimeOffset.UtcNow,
            UpdatedUtc: DateTimeOffset.UtcNow,
            Baseline: baseline,
            TargetProfiles: FirewallProfiles.Private | FirewallProfiles.Public,
            IntendedRules: new[] { rule1, rule2 },
            AppliedRuleNames: new[] { rule1.Name },
            LastError: null,
            ConflictDetails: null
        );
        _journal.SaveSession(record);
        _firewall.AddRule(rule1); // rule1 was installed in firewall before crash

        // Simulate service restart: new enforcer instance starts up
        var newEnforcer = new NetworkEnforcer(_firewall, _journal);
        var recovery = await newEnforcer.RecoverIncompleteSessionAsync();

        Assert.True(recovery.RecoveryRequired);
        Assert.True(recovery.Success);
        Assert.Equal(sessionId, recovery.RecoveredSessionId);
        Assert.Equal(1, recovery.OrphanRulesCleaned);

        // Verify rule was removed and firewall is clean
        Assert.Empty(_firewall.Rules);
    }

    [Fact]
    public async Task ConflictDetection_ExternalAdminChangedDefault_YieldsToAdmin()
    {
        var sessionId = Guid.NewGuid();
        var rule = FirewallRuleModel.CreateOutboundAllow(sessionId, "Mgmt", FirewallProtocol.TCP, "10.0.0.1", "8000");
        var session = new EnforcementSession(
            SessionId: sessionId,
            PolicyId: Guid.NewGuid(),
            PolicyVersion: 1,
            Rules: new[] { rule },
            TargetProfiles: FirewallProfiles.Private,
            CreatedUtc: DateTimeOffset.UtcNow
        );

        await _enforcer.ApplyEnforcementAsync(session);

        // Simulate external administrator or GPO setting Private default back to Allow or changing it
        _firewall.PrivateDefaultOutbound = FirewallAction.Allow;

        // When SPEMCS attempts to rollback/restore baseline:
        var rollback = await _enforcer.RemoveEnforcementAsync(sessionId);

        // Must detect conflict and NOT overwrite external admin configuration
        Assert.True(rollback.ConflictDetected);
        Assert.False(rollback.BaselineRestored);
        Assert.Equal(1, rollback.RulesRemovedCount); // Rules still cleaned up safely

        var journalRecord = _journal.GetSession(sessionId);
        Assert.NotNull(journalRecord);
        Assert.Equal(EnforcementPhase.Conflict, journalRecord.Phase);
        Assert.NotNull(journalRecord.ConflictDetails);
    }

    [Fact]
    public async Task OrphanRules_CleanedUpSafely_WithoutTouchingUnrelatedRules()
    {
        // Put unrelated rules in the firewall
        _firewall.UnrelatedRuleNames.Add("Enterprise Security Agent (Out)");

        // Put an orphan SPEMCS rule in the firewall without any active session in journal
        var orphanRule = FirewallRuleModel.CreateOutboundAllow(Guid.NewGuid(), "StaleSession", FirewallProtocol.TCP, "10.1.1.1", "80");
        _firewall.AddRule(orphanRule);

        Assert.True(_firewall.RuleExists(orphanRule.Name));
        Assert.True(_firewall.RuleExists("Enterprise Security Agent (Out)"));

        // Run startup recovery
        var recovery = await _enforcer.RecoverIncompleteSessionAsync();

        Assert.True(recovery.RecoveryRequired);
        Assert.True(recovery.Success);
        Assert.Equal(1, recovery.OrphanRulesCleaned);

        // SPEMCS orphan rule is removed
        Assert.False(_firewall.RuleExists(orphanRule.Name));

        // Unrelated rules are COMPLETELY UNTOUCHED
        Assert.True(_firewall.RuleExists("Enterprise Security Agent (Out)"));
        Assert.True(_firewall.RuleExists("Core Networking (DNS-Out)"));
    }
}
