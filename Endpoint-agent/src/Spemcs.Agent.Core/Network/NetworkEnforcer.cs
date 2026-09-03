using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Spemcs.Agent.Core.Network;

/// <summary>
/// Core network enforcement engine for SPEMCS.
/// Implements INetworkEnforcer by orchestrating the Windows Firewall adapter and SQLite rollback journal.
/// </summary>
public sealed class NetworkEnforcer : INetworkEnforcer
{
    private readonly IFirewallAdapter _firewall;
    private readonly IRollbackJournal _journal;
    private readonly ILogger<NetworkEnforcer> _logger;
    private readonly object _syncRoot = new();

    public NetworkEnforcer(
        IFirewallAdapter firewall,
        IRollbackJournal journal,
        ILogger<NetworkEnforcer>? logger = null)
    {
        _firewall = firewall ?? throw new ArgumentNullException(nameof(firewall));
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _logger = logger ?? NullLogger<NetworkEnforcer>.Instance;
    }

    public Task<FirewallProfileBaseline> CaptureBaselineAsync(CancellationToken cancellationToken = default)
    {
        lock (_syncRoot)
        {
            var baseline = _firewall.GetBaseline();
            _logger.LogInformation("Captured firewall baseline. ActiveProfiles: {Profiles}, Domain: {Domain}, Private: {Private}, Public: {Public}",
                baseline.ActiveProfiles, baseline.DomainDefaultOutbound, baseline.PrivateDefaultOutbound, baseline.PublicDefaultOutbound);
            return Task.FromResult(baseline);
        }
    }

    public Task<ApplyResult> ApplyEnforcementAsync(EnforcementSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        lock (_syncRoot)
        {
            _logger.LogInformation("Starting enforcement application for Session: {SessionId}, Policy: {PolicyId} (v{Version})",
                session.SessionId, session.PolicyId, session.PolicyVersion);

            // 1. Capture current baseline
            var baseline = _firewall.GetBaseline();

            // 2. Persist PREPARED state to durable journal
            var record = new JournalRecord(
                SessionId: session.SessionId,
                PolicyId: session.PolicyId,
                PolicyVersion: session.PolicyVersion,
                Phase: EnforcementPhase.Prepared,
                StartUtc: DateTimeOffset.UtcNow,
                UpdatedUtc: DateTimeOffset.UtcNow,
                Baseline: baseline,
                TargetProfiles: session.TargetProfiles,
                IntendedRules: session.Rules,
                AppliedRuleNames: new List<string>(),
                LastError: null,
                ConflictDetails: null
            );
            _journal.SaveSession(record);

            var installedCount = 0;
            try
            {
                // 3. APPLYING RULES: Install each allow rule and journal immediately
                _journal.UpdatePhase(session.SessionId, EnforcementPhase.ApplyingRules);

                foreach (var rule in session.Rules)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    // Verify rule ownership group
                    if (rule.Group != FirewallRuleModel.SpemcsRuleGroup)
                    {
                        throw new InvalidOperationException($"Rule '{rule.Name}' must belong to group '{FirewallRuleModel.SpemcsRuleGroup}'");
                    }

                    _logger.LogDebug("Installing firewall rule: {RuleName} ({Protocol} -> {RemoteAddresses}:{RemotePorts})",
                        rule.Name, rule.Protocol, rule.RemoteAddresses, rule.RemotePorts);

                    _firewall.AddRule(rule);
                    _journal.RecordAppliedRule(session.SessionId, rule.Name);
                    installedCount++;
                }

                // 4. Verify all rules exist in firewall
                foreach (var rule in session.Rules)
                {
                    if (!_firewall.RuleExists(rule.Name))
                    {
                        throw new InvalidOperationException($"Firewall rule '{rule.Name}' could not be verified after installation.");
                    }
                }

                // 5. ENFORCING DEFAULT BLOCK
                _journal.UpdatePhase(session.SessionId, EnforcementPhase.EnforcingDefaultBlock);
                _logger.LogInformation("Switching DefaultOutboundAction to BLOCK for profiles: {Profiles}", session.TargetProfiles);

                _firewall.SetDefaultOutboundAction(session.TargetProfiles, FirewallAction.Block);

                // 6. ACTIVE: Transition complete
                _journal.UpdatePhase(session.SessionId, EnforcementPhase.Active);
                _logger.LogInformation("Enforcement successfully ACTIVE for Session: {SessionId}. Installed {Count} rules.",
                    session.SessionId, installedCount);

                return Task.FromResult(new ApplyResult(
                    Success: true,
                    SessionId: session.SessionId,
                    Phase: EnforcementPhase.Active,
                    RulesInstalledCount: installedCount
                ));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to apply enforcement for Session: {SessionId}. Initiating emergency rollback.", session.SessionId);
                _journal.UpdatePhase(session.SessionId, EnforcementPhase.Failed, ex.Message);

                // Execute safe rollback on failure
                PerformSafeRollbackInternal(session.SessionId, baseline, session.TargetProfiles, EnforcementPhase.Failed);

                return Task.FromResult(new ApplyResult(
                    Success: false,
                    SessionId: session.SessionId,
                    Phase: EnforcementPhase.Failed,
                    RulesInstalledCount: installedCount,
                    ErrorMessage: ex.Message
                ));
            }
        }
    }

    public Task<RollbackResult> RemoveEnforcementAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        lock (_syncRoot)
        {
            _logger.LogInformation("Removing enforcement for Session: {SessionId}", sessionId);
            var sessionRecord = _journal.GetSession(sessionId);
            var baseline = sessionRecord?.Baseline ?? _firewall.GetBaseline();
            var targetProfiles = sessionRecord?.TargetProfiles ?? baseline.ActiveProfiles;
            var currentPhase = sessionRecord?.Phase ?? EnforcementPhase.Active;

            var result = PerformSafeRollbackInternal(sessionId, baseline, targetProfiles, currentPhase);
            return Task.FromResult(result);
        }
    }

    public Task<RollbackResult> RestoreBaselineAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        lock (_syncRoot)
        {
            var sessionRecord = _journal.GetSession(sessionId);
            if (sessionRecord is null)
            {
                return Task.FromResult(new RollbackResult(
                    Success: false,
                    SessionId: sessionId,
                    RulesRemovedCount: 0,
                    BaselineRestored: false,
                    ConflictDetected: false,
                    ErrorMessage: "Session record not found in rollback journal."
                ));
            }

            var baselineResult = RestoreBaselineSafely(sessionId, sessionRecord.Baseline, sessionRecord.Baseline.ActiveProfiles);
            return Task.FromResult(new RollbackResult(
                Success: baselineResult.Success,
                SessionId: sessionId,
                RulesRemovedCount: 0,
                BaselineRestored: baselineResult.Restored,
                ConflictDetected: baselineResult.Conflict,
                ErrorMessage: baselineResult.Error
            ));
        }
    }

    public Task<EnforcementStateSnapshot> GetCurrentStateAsync(CancellationToken cancellationToken = default)
    {
        lock (_syncRoot)
        {
            var baseline = _firewall.GetBaseline();
            var spemcsRules = _firewall.GetRuleNamesByGroup(FirewallRuleModel.SpemcsRuleGroup);
            var activeSession = _journal.GetLatestActiveOrIncompleteSession();

            var isEnforcing = activeSession?.Phase == EnforcementPhase.Active && spemcsRules.Count > 0;

            var snapshot = new EnforcementStateSnapshot(
                IsEnforcing: isEnforcing,
                ActiveSessionId: isEnforcing ? activeSession?.SessionId : null,
                CurrentPhase: activeSession?.Phase ?? EnforcementPhase.RolledBack,
                Baseline: baseline,
                ActiveRuleCount: spemcsRules.Count,
                ActiveRuleNames: spemcsRules,
                SnapshotUtc: DateTimeOffset.UtcNow
            );

            return Task.FromResult(snapshot);
        }
    }

    public Task<RecoveryResult> RecoverIncompleteSessionAsync(CancellationToken cancellationToken = default)
    {
        lock (_syncRoot)
        {
            _logger.LogInformation("Executing startup reconciliation and crash recovery check.");

            var spemcsRules = _firewall.GetRuleNamesByGroup(FirewallRuleModel.SpemcsRuleGroup);
            var incompleteSession = _journal.GetLatestActiveOrIncompleteSession();

            // Case 1: Clean state - No incomplete sessions and no SPEMCS rules in firewall
            if (incompleteSession is null && spemcsRules.Count == 0)
            {
                _logger.LogInformation("Startup recovery: System is clean. No orphan rules or incomplete sessions found.");
                return Task.FromResult(new RecoveryResult(
                    RecoveryRequired: false,
                    Success: true,
                    RecoveredSessionId: null,
                    OrphanRulesCleaned: 0,
                    BaselineRestored: false,
                    ConflictDetected: false,
                    Details: "Clean state."
                ));
            }

            // Case 2: Incomplete or crashed session recorded in journal
            if (incompleteSession is not null)
            {
                _logger.LogWarning("Found incomplete/crashed session: {SessionId} in phase: {Phase}. Reconciling...",
                    incompleteSession.SessionId, incompleteSession.Phase);

                var rollbackResult = PerformSafeRollbackInternal(
                    incompleteSession.SessionId,
                    incompleteSession.Baseline,
                    incompleteSession.TargetProfiles,
                    incompleteSession.Phase
                );

                return Task.FromResult(new RecoveryResult(
                    RecoveryRequired: true,
                    Success: rollbackResult.Success,
                    RecoveredSessionId: incompleteSession.SessionId,
                    OrphanRulesCleaned: rollbackResult.RulesRemovedCount,
                    BaselineRestored: rollbackResult.BaselineRestored,
                    ConflictDetected: rollbackResult.ConflictDetected,
                    Details: $"Recovered session {incompleteSession.SessionId} from phase {incompleteSession.Phase}."
                ));
            }

            // Case 3: Orphan SPEMCS rules exist in firewall without active session
            _logger.LogWarning("Found {Count} orphan rules in group '{Group}' without an active session. Cleaning up...",
                spemcsRules.Count, FirewallRuleModel.SpemcsRuleGroup);

            var cleaned = 0;
            foreach (var ruleName in spemcsRules)
            {
                if (ruleName.StartsWith("SPEMCS-", StringComparison.OrdinalIgnoreCase))
                {
                    if (_firewall.RemoveRule(ruleName))
                    {
                        cleaned++;
                    }
                }
            }

            return Task.FromResult(new RecoveryResult(
                RecoveryRequired: true,
                Success: true,
                RecoveredSessionId: null,
                OrphanRulesCleaned: cleaned,
                BaselineRestored: false,
                ConflictDetected: false,
                Details: $"Cleaned {cleaned} orphan rules."
            ));
        }
    }

    private RollbackResult PerformSafeRollbackInternal(
        Guid sessionId,
        FirewallProfileBaseline baseline,
        FirewallProfiles targetProfiles,
        EnforcementPhase currentPhase)
    {
        _logger.LogInformation("Performing safe rollback for Session: {SessionId} from Phase: {Phase}", sessionId, currentPhase);

        // Step 1: Restore profile outbound baseline FIRST if default block was reached or applied
        var defaultBlockWasAttempted = currentPhase is EnforcementPhase.EnforcingDefaultBlock
            or EnforcementPhase.Active
            or EnforcementPhase.RollingBackDefault
            or EnforcementPhase.RollingBackRules
            or EnforcementPhase.Failed;

        (bool Success, bool Restored, bool Conflict, string? Error) baselineRestore;

        if (defaultBlockWasAttempted)
        {
            _journal.UpdatePhase(sessionId, EnforcementPhase.RollingBackDefault);
            baselineRestore = RestoreBaselineSafely(sessionId, baseline, targetProfiles);
        }
        else
        {
            // Default block was never set (e.g. crash/failure during Prepared or ApplyingRules)
            baselineRestore = (Success: true, Restored: false, Conflict: false, Error: null);
        }

        // Step 2: Remove SPEMCS-owned rules
        _journal.UpdatePhase(sessionId, EnforcementPhase.RollingBackRules);
        var removedCount = 0;

        // Query rules by group
        var spemcsRules = _firewall.GetRuleNamesByGroup(FirewallRuleModel.SpemcsRuleGroup);
        var sessionPrefix = $"SPEMCS-{sessionId:N}-";

        foreach (var ruleName in spemcsRules)
        {
            // Only remove rules that belong to this session or are SPEMCS-owned
            if (ruleName.StartsWith(sessionPrefix, StringComparison.OrdinalIgnoreCase) ||
                ruleName.StartsWith("SPEMCS-", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogDebug("Removing rule: {RuleName}", ruleName);
                if (_firewall.RemoveRule(ruleName))
                {
                    removedCount++;
                }
            }
        }

        // Step 3: Record final state
        var finalPhase = baselineRestore.Conflict ? EnforcementPhase.Conflict : EnforcementPhase.RolledBack;
        _journal.UpdatePhase(sessionId, finalPhase);

        _logger.LogInformation("Rollback complete for Session: {SessionId}. Rules removed: {Count}. Baseline restored: {Restored}. Conflict: {Conflict}",
            sessionId, removedCount, baselineRestore.Restored, baselineRestore.Conflict);

        return new RollbackResult(
            Success: !baselineRestore.Conflict,
            SessionId: sessionId,
            RulesRemovedCount: removedCount,
            BaselineRestored: baselineRestore.Restored,
            ConflictDetected: baselineRestore.Conflict,
            ErrorMessage: baselineRestore.Error
        );
    }

    private (bool Success, bool Restored, bool Conflict, string? Error) RestoreBaselineSafely(
        Guid sessionId,
        FirewallProfileBaseline baseline,
        FirewallProfiles targetProfiles)
    {
        try
        {
            var current = _firewall.GetBaseline();
            var conflictDetected = false;

            // Inspect each profile: only restore if the current action is still BLOCK (owned by SPEMCS).
            // If an external admin or GPO changed it away from BLOCK, yield and record conflict.
            if (targetProfiles.HasFlag(FirewallProfiles.Domain))
            {
                if (current.DomainDefaultOutbound == FirewallAction.Block)
                {
                    _firewall.SetDefaultOutboundAction(FirewallProfiles.Domain, baseline.DomainDefaultOutbound);
                }
                else
                {
                    _logger.LogWarning("Domain profile outbound default modified externally (Current: {Current}, expected SPEMCS Block). Yielding to external policy.", current.DomainDefaultOutbound);
                    conflictDetected = true;
                }
            }

            if (targetProfiles.HasFlag(FirewallProfiles.Private))
            {
                if (current.PrivateDefaultOutbound == FirewallAction.Block)
                {
                    _firewall.SetDefaultOutboundAction(FirewallProfiles.Private, baseline.PrivateDefaultOutbound);
                }
                else
                {
                    _logger.LogWarning("Private profile outbound default modified externally (Current: {Current}, expected SPEMCS Block). Yielding to external policy.", current.PrivateDefaultOutbound);
                    conflictDetected = true;
                }
            }

            if (targetProfiles.HasFlag(FirewallProfiles.Public))
            {
                if (current.PublicDefaultOutbound == FirewallAction.Block)
                {
                    _firewall.SetDefaultOutboundAction(FirewallProfiles.Public, baseline.PublicDefaultOutbound);
                }
                else
                {
                    _logger.LogWarning("Public profile outbound default modified externally (Current: {Current}, expected SPEMCS Block). Yielding to external policy.", current.PublicDefaultOutbound);
                    conflictDetected = true;
                }
            }

            if (conflictDetected)
            {
                _journal.RecordConflict(sessionId, "External administrator or GPO modified DefaultOutboundAction while SPEMCS was active.");
                return (false, false, true, "Conflict detected: External configuration modified outbound action.");
            }

            return (true, true, false, null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to restore firewall baseline for Session: {SessionId}", sessionId);
            return (false, false, false, ex.Message);
        }
    }
}
