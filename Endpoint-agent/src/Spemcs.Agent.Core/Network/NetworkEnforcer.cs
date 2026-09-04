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
            _logger.LogInformation("Active runtime firewall profile bitmask: {Profiles} ({ProfileNames}), Domain={Domain}, Private={Private}, Public={Public}",
                baseline.ActiveProfiles, baseline.ActiveProfiles.ToString(), baseline.DomainDefaultOutbound, baseline.PrivateDefaultOutbound, baseline.PublicDefaultOutbound);

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

                // 4. READ BACK AND VERIFY ALL INSTALLED RULES BEFORE BLOCK (Requirements 4, 5, 6, 7, 10)
                LogAndVerifyRules("BEFORE_BLOCK", session.Rules, baseline.ActiveProfiles);

                // 5. ENFORCING DEFAULT BLOCK: Only AFTER all allow rules are verified!
                _journal.UpdatePhase(session.SessionId, EnforcementPhase.EnforcingDefaultBlock);
                _logger.LogInformation("Switching DefaultOutboundAction to BLOCK for profiles: {Profiles}", session.TargetProfiles);

                _firewall.SetDefaultOutboundAction(session.TargetProfiles, FirewallAction.Block);

                // Verify readback of DefaultOutboundAction immediately
                var activeBaseline = _firewall.GetBaseline();
                _logger.LogInformation("Effective firewall baseline after BLOCK: Domain={Domain}, Private={Private}, Public={Public}, ActiveProfiles={ActiveProfiles}",
                    activeBaseline.DomainDefaultOutbound, activeBaseline.PrivateDefaultOutbound, activeBaseline.PublicDefaultOutbound, activeBaseline.ActiveProfiles);

                if (session.TargetProfiles.HasFlag(FirewallProfiles.Domain) && activeBaseline.DomainDefaultOutbound != FirewallAction.Block)
                    throw new InvalidOperationException("Domain profile DefaultOutboundAction failed to apply BLOCK.");
                if (session.TargetProfiles.HasFlag(FirewallProfiles.Private) && activeBaseline.PrivateDefaultOutbound != FirewallAction.Block)
                    throw new InvalidOperationException("Private profile DefaultOutboundAction failed to apply BLOCK.");
                if (session.TargetProfiles.HasFlag(FirewallProfiles.Public) && activeBaseline.PublicDefaultOutbound != FirewallAction.Block)
                    throw new InvalidOperationException("Public profile DefaultOutboundAction failed to apply BLOCK.");

                // CRITICAL Requirement 10: Log rule details immediately AFTER setting block
                LogAndVerifyRules("AFTER_BLOCK", session.Rules, activeBaseline.ActiveProfiles);

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
                var failurePhase = _journal.GetSession(session.SessionId)?.Phase ?? EnforcementPhase.ApplyingRules;
                _journal.UpdatePhase(session.SessionId, EnforcementPhase.Failed, ex.Message);

                // Execute safe rollback on failure using the phase where failure occurred
                PerformSafeRollbackInternal(session.SessionId, baseline, session.TargetProfiles, failurePhase);

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
            if (sessionRecord is null)
            {
                _logger.LogInformation("No active enforcement session recorded for Session: {SessionId}. Nothing to remove.", sessionId);
                return Task.FromResult(new RollbackResult(
                    Success: true,
                    SessionId: sessionId,
                    RulesRemovedCount: 0,
                    BaselineRestored: false,
                    ConflictDetected: false,
                    ErrorMessage: null
                ));
            }

            var baseline = sessionRecord.Baseline;
            var targetProfiles = sessionRecord.TargetProfiles;
            var currentPhase = sessionRecord.Phase;

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
            or EnforcementPhase.RollingBackRules;

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

            void RestoreProfile(FirewallProfiles profile, FirewallAction currentAction, FirewallAction baselineAction)
            {
                if (currentAction == FirewallAction.Block)
                {
                    _firewall.SetDefaultOutboundAction(profile, baselineAction);
                }
                else
                {
                    _logger.LogWarning("{Profile} profile outbound default modified externally (Current: {Current}, expected SPEMCS Block). Yielding to external policy.", profile, currentAction);
                    conflictDetected = true;
                }
            }

            if (targetProfiles.HasFlag(FirewallProfiles.Domain))
            {
                RestoreProfile(FirewallProfiles.Domain, current.DomainDefaultOutbound, baseline.DomainDefaultOutbound);
            }

            if (targetProfiles.HasFlag(FirewallProfiles.Private))
            {
                RestoreProfile(FirewallProfiles.Private, current.PrivateDefaultOutbound, baseline.PrivateDefaultOutbound);
            }

            if (targetProfiles.HasFlag(FirewallProfiles.Public))
            {
                RestoreProfile(FirewallProfiles.Public, current.PublicDefaultOutbound, baseline.PublicDefaultOutbound);
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

    private void LogAndVerifyRules(
        string phaseDescription,
        IReadOnlyList<FirewallRuleModel> expectedRules,
        FirewallProfiles activeProfiles)
    {
        _logger.LogInformation("--- Inspecting Installed Rules [{Phase}] (Active runtime profile bitmask: {ActiveProfiles}) ---",
            phaseDescription, activeProfiles);

        var installedRules = _firewall.GetRulesByGroup(FirewallRuleModel.SpemcsRuleGroup);

        foreach (var rule in expectedRules)
        {
            if (!_firewall.RuleExists(rule.Name))
            {
                throw new InvalidOperationException($"[{phaseDescription}] Firewall rule '{rule.Name}' could not be verified in Windows Firewall.");
            }

            var matched = installedRules.FirstOrDefault(m => string.Equals(m.Name, rule.Name, StringComparison.OrdinalIgnoreCase));
            if (matched is null)
            {
                throw new InvalidOperationException($"[{phaseDescription}] Firewall rule '{rule.Name}' was not found in readback group '{FirewallRuleModel.SpemcsRuleGroup}'.");
            }

            // CRITICAL Requirement 5: Log all 13 properties
            _logger.LogInformation(
                "[{Phase}] Rule: DisplayName='{DisplayName}', Group='{Group}', Enabled={Enabled}, Direction={Direction}, Action={Action}, Protocol={Protocol}, Profiles={Profiles}, LocalAddresses='{LocalAddresses}', RemoteAddresses='{RemoteAddresses}', LocalPorts='{LocalPorts}', RemotePorts='{RemotePorts}', ApplicationName='{ApplicationName}', ServiceName='{ServiceName}'",
                phaseDescription,
                matched.Name,
                matched.Group,
                matched.Enabled,
                matched.Direction,
                matched.Action,
                matched.Protocol,
                matched.Profiles,
                matched.LocalAddresses,
                matched.RemoteAddresses,
                matched.LocalPorts,
                matched.RemotePorts,
                matched.ApplicationPath ?? "none",
                matched.ServiceName ?? "none"
            );

            if (!matched.Enabled)
            {
                throw new InvalidOperationException($"[{phaseDescription}] Firewall rule '{rule.Name}' is DISABLED.");
            }

            if (matched.Direction != rule.Direction ||
                matched.Action != rule.Action ||
                matched.Protocol != rule.Protocol)
            {
                throw new InvalidOperationException($"[{phaseDescription}] Firewall rule '{rule.Name}' failed property verification (Direction={matched.Direction} vs {rule.Direction}, Action={matched.Action} vs {rule.Action}, Protocol={matched.Protocol} vs {rule.Protocol}).");
            }

            // Requirement 6: Specifically verify that loopback rule survives under each active firewall profile and is enabled
            if (rule.Purpose.StartsWith("Loopback", StringComparison.OrdinalIgnoreCase))
            {
                if ((matched.Profiles & activeProfiles) == 0 && activeProfiles != FirewallProfiles.None)
                {
                    throw new InvalidOperationException($"[{phaseDescription}] Loopback rule '{rule.Name}' profile bitmask ({matched.Profiles}) does not cover active profile ({activeProfiles}).");
                }
            }
        }

        _logger.LogInformation("--- Finished Inspecting Installed Rules [{Phase}] ---", phaseDescription);
    }
}
