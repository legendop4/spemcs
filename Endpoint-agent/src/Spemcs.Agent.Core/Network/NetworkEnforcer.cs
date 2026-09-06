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

            // TargetProfiles, not Baseline.ActiveProfiles: the restoration key is what SPEMCS
            // MUTATED, which is durable in the journal, and not which profiles Windows happened to
            // report as active when the baseline was captured. A laptop that moved from a docked
            // Domain network to Public mid-exam still needs the Domain default put back.
            //
            // blockWasVerified is true only in Active, the single phase in which activation read-back
            // confirmed BLOCK was in force. Anywhere else, a profile that is not BLOCK is explained by
            // SPEMCS's own incomplete work rather than by a third party, so it must not be reported as
            // an external conflict.
            var baselineResult = RestoreBaselineSafely(
                sessionId,
                sessionRecord.Baseline,
                sessionRecord.TargetProfiles,
                blockWasVerified: sessionRecord.Phase is EnforcementPhase.Active);
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

                // SECURITY (CRITICAL): A session recorded as Active, or one that had written the
                // default-block and not yet verified it, may represent a LIVE, still-valid exam
                // lockdown. Never tear it down without proving the firewall is not enforcing it.
                //
                // RollingBackDefault and RollingBackRules are deliberately NOT in this set, and they
                // used to be. A session in either phase has already been DECIDED against - the exam
                // ended, expired or failed, and teardown had begun - so its lockdown is not "still
                // valid", it is unfinished cleanup. Treating it as live meant that a crash between the
                // first SetDefaultOutboundAction of a rollback and the last rule removal left the
                // profiles on BLOCK, recovery declared the enforcement healthy and preserved it, and
                // every later restart made the same call: the machine stayed deny-by-default with no
                // exam to justify it and no code path that would ever restore the baseline. Those two
                // phases now fall through to PerformSafeRollbackInternal, which is idempotent and
                // simply finishes the job.
                var lockdownMayBeLive = incompleteSession.Phase is EnforcementPhase.EnforcingDefaultBlock
                    or EnforcementPhase.Active;

                if (lockdownMayBeLive)
                {
                    try
                    {
                        var currentBaseline = _firewall.GetBaseline();
                        var enforcingTargets = (!incompleteSession.TargetProfiles.HasFlag(FirewallProfiles.Domain) || currentBaseline.DomainDefaultOutbound == FirewallAction.Block)
                                              && (!incompleteSession.TargetProfiles.HasFlag(FirewallProfiles.Private) || currentBaseline.PrivateDefaultOutbound == FirewallAction.Block)
                                              && (!incompleteSession.TargetProfiles.HasFlag(FirewallProfiles.Public) || currentBaseline.PublicDefaultOutbound == FirewallAction.Block);

                        if (enforcingTargets)
                        {
                            _logger.LogInformation("Session {SessionId} was recorded as {Phase} and the firewall is still enforcing default BLOCK on its target profiles. Preserving valid enforcement (no rollback).",
                                incompleteSession.SessionId, incompleteSession.Phase);

                            // Still reconcile ownership, because a live session is not a reason to
                            // leave ANOTHER session's orphans installed. The preserved session is
                            // added to the live set explicitly rather than relying on its phase
                            // appearing in LiveSessionIds: the decision to preserve was just made
                            // HERE, and if the two phase lists ever drift, this sweep would delete the
                            // allow rules of the very lockdown it is preserving - leaving a machine at
                            // default BLOCK with nothing permitted through it.
                            var liveDuringPreserve = LiveSessionIds();
                            liveDuringPreserve.Add(incompleteSession.SessionId);
                            var sweptWhilePreserving = CleanUpUnownedGroupRules(liveDuringPreserve);

                            return Task.FromResult(new RecoveryResult(
                                RecoveryRequired: false,
                                Success: true,
                                RecoveredSessionId: incompleteSession.SessionId,
                                OrphanRulesCleaned: sweptWhilePreserving,
                                BaselineRestored: false,
                                ConflictDetected: false,
                                Details: $"Preserved active enforcement session {incompleteSession.SessionId} (phase {incompleteSession.Phase}) during startup recovery."
                            ));
                        }

                        _logger.LogWarning("Session {SessionId} recorded as {Phase} but the firewall is NOT enforcing default BLOCK on its target profiles. Rolling back.",
                            incompleteSession.SessionId, incompleteSession.Phase);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to read firewall baseline while reconciling session {SessionId}. Proceeding with rollback.", incompleteSession.SessionId);
                    }
                }

                var rollbackResult = PerformSafeRollbackInternal(
                    incompleteSession.SessionId,
                    incompleteSession.Baseline,
                    incompleteSession.TargetProfiles,
                    incompleteSession.Phase
                );

                // Sweep whatever the rolled-back session did not own. GetLatestActiveOrIncompleteSession
                // returns ONE row, so with two crashed sessions on disk the second one's rules would
                // otherwise survive until some later startup happened to pick it. The sweep is
                // session-aware, so any session the journal still considers live keeps its rules.
                var residual = CleanUpUnownedGroupRules(LiveSessionIds(exceptSessionId: incompleteSession.SessionId));

                return Task.FromResult(new RecoveryResult(
                    RecoveryRequired: true,
                    Success: rollbackResult.Success,
                    RecoveredSessionId: incompleteSession.SessionId,
                    OrphanRulesCleaned: rollbackResult.RulesRemovedCount + residual,
                    BaselineRestored: rollbackResult.BaselineRestored,
                    ConflictDetected: rollbackResult.ConflictDetected,
                    Details: $"Recovered session {incompleteSession.SessionId} from phase {incompleteSession.Phase}."
                ));
            }

            // Case 3: Orphan SPEMCS rules exist in firewall without an active session.
            _logger.LogWarning("Found {Count} rule(s) in group '{Group}' without an active session. Reconciling ownership...",
                spemcsRules.Count, FirewallRuleModel.SpemcsRuleGroup);

            var cleaned = CleanUpUnownedGroupRules(LiveSessionIds());

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

    /// <summary>
    /// The sessions the journal still considers live, i.e. whose rules must survive a cleanup.
    /// </summary>
    /// <param name="exceptSessionId">
    /// A session that has just been rolled back, so it is no longer live no matter what phase the
    /// journal row was read at.
    /// </param>
    private HashSet<Guid> LiveSessionIds(Guid? exceptSessionId = null)
    {
        var live = new HashSet<Guid>();
        foreach (var record in _journal.GetAllSessions())
        {
            var isLive = record.Phase is EnforcementPhase.Prepared
                or EnforcementPhase.ApplyingRules
                or EnforcementPhase.EnforcingDefaultBlock
                or EnforcementPhase.Active;

            if (isLive && record.SessionId != exceptSessionId)
            {
                live.Add(record.SessionId);
            }
        }

        return live;
    }

    /// <summary>
    /// Deletes rules in the SPEMCS group that belong to no live session, and only those.
    /// </summary>
    /// <remarks>
    /// <para>
    /// WHAT THIS REPLACED. Cleanup used to be
    /// <c>if (name.StartsWith("SPEMCS-")) RemoveRule(name)</c> over every rule in the group. Its
    /// correctness rested entirely on the caller having established that no session was live, which
    /// in turn rested on <c>GetLatestActiveOrIncompleteSession</c> - a query with <c>LIMIT 1</c>.
    /// One journal row that had not yet reached a terminal phase, one concurrently-starting session,
    /// or any future change to that query's phase filter, and a startup sweep would delete a live
    /// exam's allow rules while its profiles sat at default BLOCK: the candidate loses the
    /// examination browser mid-exam and the agent reports a clean recovery.
    /// </para>
    /// <para>
    /// Ownership now decides, and it is read from the rule name because
    /// <see cref="IFirewallAdapter.GetRuleNamesByGroup"/> reads back from Windows, which stores no
    /// session field. Three outcomes:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// Attributable to a live session - PRESERVED. This is the whole point.
    /// </description></item>
    /// <item><description>
    /// Attributable to a session that is not live - DELETED. A leftover ALLOW rule is a standing hole
    /// on a host whose own baseline may be deny-by-default, so orphans cannot simply be left alone.
    /// </description></item>
    /// <item><description>
    /// Not attributable at all - DELETED, logged separately at warning level. A rule inside
    /// <see cref="FirewallRuleModel.SpemcsRuleGroup"/> that SPEMCS did not name is either an older
    /// SPEMCS naming scheme or something impersonating one; either way it is not part of a live
    /// session, and it is inside SPEMCS's own namespace. Note the containment: a rule merely NAMED
    /// like SPEMCS but outside the group is never even a candidate, because the enumeration is by
    /// group.
    /// </description></item>
    /// </list>
    /// </remarks>
    private int CleanUpUnownedGroupRules(HashSet<Guid> liveSessionIds)
    {
        var cleaned = 0;
        var preserved = 0;
        var unattributable = 0;

        foreach (var ruleName in _firewall.GetRuleNamesByGroup(FirewallRuleModel.SpemcsRuleGroup))
        {
            if (FirewallRuleModel.TryParseSessionId(ruleName, out var owner))
            {
                if (liveSessionIds.Contains(owner))
                {
                    preserved++;
                    _logger.LogInformation("Preserving rule {RuleName}: owned by live session {SessionId}.", ruleName, owner);
                    continue;
                }
            }
            else
            {
                unattributable++;
                _logger.LogWarning(
                    "Rule {RuleName} is in group '{Group}' but its name does not identify a SPEMCS session. Treating as an orphan.",
                    ruleName, FirewallRuleModel.SpemcsRuleGroup);
            }

            if (_firewall.RemoveRule(ruleName))
            {
                cleaned++;
            }
        }

        if (cleaned > 0 || preserved > 0 || unattributable > 0)
        {
            _logger.LogInformation(
                "Group ownership reconciliation: {Cleaned} orphan rule(s) removed ({Unattributable} unattributable), {Preserved} rule(s) preserved for live sessions.",
                cleaned, unattributable, preserved);
        }

        return cleaned;
    }

    private RollbackResult PerformSafeRollbackInternal(
        Guid sessionId,
        FirewallProfileBaseline baseline,
        FirewallProfiles targetProfiles,
        EnforcementPhase currentPhase)
    {
        _logger.LogInformation("Performing safe rollback for Session: {SessionId} from Phase: {Phase}", sessionId, currentPhase);

        // ---------------------------------------------------------------------
        // Step 1: Converge the profile outbound defaults on the CAPTURED baseline.
        //
        // The two facts this decision needs are different from each other, and conflating them was
        // the old defect:
        //
        //   blockWasWritten  - could SPEMCS have changed DefaultOutboundAction at all? BLOCK is
        //                      written only after every allow rule is installed and verified, so in
        //                      Prepared and ApplyingRules it provably was not written yet and there
        //                      is nothing to undo. Every other phase - including the terminal ones -
        //                      must converge. The old whitelist omitted Failed, Conflict and
        //                      RolledBack, which left a session that died in Failed with its
        //                      profiles still on BLOCK and no code path that would ever restore them.
        //
        //   blockWasVerified - did readback CONFIRM BLOCK was in force? Only Active means that. This
        //                      is the flag that licenses reporting an external-modification conflict,
        //                      and restricting it to Active is what stops a partial enforcement, a
        //                      crash during rollback, or a second rollback of an already-restored
        //                      session from being reported as somebody tampering with the firewall.
        // ---------------------------------------------------------------------
        var blockWasWritten = currentPhase is not (EnforcementPhase.Prepared or EnforcementPhase.ApplyingRules);
        var blockWasVerified = currentPhase is EnforcementPhase.Active;

        (bool Success, bool Restored, bool Conflict, string? Error) baselineRestore;

        if (blockWasWritten)
        {
            _journal.UpdatePhase(sessionId, EnforcementPhase.RollingBackDefault);
            baselineRestore = RestoreBaselineSafely(sessionId, baseline, targetProfiles, blockWasVerified);
        }
        else
        {
            _logger.LogInformation(
                "Session {SessionId} never reached the default-block write (phase {Phase}); profile defaults are untouched and need no restoration.",
                sessionId, currentPhase);
            baselineRestore = (Success: true, Restored: false, Conflict: false, Error: null);
        }

        // Step 2: Remove the rules owned by THIS session.
        _journal.UpdatePhase(sessionId, EnforcementPhase.RollingBackRules);
        var removalOutcome = RemoveSessionOwnedRules(sessionId);

        // Step 3: Record final state
        var finalPhase = baselineRestore.Conflict ? EnforcementPhase.Conflict : EnforcementPhase.RolledBack;
        _journal.UpdatePhase(sessionId, finalPhase);

        _logger.LogInformation("Rollback complete for Session: {SessionId}. Rules removed: {Count}. Baseline restored: {Restored}. Conflict: {Conflict}",
            sessionId, removalOutcome.RemovedCount, baselineRestore.Restored, baselineRestore.Conflict);

        var error = removalOutcome.Error is null
            ? baselineRestore.Error
            : string.Join(" ", new[] { baselineRestore.Error, removalOutcome.Error }.Where(s => !string.IsNullOrEmpty(s)));

        return new RollbackResult(
            // Success is a claim about CONVERGENCE, not about whether anything unusual was seen. A
            // conflict that was nevertheless converged on the baseline is a successful rollback with
            // an incident attached; callers that must react to the incident read ConflictDetected,
            // which EnforcementStateMachine.DeactivateAsync already does.
            Success: baselineRestore.Success && removalOutcome.Error is null,
            SessionId: sessionId,
            RulesRemovedCount: removalOutcome.RemovedCount,
            BaselineRestored: baselineRestore.Restored,
            ConflictDetected: baselineRestore.Conflict,
            ErrorMessage: error
        );
    }

    /// <summary>
    /// Deletes exactly the rules belonging to <paramref name="sessionId"/> and nothing else.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Ownership is established from two independent sources and the WEAKER one is used as a filter,
    /// not as an authority:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// The journal's applied-rule list is the durable record of what this session actually installed.
    /// It is authoritative about intent - but it is data on disk, so a name in it is accepted only if
    /// it also carries this session's name prefix. Without that check a corrupted or tampered journal
    /// row could name <c>"Codex"</c>, or another product's rule, and rollback would dutifully delete
    /// it by exact name.
    /// </description></item>
    /// <item><description>
    /// A scan of the SPEMCS group filtered by this session's prefix catches rules that reached the
    /// firewall but never reached the journal - the crash window between <c>AddRule</c> and
    /// <c>RecordAppliedRule</c>. Restricting the scan to the group means a rule outside SPEMCS's own
    /// group is never a candidate no matter what it is called.
    /// </description></item>
    /// </list>
    /// <para>
    /// Neither source can widen the other: the result is the union, and every member of the union has
    /// been checked against <see cref="FirewallRuleModel.SessionNamePrefix"/> for this session.
    /// </para>
    /// </remarks>
    private (int RemovedCount, string? Error) RemoveSessionOwnedRules(Guid sessionId)
    {
        var sessionPrefix = FirewallRuleModel.SessionNamePrefix(sessionId);
        var candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var rejected = new List<string>();

        foreach (var journaledName in _journal.GetSession(sessionId)?.AppliedRuleNames ?? Array.Empty<string>())
        {
            if (journaledName.StartsWith(sessionPrefix, StringComparison.OrdinalIgnoreCase))
            {
                candidates.Add(journaledName);
            }
            else
            {
                rejected.Add(journaledName);
            }
        }

        foreach (var ruleName in _firewall.GetRuleNamesByGroup(FirewallRuleModel.SpemcsRuleGroup))
        {
            if (ruleName.StartsWith(sessionPrefix, StringComparison.OrdinalIgnoreCase))
            {
                candidates.Add(ruleName);
            }
        }

        if (rejected.Count > 0)
        {
            // Loud, because the only ways to get here are journal corruption and tampering, and both
            // are worth an operator's attention. Not fatal: the prefix scan still cleans up the rules
            // this session really does own.
            _logger.LogError(
                "Rollback for session {SessionId} REFUSED to delete {Count} journaled rule name(s) that do not carry this session's prefix '{Prefix}': {Names}. The journal row may be corrupt or tampered with.",
                sessionId, rejected.Count, sessionPrefix, string.Join(", ", rejected));
        }

        var removedCount = 0;
        foreach (var ruleName in candidates)
        {
            _logger.LogDebug("Removing rule: {RuleName}", ruleName);
            if (_firewall.RemoveRule(ruleName))
            {
                removedCount++;
            }
            else
            {
                // Already gone. Expected on a retried rollback and after a crash between the COM
                // delete and the journal write, so it is not an error.
                _logger.LogDebug("Rule {RuleName} was already absent; nothing to remove.", ruleName);
            }
        }

        return (removedCount, null);
    }

    /// <summary>
    /// Restores the captured pre-exam <c>DefaultOutboundAction</c> for every targeted profile, and
    /// verifies by read-back that it landed.
    /// </summary>
    /// <param name="blockWasVerified">
    /// True only when the session reached <see cref="EnforcementPhase.Active"/>, i.e. read-back
    /// confirmed BLOCK was in force. This is what licenses an external-modification conflict; see the
    /// remarks.
    /// </param>
    /// <remarks>
    /// <para>
    /// WHAT THIS REPLACED, AND WHY. The previous implementation decided per profile with
    /// <c>if (currentAction == Block) restore; else conflict</c>. Because
    /// <see cref="FirewallAction"/> has exactly two values, "not Block" meant "Allow", and that one
    /// branch covered four completely different situations:
    /// </para>
    /// <list type="number">
    /// <item><description>
    /// A profile that never took BLOCK because enforcement failed part-way. Nothing to undo, yet it
    /// was reported as an external conflict and the activation-failure path recorded
    /// <see cref="EnforcementState.Conflict"/> instead of <see cref="EnforcementState.Failed"/> - an
    /// operator-visible unresolved incident for a rollback that had in fact left the machine perfect.
    /// </description></item>
    /// <item><description>
    /// A second rollback of a session already rolled back. Same false conflict, so stopping an exam
    /// twice, or an expiry racing an operator stop, poisoned the session record.
    /// </description></item>
    /// <item><description>
    /// A crash midway through a previous rollback. The profiles already restored looked like
    /// tampering, so recovery could not finish what it had started.
    /// </description></item>
    /// <item><description>
    /// The genuinely dangerous one. If the captured baseline was <see cref="FirewallAction.Block"/> -
    /// a host that was already deny-by-default before the exam - and something set it to
    /// <see cref="FirewallAction.Allow"/>, the old code "yielded to external policy" and returned
    /// without restoring. SPEMCS then finished its session having left the machine STRICTLY MORE OPEN
    /// than it found it, and reported <c>BaselineRestored=false</c> as if that were a safe outcome.
    /// </description></item>
    /// </list>
    /// <para>
    /// So the decision now comes from the durable baseline instead of from the live action: write the
    /// captured value wherever the current value differs, then re-read and confirm. Detecting
    /// tampering is a SEPARATE question, answered by <paramref name="blockWasVerified"/> - if BLOCK
    /// was confirmed in force and the profile is no longer BLOCK, something else changed it, and that
    /// is recorded as a conflict whether or not the convergence succeeded.
    /// </para>
    /// <para>
    /// Converging even in case 4 does mean SPEMCS re-asserts a BLOCK an administrator may have
    /// cleared mid-exam. That is the correct trade: the baseline is the machine's own pre-exam
    /// posture, restoring it is exactly what requirement 9 asks for, and the alternative is a
    /// monitoring product that silently downgrades a host's security because someone touched it while
    /// it was running. The event is not hidden - it is journaled as a conflict and logged with both
    /// values.
    /// </para>
    /// </remarks>
    private (bool Success, bool Restored, bool Conflict, string? Error) RestoreBaselineSafely(
        Guid sessionId,
        FirewallProfileBaseline baseline,
        FirewallProfiles targetProfiles,
        bool blockWasVerified)
    {
        try
        {
            var current = _firewall.GetBaseline();
            var externallyModified = new List<string>();

            void RestoreProfile(FirewallProfiles profile)
            {
                if (!targetProfiles.HasFlag(profile)) return;

                var currentAction = current.ActionFor(profile)!.Value;
                var baselineAction = baseline.ActionFor(profile)!.Value;

                if (blockWasVerified && currentAction != FirewallAction.Block)
                {
                    // SPEMCS left this profile on BLOCK and verified it. It is not BLOCK now, so a
                    // third party changed it. Recorded regardless of which way the change went.
                    externallyModified.Add($"{profile} (found {currentAction}, SPEMCS had enforced Block, pre-exam baseline was {baselineAction})");
                }

                if (currentAction == baselineAction)
                {
                    _logger.LogDebug("{Profile} profile outbound default already matches the captured baseline ({Action}); no write needed.",
                        profile, baselineAction);
                    return;
                }

                _logger.LogInformation("Restoring {Profile} profile outbound default: {Current} -> {Baseline} (captured pre-exam value).",
                    profile, currentAction, baselineAction);
                _firewall.SetDefaultOutboundAction(profile, baselineAction);
            }

            RestoreProfile(FirewallProfiles.Domain);
            RestoreProfile(FirewallProfiles.Private);
            RestoreProfile(FirewallProfiles.Public);

            // VERIFY. BaselineRestored must be a measurement, not an intention: SetDefaultOutboundAction
            // can be silently ignored by a GPO that re-asserts its own default, which is the exact
            // failure mode readback exists to catch during activation. Claiming "restored" without
            // reading back would let a machine be left on BLOCK after the exam while the journal says
            // it was cleaned up.
            var afterwards = _firewall.GetBaseline();
            var notConverged = new List<string>();

            void Verify(FirewallProfiles profile)
            {
                if (!targetProfiles.HasFlag(profile)) return;
                var actual = afterwards.ActionFor(profile)!.Value;
                var expected = baseline.ActionFor(profile)!.Value;
                if (actual != expected)
                {
                    notConverged.Add($"{profile} (expected {expected}, still reports {actual})");
                }
            }

            Verify(FirewallProfiles.Domain);
            Verify(FirewallProfiles.Private);
            Verify(FirewallProfiles.Public);

            if (externallyModified.Count > 0)
            {
                var details = $"External administrator, GPO or third party modified DefaultOutboundAction while SPEMCS was enforcing: {string.Join("; ", externallyModified)}.";
                _logger.LogWarning("{Details}", details);
                _journal.RecordConflict(sessionId, details);
            }

            if (notConverged.Count > 0)
            {
                var error = $"Baseline restoration did not take effect for: {string.Join("; ", notConverged)}.";
                _logger.LogError("Session {SessionId}: {Error}", sessionId, error);
                return (false, false, true, error);
            }

            return (true, true, externallyModified.Count > 0,
                externallyModified.Count > 0
                    ? $"Pre-exam baseline restored, but an external modification was detected during enforcement: {string.Join("; ", externallyModified)}."
                    : null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to restore firewall baseline for Session: {SessionId}", sessionId);
            return (false, false, false, ex.Message);
        }
    }

    /// <summary>
    /// Semantic-equivalence comparison for firewall properties.
    /// Windows Firewall COM normalizes unset ports/addresses to "*" (and "Any"/"LocalSubnet" for some fields),
    /// so a raw ordinal comparison is insufficient: "*" on either side means "any"/unset.
    /// Comparison is case-insensitive and whitespace-trimmed; IPv6 addresses are compared case-insensitively.
    /// </summary>
    private static bool PropertyMatches(string? expected, string? actual)
    {
        if (string.Equals(expected ?? "*", actual ?? "*", StringComparison.OrdinalIgnoreCase)) return true;
        var e = (expected ?? "").Trim();
        var a = (actual ?? "").Trim();
        return string.Equals(e, a, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Address-field comparison. Windows Firewall rewrites an address specification on the way in
    /// (IPv4 CIDR becomes a dotted-decimal mask, a bare IPv4 host gains /255.255.255.255, a bare
    /// IPv6 host becomes a degenerate range), so the readback of a rule written exactly as intended
    /// is not textually equal to the rule we asked for. Comparing those two literally rejects every
    /// IPv4 rule SPEMCS installs - the loopback rule included - and aborts enforcement before the
    /// default-block is ever applied. Compare the address sets instead; see
    /// <see cref="FirewallAddressSpec"/>.
    /// </summary>
    private static bool AddressPropertyMatches(string? expected, string? actual) =>
        PropertyMatches(expected, actual) || FirewallAddressSpec.AreEquivalent(expected, actual);

    private static bool PortPropertyMatches(string? expected, string? actual)
    {
        if (PropertyMatches(expected, actual)) return true;
        // Windows Firewall represents "all ports" as "*"; "Any" appears on some reads.
        var e = (expected ?? "*").Trim();
        var a = (actual ?? "*").Trim();
        return (e is "*" or "Any") && (a is "*" or "Any");
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

            var failures = new List<string>();

            if (!string.Equals(matched.Name, rule.Name, StringComparison.OrdinalIgnoreCase))
                failures.Add($"Name '{matched.Name}' != '{rule.Name}'");
            if (!string.Equals(matched.Group, rule.Group, StringComparison.OrdinalIgnoreCase))
                failures.Add($"Group '{matched.Group}' != '{rule.Group}'");
            if (!matched.Enabled)
                failures.Add("Enabled=false");
            if (matched.Direction != rule.Direction)
                failures.Add($"Direction {matched.Direction} != {rule.Direction}");
            if (matched.Action != rule.Action)
                failures.Add($"Action {matched.Action} != {rule.Action}");
            if (matched.Protocol != rule.Protocol)
                failures.Add($"Protocol {matched.Protocol} != {rule.Protocol}");
            // Windows may report an unset (Any) protocol as 256 on reads; accept that as equivalent to Any.
            if (!PortPropertyMatches(rule.LocalPorts, matched.LocalPorts))
                failures.Add($"LocalPorts '{matched.LocalPorts}' != '{rule.LocalPorts}'");
            if (!PortPropertyMatches(rule.RemotePorts, matched.RemotePorts))
                failures.Add($"RemotePorts '{matched.RemotePorts}' != '{rule.RemotePorts}'");
            if (!AddressPropertyMatches(rule.RemoteAddresses, matched.RemoteAddresses))
                failures.Add($"RemoteAddresses '{matched.RemoteAddresses}' != '{rule.RemoteAddresses}'");
            if (!AddressPropertyMatches(rule.LocalAddresses, matched.LocalAddresses))
                failures.Add($"LocalAddresses '{matched.LocalAddresses}' != '{rule.LocalAddresses}'");
            // ApplicationName: expected rule may be intentionally application-scoped (null = all programs).
            if (!PropertyMatches(rule.ApplicationPath, matched.ApplicationPath))
                failures.Add($"ApplicationName '{matched.ApplicationPath ?? "null"}' != '{rule.ApplicationPath ?? "null"}'");
            // Profiles: matched bitmask MUST contain every profile bit we requested; extra bits are tolerated.
            if ((rule.Profiles & matched.Profiles) != rule.Profiles)
                failures.Add($"Profiles {matched.Profiles} does not cover requested {rule.Profiles}");
            if (rule.ServiceName is not null && !PropertyMatches(rule.ServiceName, matched.ServiceName))
                failures.Add($"ServiceName '{matched.ServiceName}' != '{rule.ServiceName}'");

            if (failures.Count > 0)
            {
                throw new InvalidOperationException($"[{phaseDescription}] Firewall rule '{rule.Name}' failed full property verification: {string.Join("; ", failures)}.");
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
