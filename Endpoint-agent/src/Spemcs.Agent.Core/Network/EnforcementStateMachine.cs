using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Spemcs.Agent.Core.Network;

public sealed record EnforcementActivationResult(
    bool Success,
    Guid SessionId,
    EnforcementState State,
    string? FailureReason = null
);

public sealed record EnforcementDeactivationResult(
    bool Success,
    Guid SessionId,
    EnforcementState State,
    bool RollbackCompleted,
    bool ConflictDetected,
    string? FailureReason = null
);

/// <summary>
/// Authoritative endpoint enforcement state machine coordinator.
/// Orchestrates policy verification, firewall rule installation, default-outbound blocking,
/// live Windows readback verification, safe failure rollback, and signed expiry.
/// </summary>
public interface IEnforcementStateMachine
{
    EnforcementState CurrentState { get; }
    DurableEnforcementRecord? CurrentSession { get; }

    Task<EnforcementActivationResult> ActivateAsync(
        Guid sessionId,
        SignedPolicyMessage signedMessage,
        Guid expectedExamId,
        FirewallProfiles targetProfiles = FirewallProfiles.All,
        DateTimeOffset? currentTimeUtc = null,
        CancellationToken cancellationToken = default);

    Task<EnforcementDeactivationResult> DeactivateAsync(
        Guid sessionId,
        string reason = "Exam stopped",
        CancellationToken cancellationToken = default);

    Task CheckExpiryAsync(DateTimeOffset? currentTimeUtc = null, CancellationToken cancellationToken = default);

    Task<RecoveryResult> ReconcileStartupStateAsync(CancellationToken cancellationToken = default);

    Task<PolicyUpdateResult> UpdatePolicyAsync(
        SignedPolicyMessage updateMessage,
        DateTimeOffset? currentTimeUtc = null,
        CancellationToken cancellationToken = default);
}

public sealed class EnforcementStateMachine : IEnforcementStateMachine
{
    private readonly IPolicyReceiver _receiver;
    private readonly INetworkEnforcer _enforcer;
    private readonly IFirewallAdapter _firewall;
    private readonly IRollbackJournal _journal;
    private readonly IManagementConnectivityVerifier _connectivity;
    private readonly ILogger<EnforcementStateMachine> _logger;

    private readonly SemaphoreSlim _gate = new(1, 1);
    private DurableEnforcementRecord? _currentSession;
    private EnforcementState _state = EnforcementState.Idle;

    public EnforcementState CurrentState => _state;
    public DurableEnforcementRecord? CurrentSession => _currentSession;

    public EnforcementStateMachine(
        IPolicyReceiver receiver,
        INetworkEnforcer enforcer,
        IFirewallAdapter firewall,
        IRollbackJournal journal,
        IManagementConnectivityVerifier connectivity,
        ILogger<EnforcementStateMachine>? logger = null)
    {
        _receiver = receiver ?? throw new ArgumentNullException(nameof(receiver));
        _enforcer = enforcer ?? throw new ArgumentNullException(nameof(enforcer));
        _firewall = firewall ?? throw new ArgumentNullException(nameof(firewall));
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _connectivity = connectivity ?? throw new ArgumentNullException(nameof(connectivity));
        _logger = logger ?? NullLogger<EnforcementStateMachine>.Instance;

        // Load existing active session from SQLite journal if present
        _currentSession = _journal.GetActiveEnforcementState();
        _state = _currentSession?.State ?? EnforcementState.Idle;
    }

    public async Task<EnforcementActivationResult> ActivateAsync(
        Guid sessionId,
        SignedPolicyMessage signedMessage,
        Guid expectedExamId,
        FirewallProfiles targetProfiles = FirewallProfiles.All,
        DateTimeOffset? currentTimeUtc = null,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            _logger.LogInformation("Enforcement activation requested for Session: {SessionId}, Exam: {ExamId}",
                sessionId, expectedExamId);

            // -----------------------------------------------------------------
            // Precondition 1: Duplicate and Conflict Handling (Section 13)
            // -----------------------------------------------------------------
            if (_state == EnforcementState.Active && _currentSession is not null)
            {
                if (_currentSession.SessionId == sessionId && _currentSession.ExamId == expectedExamId)
                {
                    _logger.LogInformation("Idempotent activation: Session {SessionId} is already ACTIVE.", sessionId);
                    return new EnforcementActivationResult(true, sessionId, EnforcementState.Active);
                }

                _logger.LogWarning("Activation rejected: conflicting active session {ActiveSession} already in progress.",
                    _currentSession.SessionId);
                return new EnforcementActivationResult(false, sessionId, _state,
                    $"Another session '{_currentSession.SessionId}' is already active.");
            }

            // Transition: POLICY_PENDING
            _state = EnforcementState.PolicyPending;

            // -----------------------------------------------------------------
            // Precondition 2: Policy Verification via M5 (Section 4 & 6)
            // -----------------------------------------------------------------
            var validation = await _receiver.ProcessPolicyMessageAsync(
                signedMessage,
                expectedExamId,
                currentTimeUtc,
                commitVersion: true,
                cancellationToken: cancellationToken);

            if (validation.Status != PolicyAcceptanceStatus.Accepted || validation.ValidatedPolicy is null)
            {
                _logger.LogWarning("Activation aborted: policy rejected ({Status}) - {Details}",
                    validation.Status, validation.Details);

                _state = EnforcementState.Failed;
                var failedRecord = new DurableEnforcementRecord(
                    SessionId: sessionId,
                    ExamId: expectedExamId,
                    PolicyId: Guid.Empty,
                    PolicyVersion: 0,
                    State: EnforcementState.Failed,
                    ActivationUtc: DateTimeOffset.UtcNow,
                    ExpiresAtUtc: DateTimeOffset.UtcNow,
                    LastTransitionUtc: DateTimeOffset.UtcNow,
                    FailureReason: $"Policy validation failed: {validation.Status} - {validation.Details}"
                );
                _journal.SaveEnforcementState(failedRecord);

                return new EnforcementActivationResult(false, sessionId, EnforcementState.Failed,
                    $"Policy validation failed: {validation.Status} ({validation.Details})");
            }

            var policy = validation.ValidatedPolicy;
            _state = EnforcementState.PolicyValidated;

            // -----------------------------------------------------------------
            // Step 3: Persist Activation Intent (PREPARING)
            // -----------------------------------------------------------------
            _state = EnforcementState.Preparing;
            var now = currentTimeUtc ?? DateTimeOffset.UtcNow;
            _currentSession = new DurableEnforcementRecord(
                SessionId: sessionId,
                ExamId: expectedExamId,
                PolicyId: policy.PolicyId,
                PolicyVersion: policy.Version,
                State: EnforcementState.Preparing,
                ActivationUtc: now,
                ExpiresAtUtc: policy.ExpiresAt,
                LastTransitionUtc: now,
                FailureReason: null
            );
            _journal.SaveEnforcementState(_currentSession);

            // -----------------------------------------------------------------
            // Step 4: Build M4 Firewall Rules (Section 5)
            // -----------------------------------------------------------------
            var rules = new List<FirewallRuleModel>();

            // Management server rules (TCP)
            foreach (var mgmtIp in policy.ManagementServer.IpAddresses)
            {
                rules.Add(FirewallRuleModel.CreateOutboundAllow(
                    sessionId,
                    "Mgmt",
                    FirewallProtocol.TCP,
                    mgmtIp,
                    policy.ManagementServer.Port.ToString(),
                    profiles: targetProfiles));
            }

            // Vendor & exam allowed destinations
            foreach (var dest in policy.AllowedDestinations)
            {
                foreach (var ip in dest.IpRanges)
                {
                    if (dest.TcpPorts.Count > 0)
                    {
                        var tcpPortsStr = string.Join(",", dest.TcpPorts);
                        rules.Add(FirewallRuleModel.CreateOutboundAllow(
                            sessionId,
                            dest.Name,
                            FirewallProtocol.TCP,
                            ip,
                            tcpPortsStr,
                            profiles: targetProfiles));
                    }

                    if (dest.UdpPorts.Count > 0)
                    {
                        var udpPortsStr = string.Join(",", dest.UdpPorts);
                        rules.Add(FirewallRuleModel.CreateOutboundAllow(
                            sessionId,
                            dest.Name,
                            FirewallProtocol.UDP,
                            ip,
                            udpPortsStr,
                            profiles: targetProfiles));
                    }
                }
            }

            var enforcementSession = new EnforcementSession(
                SessionId: sessionId,
                PolicyId: policy.PolicyId,
                PolicyVersion: policy.Version,
                Rules: rules,
                TargetProfiles: targetProfiles,
                CreatedUtc: now
            );

            // -----------------------------------------------------------------
            // Step 5: Execute Two-Phase Apply via M4 (APPLYING_RULES -> ENFORCING)
            // -----------------------------------------------------------------
            _state = EnforcementState.ApplyingRules;
            _journal.UpdateEnforcementState(sessionId, EnforcementState.ApplyingRules);

            var applyResult = await _enforcer.ApplyEnforcementAsync(enforcementSession, cancellationToken);
            if (!applyResult.Success)
            {
                _logger.LogError("Firewall rule application failed: {Error}. Initiating safe rollback.", applyResult.ErrorMessage);
                return await HandleApplyFailureAsync(sessionId, applyResult.ErrorMessage ?? "Firewall mutation failed", cancellationToken);
            }

            // -----------------------------------------------------------------
            // Step 6: Verify Actual Windows Firewall Readback (Section 9)
            // -----------------------------------------------------------------
            _state = EnforcementState.Enforcing;
            _journal.UpdateEnforcementState(sessionId, EnforcementState.Enforcing);

            var baseline = _firewall.GetBaseline();
            var readbackSuccess = true;

            if (targetProfiles.HasFlag(FirewallProfiles.Domain) && baseline.DomainDefaultOutbound != FirewallAction.Block)
                readbackSuccess = false;
            if (targetProfiles.HasFlag(FirewallProfiles.Private) && baseline.PrivateDefaultOutbound != FirewallAction.Block)
                readbackSuccess = false;
            if (targetProfiles.HasFlag(FirewallProfiles.Public) && baseline.PublicDefaultOutbound != FirewallAction.Block)
                readbackSuccess = false;

            if (!readbackSuccess)
            {
                _logger.LogError("Readback verification failed: Windows Firewall profile did not report BLOCK action.");
                return await HandleApplyFailureAsync(sessionId, "DefaultOutboundAction readback verification failed", cancellationToken);
            }

            // -----------------------------------------------------------------
            // Step 7: Verify Required Management Connectivity Post-Enforcement (Section 5 Step 10)
            // -----------------------------------------------------------------
            var mgmtCheck = await _connectivity.VerifyConnectivityAsync(policy.ManagementServer, cancellationToken);
            if (!mgmtCheck)
            {
                _logger.LogError("Management connectivity failed under enforced firewall rules. Rolling back.");
                return await HandleApplyFailureAsync(sessionId, "Management plane unreachable under enforced rules", cancellationToken);
            }

            // -----------------------------------------------------------------
            // Step 8: Mark ACTIVE
            // -----------------------------------------------------------------
            _state = EnforcementState.Active;
            _journal.UpdateEnforcementState(sessionId, EnforcementState.Active);
            _currentSession = _currentSession with { State = EnforcementState.Active };

            _logger.LogInformation("Enforcement state machine successfully reached ACTIVE for Session: {SessionId}", sessionId);
            return new EnforcementActivationResult(true, sessionId, EnforcementState.Active);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during activation of Session: {SessionId}", sessionId);
            return await HandleApplyFailureAsync(sessionId, ex.Message, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<EnforcementDeactivationResult> DeactivateAsync(
        Guid sessionId,
        string reason = "Exam stopped",
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            _logger.LogInformation("Deactivation requested for Session: {SessionId}, Reason: {Reason}", sessionId, reason);

            _state = EnforcementState.Stopping;
            _journal.UpdateEnforcementState(sessionId, EnforcementState.Stopping);

            _state = EnforcementState.RollingBack;
            _journal.UpdateEnforcementState(sessionId, EnforcementState.RollingBack);

            var rollbackResult = await _enforcer.RemoveEnforcementAsync(sessionId, cancellationToken);

            if (rollbackResult.ConflictDetected)
            {
                _logger.LogWarning("Deactivation detected external administrative/GPO conflict.");
                _state = EnforcementState.Conflict;
                _journal.UpdateEnforcementState(sessionId, EnforcementState.Conflict,
                    failureReason: "External configuration conflict detected during rollback.",
                    conflictDetected: true);

                return new EnforcementDeactivationResult(
                    Success: false,
                    SessionId: sessionId,
                    State: EnforcementState.Conflict,
                    RollbackCompleted: false,
                    ConflictDetected: true,
                    FailureReason: rollbackResult.ErrorMessage
                );
            }

            _state = EnforcementState.RolledBack;
            _journal.UpdateEnforcementState(sessionId, EnforcementState.RolledBack, rollbackCompleted: true);

            _state = EnforcementState.Idle;
            _currentSession = null;

            _logger.LogInformation("Deactivation complete. Endpoint returned to IDLE for Session: {SessionId}", sessionId);
            return new EnforcementDeactivationResult(
                Success: true,
                SessionId: sessionId,
                State: EnforcementState.Idle,
                RollbackCompleted: true,
                ConflictDetected: false
            );
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task CheckExpiryAsync(DateTimeOffset? currentTimeUtc = null, CancellationToken cancellationToken = default)
    {
        if (_state != EnforcementState.Active || _currentSession is null)
            return;

        var now = currentTimeUtc ?? DateTimeOffset.UtcNow;
        if (now >= _currentSession.ExpiresAtUtc)
        {
            _logger.LogWarning("Active policy has reached signed expiry time {ExpiresAt}. Triggering automatic rollback.",
                _currentSession.ExpiresAtUtc);

            await DeactivateAsync(_currentSession.SessionId, "Policy signed validity window expired", cancellationToken);
        }
    }

    public async Task<RecoveryResult> ReconcileStartupStateAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            _logger.LogInformation("Executing state machine startup reconciliation.");

            var incompleteState = _journal.GetActiveEnforcementState();
            if (incompleteState is null)
            {
                // Clean state
                _state = EnforcementState.Idle;
                _currentSession = null;
                return await _enforcer.RecoverIncompleteSessionAsync(cancellationToken);
            }

            var now = DateTimeOffset.UtcNow;

            // Check if expired while offline
            if (now >= incompleteState.ExpiresAtUtc)
            {
                _logger.LogWarning("Found session {SessionId} expired while offline. Performing emergency cleanup.",
                    incompleteState.SessionId);

                await _enforcer.RemoveEnforcementAsync(incompleteState.SessionId, cancellationToken);
                _journal.UpdateEnforcementState(incompleteState.SessionId, EnforcementState.RolledBack,
                    failureReason: "Expired during offline period", rollbackCompleted: true);

                _state = EnforcementState.Idle;
                _currentSession = null;

                return new RecoveryResult(
                    RecoveryRequired: true,
                    Success: true,
                    RecoveredSessionId: incompleteState.SessionId,
                    OrphanRulesCleaned: 0,
                    BaselineRestored: true,
                    ConflictDetected: false,
                    Details: "Cleaned up session expired during offline period."
                );
            }

            // If session was incomplete (Preparing, ApplyingRules, Enforcing, RollingBack)
            if (incompleteState.State != EnforcementState.Active)
            {
                _logger.LogWarning("Found incomplete activation {SessionId} in state {State}. Rolling back.",
                    incompleteState.SessionId, incompleteState.State);

                await _enforcer.RemoveEnforcementAsync(incompleteState.SessionId, cancellationToken);
                _journal.UpdateEnforcementState(incompleteState.SessionId, EnforcementState.RolledBack,
                    failureReason: $"Incomplete activation state: {incompleteState.State}", rollbackCompleted: true);

                _state = EnforcementState.Idle;
                _currentSession = null;

                return new RecoveryResult(
                    RecoveryRequired: true,
                    Success: true,
                    RecoveredSessionId: incompleteState.SessionId,
                    OrphanRulesCleaned: 0,
                    BaselineRestored: true,
                    ConflictDetected: false,
                    Details: $"Rolled back incomplete activation {incompleteState.SessionId}."
                );
            }

            // Session was marked Active: verify if firewall state matches reality
            var baseline = _firewall.GetBaseline();
            var isEnforced = baseline.PrivateDefaultOutbound == FirewallAction.Block ||
                             baseline.PublicDefaultOutbound == FirewallAction.Block;

            if (!isEnforced)
            {
                _logger.LogWarning("Session {SessionId} was marked ACTIVE but firewall is not enforcing BLOCK. Reconciling.",
                    incompleteState.SessionId);

                await _enforcer.RemoveEnforcementAsync(incompleteState.SessionId, cancellationToken);
                _journal.UpdateEnforcementState(incompleteState.SessionId, EnforcementState.Conflict,
                    failureReason: "Firewall default outbound block was missing on startup.", conflictDetected: true);

                _state = EnforcementState.Conflict;
                _currentSession = incompleteState with { State = EnforcementState.Conflict };

                return new RecoveryResult(
                    RecoveryRequired: true,
                    Success: true,
                    RecoveredSessionId: incompleteState.SessionId,
                    OrphanRulesCleaned: 0,
                    BaselineRestored: false,
                    ConflictDetected: true,
                    Details: "Firewall was not enforcing block on startup; recorded conflict."
                );
            }

            // Check if there was an in-flight update when service terminated
            var pendingUpdate = _journal.GetIncompleteUpdate(incompleteState.SessionId);
            if (pendingUpdate is not null)
            {
                if (incompleteState.PolicyVersion == pendingUpdate.NewPolicyVersion &&
                    incompleteState.PolicyId == pendingUpdate.NewPolicyId)
                {
                    // Case B: SQLite already committed Policy B before final journal update
                    _logger.LogInformation("Startup reconciliation: update {UpdateId} was committed to SQLite before journal mark. Finalizing.",
                        pendingUpdate.UpdateId);
                    _journal.UpdateUpdateJournalPhase(pendingUpdate.UpdateId, PolicyUpdatePhase.UpdateCommitted);
                }
                else
                {
                    // Case A / Case C: Update was not committed. Roll back candidate rules, preserve committed Policy A!
                    _logger.LogWarning("Startup reconciliation: update {UpdateId} was in-flight in phase {Phase}. Rolling back candidate rules to preserve committed Policy v{Version}.",
                        pendingUpdate.UpdateId, pendingUpdate.Phase, incompleteState.PolicyVersion);

                    foreach (var rule in pendingUpdate.CandidateRules)
                    {
                        try { _firewall.RemoveRule(rule.Name); _journal.RemoveAppliedRule(incompleteState.SessionId, rule.Name); } catch { }
                    }

                    _journal.UpdateUpdateJournalPhase(pendingUpdate.UpdateId, PolicyUpdatePhase.UpdateFailed,
                        "Interrupted by service restart before commit");
                }
            }

            _state = EnforcementState.Active;
            _currentSession = incompleteState;
            _logger.LogInformation("Recovered existing valid ACTIVE session: {SessionId}", incompleteState.SessionId);

            return new RecoveryResult(
                RecoveryRequired: false,
                Success: true,
                RecoveredSessionId: incompleteState.SessionId,
                OrphanRulesCleaned: 0,
                BaselineRestored: false,
                ConflictDetected: false,
                Details: "Active session restored successfully."
            );
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<PolicyUpdateResult> UpdatePolicyAsync(
        SignedPolicyMessage updateMessage,
        DateTimeOffset? currentTimeUtc = null,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            // 1. Must be in ACTIVE state with a valid current session
            if (_state != EnforcementState.Active || _currentSession is null)
            {
                _logger.LogWarning("Policy update rejected: endpoint is in state {State}, not ACTIVE.", _state);
                return new PolicyUpdateResult(false, _currentSession?.SessionId ?? Guid.Empty, 0, 0,
                    $"Cannot update policy: endpoint is in state '{_state}', must be ACTIVE.");
            }

            var sessionId = _currentSession.SessionId;
            var currentExamId = _currentSession.ExamId;
            var currentVersion = _currentSession.PolicyVersion;
            var currentPolicyId = _currentSession.PolicyId;

            _logger.LogInformation("Processing dynamic policy update for Session: {SessionId}, Exam: {ExamId}, CurrentVersion: {Version}",
                sessionId, currentExamId, currentVersion);

            // 2. Validate Candidate Policy via M5 PolicyReceiver (commitVersion = false)
            var validation = await _receiver.ProcessPolicyMessageAsync(
                updateMessage,
                currentExamId,
                currentTimeUtc,
                commitVersion: false,
                cancellationToken: cancellationToken);

            if (validation.Status != PolicyAcceptanceStatus.Accepted || validation.ValidatedPolicy is null)
            {
                _logger.LogWarning("Candidate policy rejected ({Status}): {Details}. Current policy v{CurrentVersion} remains active.",
                    validation.Status, validation.Details, currentVersion);
                return new PolicyUpdateResult(false, sessionId, currentVersion, 0,
                    $"Candidate validation failed: {validation.Status} ({validation.Details})");
            }

            var candidate = validation.ValidatedPolicy;

            // 3. Version Monotonicity Check: candidate.Version > currentVersion
            if (candidate.Version <= currentVersion)
            {
                _logger.LogWarning("Version rollback/replay rejected: candidate v{NewVersion} <= current v{CurrentVersion}.",
                    candidate.Version, currentVersion);
                return new PolicyUpdateResult(false, sessionId, currentVersion, candidate.Version,
                    $"Candidate version {candidate.Version} must be strictly greater than active version {currentVersion}.");
            }

            // 4. Exam binding check
            if (candidate.ExamId != currentExamId)
            {
                _logger.LogWarning("Exam mismatch rejected: candidate exam {CandidateExam} != active {ActiveExam}.",
                    candidate.ExamId, currentExamId);
                return new PolicyUpdateResult(false, sessionId, currentVersion, candidate.Version,
                    $"Candidate exam ID '{candidate.ExamId}' does not match active exam ID '{currentExamId}'.");
            }

            // 5. Generate Candidate Firewall Rules
            var now = currentTimeUtc ?? DateTimeOffset.UtcNow;
            var targetProfiles = FirewallProfiles.All;
            var candidateRules = new List<FirewallRuleModel>();

            // Management server rules
            foreach (var mgmtIp in candidate.ManagementServer.IpAddresses)
            {
                candidateRules.Add(FirewallRuleModel.CreateOutboundAllow(
                    sessionId,
                    "Mgmt",
                    FirewallProtocol.TCP,
                    mgmtIp,
                    candidate.ManagementServer.Port.ToString(),
                    profiles: targetProfiles));
            }

            // Vendor rules
            foreach (var dest in candidate.AllowedDestinations)
            {
                foreach (var ip in dest.IpRanges)
                {
                    if (dest.TcpPorts.Count > 0)
                    {
                        var tcpPortsStr = string.Join(",", dest.TcpPorts);
                        candidateRules.Add(FirewallRuleModel.CreateOutboundAllow(
                            sessionId,
                            dest.Name,
                            FirewallProtocol.TCP,
                            ip,
                            tcpPortsStr,
                            profiles: targetProfiles));
                    }

                    if (dest.UdpPorts.Count > 0)
                    {
                        var udpPortsStr = string.Join(",", dest.UdpPorts);
                        candidateRules.Add(FirewallRuleModel.CreateOutboundAllow(
                            sessionId,
                            dest.Name,
                            FirewallProtocol.UDP,
                            ip,
                            udpPortsStr,
                            profiles: targetProfiles));
                    }
                }
            }

            // Diff rules:
            var currentInstalledRules = _firewall.GetRulesByGroup(FirewallRuleModel.SpemcsRuleGroup);
            var currentRuleNames = currentInstalledRules.Select(r => r.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var candidateRuleNames = candidateRules.Select(r => r.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);

            var rulesToInstall = candidateRules.Where(r => !currentRuleNames.Contains(r.Name)).ToList();
            var rulesToRetire = currentInstalledRules.Where(r => !candidateRuleNames.Contains(r.Name)).ToList();
            var retiredRuleNames = rulesToRetire.Select(r => r.Name).ToList();

            // 6. Record Update Transaction in SQLite Journal
            var updateId = Guid.NewGuid();
            var updateRecord = new DurableUpdateJournalRecord(
                UpdateId: updateId,
                SessionId: sessionId,
                ExamId: currentExamId,
                OldPolicyId: currentPolicyId,
                OldPolicyVersion: currentVersion,
                NewPolicyId: candidate.PolicyId,
                NewPolicyVersion: candidate.Version,
                Phase: PolicyUpdatePhase.UpdatePending,
                StartedUtc: now,
                CompletedUtc: null,
                CandidateRules: candidateRules,
                RetiredRuleNames: retiredRuleNames,
                FailureReason: null
            );
            _journal.SaveUpdateJournal(updateRecord);

            // -----------------------------------------------------------------
            // Phase B: Install New Allow Rules (Additive first!)
            // -----------------------------------------------------------------
            _journal.UpdateUpdateJournalPhase(updateId, PolicyUpdatePhase.UpdateApplying);
            var newlyInstalled = new List<FirewallRuleModel>();

            try
            {
                foreach (var rule in rulesToInstall)
                {
                    _firewall.AddRule(rule);
                    _journal.RecordAppliedRule(sessionId, rule.Name);
                    newlyInstalled.Add(rule);
                }

                // -------------------------------------------------------------
                // Phase C: Verify New Candidate Rules Exist in Firewall
                // -------------------------------------------------------------
                _journal.UpdateUpdateJournalPhase(updateId, PolicyUpdatePhase.UpdateVerifying);
                foreach (var rule in candidateRules)
                {
                    if (!_firewall.RuleExists(rule.Name))
                    {
                        throw new InvalidOperationException($"Candidate rule '{rule.Name}' verification failed after installation.");
                    }
                }

                // -------------------------------------------------------------
                // Phase D: Verify Management Connectivity with Candidate Rules
                // -------------------------------------------------------------
                var mgmtCheck = await _connectivity.VerifyConnectivityAsync(candidate.ManagementServer, cancellationToken);
                if (!mgmtCheck)
                {
                    throw new InvalidOperationException("Management plane unreachable under candidate rule set.");
                }

                // -------------------------------------------------------------
                // Phase E: Retire Old Rules No Longer Present
                // -------------------------------------------------------------
                foreach (var oldRule in rulesToRetire)
                {
                    _firewall.RemoveRule(oldRule.Name);
                    _journal.RemoveAppliedRule(sessionId, oldRule.Name);
                }

                // -------------------------------------------------------------
                // Phase F: Verify Final Restrictive State (Block Readback)
                // -------------------------------------------------------------
                var baseline = _firewall.GetBaseline();
                var readbackSuccess = baseline.PrivateDefaultOutbound == FirewallAction.Block ||
                                      baseline.PublicDefaultOutbound == FirewallAction.Block;

                if (!readbackSuccess)
                {
                    throw new InvalidOperationException("DefaultOutboundAction readback check failed during policy update.");
                }

                // -------------------------------------------------------------
                // Phase G: Commit Candidate Policy
                // -------------------------------------------------------------
                _journal.UpdateUpdateJournalPhase(updateId, PolicyUpdatePhase.UpdateCommitting);

                _currentSession = _currentSession with
                {
                    PolicyId = candidate.PolicyId,
                    PolicyVersion = candidate.Version,
                    ExpiresAtUtc = candidate.ExpiresAt,
                    LastTransitionUtc = DateTimeOffset.UtcNow
                };

                _journal.SaveEnforcementState(_currentSession);
                _journal.RecordPolicyVersion(currentExamId, candidate.Version);
                _journal.UpdateUpdateJournalPhase(updateId, PolicyUpdatePhase.UpdateCommitted);

                _logger.LogInformation("Policy update committed successfully: Session {SessionId} now on v{NewVersion}.",
                    sessionId, candidate.Version);

                return new PolicyUpdateResult(true, sessionId, currentVersion, candidate.Version);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Policy update failed during transition. Executing update rollback to preserve Policy v{CurrentVersion}.",
                    currentVersion);

                // Update Rollback: Clean up newly installed rules, re-add retired rules if any were removed
                _journal.UpdateUpdateJournalPhase(updateId, PolicyUpdatePhase.UpdateRollback, ex.Message);

                foreach (var rule in newlyInstalled)
                {
                    try { _firewall.RemoveRule(rule.Name); _journal.RemoveAppliedRule(sessionId, rule.Name); } catch { }
                }

                foreach (var retiredRule in rulesToRetire)
                {
                    try { _firewall.AddRule(retiredRule); _journal.RecordAppliedRule(sessionId, retiredRule.Name); } catch { }
                }

                _journal.UpdateUpdateJournalPhase(updateId, PolicyUpdatePhase.UpdateFailed, ex.Message);

                // Policy A remains ACTIVE!
                return new PolicyUpdateResult(false, sessionId, currentVersion, candidate.Version,
                    $"Update failed and safely rolled back to active v{currentVersion}: {ex.Message}");
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<EnforcementActivationResult> HandleApplyFailureAsync(
        Guid sessionId,
        string failureReason,
        CancellationToken cancellationToken)
    {
        _state = EnforcementState.RollingBack;
        _journal.UpdateEnforcementState(sessionId, EnforcementState.RollingBack, failureReason: failureReason);

        var rollback = await _enforcer.RemoveEnforcementAsync(sessionId, cancellationToken);

        if (rollback.ConflictDetected)
        {
            _state = EnforcementState.Conflict;
            _journal.UpdateEnforcementState(sessionId, EnforcementState.Conflict,
                failureReason: failureReason, conflictDetected: true);
            _currentSession = null;
            return new EnforcementActivationResult(false, sessionId, EnforcementState.Conflict,
                $"Activation failed and rollback detected conflict: {failureReason}");
        }

        _state = EnforcementState.Failed;
        _journal.UpdateEnforcementState(sessionId, EnforcementState.Failed,
            failureReason: failureReason, rollbackCompleted: true);
        _currentSession = null;

        return new EnforcementActivationResult(false, sessionId, EnforcementState.Failed, failureReason);
    }
}
