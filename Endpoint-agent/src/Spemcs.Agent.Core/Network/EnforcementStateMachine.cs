using System;
using System.Collections.Generic;
using System.IO;
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
    private readonly IBrowserExecutableResolver _browserResolver;
    private readonly IApprovedBrowserContext? _approvedBrowser;
    private readonly ILogger<EnforcementStateMachine> _logger;

    private readonly SemaphoreSlim _gate = new(1, 1);
    private DurableEnforcementRecord? _currentSession;
    private EnforcementState _state = EnforcementState.Idle;

    public EnforcementState CurrentState => _state;
    public DurableEnforcementRecord? CurrentSession => _currentSession;

    /// <param name="browserResolver">
    /// Resolves the approved browser family named in the signed policy to a concrete, trusted
    /// executable path (requirements 4 and 5). Optional only so existing call sites keep compiling;
    /// when omitted the real <see cref="BrowserExecutableResolver"/> is used, which fails closed if
    /// no trusted browser is installed.
    /// </param>
    /// <param name="approvedBrowser">
    /// Shared context through which the SIGNED approved-browser family reaches the detection side of
    /// the agent (process classifier, network policy evaluator). Activation binds it; rollback
    /// releases it. Optional so that firewall-only tests and existing call sites keep compiling -
    /// when omitted, enforcement still scopes rules correctly, but the monitor falls back to its
    /// host-configured family.
    /// </param>
    public EnforcementStateMachine(
        IPolicyReceiver receiver,
        INetworkEnforcer enforcer,
        IFirewallAdapter firewall,
        IRollbackJournal journal,
        IManagementConnectivityVerifier connectivity,
        ILogger<EnforcementStateMachine>? logger = null,
        IBrowserExecutableResolver? browserResolver = null,
        IApprovedBrowserContext? approvedBrowser = null)
    {
        _receiver = receiver ?? throw new ArgumentNullException(nameof(receiver));
        _enforcer = enforcer ?? throw new ArgumentNullException(nameof(enforcer));
        _firewall = firewall ?? throw new ArgumentNullException(nameof(firewall));
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _connectivity = connectivity ?? throw new ArgumentNullException(nameof(connectivity));
        _browserResolver = browserResolver ?? new BrowserExecutableResolver();
        _approvedBrowser = approvedBrowser;
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
            // Precondition 3: Resolve the Approved Examination Browser (Requirements 4 & 5)
            // -----------------------------------------------------------------
            // Vendor destination allow rules are scoped to this executable. Resolution happens
            // BEFORE any durable Preparing record is written and before a single firewall rule is
            // touched, so a machine without a trusted approved browser leaves the firewall
            // completely untouched instead of needing a rollback.
            //
            // Failing closed here is deliberate: the alternative (installing unscoped rules) would
            // hand the exam allowlist to every process on the machine.
            var browserResolution = _browserResolver.Resolve(policy.ApprovedBrowser);
            if (!browserResolution.Success || string.IsNullOrWhiteSpace(browserResolution.ExecutablePath))
            {
                _logger.LogError(
                    "Activation aborted: could not resolve approved browser {ApprovedBrowser} to a trusted executable. {Details}",
                    policy.ApprovedBrowser, browserResolution.Details);

                _state = EnforcementState.Failed;
                var browserFailureReason =
                    $"Approved browser '{policy.ApprovedBrowser}' could not be resolved to a trusted executable, " +
                    $"so vendor allow rules cannot be scoped to it. {browserResolution.Details}";

                _journal.SaveEnforcementState(new DurableEnforcementRecord(
                    SessionId: sessionId,
                    ExamId: expectedExamId,
                    PolicyId: policy.PolicyId,
                    PolicyVersion: policy.Version,
                    State: EnforcementState.Failed,
                    ActivationUtc: DateTimeOffset.UtcNow,
                    ExpiresAtUtc: DateTimeOffset.UtcNow,
                    LastTransitionUtc: DateTimeOffset.UtcNow,
                    FailureReason: browserFailureReason
                ));

                return new EnforcementActivationResult(false, sessionId, EnforcementState.Failed, browserFailureReason);
            }

            var browserExecutablePath = browserResolution.ExecutablePath;

            if (browserResolution.IsUserWritableLocation)
            {
                // Not fatal - a per-user Chrome install is legitimate - but the firewall matches on
                // path, so an operator needs to know the allowlisted image is user-writable.
                _logger.LogWarning(
                    "Approved browser {ApprovedBrowser} resolved to a USER-WRITABLE location: {Details}",
                    policy.ApprovedBrowser, browserResolution.Details);
            }
            else
            {
                _logger.LogInformation("Approved browser resolved: {Details}", browserResolution.Details);
            }

            // -----------------------------------------------------------------
            // Precondition 4: Publish the SIGNED family to the detection path (Requirement 4)
            // -----------------------------------------------------------------
            // The firewall is about to grant network access to exactly one executable. Unless the
            // process classifier and the network policy evaluator agree on which browser that is,
            // the endpoint contradicts itself: the approved browser gets reported as a violation
            // while a non-approved browser's (already blocked) traffic is suppressed from telemetry.
            // Binding here - after signature verification, before any firewall mutation - means the
            // monitor can only ever be told a family that came out of the signed policy.
            if (_approvedBrowser is not null
                && !_approvedBrowser.BindSignedPolicy(
                    sessionId,
                    policy.ApprovedBrowser,
                    $"signed policy {policy.PolicyId} v{policy.Version}"))
            {
                // Reached only if a DIFFERENT session still owns the binding. The duplicate/conflict
                // precondition above already refuses a second concurrent session, so this means a
                // previous session was torn down without releasing. Failing closed is the only safe
                // answer: continuing would enforce this exam's browser while the monitor keeps
                // approving the previous one.
                var bindingOwner = _approvedBrowser.Current.SessionId;
                var bindConflictReason =
                    $"Approved browser context is still bound to session '{bindingOwner}'. " +
                    "Enforcement and monitoring would disagree about the approved browser, so activation " +
                    "was refused rather than applied inconsistently.";

                _logger.LogError(
                    "Activation aborted: approved-browser context still bound to session {OwnerSessionId}.",
                    bindingOwner);

                _state = EnforcementState.Failed;
                _journal.SaveEnforcementState(new DurableEnforcementRecord(
                    SessionId: sessionId,
                    ExamId: expectedExamId,
                    PolicyId: policy.PolicyId,
                    PolicyVersion: policy.Version,
                    State: EnforcementState.Failed,
                    ActivationUtc: DateTimeOffset.UtcNow,
                    ExpiresAtUtc: DateTimeOffset.UtcNow,
                    LastTransitionUtc: DateTimeOffset.UtcNow,
                    FailureReason: bindConflictReason
                ));

                return new EnforcementActivationResult(false, sessionId, EnforcementState.Failed, bindConflictReason);
            }

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
            var rules = BuildSessionRules(sessionId, policy, targetProfiles, browserExecutablePath);

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
            var readbackSuccess = AllTargetProfilesAreBlocking(
                targetProfiles, baseline, sessionId, "Activation readback");

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

                // Released even though rollback did not fully complete. The exam is over either way,
                // and holding the binding would only prevent the NEXT session from starting; the
                // conflict itself is recorded durably for an operator to act on.
                ReleaseApprovedBrowserBinding(sessionId, "deactivation hit an external configuration conflict");

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
            ReleaseApprovedBrowserBinding(sessionId, reason);

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
                ReleaseApprovedBrowserBinding(incompleteState.SessionId, "session expired while the service was stopped");

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
                ReleaseApprovedBrowserBinding(incompleteState.SessionId, "incomplete activation rolled back at startup");

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
            var reconcileProfiles = GetSessionTargetProfiles(incompleteState.SessionId);
            var isEnforced = AllTargetProfilesAreBlocking(
                reconcileProfiles, baseline, incompleteState.SessionId, "Startup reconciliation");

            if (!isEnforced)
            {
                _logger.LogWarning("Session {SessionId} was marked ACTIVE but firewall is not enforcing BLOCK on every targeted profile ({Profiles}). Reconciling.",
                    incompleteState.SessionId, reconcileProfiles);

                await _enforcer.RemoveEnforcementAsync(incompleteState.SessionId, cancellationToken);
                _journal.UpdateEnforcementState(incompleteState.SessionId, EnforcementState.Conflict,
                    failureReason: $"Firewall default outbound block was missing on startup for one or more of {reconcileProfiles}.",
                    conflictDetected: true);

                _state = EnforcementState.Conflict;
                _currentSession = incompleteState with { State = EnforcementState.Conflict };
                ReleaseApprovedBrowserBinding(incompleteState.SessionId,
                    "session was ACTIVE in the journal but the firewall was not enforcing at startup");

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
            RebindApprovedBrowserAfterRestart(incompleteState.SessionId);
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

            // 5. Resolve the approved examination browser for the candidate policy.
            //    Same fail-closed contract as activation: no trusted browser means no scoped rules,
            //    and unscoped vendor rules are not an acceptable fallback. The active policy stays
            //    in force, so refusing the update is strictly safe.
            var candidateBrowser = _browserResolver.Resolve(candidate.ApprovedBrowser);
            if (!candidateBrowser.Success || string.IsNullOrWhiteSpace(candidateBrowser.ExecutablePath))
            {
                _logger.LogError(
                    "Policy update rejected: approved browser {ApprovedBrowser} could not be resolved to a trusted executable. {Details}",
                    candidate.ApprovedBrowser, candidateBrowser.Details);
                return new PolicyUpdateResult(false, sessionId, currentVersion, candidate.Version,
                    $"Approved browser '{candidate.ApprovedBrowser}' could not be resolved to a trusted executable; " +
                    $"vendor allow rules must be scoped to it. {candidateBrowser.Details}");
            }

            var candidateBrowserPath = candidateBrowser.ExecutablePath;

            // 6. Generate Candidate Firewall Rules
            var now = currentTimeUtc ?? DateTimeOffset.UtcNow;

            // Reuse the profile set the session was activated with instead of assuming All.
            // A session started for Private|Public must not silently widen to Domain on update
            // (and vice versa: a Domain-inclusive session must not narrow). The journal is the
            // durable record of that choice, so it survives a service restart.
            var targetProfiles = _journal.GetSession(sessionId)?.TargetProfiles ?? FirewallProfiles.All;
            var candidateRules = BuildSessionRules(sessionId, candidate, targetProfiles, candidateBrowserPath);

            // Diff rules - restricted to THIS session's rules.
            //
            // Requirement 9: GetRulesByGroup returns every SPEMCS rule on the machine. Diffing
            // against the whole group would mark a concurrent session's rules as "not in my
            // candidate set" and retire them, tearing down another exam's lockdown. Rule names are
            // session-prefixed, which is what makes ownership decidable here.
            var sessionRulePrefix = $"SPEMCS-{sessionId:N}-";
            var currentInstalledRules = _firewall.GetRulesByGroup(FirewallRuleModel.SpemcsRuleGroup)
                .Where(r => r.Name.StartsWith(sessionRulePrefix, StringComparison.OrdinalIgnoreCase))
                .ToList();

            // A mid-exam browser change would leave the endpoint internally contradictory: the
            // firewall would permit the new browser while the process classifier still approves the
            // browser bound at activation (see IApprovedBrowserContext - the binding is deliberately
            // not re-asserted here). Detect it from live firewall state rather than memory so the
            // check also holds after a service restart.
            var installedScopedPaths = currentInstalledRules
                .Where(r => !string.IsNullOrWhiteSpace(r.ApplicationPath))
                .Select(r => r.ApplicationPath!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            var conflictingPath = installedScopedPaths
                .FirstOrDefault(p => !string.Equals(p, candidateBrowserPath, StringComparison.OrdinalIgnoreCase));

            if (conflictingPath is not null)
            {
                _logger.LogError(
                    "Policy update rejected: candidate scopes rules to '{CandidatePath}' but the active session is scoped to '{InstalledPath}'. Mid-exam browser changes are not permitted.",
                    candidateBrowserPath, conflictingPath);
                return new PolicyUpdateResult(false, sessionId, currentVersion, candidate.Version,
                    $"Candidate policy would re-scope enforcement from '{conflictingPath}' to '{candidateBrowserPath}'. " +
                    "The approved examination browser cannot change mid-session: the process classifier is fixed at " +
                    "session start, so the firewall and the monitor would disagree. Stop and restart the session instead.");
            }

            var currentRuleNames = currentInstalledRules.Select(r => r.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var candidateRuleNames = candidateRules.Select(r => r.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);

            var rulesToInstall = candidateRules.Where(r => !currentRuleNames.Contains(r.Name)).ToList();
            var rulesToRetire = currentInstalledRules.Where(r => !candidateRuleNames.Contains(r.Name)).ToList();
            var retiredRuleNames = rulesToRetire.Select(r => r.Name).ToList();

            // 7. Record Update Transaction in SQLite Journal
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
                // Checked against this session's own profile set (resolved at Phase 6 from the
                // journal), not a fixed Private|Public pair: a rule swap must not be allowed to
                // commit while any profile the session claims to lock down has drifted off BLOCK.
                var baseline = _firewall.GetBaseline();
                var readbackSuccess = AllTargetProfilesAreBlocking(
                    targetProfiles, baseline, sessionId, "Policy update Phase F readback");

                if (!readbackSuccess)
                {
                    throw new InvalidOperationException(
                        $"DefaultOutboundAction readback check failed during policy update: not every targeted profile ({targetProfiles}) reports BLOCK.");
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

    /// <summary>
    /// Builds the complete set of SPEMCS-owned outbound ALLOW rules for a session.
    /// </summary>
    /// <param name="sessionId">Session that owns (and will roll back) these rules.</param>
    /// <param name="policy">The verified, signed policy.</param>
    /// <param name="targetProfiles">Profiles the rules apply to.</param>
    /// <param name="browserExecutablePath">
    /// Absolute path to the approved examination browser, already resolved and trust-verified by
    /// <see cref="IBrowserExecutableResolver"/>.
    /// <para>
    /// REQUIREMENTS 4 &amp; 5. Every vendor/exam destination rule below is scoped to this
    /// executable. Without it, the allowlist is usable by every process on the machine: a student
    /// could reach the permitted destinations with curl.exe, python.exe, or a tunnelling client
    /// and exfiltrate through the one hole the exam has to leave open. The parameter is
    /// deliberately REQUIRED with no default - a caller that has not resolved a browser must not
    /// be able to accidentally produce unscoped rules.
    /// </para>
    /// </param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="browserExecutablePath"/> is missing or not rooted. Throwing is
    /// the fail-closed behaviour: it is strictly better for activation to abort than to install a
    /// machine-wide allowlist.
    /// </exception>
    public static List<FirewallRuleModel> BuildSessionRules(
        Guid sessionId,
        ValidatedPolicy policy,
        FirewallProfiles targetProfiles,
        string browserExecutablePath)
    {
        ArgumentNullException.ThrowIfNull(policy);

        if (string.IsNullOrWhiteSpace(browserExecutablePath))
        {
            throw new ArgumentException(
                "browserExecutablePath is required: vendor allow rules must be scoped to the approved " +
                "examination browser (requirements 4 and 5). Refusing to build unscoped rules.",
                nameof(browserExecutablePath));
        }

        if (!Path.IsPathRooted(browserExecutablePath))
        {
            // A relative path in a firewall rule is resolved against an unspecified working
            // directory - it would either match nothing or match the wrong image.
            throw new ArgumentException(
                $"browserExecutablePath must be an absolute path; got '{browserExecutablePath}'.",
                nameof(browserExecutablePath));
        }

        var rules = new List<FirewallRuleModel>();

        // 1. Explicit product-owned loopback rules (Outbound Any, Local <-> Remote 127.0.0.1 and ::1)
        //
        //    Intentionally NOT program-scoped. Loopback carries the agent's own IPC (named pipes
        //    fall back to TCP loopback on some stacks), the local DNS stub resolver, and browser
        //    helper processes. Restricting loopback to a single executable would break the agent's
        //    own control plane, and loopback traffic cannot leave the machine, so it is not an
        //    exfiltration path.
        rules.Add(FirewallRuleModel.CreateLoopbackIPv4Allow(sessionId, targetProfiles));
        rules.Add(FirewallRuleModel.CreateLoopbackIPv6Allow(sessionId, targetProfiles));

        // 2. Management server allow rules (Outbound TCP, clean IP, specific port).
        //
        //    Also intentionally NOT program-scoped: this channel belongs to the SPEMCS agent
        //    (a Windows service), not to the browser. Scoping it to the browser would sever the
        //    agent's link to the management plane the moment default-deny engages - and step 7 of
        //    ActivateAsync would then roll the whole activation back. It stays narrow by being
        //    pinned to specific management IPs and a single port.
        foreach (var mgmtIp in policy.ManagementServer.IpAddresses)
        {
            var cleanIp = mgmtIp.Contains('/') ? mgmtIp.Split('/')[0] : mgmtIp;
            rules.Add(FirewallRuleModel.CreateOutboundAllow(
                sessionId: sessionId,
                purpose: "Mgmt",
                protocol: FirewallProtocol.TCP,
                remoteAddresses: cleanIp,
                remotePorts: policy.ManagementServer.Port.ToString(),
                localAddresses: "*",
                applicationPath: null,
                serviceName: null,
                profiles: targetProfiles));
        }

        // 3. Vendor & exam allowed destinations - ALWAYS scoped to the approved browser.
        foreach (var dest in policy.AllowedDestinations)
        {
            foreach (var ip in dest.IpRanges)
            {
                if (dest.TcpPorts.Count > 0)
                {
                    var tcpPortsStr = string.Join(",", dest.TcpPorts);
                    rules.Add(FirewallRuleModel.CreateOutboundAllow(
                        sessionId: sessionId,
                        purpose: dest.Name,
                        protocol: FirewallProtocol.TCP,
                        remoteAddresses: ip,
                        remotePorts: tcpPortsStr,
                        localAddresses: "*",
                        applicationPath: browserExecutablePath,
                        profiles: targetProfiles));
                }

                if (dest.UdpPorts.Count > 0)
                {
                    var udpPortsStr = string.Join(",", dest.UdpPorts);
                    rules.Add(FirewallRuleModel.CreateOutboundAllow(
                        sessionId: sessionId,
                        purpose: dest.Name,
                        protocol: FirewallProtocol.UDP,
                        remoteAddresses: ip,
                        remotePorts: udpPortsStr,
                        localAddresses: "*",
                        applicationPath: browserExecutablePath,
                        profiles: targetProfiles));
                }
            }
        }

        return rules;
    }

    /// <summary>
    /// Restores the approved-browser binding for a session that was still ACTIVE when the service
    /// restarted.
    /// <para>
    /// The binding lives in memory, so it dies with the process while the exam keeps running. The
    /// family is recovered from evidence rather than re-asserted: the installed allow rules are
    /// scoped to the approved browser's executable, so the image name on those rules is what the
    /// firewall is actually enforcing. Deriving it this way means the monitor cannot disagree with
    /// the firewall even though the signed policy itself is no longer in memory.
    /// </para>
    /// <para>
    /// Fails soft. If nothing can be derived, enforcement is unaffected - the firewall rules are
    /// already installed and still scoped correctly - and monitoring falls back to the
    /// host-configured family, which is logged as a warning so the resulting noise is explainable.
    /// </para>
    /// </summary>
    private void RebindApprovedBrowserAfterRestart(Guid sessionId)
    {
        if (_approvedBrowser is null)
        {
            return;
        }

        var families = new HashSet<ApprovedBrowserFamily>();

        try
        {
            var sessionRulePrefix = $"SPEMCS-{sessionId:N}-";

            var scopedImageNames = _firewall.GetRulesByGroup(FirewallRuleModel.SpemcsRuleGroup)
                .Where(r => r.Name.StartsWith(sessionRulePrefix, StringComparison.OrdinalIgnoreCase)
                            && !string.IsNullOrWhiteSpace(r.ApplicationPath))
                .Select(r => Path.GetFileName(r.ApplicationPath!))
                .Where(n => !string.IsNullOrWhiteSpace(n))
                .Distinct(StringComparer.OrdinalIgnoreCase);

            foreach (var imageName in scopedImageNames)
            {
                if (ApprovedBrowserFamilies.TryResolveFromProcessName(imageName, out var family))
                {
                    families.Add(family);
                }
            }
        }
        catch (Exception ex)
        {
            // Reading the firewall can fail (service stopped, COM error). Enforcement state is
            // untouched by this method, so degrading to host configuration is safe.
            _logger.LogWarning(ex,
                "Could not read installed rules to recover the approved browser for session {SessionId}.",
                sessionId);
            return;
        }

        if (families.Count != 1)
        {
            _logger.LogWarning(
                "Could not determine the approved browser for recovered session {SessionId} from installed rules " +
                "({MatchCount} candidate families). Monitoring will use the host-configured family ({Family}); " +
                "browser-related findings for this session may be inaccurate until it is restarted.",
                sessionId, families.Count, _approvedBrowser.Effective);
            return;
        }

        var recovered = families.Single();

        if (_approvedBrowser.BindSignedPolicy(sessionId, recovered,
                $"recovered at startup from installed rules for session {sessionId}"))
        {
            _logger.LogInformation(
                "Approved browser {Family} recovered for ACTIVE session {SessionId} from its installed firewall rules.",
                recovered, sessionId);
        }
        else
        {
            _logger.LogError(
                "Approved browser {Family} could not be re-bound for recovered session {SessionId}: the context is " +
                "held by session {OwnerSessionId}.",
                recovered, sessionId, _approvedBrowser.Current.SessionId);
        }
    }

    /// <summary>
    /// Hands the approved-browser decision back to host configuration once this session no longer
    /// has firewall rules installed.
    /// <para>
    /// Called from EVERY terminal path (deactivation, activation failure, conflict, expiry, startup
    /// reconciliation). That completeness is load-bearing: <see cref="ActivateAsync"/> refuses to
    /// start while another session owns the binding, so a missed release would stop the next exam on
    /// this machine from starting until the service restarts.
    /// </para>
    /// </summary>
    private void ReleaseApprovedBrowserBinding(Guid sessionId, string reason)
    {
        if (_approvedBrowser is null)
        {
            return;
        }

        if (_approvedBrowser.ReleaseSignedPolicy(sessionId))
        {
            _logger.LogInformation(
                "Approved-browser binding released for session {SessionId} ({Reason}); monitoring reverts to host configuration ({Family}).",
                sessionId, reason, _approvedBrowser.Effective);
        }
        else
        {
            // Not an error: the common cases are "never bound" (activation failed before the bind
            // step) and "already released" (expiry racing an operator stop).
            _logger.LogDebug(
                "No approved-browser binding held by session {SessionId} to release ({Reason}).",
                sessionId, reason);
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
            ReleaseApprovedBrowserBinding(sessionId, "activation failed; rollback reported a conflict");
            return new EnforcementActivationResult(false, sessionId, EnforcementState.Conflict,
                $"Activation failed and rollback detected conflict: {failureReason}");
        }

        _state = EnforcementState.Failed;
        _journal.UpdateEnforcementState(sessionId, EnforcementState.Failed,
            failureReason: failureReason, rollbackCompleted: true);
        _currentSession = null;
        ReleaseApprovedBrowserBinding(sessionId, "activation failed and was rolled back");

        return new EnforcementActivationResult(false, sessionId, EnforcementState.Failed, failureReason);
    }

    /// <summary>
    /// The profile set a session was activated with, read from the durable journal.
    /// </summary>
    /// <remarks>
    /// <see cref="DurableEnforcementRecord"/> does not carry the profile mask - only
    /// <see cref="JournalRecord"/> does - so any code holding a <c>DurableEnforcementRecord</c> (for
    /// example after a service restart) must come back here rather than assume a value. The fallback
    /// is <see cref="FirewallProfiles.All"/> because it is the strict reading: it asserts that every
    /// profile must be BLOCK, so a missing journal row can only ever cause a false conflict that a
    /// human investigates, never a false "enforced" that leaves a candidate online.
    /// </remarks>
    private FirewallProfiles GetSessionTargetProfiles(Guid sessionId)
        => _journal.GetSession(sessionId)?.TargetProfiles ?? FirewallProfiles.All;

    /// <summary>
    /// Requirement 6: reports whether EVERY profile the session claims to enforce is actually
    /// reporting <see cref="FirewallAction.Block"/> as its default outbound action.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This replaced an OR over Private and Public only. That test was wrong twice over. It ignored
    /// Domain, so a domain-joined lab PC - the normal case for a university lab - could report
    /// "enforced" with its active profile wide open. And because it was an OR, one profile being
    /// BLOCK vouched for the others: a machine that had switched networks mid-exam, or where a GPO
    /// refresh reverted a single profile, still passed.
    /// </para>
    /// <para>
    /// Every profile is inspected before returning so the log names all of the ones that are
    /// unenforced, not just the first. That difference matters when diagnosing whether one profile
    /// drifted or the whole lockdown never applied.
    /// </para>
    /// </remarks>
    private bool AllTargetProfilesAreBlocking(
        FirewallProfiles targetProfiles,
        FirewallProfileBaseline baseline,
        Guid sessionId,
        string context)
    {
        var unenforced = new List<string>();

        if (targetProfiles.HasFlag(FirewallProfiles.Domain) && baseline.DomainDefaultOutbound != FirewallAction.Block)
            unenforced.Add(nameof(FirewallProfiles.Domain));
        if (targetProfiles.HasFlag(FirewallProfiles.Private) && baseline.PrivateDefaultOutbound != FirewallAction.Block)
            unenforced.Add(nameof(FirewallProfiles.Private));
        if (targetProfiles.HasFlag(FirewallProfiles.Public) && baseline.PublicDefaultOutbound != FirewallAction.Block)
            unenforced.Add(nameof(FirewallProfiles.Public));

        // FirewallProfiles.None would make the loop above vacuously true and report "enforced" for a
        // session that locks down nothing. Treat it as a failure: it can only come from a corrupt or
        // truncated journal row, and default-deny is the invariant being verified.
        if (targetProfiles == FirewallProfiles.None)
        {
            _logger.LogError(
                "{Context}: session {SessionId} has an empty target profile set; refusing to treat it as enforced.",
                context, sessionId);
            return false;
        }

        if (unenforced.Count == 0) return true;

        _logger.LogError(
            "{Context}: session {SessionId} targets profiles {Targeted} but DefaultOutboundAction is not BLOCK for {Unenforced}.",
            context, sessionId, targetProfiles, string.Join(", ", unenforced));
        return false;
    }
}
