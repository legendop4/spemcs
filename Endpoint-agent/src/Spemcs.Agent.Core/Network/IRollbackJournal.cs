using System;
using System.Collections.Generic;

namespace Spemcs.Agent.Core.Network;

/// <summary>
/// Durable SQLite-backed rollback journal interface.
/// </summary>
public interface IRollbackJournal
{
    /// <summary>Records or updates an enforcement session record.</summary>
    void SaveSession(JournalRecord record);

    /// <summary>Updates the current phase of a session.</summary>
    void UpdatePhase(Guid sessionId, EnforcementPhase phase, string? lastError = null);

    /// <summary>Records an applied rule name for the session.</summary>
    void RecordAppliedRule(Guid sessionId, string ruleName);

    /// <summary>Removes an applied rule record when retired during dynamic update.</summary>
    void RemoveAppliedRule(Guid sessionId, string ruleName);

    /// <summary>Retrieves a specific journal record by session ID.</summary>
    JournalRecord? GetSession(Guid sessionId);

    /// <summary>Retrieves the latest or incomplete active session, if any exists.</summary>
    JournalRecord? GetLatestActiveOrIncompleteSession();

    /// <summary>Lists all journal records.</summary>
    IReadOnlyList<JournalRecord> GetAllSessions();

    /// <summary>Marks a session as resolved/conflict.</summary>
    void RecordConflict(Guid sessionId, string conflictDetails);

    /// <summary>Retrieves the highest seen/accepted policy version for an exam context.</summary>
    int GetHighestPolicyVersion(Guid examId);

    /// <summary>Persists an accepted policy version for an exam context to prevent replay/rollback.</summary>
    void RecordPolicyVersion(Guid examId, int version);

    /// <summary>Persists a durable enforcement state machine record.</summary>
    void SaveEnforcementState(DurableEnforcementRecord record);

    /// <summary>Updates the state of an active enforcement record.</summary>
    void UpdateEnforcementState(Guid sessionId, EnforcementState state, string? failureReason = null, bool rollbackCompleted = false, bool conflictDetected = false);

    /// <summary>Retrieves durable enforcement state by session ID.</summary>
    DurableEnforcementRecord? GetEnforcementState(Guid sessionId);

    /// <summary>Retrieves the latest active enforcement state record if present.</summary>
    DurableEnforcementRecord? GetActiveEnforcementState();

    /// <summary>Retrieves all durable enforcement records.</summary>
    IReadOnlyList<DurableEnforcementRecord> GetAllEnforcementStates();

    /// <summary>Persists a dynamic policy update transaction record.</summary>
    void SaveUpdateJournal(DurableUpdateJournalRecord record);

    /// <summary>Updates the phase of a dynamic policy update transaction.</summary>
    void UpdateUpdateJournalPhase(Guid updateId, PolicyUpdatePhase phase, string? failureReason = null);

    /// <summary>Retrieves any in-flight/incomplete policy update for a session.</summary>
    DurableUpdateJournalRecord? GetIncompleteUpdate(Guid sessionId);

    /// <summary>Retrieves a policy update record by update ID.</summary>
    DurableUpdateJournalRecord? GetUpdate(Guid updateId);

    /// <summary>Records a processed control command to prevent replay across restarts.</summary>
    void RecordProcessedCommand(string commandId, string action, Guid examId, Guid? sessionId, DateTimeOffset expiresUtc);

    /// <summary>Checks if a control command has already been processed.</summary>
    bool IsCommandProcessed(string commandId);

    /// <summary>Persists a revoked key ID.</summary>
    void SaveRevokedKey(string keyId, string reason);

    /// <summary>Retrieves all persisted revoked key IDs.</summary>
    IReadOnlySet<string> GetRevokedKeys();
}
