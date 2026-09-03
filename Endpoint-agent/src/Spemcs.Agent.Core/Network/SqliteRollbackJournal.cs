using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Spemcs.Agent.Core.Network;

/// <summary>
/// Durable SQLite-backed rollback journal implementation for network enforcement.
/// Survives service restarts, process crashes, and system reboots.
/// </summary>
public sealed class SqliteRollbackJournal : IRollbackJournal
{
    private readonly string _connectionString;
    private readonly object _gate = new();

    public SqliteRollbackJournal(string? root = null)
    {
        root ??= Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Spemcs");
        Directory.CreateDirectory(root);

        var dbPath = Path.Combine(root, "network_journal.db");
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = dbPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false
        }.ToString();

        InitializeDatabase();
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
    }

    private void InitializeDatabase()
    {
        lock (_gate)
        {
            using var conn = Open();
            using (var pragma = conn.CreateCommand())
            {
                pragma.CommandText = "PRAGMA journal_mode=WAL;";
                pragma.ExecuteNonQuery();
            }

            using var tx = conn.BeginTransaction();
            using (var cmd = conn.CreateCommand())
            {
                cmd.Transaction = tx;
                cmd.CommandText = @"
                    CREATE TABLE IF NOT EXISTS network_enforcement_journal (
                        session_id TEXT PRIMARY KEY,
                        policy_id TEXT NOT NULL,
                        policy_version INTEGER NOT NULL,
                        phase TEXT NOT NULL,
                        start_utc TEXT NOT NULL,
                        updated_utc TEXT NOT NULL,
                        baseline_json TEXT NOT NULL,
                        target_profiles INTEGER NOT NULL DEFAULT 7,
                        intended_rules_json TEXT NOT NULL,
                        applied_rules_json TEXT NOT NULL,
                        last_error TEXT NULL,
                        conflict_details TEXT NULL
                    );
                    CREATE TABLE IF NOT EXISTS applied_rules (
                        session_id TEXT NOT NULL,
                        rule_name TEXT NOT NULL,
                        applied_utc TEXT NOT NULL,
                        PRIMARY KEY (session_id, rule_name)
                    );
                    CREATE TABLE IF NOT EXISTS exam_policy_versions (
                        exam_id TEXT PRIMARY KEY,
                        highest_version INTEGER NOT NULL,
                        updated_utc TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS durable_enforcement_state (
                        session_id TEXT PRIMARY KEY,
                        exam_id TEXT NOT NULL,
                        policy_id TEXT NOT NULL,
                        policy_version INTEGER NOT NULL,
                        state TEXT NOT NULL,
                        activation_utc TEXT NOT NULL,
                        expires_at_utc TEXT NOT NULL,
                        last_transition_utc TEXT NOT NULL,
                        failure_reason TEXT NULL,
                        rollback_completed INTEGER NOT NULL DEFAULT 0,
                        conflict_detected INTEGER NOT NULL DEFAULT 0
                    );
                    CREATE TABLE IF NOT EXISTS policy_update_journal (
                        update_id TEXT PRIMARY KEY,
                        session_id TEXT NOT NULL,
                        exam_id TEXT NOT NULL,
                        old_policy_id TEXT NOT NULL,
                        old_policy_version INTEGER NOT NULL,
                        new_policy_id TEXT NOT NULL,
                        new_policy_version INTEGER NOT NULL,
                        phase TEXT NOT NULL,
                        started_utc TEXT NOT NULL,
                        completed_utc TEXT NULL,
                        candidate_rules_json TEXT NOT NULL,
                        retired_rules_json TEXT NOT NULL,
                        failure_reason TEXT NULL
                    );

                    CREATE TABLE IF NOT EXISTS durable_processed_commands (
                        command_id TEXT PRIMARY KEY,
                        action TEXT NOT NULL,
                        exam_id TEXT NOT NULL,
                        session_id TEXT NULL,
                        received_utc TEXT NOT NULL,
                        expires_utc TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS revoked_signing_keys (
                        key_id TEXT PRIMARY KEY,
                        reason TEXT NOT NULL,
                        revoked_utc TEXT NOT NULL
                    );
                ";
                cmd.ExecuteNonQuery();

                // Prune expired commands older than 24 hours
                using var pruneCmd = conn.CreateCommand();
                pruneCmd.Transaction = tx;
                pruneCmd.CommandText = "DELETE FROM durable_processed_commands WHERE expires_utc < $cutoff;";
                pruneCmd.Parameters.AddWithValue("$cutoff", DateTimeOffset.UtcNow.AddDays(-1).ToString("O", CultureInfo.InvariantCulture));
                pruneCmd.ExecuteNonQuery();
            }
            tx.Commit();
        }
    }

    public void SaveSession(JournalRecord record)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var tx = conn.BeginTransaction();
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = @"
                INSERT INTO network_enforcement_journal (
                    session_id, policy_id, policy_version, phase,
                    start_utc, updated_utc, baseline_json, target_profiles, intended_rules_json,
                    applied_rules_json, last_error, conflict_details
                ) VALUES (
                    $sessionId, $policyId, $version, $phase,
                    $startUtc, $updatedUtc, $baseline, $profiles, $intended,
                    $applied, $error, $conflict
                ) ON CONFLICT(session_id) DO UPDATE SET
                    phase = excluded.phase,
                    updated_utc = excluded.updated_utc,
                    applied_rules_json = excluded.applied_rules_json,
                    last_error = excluded.last_error,
                    conflict_details = excluded.conflict_details;
            ";

            cmd.Parameters.AddWithValue("$sessionId", record.SessionId.ToString());
            cmd.Parameters.AddWithValue("$policyId", record.PolicyId.ToString());
            cmd.Parameters.AddWithValue("$version", record.PolicyVersion);
            cmd.Parameters.AddWithValue("$phase", record.Phase.ToString());
            cmd.Parameters.AddWithValue("$startUtc", record.StartUtc.ToString("O", CultureInfo.InvariantCulture));
            cmd.Parameters.AddWithValue("$updatedUtc", record.UpdatedUtc.ToString("O", CultureInfo.InvariantCulture));
            cmd.Parameters.AddWithValue("$baseline", JsonSerializer.Serialize(record.Baseline));
            cmd.Parameters.AddWithValue("$profiles", (int)record.TargetProfiles);
            cmd.Parameters.AddWithValue("$intended", JsonSerializer.Serialize(record.IntendedRules));
            cmd.Parameters.AddWithValue("$applied", JsonSerializer.Serialize(record.AppliedRuleNames));
            cmd.Parameters.AddWithValue("$error", (object?)record.LastError ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$conflict", (object?)record.ConflictDetails ?? DBNull.Value);

            cmd.ExecuteNonQuery();
            tx.Commit();
        }
    }

    public void UpdatePhase(Guid sessionId, EnforcementPhase phase, string? lastError = null)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var tx = conn.BeginTransaction();
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = @"
                UPDATE network_enforcement_journal
                SET phase = $phase,
                    updated_utc = $now,
                    last_error = CASE WHEN $error IS NOT NULL THEN $error ELSE last_error END
                WHERE session_id = $sessionId;
            ";
            cmd.Parameters.AddWithValue("$phase", phase.ToString());
            cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            cmd.Parameters.AddWithValue("$error", (object?)lastError ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$sessionId", sessionId.ToString());

            cmd.ExecuteNonQuery();
            tx.Commit();
        }
    }

    public void RecordAppliedRule(Guid sessionId, string ruleName)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var tx = conn.BeginTransaction();

            using (var insertCmd = conn.CreateCommand())
            {
                insertCmd.Transaction = tx;
                insertCmd.CommandText = @"
                    INSERT OR IGNORE INTO applied_rules (session_id, rule_name, applied_utc)
                    VALUES ($sessionId, $ruleName, $now);
                ";
                insertCmd.Parameters.AddWithValue("$sessionId", sessionId.ToString());
                insertCmd.Parameters.AddWithValue("$ruleName", ruleName);
                insertCmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
                insertCmd.ExecuteNonQuery();
            }

            // Sync into applied_rules_json in the journal row
            var ruleNames = new List<string>();
            using (var selectCmd = conn.CreateCommand())
            {
                selectCmd.Transaction = tx;
                selectCmd.CommandText = "SELECT rule_name FROM applied_rules WHERE session_id = $sessionId ORDER BY rule_name";
                selectCmd.Parameters.AddWithValue("$sessionId", sessionId.ToString());
                using var reader = selectCmd.ExecuteReader();
                while (reader.Read())
                {
                    ruleNames.Add(reader.GetString(0));
                }
            }

            using (var updateCmd = conn.CreateCommand())
            {
                updateCmd.Transaction = tx;
                updateCmd.CommandText = @"
                    UPDATE network_enforcement_journal
                    SET applied_rules_json = $applied,
                        updated_utc = $now
                    WHERE session_id = $sessionId;
                ";
                updateCmd.Parameters.AddWithValue("$applied", JsonSerializer.Serialize(ruleNames));
                updateCmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
                updateCmd.Parameters.AddWithValue("$sessionId", sessionId.ToString());
                updateCmd.ExecuteNonQuery();
            }

            tx.Commit();
        }
    }

    public void RemoveAppliedRule(Guid sessionId, string ruleName)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var tx = conn.BeginTransaction();
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "DELETE FROM applied_rules WHERE session_id = $sessionId AND rule_name = $ruleName;";
            cmd.Parameters.AddWithValue("$sessionId", sessionId.ToString());
            cmd.Parameters.AddWithValue("$ruleName", ruleName);
            cmd.ExecuteNonQuery();
            tx.Commit();
        }
    }

    public JournalRecord? GetSession(Guid sessionId)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT * FROM network_enforcement_journal WHERE session_id = $sessionId";
            cmd.Parameters.AddWithValue("$sessionId", sessionId.ToString());
            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                return MapRecord(reader);
            }
            return null;
        }
    }

    public JournalRecord? GetLatestActiveOrIncompleteSession()
    {
        lock (_gate)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            // Incomplete or active phases
            cmd.CommandText = @"
                SELECT * FROM network_enforcement_journal
                WHERE phase IN ('Prepared', 'ApplyingRules', 'EnforcingDefaultBlock', 'Active', 'RollingBackDefault', 'RollingBackRules')
                ORDER BY updated_utc DESC
                LIMIT 1;
            ";
            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                return MapRecord(reader);
            }
            return null;
        }
    }

    public IReadOnlyList<JournalRecord> GetAllSessions()
    {
        lock (_gate)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT * FROM network_enforcement_journal ORDER BY start_utc DESC";
            var list = new List<JournalRecord>();
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(MapRecord(reader));
            }
            return list;
        }
    }

    public void RecordConflict(Guid sessionId, string conflictDetails)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var tx = conn.BeginTransaction();
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = @"
                UPDATE network_enforcement_journal
                SET phase = $conflictPhase,
                    conflict_details = $details,
                    updated_utc = $now
                WHERE session_id = $sessionId;
            ";
            cmd.Parameters.AddWithValue("$conflictPhase", EnforcementPhase.Conflict.ToString());
            cmd.Parameters.AddWithValue("$details", conflictDetails);
            cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            cmd.Parameters.AddWithValue("$sessionId", sessionId.ToString());
            cmd.ExecuteNonQuery();
            tx.Commit();
        }
    }

    private static JournalRecord MapRecord(SqliteDataReader reader)
    {
        var sessionId = Guid.Parse(reader.GetString(reader.GetOrdinal("session_id")));
        var policyId = Guid.Parse(reader.GetString(reader.GetOrdinal("policy_id")));
        var version = reader.GetInt32(reader.GetOrdinal("policy_version"));
        var phaseStr = reader.GetString(reader.GetOrdinal("phase"));
        var phase = Enum.TryParse<EnforcementPhase>(phaseStr, out var parsedPhase) ? parsedPhase : EnforcementPhase.Failed;
        var startUtc = DateTimeOffset.Parse(reader.GetString(reader.GetOrdinal("start_utc")), CultureInfo.InvariantCulture);
        var updatedUtc = DateTimeOffset.Parse(reader.GetString(reader.GetOrdinal("updated_utc")), CultureInfo.InvariantCulture);
        var baselineJson = reader.GetString(reader.GetOrdinal("baseline_json"));
        var baseline = JsonSerializer.Deserialize<FirewallProfileBaseline>(baselineJson)!;

        var targetProfilesCol = reader.GetOrdinal("target_profiles");
        var targetProfiles = targetProfilesCol >= 0 ? (FirewallProfiles)reader.GetInt32(targetProfilesCol) : FirewallProfiles.All;

        var intendedJson = reader.GetString(reader.GetOrdinal("intended_rules_json"));
        var intended = JsonSerializer.Deserialize<List<FirewallRuleModel>>(intendedJson) ?? new List<FirewallRuleModel>();
        var appliedJson = reader.GetString(reader.GetOrdinal("applied_rules_json"));
        var applied = JsonSerializer.Deserialize<List<string>>(appliedJson) ?? new List<string>();

        var errorCol = reader.GetOrdinal("last_error");
        var error = reader.IsDBNull(errorCol) ? null : reader.GetString(errorCol);

        var conflictCol = reader.GetOrdinal("conflict_details");
        var conflict = reader.IsDBNull(conflictCol) ? null : reader.GetString(conflictCol);

        return new JournalRecord(
            SessionId: sessionId,
            PolicyId: policyId,
            PolicyVersion: version,
            Phase: phase,
            StartUtc: startUtc,
            UpdatedUtc: updatedUtc,
            Baseline: baseline,
            TargetProfiles: targetProfiles,
            IntendedRules: intended,
            AppliedRuleNames: applied,
            LastError: error,
            ConflictDetails: conflict
        );
    }

    public int GetHighestPolicyVersion(Guid examId)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT highest_version FROM exam_policy_versions WHERE exam_id = $examId";
            cmd.Parameters.AddWithValue("$examId", examId.ToString());
            var result = cmd.ExecuteScalar();
            if (result is long l) return (int)l;
            if (result is int i) return i;
            return 0;
        }
    }

    public void RecordPolicyVersion(Guid examId, int version)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var tx = conn.BeginTransaction();
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = @"
                INSERT INTO exam_policy_versions (exam_id, highest_version, updated_utc)
                VALUES ($examId, $version, $now)
                ON CONFLICT(exam_id) DO UPDATE SET
                    highest_version = CASE WHEN excluded.highest_version > exam_policy_versions.highest_version
                                           THEN excluded.highest_version
                                           ELSE exam_policy_versions.highest_version END,
                    updated_utc = excluded.updated_utc;
            ";
            cmd.Parameters.AddWithValue("$examId", examId.ToString());
            cmd.Parameters.AddWithValue("$version", version);
            cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            cmd.ExecuteNonQuery();
            tx.Commit();
        }
    }

    public void SaveEnforcementState(DurableEnforcementRecord record)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var tx = conn.BeginTransaction();
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = @"
                INSERT INTO durable_enforcement_state (
                    session_id, exam_id, policy_id, policy_version,
                    state, activation_utc, expires_at_utc, last_transition_utc,
                    failure_reason, rollback_completed, conflict_detected
                ) VALUES (
                    $sessionId, $examId, $policyId, $policyVersion,
                    $state, $activationUtc, $expiresAtUtc, $lastTransitionUtc,
                    $failureReason, $rollbackCompleted, $conflictDetected
                ) ON CONFLICT(session_id) DO UPDATE SET
                    policy_id = excluded.policy_id,
                    policy_version = excluded.policy_version,
                    state = excluded.state,
                    expires_at_utc = excluded.expires_at_utc,
                    last_transition_utc = excluded.last_transition_utc,
                    failure_reason = excluded.failure_reason,
                    rollback_completed = excluded.rollback_completed,
                    conflict_detected = excluded.conflict_detected;
            ";

            cmd.Parameters.AddWithValue("$sessionId", record.SessionId.ToString());
            cmd.Parameters.AddWithValue("$examId", record.ExamId.ToString());
            cmd.Parameters.AddWithValue("$policyId", record.PolicyId.ToString());
            cmd.Parameters.AddWithValue("$policyVersion", record.PolicyVersion);
            cmd.Parameters.AddWithValue("$state", record.State.ToString());
            cmd.Parameters.AddWithValue("$activationUtc", record.ActivationUtc.ToString("O", CultureInfo.InvariantCulture));
            cmd.Parameters.AddWithValue("$expiresAtUtc", record.ExpiresAtUtc.ToString("O", CultureInfo.InvariantCulture));
            cmd.Parameters.AddWithValue("$lastTransitionUtc", record.LastTransitionUtc.ToString("O", CultureInfo.InvariantCulture));
            cmd.Parameters.AddWithValue("$failureReason", (object?)record.FailureReason ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$rollbackCompleted", record.RollbackCompleted ? 1 : 0);
            cmd.Parameters.AddWithValue("$conflictDetected", record.ConflictDetected ? 1 : 0);
            cmd.ExecuteNonQuery();
            tx.Commit();
        }
    }

    public void UpdateEnforcementState(
        Guid sessionId,
        EnforcementState state,
        string? failureReason = null,
        bool rollbackCompleted = false,
        bool conflictDetected = false)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var tx = conn.BeginTransaction();
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = @"
                UPDATE durable_enforcement_state
                SET state = $state,
                    last_transition_utc = $now,
                    failure_reason = COALESCE($failureReason, failure_reason),
                    rollback_completed = CASE WHEN $rollbackCompleted = 1 THEN 1 ELSE rollback_completed END,
                    conflict_detected = CASE WHEN $conflictDetected = 1 THEN 1 ELSE conflict_detected END
                WHERE session_id = $sessionId;
            ";
            cmd.Parameters.AddWithValue("$state", state.ToString());
            cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            cmd.Parameters.AddWithValue("$failureReason", (object?)failureReason ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$rollbackCompleted", rollbackCompleted ? 1 : 0);
            cmd.Parameters.AddWithValue("$conflictDetected", conflictDetected ? 1 : 0);
            cmd.Parameters.AddWithValue("$sessionId", sessionId.ToString());
            cmd.ExecuteNonQuery();
            tx.Commit();
        }
    }

    public DurableEnforcementRecord? GetEnforcementState(Guid sessionId)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT * FROM durable_enforcement_state WHERE session_id = $sessionId";
            cmd.Parameters.AddWithValue("$sessionId", sessionId.ToString());
            using var reader = cmd.ExecuteReader();
            return reader.Read() ? MapEnforcementRecord(reader) : null;
        }
    }

    public DurableEnforcementRecord? GetActiveEnforcementState()
    {
        lock (_gate)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                SELECT * FROM durable_enforcement_state
                WHERE state IN ('PolicyPending', 'PolicyValidated', 'Preparing', 'ApplyingRules', 'Enforcing', 'Active', 'Stopping', 'RollingBack')
                ORDER BY last_transition_utc DESC
                LIMIT 1;
            ";
            using var reader = cmd.ExecuteReader();
            return reader.Read() ? MapEnforcementRecord(reader) : null;
        }
    }

    public IReadOnlyList<DurableEnforcementRecord> GetAllEnforcementStates()
    {
        lock (_gate)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT * FROM durable_enforcement_state ORDER BY activation_utc ASC;";
            using var reader = cmd.ExecuteReader();
            var list = new List<DurableEnforcementRecord>();
            while (reader.Read())
            {
                list.Add(MapEnforcementRecord(reader));
            }
            return list;
        }
    }

    private static DurableEnforcementRecord MapEnforcementRecord(SqliteDataReader reader)
    {
        var sessionId = Guid.Parse(reader.GetString(reader.GetOrdinal("session_id")));
        var examId = Guid.Parse(reader.GetString(reader.GetOrdinal("exam_id")));
        var policyId = Guid.Parse(reader.GetString(reader.GetOrdinal("policy_id")));
        var version = reader.GetInt32(reader.GetOrdinal("policy_version"));
        var stateStr = reader.GetString(reader.GetOrdinal("state"));
        var state = Enum.TryParse<EnforcementState>(stateStr, out var parsedState) ? parsedState : EnforcementState.Failed;
        var actUtc = DateTimeOffset.Parse(reader.GetString(reader.GetOrdinal("activation_utc")), CultureInfo.InvariantCulture);
        var expUtc = DateTimeOffset.Parse(reader.GetString(reader.GetOrdinal("expires_at_utc")), CultureInfo.InvariantCulture);
        var lastUtc = DateTimeOffset.Parse(reader.GetString(reader.GetOrdinal("last_transition_utc")), CultureInfo.InvariantCulture);
        var failCol = reader.GetOrdinal("failure_reason");
        var failure = reader.IsDBNull(failCol) ? null : reader.GetString(failCol);
        var rollbackCompleted = reader.GetInt32(reader.GetOrdinal("rollback_completed")) == 1;
        var conflictDetected = reader.GetInt32(reader.GetOrdinal("conflict_detected")) == 1;

        return new DurableEnforcementRecord(
            SessionId: sessionId,
            ExamId: examId,
            PolicyId: policyId,
            PolicyVersion: version,
            State: state,
            ActivationUtc: actUtc,
            ExpiresAtUtc: expUtc,
            LastTransitionUtc: lastUtc,
            FailureReason: failure,
            RollbackCompleted: rollbackCompleted,
            ConflictDetected: conflictDetected
        );
    }

    public void SaveUpdateJournal(DurableUpdateJournalRecord record)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var tx = conn.BeginTransaction();
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = @"
                INSERT INTO policy_update_journal (
                    update_id, session_id, exam_id,
                    old_policy_id, old_policy_version,
                    new_policy_id, new_policy_version,
                    phase, started_utc, completed_utc,
                    candidate_rules_json, retired_rules_json, failure_reason
                ) VALUES (
                    $updateId, $sessionId, $examId,
                    $oldPolicyId, $oldPolicyVersion,
                    $newPolicyId, $newPolicyVersion,
                    $phase, $startedUtc, $completedUtc,
                    $candidateRulesJson, $retiredRulesJson, $failureReason
                ) ON CONFLICT(update_id) DO UPDATE SET
                    phase = excluded.phase,
                    completed_utc = excluded.completed_utc,
                    failure_reason = excluded.failure_reason;
            ";

            cmd.Parameters.AddWithValue("$updateId", record.UpdateId.ToString());
            cmd.Parameters.AddWithValue("$sessionId", record.SessionId.ToString());
            cmd.Parameters.AddWithValue("$examId", record.ExamId.ToString());
            cmd.Parameters.AddWithValue("$oldPolicyId", record.OldPolicyId.ToString());
            cmd.Parameters.AddWithValue("$oldPolicyVersion", record.OldPolicyVersion);
            cmd.Parameters.AddWithValue("$newPolicyId", record.NewPolicyId.ToString());
            cmd.Parameters.AddWithValue("$newPolicyVersion", record.NewPolicyVersion);
            cmd.Parameters.AddWithValue("$phase", record.Phase.ToString());
            cmd.Parameters.AddWithValue("$startedUtc", record.StartedUtc.ToString("O", CultureInfo.InvariantCulture));
            cmd.Parameters.AddWithValue("$completedUtc", record.CompletedUtc.HasValue ? record.CompletedUtc.Value.ToString("O", CultureInfo.InvariantCulture) : DBNull.Value);
            cmd.Parameters.AddWithValue("$candidateRulesJson", System.Text.Json.JsonSerializer.Serialize(record.CandidateRules));
            cmd.Parameters.AddWithValue("$retiredRulesJson", System.Text.Json.JsonSerializer.Serialize(record.RetiredRuleNames));
            cmd.Parameters.AddWithValue("$failureReason", (object?)record.FailureReason ?? DBNull.Value);
            cmd.ExecuteNonQuery();
            tx.Commit();
        }
    }

    public void UpdateUpdateJournalPhase(Guid updateId, PolicyUpdatePhase phase, string? failureReason = null)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var tx = conn.BeginTransaction();
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = @"
                UPDATE policy_update_journal
                SET phase = $phase,
                    completed_utc = CASE WHEN $phase IN ('UpdateCommitted', 'UpdateFailed', 'UpdateRollback') THEN $now ELSE completed_utc END,
                    failure_reason = COALESCE($failureReason, failure_reason)
                WHERE update_id = $updateId;
            ";
            cmd.Parameters.AddWithValue("$phase", phase.ToString());
            cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            cmd.Parameters.AddWithValue("$failureReason", (object?)failureReason ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$updateId", updateId.ToString());
            cmd.ExecuteNonQuery();
            tx.Commit();
        }
    }

    public DurableUpdateJournalRecord? GetIncompleteUpdate(Guid sessionId)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                SELECT * FROM policy_update_journal
                WHERE session_id = $sessionId
                  AND phase IN ('UpdatePending', 'UpdateApplying', 'UpdateVerifying', 'UpdateCommitting', 'UpdateRollback')
                ORDER BY started_utc DESC
                LIMIT 1;
            ";
            cmd.Parameters.AddWithValue("$sessionId", sessionId.ToString());
            using var reader = cmd.ExecuteReader();
            return reader.Read() ? MapUpdateRecord(reader) : null;
        }
    }

    public DurableUpdateJournalRecord? GetUpdate(Guid updateId)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT * FROM policy_update_journal WHERE update_id = $updateId";
            cmd.Parameters.AddWithValue("$updateId", updateId.ToString());
            using var reader = cmd.ExecuteReader();
            return reader.Read() ? MapUpdateRecord(reader) : null;
        }
    }

    private static DurableUpdateJournalRecord MapUpdateRecord(SqliteDataReader reader)
    {
        var updateId = Guid.Parse(reader.GetString(reader.GetOrdinal("update_id")));
        var sessionId = Guid.Parse(reader.GetString(reader.GetOrdinal("session_id")));
        var examId = Guid.Parse(reader.GetString(reader.GetOrdinal("exam_id")));
        var oldPolicyId = Guid.Parse(reader.GetString(reader.GetOrdinal("old_policy_id")));
        var oldVersion = reader.GetInt32(reader.GetOrdinal("old_policy_version"));
        var newPolicyId = Guid.Parse(reader.GetString(reader.GetOrdinal("new_policy_id")));
        var newVersion = reader.GetInt32(reader.GetOrdinal("new_policy_version"));
        var phaseStr = reader.GetString(reader.GetOrdinal("phase"));
        var phase = Enum.TryParse<PolicyUpdatePhase>(phaseStr, out var parsedPhase) ? parsedPhase : PolicyUpdatePhase.UpdateFailed;
        var startedUtc = DateTimeOffset.Parse(reader.GetString(reader.GetOrdinal("started_utc")), CultureInfo.InvariantCulture);

        var compCol = reader.GetOrdinal("completed_utc");
        DateTimeOffset? completedUtc = reader.IsDBNull(compCol)
            ? null
            : DateTimeOffset.Parse(reader.GetString(compCol), CultureInfo.InvariantCulture);

        var candJson = reader.GetString(reader.GetOrdinal("candidate_rules_json"));
        var candidateRules = System.Text.Json.JsonSerializer.Deserialize<List<FirewallRuleModel>>(candJson)
                             ?? new List<FirewallRuleModel>();

        var retJson = reader.GetString(reader.GetOrdinal("retired_rules_json"));
        var retiredRules = System.Text.Json.JsonSerializer.Deserialize<List<string>>(retJson)
                           ?? new List<string>();

        var failCol = reader.GetOrdinal("failure_reason");
        var failureReason = reader.IsDBNull(failCol) ? null : reader.GetString(failCol);

        return new DurableUpdateJournalRecord(
            UpdateId: updateId,
            SessionId: sessionId,
            ExamId: examId,
            OldPolicyId: oldPolicyId,
            OldPolicyVersion: oldVersion,
            NewPolicyId: newPolicyId,
            NewPolicyVersion: newVersion,
            Phase: phase,
            StartedUtc: startedUtc,
            CompletedUtc: completedUtc,
            CandidateRules: candidateRules,
            RetiredRuleNames: retiredRules,
            FailureReason: failureReason
        );
    }

    public void RecordProcessedCommand(string commandId, string action, Guid examId, Guid? sessionId, DateTimeOffset expiresUtc)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var tx = conn.BeginTransaction();
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = @"
                INSERT INTO durable_processed_commands (command_id, action, exam_id, session_id, received_utc, expires_utc)
                VALUES ($commandId, $action, $examId, $sessionId, $receivedUtc, $expiresUtc)
                ON CONFLICT(command_id) DO NOTHING;
            ";
            cmd.Parameters.AddWithValue("$commandId", commandId);
            cmd.Parameters.AddWithValue("$action", action);
            cmd.Parameters.AddWithValue("$examId", examId.ToString());
            cmd.Parameters.AddWithValue("$sessionId", sessionId.HasValue ? sessionId.Value.ToString() : (object)DBNull.Value);
            cmd.Parameters.AddWithValue("$receivedUtc", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            cmd.Parameters.AddWithValue("$expiresUtc", expiresUtc.ToString("O", CultureInfo.InvariantCulture));
            cmd.ExecuteNonQuery();
            tx.Commit();
        }
    }

    public bool IsCommandProcessed(string commandId)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM durable_processed_commands WHERE command_id = $commandId";
            cmd.Parameters.AddWithValue("$commandId", commandId);
            var count = Convert.ToInt64(cmd.ExecuteScalar());
            return count > 0;
        }
    }

    public void SaveRevokedKey(string keyId, string reason)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var tx = conn.BeginTransaction();
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = @"
                INSERT INTO revoked_signing_keys (key_id, reason, revoked_utc)
                VALUES ($keyId, $reason, $now)
                ON CONFLICT(key_id) DO UPDATE SET reason = excluded.reason;
            ";
            cmd.Parameters.AddWithValue("$keyId", keyId);
            cmd.Parameters.AddWithValue("$reason", reason);
            cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            cmd.ExecuteNonQuery();
            tx.Commit();
        }
    }

    public IReadOnlySet<string> GetRevokedKeys()
    {
        lock (_gate)
        {
            var result = new HashSet<string>(StringComparer.Ordinal);
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT key_id FROM revoked_signing_keys";
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                result.Add(reader.GetString(0));
            }
            return result;
        }
    }
}
