using Microsoft.Data.Sqlite;
using System.Globalization;
using System.Text.Json;

namespace Spemcs.Agent.Core;

public sealed class SqliteAgentStore : IAgentStore
{
    private readonly string _connectionString; private readonly object _gate = new();
    public SqliteAgentStore(string? root = null)
    {
        root ??= Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Spemcs"); Directory.CreateDirectory(root);
        _connectionString = new SqliteConnectionStringBuilder { DataSource = Path.Combine(root, "agent.db"), Mode = SqliteOpenMode.ReadWriteCreate, Pooling = false }.ToString();
        using var c = Open(); using (var pragma = c.CreateCommand()) { pragma.CommandText = "PRAGMA journal_mode=WAL;"; pragma.ExecuteNonQuery(); } using var transaction = c.BeginTransaction();
        Execute(c, transaction, "CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS events (event_id TEXT PRIMARY KEY, payload TEXT NOT NULL, status INTEGER NOT NULL, created_utc TEXT NOT NULL, attempt_count INTEGER NOT NULL DEFAULT 0, next_attempt_utc TEXT NULL, uploaded_utc TEXT NULL, resolution_status INTEGER NOT NULL DEFAULT 0); UPDATE events SET status=0 WHERE status=1;");
        EnsureColumn(c, transaction, "events", "attempt_count", "INTEGER NOT NULL DEFAULT 0"); EnsureColumn(c, transaction, "events", "next_attempt_utc", "TEXT NULL"); EnsureColumn(c, transaction, "events", "uploaded_utc", "TEXT NULL"); EnsureColumn(c, transaction, "events", "resolution_status", "INTEGER NOT NULL DEFAULT 0"); Execute(c, transaction, "PRAGMA user_version=3;"); transaction.Commit();
    }
    public AgentSnapshot LoadSnapshot()
    {
        lock (_gate) { using var c = Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT key,value FROM config"; var values = new Dictionary<string, string>(); using var reader = cmd.ExecuteReader(); while (reader.Read()) values[reader.GetString(0)] = reader.GetString(1); var registration = values.TryGetValue("registration", out var reg) ? JsonSerializer.Deserialize<DeviceRegistration>(reg) : null; var session = values.TryGetValue("session", out var ses) ? JsonSerializer.Deserialize<AgentSession>(ses) : null; var state = values.TryGetValue("state", out var st) && Enum.TryParse<AgentState>(st, out var parsed) ? parsed : AgentState.Idle; return new AgentSnapshot(state, registration, session); }
    }
    public void SaveRegistration(DeviceRegistration registration) => Set("registration", JsonSerializer.Serialize(registration));
    public void SaveState(AgentState state, AgentSession? session) { lock (_gate) { using var c = Open(); using var tx = c.BeginTransaction(); Set(c, tx, "state", state.ToString()); Set(c, tx, "session", JsonSerializer.Serialize(session)); tx.Commit(); } }
    public void Enqueue(ViolationEvent violation)
    { lock (_gate) { using var c = Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "INSERT OR IGNORE INTO events(event_id,payload,status,created_utc,resolution_status) VALUES($id,$payload,$status,$utc,$resolution)"; cmd.Parameters.AddWithValue("$id", violation.EventId.ToString()); cmd.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(violation)); cmd.Parameters.AddWithValue("$status", (int)EventDeliveryStatus.Pending); cmd.Parameters.AddWithValue("$utc", violation.TimestampUtc.ToString("O", CultureInfo.InvariantCulture)); cmd.Parameters.AddWithValue("$resolution", (int)violation.ResolutionStatus); cmd.ExecuteNonQuery(); } }
    public IReadOnlyList<ViolationEvent> GetPendingEvents(int limit = 100) => GetEvents(EventDeliveryStatus.Pending, limit);
    public IReadOnlyList<ViolationEvent> ClaimPendingEvents(int limit = 100, DateTimeOffset? nowUtc = null)
    {
        lock (_gate)
        {
            var now = nowUtc ?? DateTimeOffset.UtcNow; using var c = Open(); using var tx = c.BeginTransaction(); using (var reset = c.CreateCommand()) { reset.Transaction = tx; reset.CommandText = "UPDATE events SET status=$pending WHERE status=$failed AND (next_attempt_utc IS NULL OR next_attempt_utc <= $now)"; reset.Parameters.AddWithValue("$pending", (int)EventDeliveryStatus.Pending); reset.Parameters.AddWithValue("$failed", (int)EventDeliveryStatus.Failed); reset.Parameters.AddWithValue("$now", now.ToString("O", CultureInfo.InvariantCulture)); reset.ExecuteNonQuery(); }
            var ids = new List<string>(); using (var select = c.CreateCommand()) { select.Transaction = tx; select.CommandText = "SELECT event_id FROM events WHERE status=$pending ORDER BY created_utc LIMIT $limit"; select.Parameters.AddWithValue("$pending", (int)EventDeliveryStatus.Pending); select.Parameters.AddWithValue("$limit", limit); using var reader = select.ExecuteReader(); while (reader.Read()) ids.Add(reader.GetString(0)); }
            foreach (var id in ids) using (var update = c.CreateCommand()) { update.Transaction = tx; update.CommandText = "UPDATE events SET status=$uploading, attempt_count=attempt_count+1 WHERE event_id=$id"; update.Parameters.AddWithValue("$uploading", (int)EventDeliveryStatus.Uploading); update.Parameters.AddWithValue("$id", id); update.ExecuteNonQuery(); }
            tx.Commit(); return ReadByIds(c, ids, EventDeliveryStatus.Uploading);
        }
    }
    public int GetAttemptCount(Guid eventId) { lock (_gate) { using var c = Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT attempt_count FROM events WHERE event_id=$id"; cmd.Parameters.AddWithValue("$id", eventId.ToString()); var res = cmd.ExecuteScalar(); if (res is long l) return (int)l; if (res is int i) return i; if (res != null && int.TryParse(res.ToString(), out var parsed)) return parsed; return 0; } }

    public void MarkUploadFailed(Guid eventId, DateTimeOffset retryAtUtc) { lock (_gate) { using var c = Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "UPDATE events SET status=$status,next_attempt_utc=$retry WHERE event_id=$id"; cmd.Parameters.AddWithValue("$status", (int)EventDeliveryStatus.Failed); cmd.Parameters.AddWithValue("$retry", retryAtUtc.ToString("O", CultureInfo.InvariantCulture)); cmd.Parameters.AddWithValue("$id", eventId.ToString()); cmd.ExecuteNonQuery(); } }
    public void MarkUploaded(Guid eventId) { lock (_gate) { using var c = Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "UPDATE events SET status=$status,uploaded_utc=$uploaded,next_attempt_utc=NULL WHERE event_id=$id"; cmd.Parameters.AddWithValue("$status", (int)EventDeliveryStatus.Uploaded); cmd.Parameters.AddWithValue("$uploaded", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture)); cmd.Parameters.AddWithValue("$id", eventId.ToString()); cmd.ExecuteNonQuery(); } }
    public int PurgeUploaded(DateTimeOffset olderThanUtc) { lock (_gate) { using var c = Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "DELETE FROM events WHERE status=$status AND uploaded_utc IS NOT NULL AND uploaded_utc < $cutoff"; cmd.Parameters.AddWithValue("$status", (int)EventDeliveryStatus.Uploaded); cmd.Parameters.AddWithValue("$cutoff", olderThanUtc.ToString("O", CultureInfo.InvariantCulture)); return cmd.ExecuteNonQuery(); } }
    public IReadOnlyList<ViolationEvent> GetEvents(EventDeliveryStatus? status = null, int limit = 100)
    { lock (_gate) { using var c = Open(); using var cmd = c.CreateCommand(); cmd.CommandText = status is null ? "SELECT event_id,payload,status,resolution_status FROM events ORDER BY created_utc LIMIT $limit" : "SELECT event_id,payload,status,resolution_status FROM events WHERE status=$status ORDER BY created_utc LIMIT $limit"; cmd.Parameters.AddWithValue("$limit", limit); if (status is not null) cmd.Parameters.AddWithValue("$status", (int)status.Value); return Read(cmd); } }
    public void ResolveEvent(Guid eventId, EventResolutionStatus status) { lock (_gate) { using var c = Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "UPDATE events SET resolution_status=$status WHERE event_id=$id"; cmd.Parameters.AddWithValue("$status", (int)status); cmd.Parameters.AddWithValue("$id", eventId.ToString()); cmd.ExecuteNonQuery(); } }
    public IReadOnlyList<ViolationEvent> GetActiveEvents(int limit = 100)
    { lock (_gate) { using var c = Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT event_id,payload,status,resolution_status FROM events WHERE resolution_status=0 ORDER BY created_utc LIMIT $limit"; cmd.Parameters.AddWithValue("$limit", limit); return Read(cmd); } }
    private IReadOnlyList<ViolationEvent> ReadByIds(SqliteConnection c, IReadOnlyList<string> ids, EventDeliveryStatus status) { if (ids.Count == 0) return []; using var cmd = c.CreateCommand(); cmd.CommandText = $"SELECT event_id,payload,status,resolution_status FROM events WHERE event_id IN ({string.Join(',', ids.Select((_, i) => "$id" + i))})"; for (var i = 0; i < ids.Count; i++) cmd.Parameters.AddWithValue("$id" + i, ids[i]); return Read(cmd); }
    private static IReadOnlyList<ViolationEvent> Read(SqliteCommand cmd) { using var reader = cmd.ExecuteReader(); var result = new List<ViolationEvent>(); while (reader.Read()) { var item = JsonSerializer.Deserialize<ViolationEvent>(reader.GetString(1)); if (item is not null) result.Add(item with { DeliveryStatus = (EventDeliveryStatus)reader.GetInt32(2), ResolutionStatus = (EventResolutionStatus)reader.GetInt32(3) }); } return result; }
    private void Set(string key, string value) { lock (_gate) { using var c = Open(); using var tx = c.BeginTransaction(); Set(c, tx, key, value); tx.Commit(); } }
    private static void Set(SqliteConnection c, SqliteTransaction tx, string key, string value) { using var cmd = c.CreateCommand(); cmd.Transaction = tx; cmd.CommandText = "INSERT INTO config(key,value) VALUES($key,$value) ON CONFLICT(key) DO UPDATE SET value=excluded.value"; cmd.Parameters.AddWithValue("$key", key); cmd.Parameters.AddWithValue("$value", value); cmd.ExecuteNonQuery(); }
    private static void Execute(SqliteConnection c, SqliteTransaction tx, string sql) { using var cmd = c.CreateCommand(); cmd.Transaction = tx; cmd.CommandText = sql; cmd.ExecuteNonQuery(); }
    private static void EnsureColumn(SqliteConnection c, SqliteTransaction tx, string table, string column, string definition) { var exists = false; using (var check = c.CreateCommand()) { check.Transaction = tx; check.CommandText = $"PRAGMA table_info({table})"; using var reader = check.ExecuteReader(); while (reader.Read()) if (reader.GetString(1).Equals(column, StringComparison.OrdinalIgnoreCase)) { exists = true; break; } } if (!exists) Execute(c, tx, $"ALTER TABLE {table} ADD COLUMN {column} {definition}"); }
    private SqliteConnection Open() { var c = new SqliteConnection(_connectionString); c.Open(); return c; }
}
