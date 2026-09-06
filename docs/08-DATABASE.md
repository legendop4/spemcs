# 08. Database Schema, Data Dictionary & Migrations

---

## What Am I Looking At?

![Complete Database ERD](diagrams/03-database-erd.svg)

This document is the authoritative guide to data persistence in SPEMCS. It documents:
1. **Central Persistence**: **14 PostgreSQL relational tables** managed via SQLAlchemy ORM and Alembic migrations.
2. **Local Endpoint Persistence**: The SQLite rollback journal ([`sqlite_rollback_journal.db`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/SqliteRollbackJournal.cs)) for crash recovery.
3. **The `alerts.exam_id` Nullability Case Study**: Why this relationship is designed as `UUID NULL`.

```text
Evidence Standard:
Method: Direct introspection of SQLAlchemy Base.metadata.tables from backend.models.*
Verified Count: Exactly 14 PostgreSQL tables + 1 SQLite local agent table
Migrations: Alembic 0001_baseline.py, 0002_add_network_enforcement.py
Confidence: ✅ VERIFIED
```

---

## Complete Data Dictionary (14 PostgreSQL Tables)

### 1. `users`
- **Purpose**: Administrator and proctor user accounts.
- **Model**: [`backend/backend/models/user.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/models/user.py)
- **Columns (10)**:
  - `user_id`: `UUID` (PK, NOT NULL)
  - `name`: `VARCHAR(100)` (NOT NULL)
  - `username`: `VARCHAR(50)` (NOT NULL, UNIQUE, INDEXED)
  - `email`: `VARCHAR(100)` (NOT NULL, UNIQUE, INDEXED)
  - `password`: `VARCHAR(255)` (NOT NULL) — Legacy plaintext field
  - `password_hash`: `VARCHAR(255)` (NOT NULL) — Bcrypt / PBKDF2 hash
  - `role`: `VARCHAR(20)` (NOT NULL) — Values: `admin`, `proctor`
  - `avatar_color`: `VARCHAR(20)` (NOT NULL, Default: `#3b82f6`)
  - `is_active`: `BOOLEAN` (NOT NULL, Default: `True`)
  - `created_at`: `DATETIME` (NOT NULL, Default: `utcnow`)

---

### 2. `devices`
- **Purpose**: Enrolled computer lab workstations.
- **Model**: [`backend/backend/models/device.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/models/device.py)
- **Columns (10)**:
  - `device_id`: `UUID` (PK, NOT NULL)
  - `hardware_uuid`: `VARCHAR(100)` (NULLABLE, UNIQUE, INDEXED) — Machine UUID bound to HMAC tokens
  - `device_name`: `VARCHAR(100)` (NOT NULL)
  - `building_name`: `VARCHAR(50)` (NULLABLE)
  - `lab_name`: `VARCHAR(50)` (NULLABLE)
  - `pc_number`: `VARCHAR(10)` (NULLABLE)
  - `registered_ip`: `VARCHAR(50)` (NULLABLE)
  - `status`: `VARCHAR(20)` (NOT NULL, Default: `ONLINE`) — `ONLINE`, `OFFLINE`, `UNASSIGNED`
  - `last_seen`: `DATETIME` (NULLABLE) — Updated on heartbeat
  - `created_at`: `DATETIME` (NOT NULL, Default: `utcnow`)

---

### 3. `exams`
- **Purpose**: Examination sessions, scheduling, and lockdown configuration.
- **Model**: [`backend/backend/models/exam.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/models/exam.py)
- **Columns (11)**:
  - `exam_id`: `UUID` (PK, NOT NULL)
  - `exam_name`: `VARCHAR(150)` (NOT NULL)
  - `section`: `VARCHAR(150)` (NULLABLE)
  - `exam_link`: `TEXT` (NULLABLE) — Target exam portal URL
  - `approved_browser`: `VARCHAR(20)` (NOT NULL, Default: `chrome`) — `chrome`, `edge`
  - `status`: `VARCHAR(20)` (NOT NULL, Default: `PENDING`) — `PENDING`, `ACTIVE`, `STOPPED`
  - `network_enforcement`: `BOOLEAN` (NOT NULL, Default: `False`)
  - `vendor_profile_id`: `UUID` (NULLABLE, FK $\rightarrow$ `vendor_profiles.vendor_id`)
  - `started_at`: `DATETIME` (NULLABLE)
  - `ended_at`: `DATETIME` (NULLABLE)
  - `created_at`: `DATETIME` (NOT NULL, Default: `utcnow`)

---

### 4. `exam_devices`
- **Purpose**: Association mapping linking workstations to an examination.
- **Model**: [`backend/backend/models/exam_device.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/models/exam_device.py)
- **Columns (4)**:
  - `id`: `UUID` (PK, NOT NULL)
  - `exam_id`: `UUID` (NOT NULL, FK $\rightarrow$ `exams.exam_id` ON DELETE CASCADE)
  - `device_id`: `UUID` (NOT NULL, FK $\rightarrow$ `devices.device_id` ON DELETE CASCADE)
  - `status`: `VARCHAR(20)` (NOT NULL, Default: `ASSIGNED`) — `ASSIGNED`, `LOCKED`, `UNLOCKED`

---

### 5. `exam_sessions`
- **Purpose**: Tracks individual student exam attempts on specific devices.
- **Model**: [`backend/backend/models/exam_session.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/models/exam_session.py)
- **Columns (7)**:
  - `session_id`: `UUID` (PK, NOT NULL)
  - `exam_id`: `UUID` (NOT NULL, FK $\rightarrow$ `exams.exam_id`)
  - `device_id`: `UUID` (NOT NULL, FK $\rightarrow$ `devices.device_id`)
  - `student_roll_number`: `VARCHAR(50)` (NOT NULL, INDEXED)
  - `status`: `VARCHAR(20)` (NOT NULL, Default: `ACTIVE`) — `ACTIVE`, `COMPLETED`, `TERMINATED`
  - `started_at`: `DATETIME` (NOT NULL, Default: `utcnow`)
  - `ended_at`: `DATETIME` (NULLABLE)

---

### 6. `events`
- **Purpose**: Raw process and network telemetry stream reported by endpoints.
- **Model**: [`backend/backend/models/event.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/models/event.py)
- **Columns (14)**:
  - `event_id`: `UUID` (PK, NOT NULL)
  - `session_id`: `UUID` (NULLABLE, FK $\rightarrow$ `exam_sessions.session_id`)
  - `device_id`: `UUID` (NOT NULL, FK $\rightarrow$ `devices.device_id`)
  - `device_name`: `VARCHAR` (NOT NULL)
  - `ip_address`: `VARCHAR` (NULLABLE)
  - `student_roll_number`: `VARCHAR` (NULLABLE)
  - `event_type`: `VARCHAR` (NOT NULL) — `PROCESS_STARTED`, `PROCESS_VIOLATION`, `NETWORK_BLOCK`
  - `timestamp`: `DATETIME` (NOT NULL, Default: `utcnow`, INDEXED)
  - `process_name`: `VARCHAR` (NULLABLE)
  - `pid`: `INTEGER` (NULLABLE)
  - `executable_path`: `VARCHAR` (NULLABLE)
  - `classification`: `VARCHAR` (NOT NULL) — `ALLOWED`, `PROHIBITED`, `SUSPICIOUS`
  - `reason`: `VARCHAR` (NULLABLE)
  - `resolution_status`: `VARCHAR` (NULLABLE)

---

### 7. `alerts` (The Nullable `exam_id` Case Study)
- **Purpose**: High-priority security violation notifications surfaced to proctors.
- **Model**: [`backend/backend/models/alert.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/models/alert.py)
- **Columns (9)**:
  - `alert_id`: `UUID` (PK, NOT NULL)
  - `event_id`: `UUID` (NOT NULL, FK $\rightarrow$ `events.event_id`)
  - `exam_id`: `UUID` (NULLABLE, FK $\rightarrow$ `exams.exam_id`) — **EXPLICITLY NULLABLE**
  - `device_id`: `UUID` (NOT NULL, FK $\rightarrow$ `devices.device_id`)
  - `agent_event_id`: `VARCHAR(100)` (NULLABLE)
  - `severity`: `VARCHAR(20)` (NOT NULL) — `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
  - `message`: `VARCHAR` (NOT NULL)
  - `status`: `VARCHAR(20)` (NOT NULL, Default: `PENDING`) — `PENDING`, `RESOLVED`, `DISMISSED`
  - `created_at`: `DATETIME` (NOT NULL, Default: `utcnow`, INDEXED)

> [!IMPORTANT]
> **Case Study: Why `alerts.exam_id` is Nullable**:
> In institutional university environments, computers in labs operate with background monitoring services running even when no active exam is scheduled. If a student sits at a computer outside exam hours and launches prohibited remote desktop software (e.g. AnyDesk, TeamViewer) or attempts to install hacking tools, the agent records and transmits the violation.
> Because there is no active exam at that moment, `exam_id` is `None`. If the database column were defined as `NOT NULL`, SQLAlchemy would raise an integrity constraint violation, rolling back the database transaction and **dropping the event completely**. Making `alerts.exam_id` nullable guarantees that out-of-exam lab violations are safely archived.

---

### 8. `reports`
- **Purpose**: Post-examination aggregated compliance reports.
- **Model**: [`backend/backend/models/report.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/models/report.py)
- **Columns (7)**:
  - `report_id`: `UUID` (PK, NOT NULL)
  - `exam_id`: `UUID` (NOT NULL, FK $\rightarrow$ `exams.exam_id`)
  - `generated_at`: `DATETIME` (NOT NULL, Default: `utcnow`)
  - `summary`: `JSONB` (NULLABLE) — High-level statistics
  - `report_data`: `JSONB` (NULLABLE) — Detailed student and device timeline
  - `alert_count`: `INTEGER` (NOT NULL, Default: 0)
  - `event_count`: `INTEGER` (NOT NULL, Default: 0)

---

### 9. `audit_logs`
- **Purpose**: Immutable administrative action trail.
- **Model**: [`backend/backend/models/audit_log.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/models/audit_log.py)
- **Columns (8)**:
  - `log_id`: `UUID` (PK, NOT NULL)
  - `user_id`: `UUID` (NULLABLE, FK $\rightarrow$ `users.user_id`)
  - `action`: `VARCHAR(50)` (NOT NULL) — e.g. `LOGIN`, `EXAM_ACTIVATED`, `KEY_ROTATED`
  - `entity_type`: `VARCHAR(50)` (NULLABLE)
  - `entity_id`: `VARCHAR(100)` (NULLABLE)
  - `details`: `JSONB` (NULLABLE)
  - `ip_address`: `VARCHAR(50)` (NULLABLE)
  - `created_at`: `DATETIME` (NOT NULL, Default: `utcnow`, INDEXED)

---

### 10. `labs` & 11. `lab_devices`
- **Purpose**: Physical computer lab groupings and device allocation.
- **Models**:
  - [`backend/backend/models/lab.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/models/lab.py)
  - [`backend/backend/models/lab_device.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/models/lab_device.py)
- **`labs` Columns (8)**: `lab_id` (PK), `building_id`, `lab_name`, `description`, `capacity`, `spemcs_enabled`, `status`, `created_at`.
- **`lab_devices` Columns (3)**: `id` (PK), `lab_id` (FK $\rightarrow$ `labs`), `device_id` (FK $\rightarrow$ `devices`).

---

### 12. `vendor_profiles`
- **Purpose**: Whitelisted domain names, IP CIDRs, and ports for testing vendors (Moodle, Canvas).
- **Model**: [`backend/backend/models/vendor_profile.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/models/vendor_profile.py)
- **Columns (8)**:
  - `vendor_id`: `UUID` (PK, NOT NULL)
  - `vendor_name`: `VARCHAR(100)` (NOT NULL)
  - `description`: `VARCHAR(255)` (NULLABLE)
  - `required_domains`: `JSONB` (NOT NULL) — Array of domain strings
  - `approved_ip_ranges`: `JSONB` (NOT NULL) — Array of IPv4/IPv6 CIDR strings
  - `required_tcp_ports`: `JSONB` (NOT NULL) — e.g. `[80, 443]`
  - `required_udp_ports`: `JSONB` (NOT NULL) — e.g. `[]`
  - `created_at`: `DATETIME` (NOT NULL, Default: `utcnow`)

---

### 13. `network_policies`
- **Purpose**: Immutable compiled and signed network lockdown policies.
- **Model**: [`backend/backend/models/network_policy.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/models/network_policy.py)
- **Columns (13)**:
  - `policy_id`: `UUID` (PK, NOT NULL)
  - `exam_id`: `UUID` (NOT NULL, FK $\rightarrow$ `exams.exam_id`)
  - `version`: `INTEGER` (NOT NULL, Monotonic sequence counter)
  - `vendor_profile_id`: `UUID` (NULLABLE, FK $\rightarrow$ `vendor_profiles.vendor_id`)
  - `approved_browser`: `VARCHAR(20)` (NOT NULL)
  - `allowed_destinations`: `JSONB` (NOT NULL)
  - `management_server`: `JSONB` (NOT NULL)
  - `not_before`: `DATETIME` (NOT NULL)
  - `expires_at`: `DATETIME` (NOT NULL)
  - `key_id`: `VARCHAR(64)` (NOT NULL) — RSA signing key fingerprint
  - `schema_version`: `VARCHAR(10)` (NOT NULL, Default: `2.0`)
  - `signature`: `TEXT` (NULLABLE) — Base64 RSA-PSS signature
  - `created_at`: `DATETIME` (NOT NULL, Default: `utcnow`)

---

### 14. `device_policy_states`
- **Purpose**: Tracks policy installation status on individual workstations for pre-flight readiness checks.
- **Model**: [`backend/backend/models/device_policy_state.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/models/device_policy_state.py)
- **Columns (9)**:
  - `id`: `UUID` (PK, NOT NULL)
  - `exam_id`: `UUID` (NOT NULL, FK $\rightarrow$ `exams.exam_id`)
  - `device_id`: `UUID` (NOT NULL, FK $\rightarrow$ `devices.device_id`)
  - `policy_id`: `UUID` (NOT NULL, FK $\rightarrow$ `network_policies.policy_id`)
  - `status`: `VARCHAR(30)` (NOT NULL, Default: `PENDING`) — `PENDING`, `APPLIED`, `FAILED`
  - `rules_installed`: `INTEGER` (NOT NULL, Default: 0)
  - `last_error`: `VARCHAR(255)` (NULLABLE)
  - `applied_at`: `DATETIME` (NULLABLE)
  - `updated_at`: `DATETIME` (NOT NULL, Default: `utcnow`)

---

## Local Endpoint Persistence (SQLite Rollback Journal)

Located on each candidate PC at `%ProgramData%\Spemcs\sqlite_rollback_journal.db`.

```sql
CREATE TABLE IF NOT EXISTS rollback_journal (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    original_state TEXT NOT NULL,
    applied_state TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    rolled_back_at TEXT
);
```

### Crash Recovery Guarantees:
- Written **synchronously before** the firewall rule is applied via COM.
- SQLite WAL mode ensures transactional durability even if power is abruptly disconnected.
- On service startup, `SqliteRollbackJournal.ReconcileStartupStateAsync()` queries active sessions and cleans up orphaned rules.

---

## Alembic Migration History & Startup Checks

1. **`0001_baseline.py`**:
   - Creates `users`, `devices`, `exams`, `exam_devices`, `exam_sessions`, `events`, `alerts`, `reports`, `audit_logs`, `labs`, `lab_devices`.
2. **`0002_add_network_enforcement.py`**:
   - Adds `network_policies`, `vendor_profiles`, `device_policy_states`.
   - Adds `network_enforcement` boolean flag to `exams`.
3. **Startup Schema Check ([`schema_check.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/app/schema_check.py))**:
   - Executes during FastAPI startup lifespan.
   - Inspects `alembic_version` table and validates that database migration revision matches current code head.
   - If mismatch is detected, aborts application boot with `SchemaVersionMismatchError`.
