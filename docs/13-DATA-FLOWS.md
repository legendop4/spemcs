# 13. Data Flows: Follow the Packet, Request & Event

---

## What Am I Looking At?

![Follow the Packet & Event](diagrams/09-packet-event-flow.svg)

This document is the dedicated **"Follow the Information"** reference manual for SPEMCS. It traces the lifecycle of packets, HTTP requests, IPC messages, and telemetry events across the entire architecture.

To prevent diagram clutter, every data flow is split into three progressive levels of depth:
- **Level 1: Conceptual**: What occurs from a high-level operational perspective.
- **Level 2: Subsystem**: How components, network boundaries, and sockets interact.
- **Level 3: Implementation**: Exact call stacks, header fields, JSON payloads, and SQL queries.

---

## Flow 1: Device Registration & Enrollment

### Level 1: Conceptual
A new lab computer powers on. The background Windows service starts, recognizes that it has no saved machine credential, reaches out to the management server presenting an installation password, and receives a permanent machine identity card.

### Level 2: Subsystem
```mermaid
sequenceDiagram
    autonumber
    participant Workstation as Windows Service (Session 0)
    participant Edge as Server Nginx Proxy
    participant Backend as FastAPI App (routes/agent_api.py)
    participant Dep as Dependencies (require_enrollment_key)
    participant DB as PostgreSQL (devices table)

    Workstation->>Edge: POST /api/v1/devices/register
    Edge->>Backend: Proxies request to port 8002
    Backend->>Dep: Checks X-Enrollment-Key header
    Dep->>Dep: hmac.compare_digest()
    Backend->>DB: INSERT INTO devices ... RETURNING device_id
    Backend->>Backend: Signs HMAC device token (DEVICE_TOKEN_SECRET)
    Backend-->>Workstation: 200 OK: { device_id, token, expires_at }
```

### Level 3: Implementation Code Trace
1. **Endpoint Initiation**:
   - Class: [`DeviceCredentialStore.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Service/DeviceCredentialStore.cs)
   - Method: `EnsureEnrolledAsync()`
   - Payload:
     ```json
     {
       "hardware_uuid": "4C4C4544-004D-4A10-8053-C8C04F343232",
       "device_name": "LAB-B-PC-14",
       "registered_ip": "192.168.1.114"
     }
     ```
   - Headers: `X-Enrollment-Key: spemcs-enrollment-bootstrap-key-default`.
2. **Backend Authentication & Ownership**:
   - Gate: `dependencies.py::require_enrollment_key(x_enrollment_key)`
   - Handler: `routes/agent_api.py::register_device(db, payload)`
   - Database Query:
     ```sql
     INSERT INTO devices (device_id, hardware_uuid, device_name, status, created_at)
     VALUES ('8a329d48...', '4C4C4544...', 'LAB-B-PC-14', 'ONLINE', NOW())
     ON CONFLICT (hardware_uuid) DO UPDATE SET last_seen = NOW();
     ```
3. **Credential Storage**:
   - Token stored in DPAPI-protected store on client: `C:\ProgramData\Spemcs\credential_store`.

---

## Flow 2: Policy Compilation, RSA-PSS Signing & Distribution

### Level 1: Conceptual
An administrator selects an exam and clicks "Compile Policy". The server gathers all required vendor IP addresses, formats them into a strict document, stamps an unbreakable digital signature on the bottom using an RSA private key, and stores it. When the exam starts, endpoints fetch and verify this signed document.

### Level 2: Subsystem
```mermaid
sequenceDiagram
    autonumber
    participant Admin as Administrator (Dashboard)
    participant Compiler as services/policy_compiler.py
    participant Signer as services/policy_signer.py
    participant KeyMgr as services/signing_key_manager.py
    participant DB as PostgreSQL (network_policies)
    participant Agent as Agent PolicyReceiver.cs

    Admin->>Compiler: POST /api/policies/compile/{exam_id}
    Compiler->>Signer: Generates RFC 8785 Canonical JSON
    Signer->>KeyMgr: get_active_private_key()
    Signer->>Signer: RSA-PSS Signature (SHA-256 / MGF1 / salt 32)
    Signer->>DB: INSERT INTO network_policies
    
    Note over Agent: Exam activation triggers policy fetch
    Agent->>DB: GET /api/policies/exam/{id}
    Agent->>Agent: PolicyReceiver.VerifySignature()
    Note over Agent: Validates against cached RSA public keyring
```

### Level 3: Implementation Code Trace
1. **Compilation Engine**:
   - Source: [`backend/backend/services/policy_compiler.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/policy_compiler.py)
   - Function: `compile_exam_policy(exam_id, db)`
   - Assembles:
     ```json
     {
       "schema_version": "2.0",
       "exam_id": "18f921bb-442a-4467-8cfb-81014da40348",
       "version": 1,
       "approved_browser": "chrome",
       "allowed_destinations": ["198.51.100.0/24", "203.0.113.5"],
       "management_server": ["10.100.0.5"],
       "not_before": "2026-09-06T02:00:00Z",
       "expires_at": "2026-09-06T06:00:00Z",
       "key_id": "9f83a21b4e0987c1"
     }
     ```
2. **Cryptographic Signing**:
   - Source: [`backend/backend/services/policy_signer.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/policy_signer.py)
   - Inverted parameter verification: guarantees key ID agreements before signature.
3. **Agent Verification**:
   - Class: [`PolicyReceiver.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/PolicyReceiver.cs)
   - Method: `VerifySignature(rawJson, signatureBase64, keyId)`
   - C# Cryptography API: `RSA.VerifyData(..., RSASignaturePadding.Pss)`.

---

## Flow 3: Exam Activation & Lockdown Enforcement

### Level 1: Conceptual
The admin clicks "Activate Exam". The server verifies all assigned computers are online and armed. Once approved, the agent tells the Windows Firewall to block all outbound internet except for the student's browser connecting to the exam platform.

### Level 2: Subsystem
```mermaid
sequenceDiagram
    autonumber
    participant Admin as Admin Browser
    participant Server as FastAPI (routes/exams.py)
    participant Ready as services/enforcement_readiness.py
    participant Agent as Agent Service (Session 0)
    participant FW as Windows Firewall COM
    participant DB_L as SQLite Journal

    Admin->>Server: POST /api/exams/{id}/activate
    Server->>Ready: evaluate_exam_readiness()
    Ready-->>Server: All assigned devices ready (200 OK)
    Server->>Server: exams.status = 'ACTIVE'
    Server-->>Agent: Command: ENFORCE_POLICY
    Agent->>DB_L: RecordBaselineAsync() (Snapshot profile states)
    Agent->>FW: set_DefaultOutboundAction(All, NET_FW_ACTION_BLOCK)
    Agent->>FW: AddRule(SPEMCS-{sessionId}-BrowserAllow)
    Agent->>DB_L: RecordRuleAddedAsync("SPEMCS-...")
```

### Level 3: Implementation Code Trace
1. **Enforcement Readiness Evaluation**:
   - File: [`backend/backend/services/enforcement_readiness.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/enforcement_readiness.py)
   - Checks: `policy_id` exists; device `rules_installed > 0`.
2. **Firewall Mutation**:
   - File: [`WindowsFirewallAdapter.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/WindowsFirewallAdapter.cs)
   - COM Method: `_policy.set_DefaultOutboundAction(7, NET_FW_ACTION_BLOCK)`.
3. **Journal Logging**:
   - File: [`SqliteRollbackJournal.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/SqliteRollbackJournal.cs)
   - Commits active rule entries inside a transactional SQLite write lock.

---

## Flow 4: Process Telemetry & Alert Ingestion

### Level 1: Conceptual
A student launches Discord. The Windows kernel detects the new program and notifies the agent in under 50 milliseconds. The agent recognizes Discord as prohibited, transmits an alert to the server, and the proctor's screen instantly flashes red.

### Level 2: Subsystem
```mermaid
sequenceDiagram
    autonumber
    participant Kernel as Windows OS Kernel
    participant Classifier as ProcessClassifier.cs (Session 0)
    participant Uploader as EventUploaderWorker.cs
    participant Server as routes/events.py
    participant Hub as realtime.py (WebSocket)
    participant Proctor as LiveMonitorPage.tsx

    Kernel->>Classifier: WMI __InstanceCreationEvent (PID: 4120, Discord.exe)
    Classifier->>Classifier: Evaluates prohibited rule -> "Communication"
    Classifier->>Uploader: Enqueue(EventTelemetry)
    Uploader->>Server: POST /api/v1/events (Header: X-Device-Token)
    Server->>Server: EventService.ingest_event() -> writes events & alerts
    Server->>Hub: broadcast_dashboard_event("ALERT_CREATED")
    Hub-->>Proctor: WS Push Frame -> Tile Flashes Red
```

### Level 3: Implementation Code Trace
1. **Kernel Hook**:
   - Class: `ConfigurableProcessClassifier`
   - Trigger: `Win32_Process.Create` event.
2. **HTTP Transmission**:
   - Endpoint: `POST /api/v1/events`
   - Authentication: `require_device` validates HMAC token; asserts hardware ownership.
3. **Database & WebSocket Hand-off**:
   - File: [`backend/backend/services/event_service.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/event_service.py)
   - SQL: `INSERT INTO alerts (alert_id, event_id, severity, message, status) VALUES (...)`
   - WS Frame: `{ "type": "ALERT_CREATED", "payload": { "device_id": "...", "process": "Discord.exe" } }`.

---

## Flow 5: Exam Deactivation & Firewall Rollback

### Level 1: Conceptual
The exam is finished. The admin clicks "Stop Exam". The server signals the agent to dismantle all security rules. The agent reads its SQLite journal, deletes every rule it created, resets the default outbound action to allow, and reports that the machine is clean.

### Level 2: Subsystem
```mermaid
sequenceDiagram
    autonumber
    participant Admin as Admin Dashboard
    participant Server as FastAPI (routes/exams.py)
    participant Agent as Agent Service (Session 0)
    participant DB_L as SQLite Journal
    participant FW as Windows Firewall COM

    Admin->>Server: POST /api/exams/{id}/deactivate
    Server->>Server: exams.status = 'STOPPED'
    Server-->>Agent: Command: DEACTIVATE_LOCKDOWN
    Agent->>DB_L: Fetch active rules for current session
    loop For each rule in journal
        Agent->>FW: RemoveRule(ruleName)
    end
    Agent->>FW: set_DefaultOutboundAction(All, NET_FW_ACTION_ALLOW)
    Agent->>DB_L: UPDATE rollback_journal SET status='ROLLED_BACK'
    Agent-->>Server: Report: ROLLBACK_COMPLETED
```

### Level 3: Implementation Code Trace
1. **Rollback Execution**:
   - File: [`SqliteRollbackJournal.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/SqliteRollbackJournal.cs)
   - Method: `RollbackSessionAsync(Guid sessionId)`
   - Iterates through all recorded rules tagged with `SPEMCS-{sessionId}`.
2. **Baseline Restoration**:
   - File: [`WindowsFirewallAdapter.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/WindowsFirewallAdapter.cs)
   - Reverts `DefaultOutboundAction` back to `NET_FW_ACTION_ALLOW` (0).
3. **Completion Event**:
   - Emits `ENFORCEMENT_ROLLED_BACK` event to backend server; workstation status returns to normal.
