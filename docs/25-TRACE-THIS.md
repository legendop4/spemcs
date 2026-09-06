# 25. Trace This: 10 End-to-End "Follow the Button Click" Code Traces

---

## What Am I Looking At?

![Follow the Button Click](diagrams/10-button-click-execution-trace.svg)

This document provides **ten exhaustive, step-by-step code execution traces** across SPEMCS. Whenever an operator clicks a button in the web dashboard, or a candidate takes an action on a lab workstation, this guide traces the exact path through:

$$\text{User Action} \rightarrow \text{UI} \rightarrow \text{API} \rightarrow \text{Auth} \rightarrow \text{Authorization} \rightarrow \text{Service} \rightarrow \text{DB/OS} \rightarrow \text{Event} \rightarrow \text{WebSocket} \rightarrow \text{UI}$$

---

## 1. Trace 1: Operator Logs In via Web Dashboard

1. **User Action**: Operator enters username `admin` and password `admin123` on [`LoginPage.tsx`](file:///c:/Users/shrma/Desktop/spemcsnew/frontend/src/pages/LoginPage.tsx) and clicks "Sign In".
2. **UI Handler**: `LoginPage.handleSubmit()` calls `authService.login(username, password)`.
3. **API Call**: Sends HTTP `POST /api/auth/token` with `Content-Type: application/x-www-form-urlencoded`.
4. **Auth / Gate**: Public endpoint; passes into [`backend/routes/auth.py::login_for_access_token`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/routes/auth.py).
5. **Authorization**: None required.
6. **Service**: Calls [`auth_service.authenticate_user(db, username, password)`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/auth_service.py).
7. **DB / OS**: Executes `SELECT * FROM users WHERE username = 'admin'`; verifies hash with `verify_password()`.
8. **Event**: Records `LOGIN` action in `audit_logs` table.
9. **Response**: Returns HTTP 200 with JSON: `{ "access_token": "<jwt>", "token_type": "bearer" }`.
10. **UI Re-render**: `AppContext` stores token in `localStorage`, sets `isAuthenticated=true`, and redirects to `/dashboard`.

---

## 2. Trace 2: Admin Creates an Exam with Vendor Profile

1. **User Action**: Admin fills out exam form (Name: "CS101", Browser: "chrome", Vendor: "Moodle") on [`ExamShieldPage.tsx`](file:///c:/Users/shrma/Desktop/spemcsnew/frontend/src/pages/ExamShieldPage.tsx) and clicks "Create Exam".
2. **UI Handler**: Calls `examService.createExam(payload)`.
3. **API Call**: Sends HTTP `POST /api/exams` with `Authorization: Bearer <jwt>`.
4. **Auth**: `dependencies.require_authenticated` validates Bearer JWT with `SECRET_KEY`.
5. **Authorization**: `dependencies.require_admin` asserts `current_user.role == "admin"`.
6. **Service**: Calls `ExamService.create_exam(db, exam_data)`.
7. **DB / OS**: Executes `INSERT INTO exams (exam_id, exam_name, status, network_enforcement, ...) VALUES (...)`.
8. **Event**: Records `EXAM_CREATED` in `audit_logs`.
9. **Response**: Returns HTTP 200 with created `ExamRead` schema.
10. **UI Re-render**: `ExamShieldPage` updates exam list and displays "Exam Created" toast.

---

## 3. Trace 3: Admin Clicks "Activate Exam" in ExamShield

1. **User Action**: Admin clicks "Activate Exam" button on [`ExamShieldPage.tsx`](file:///c:/Users/shrma/Desktop/spemcsnew/frontend/src/pages/ExamShieldPage.tsx).
2. **UI Handler**: Calls `examService.activateExam(examId)`.
3. **API Call**: Sends HTTP `POST /api/exams/{id}/activate`.
4. **Auth**: `dependencies.require_authenticated` verifies JWT.
5. **Authorization**: `dependencies.require_admin` verifies administrator role.
6. **Service**: Calls [`enforcement_readiness.evaluate_exam_readiness()`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/enforcement_readiness.py). Verifies policy is signed and all assigned devices have `rules_installed > 0`.
7. **DB / OS**: Executes `UPDATE exams SET status = 'ACTIVE', started_at = NOW() WHERE exam_id = ...`.
8. **Event**: Emits `EXAM_STATE` event to [`realtime.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/websocket/realtime.py).
9. **WebSocket / Response**: Returns HTTP 200; pushes WS frame to all connected proctor dashboards.
10. **UI Re-render**: Exam badge turns green ("ACTIVE"); button transforms to "Stop Exam".

---

## 4. Trace 4: Candidate Launches UI & Enters Roll Number

1. **User Action**: Candidate sits at lab PC, types Roll Number `CS-2024-042` into WPF UI, and clicks "Verify".
2. **UI Handler**: [`MainWindow.xaml.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.UI/MainWindow.xaml.cs) bundles data into `StudentVerifyMessage`.
3. **IPC Call**: Sends JSON payload across Named Pipe: `\\.\pipe\spemcs-control-v1`.
4. **Auth**: [`ControlPipeWorker.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Service/ControlPipeWorker.cs) validates client DACL against active console session token.
5. **Service**: Service routes request to `BackendAdapters.VerifyStudentAsync()`.
6. **API Call**: Agent sends `POST /api/v1/sessions/verify-student` with `X-Device-Token`.
7. **DB / OS**: Backend executes `INSERT INTO exam_sessions (session_id, student_roll_number, status, started_at)`.
8. **Event**: Emits `STUDENT_VERIFIED` telemetry.
9. **Pipe Response**: Service returns success response over named pipe to WPF UI.
10. **UI Re-render**: WPF UI displays green checkmark: "Verified: Jane Doe. Awaiting Exam Start."

---

## 5. Trace 5: Agent Enforces Windows Firewall Lockdown

1. **Trigger**: Agent receives `ENFORCE_POLICY` command via WebSocket or polling.
2. **Component**: [`AgentWorker.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Service/AgentWorker.cs) passes policy to `EnforcementStateMachine`.
3. **State Machine**: Transitions from `ARMED` to `ENFORCING`.
4. **Rollback Snapshot**: Calls [`SqliteRollbackJournal.RecordBaselineAsync()`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/SqliteRollbackJournal.cs), storing pre-exam firewall state.
5. **Firewall COM Call**: [`WindowsFirewallAdapter.SetDefaultOutboundAction(7, NET_FW_ACTION_BLOCK)`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/WindowsFirewallAdapter.cs).
6. **Dynamic Rule Injection**: Injects `SPEMCS-{sessionId}-BrowserAllow` scoped strictly to `chrome.exe` and vendor CIDRs.
7. **Registry Policy**: Writes `DnsOverHttpsMode = "off"` to `HKLM\SOFTWARE\Policies\Google\Chrome`.
8. **Journal Commit**: SQLite journal marks rule additions as `ACTIVE`.
9. **State Transition**: State machine transitions to `ENFORCED`.
10. **UI Notification**: Named pipe notifies WPF UI; lock screen overlay arms.

---

## 6. Trace 6: Candidate Attempts Unauthorized Network Connection

1. **User Action**: Candidate opens command prompt and types `curl https://chatgpt.com` or attempts to open Discord.
2. **OS Kernel Interception**: Packet reaches Windows Filtering Platform (WFP) driver.
3. **Rule Match**:
   - Outbound Default Action is `NET_FW_ACTION_BLOCK`.
   - Packet executable is `curl.exe` (does not match approved browser path).
   - Destination IP does not match vendor CIDR allow list.
4. **Kernel Action**: Packet dropped; TCP RST / ICMP destination unreachable sent locally.
5. **Telemetry Polling**: `NetworkCollector.cs` observes blocked connection attempt.
6. **Agent Queue**: Enqueues `NETWORK_BLOCK` event in `EventUploaderWorker`.
7. **HTTP Upload**: Sends `POST /api/v1/events` with `X-Device-Token`.
8. **DB Persistence**: Backend inserts row into `events` table.
9. **WebSocket Push**: Backend broadcasts `ALERT_CREATED` to `/api/v1/ws/dashboard`.
10. **UI Re-render**: Proctor's screen shows warning: "Blocked outbound connection attempt on PC #14".

---

## 7. Trace 7: Candidate Launches Prohibited Process (AnyDesk)

1. **User Action**: Candidate double-clicks `AnyDesk.exe` from Downloads folder.
2. **OS Kernel Event**: Windows kernel spawns process in Session 1+ and fires WMI `__InstanceCreationEvent`.
3. **Agent Interception**: [`ConfigurableProcessClassifier.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/ProcessServices.cs) intercepts event in Session 0 in $< 50\text{ ms}$.
4. **Classification**: Evaluates process name against rules; categorizes as `RemoteDesktop` (Severity: `CRITICAL`).
5. **Telemetry Transmission**: `EventUploaderWorker` sends `POST /api/v1/events` with device HMAC token.
6. **Backend Ingestion**: [`EventService.py::ingest_event()`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/event_service.py) writes to `events` table.
7. **Alert Creation**: Inserts record into `alerts` table (`severity: "CRITICAL"`, `status: "PENDING"`).
8. **WebSocket Broadcast**: `RealtimeManager` broadcasts frame across all active proctor connections.
9. **Audio / Visual Chime**: Proctor's browser plays alert sound.
10. **UI Re-render**: Seat #14 on [`LiveMonitorPage.tsx`](file:///c:/Users/shrma/Desktop/spemcsnew/frontend/src/pages/LiveMonitorPage.tsx) pulses bright red.

---

## 8. Trace 8: Proctor Resolves an Alert on Live Monitor

1. **User Action**: Proctor approaches student, ensures AnyDesk is closed, clicks red seat tile on [`LiveMonitorPage.tsx`](file:///c:/Users/shrma/Desktop/spemcsnew/frontend/src/pages/LiveMonitorPage.tsx), and clicks "Resolve Alert".
2. **UI Handler**: Opens resolution modal; proctor enters reason: "Accidental launch, closed immediately".
3. **API Call**: Sends HTTP `PATCH /api/alerts/{id}` with `{ "status": "RESOLVED", "reason": "..." }`.
4. **Auth**: `dependencies.require_staff` verifies proctor JWT.
5. **Service**: Updates `alerts.status = 'RESOLVED'` in database.
6. **DB Commit**: Writes resolution note to `audit_logs` table with proctor user ID and timestamp.
7. **WebSocket Push**: Broadcasts `ALERT_RESOLVED` frame over `/ws/dashboard`.
8. **UI Re-render**: Seat tile stops pulsing red and returns to green/active state; toast confirms resolution.

---

## 9. Trace 9: Admin Clicks "Stop Exam" (Firewall Rollback)

1. **User Action**: Admin clicks "Stop Exam" on [`ExamShieldPage.tsx`](file:///c:/Users/shrma/Desktop/spemcsnew/frontend/src/pages/ExamShieldPage.tsx).
2. **API Call**: Sends HTTP `POST /api/exams/{id}/deactivate`.
3. **Backend Service**: Calls `ExamService.deactivate_exam()`; updates `exams.status = 'STOPPED'`.
4. **Agent Signal**: Sends `DEACTIVATE_LOCKDOWN` command to all assigned agents.
5. **Rollback Execution**: [`SqliteRollbackJournal.RollbackSessionAsync()`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/SqliteRollbackJournal.cs) queries active session rules.
6. **Rule Removal**: Iterates and deletes all `SPEMCS-*` tagged firewall rules via COM.
7. **Firewall Reset**: Sets `DefaultOutboundAction` back to `NET_FW_ACTION_ALLOW` (Profiles: All).
8. **Registry Cleanup**: Purges DoH suppression policies from HKLM.
9. **Journal Update**: Marks journal records as `ROLLED_BACK`.
10. **UI Re-render**: Candidate WPF UI displays: "Exam Concluded. Internet Restored."

---

## 10. Trace 10: Workstation Experiences Sudden Reboot Mid-Exam

1. **Event**: Power cord is accidentally kicked; lab PC powers off mid-exam and reboots.
2. **Boot Phase**: Windows boots; Service Control Manager starts `Spemcs.Agent.Service` in Session 0 before student logs in.
3. **Startup Reconciliation**: [`SqliteRollbackJournal.ReconcileStartupStateAsync()`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/SqliteRollbackJournal.cs) opens `sqlite_rollback_journal.db`.
4. **State Inspection**: Finds active rules from session `18f921bb-...`.
5. **Server Query**: Agent queries backend: `GET /api/exams/{id}` to verify exam status.
6. **Scenario A (Exam Ongoing)**: Backend confirms exam is still `ACTIVE`. Agent leaves firewall locked, opens named pipe, and waits for student to log back in.
7. **Scenario B (Exam Concluded)**: Backend confirms exam is `STOPPED`. Agent executes emergency rollback, deletes all rules, resets default outbound to allow, and logs startup recovery.
8. **Desktop Launch**: Once student logs in, service detects active console session and re-launches WPF UI.
9. **Student Resume**: Candidate enters PIN and resumes exam without permanent workstation lockout.
10. **Audit Log**: Backend records `DEVICE_REBOOT_RECONCILED` in `audit_logs`.
