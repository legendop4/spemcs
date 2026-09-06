# 04. Components Encyclopedia: 3-Layer Systems Guide

---

## What Am I Looking At?

This document is the core architectural encyclopedia of SPEMCS. Every major component across the endpoint agent, backend management server, and frontend dashboard is analyzed across **Three Progressive Layers**:
1. **Beginner View**: Real-world analogy explaining the core purpose in plain English.
2. **System View**: Architectural placement within SPEMCS, showing who communicates with it.
3. **Code View**: Exact file paths, class names, method signatures, parameters, return types, and failure handling.

---

## Component Index

1. [`EnforcementStateMachine`](#1-enforcementstatemachine)
2. [`WindowsFirewallAdapter`](#2-windowsfirewalladapter)
3. [`SqliteRollbackJournal`](#3-sqliterollbackjournal)
4. [`ControlPipeWorker` & Named Pipe IPC](#4-controlpipeworker--named-pipe-ipc)
5. [`InteractiveSessionUiLauncher`](#5-interactivesessionuilauncher)
6. [`ConfigurableProcessClassifier` & Process Monitor](#6-configurableprocessclassifier--process-monitor)
7. [`PolicyCompiler`](#7-policycompiler)
8. [`PolicySigner` & `SigningKeyManager`](#8-policysigner--signingkeymanager)
9. [`RealtimeManager` & WebSocket Hubs](#9-realtimemanager--websocket-hubs)
10. [`EventService` & Alert Ingestion](#10-eventservice--alert-ingestion)
11. [`AppShell` & Global State Management](#11-appshell--global-state-management)
12. [`ExamShieldPage` & `LiveMonitorPage`](#12-examshieldpage--livemonitorpage)

---

## 1. EnforcementStateMachine

### Layer 1: Beginner View (Real-World Analogy)
Think of the `EnforcementStateMachine` like the electronic flight control computer on an airplane. The plane cannot suddenly enter "Cruise" without going through "Taxi", "Takeoff", and "Climb" first. If an engine alert sounds, it transitions into "Emergency Descent". It guarantees that the system never enters an illegal state (e.g. attempting to lock down a firewall when no cryptographic policy has been received).

### Layer 2: System View
Sits at the heart of [`Spemcs.Agent.Core.Network`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/EnforcementStateMachine.cs). It mediates all requests from `AgentWorker` and `ControlPipeWorker` before commanding `WindowsFirewallAdapter` and `SqliteRollbackJournal`.

```
[ Backend / UI Request ] 
          │
          ▼
┌──────────────────────────────────────────────┐
│          EnforcementStateMachine             │
│   UNARMED ──► ARMED ──► ENFORCED ──► ROLLBACK│
└──────────────────────────────────────────────┘
          │                   │
          ▼                   ▼
 [ WindowsFirewallAdapter ] [ SqliteRollbackJournal ]
```

### Layer 3: Code View
- **File**: [`Endpoint-agent/src/Spemcs.Agent.Core/Network/EnforcementStateMachine.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/EnforcementStateMachine.cs)
- **Class**: `public class EnforcementStateMachine`
- **States**: `EnforcementState.Unarmed`, `EnforcementState.Armed`, `EnforcementState.Enforcing`, `EnforcementState.Enforced`, `EnforcementState.RollingBack`, `EnforcementState.Failed`.
- **Primary Methods**:
  - `public async Task<EnforcementResult> ArmPolicyAsync(SignedNetworkPolicy policy)`
  - `public async Task<EnforcementResult> EnforceAsync(Guid sessionId)`
  - `public async Task<EnforcementResult> RollbackAsync(Guid sessionId)`
- **What Happens When It Fails?**:
  - If a transition fails (e.g. firewall throws an error while locking down), the state machine transitions to `EnforcementState.Failed`, triggers an immediate call to `RollbackAsync()`, and writes a high-priority event to the local audit log.
- **Evidence**:
  ```text
  Evidence: Endpoint-agent/src/Spemcs.Agent.Core/Network/EnforcementStateMachine.cs
  Symbol: EnforcementStateMachine.EnforceAsync
  Confidence: ✅ VERIFIED
  ```

---

## 2. WindowsFirewallAdapter

### Layer 1: Beginner View (Real-World Analogy)
Think of `WindowsFirewallAdapter` as the heavy iron vault door of a bank. Normally, the bank doors are open during business hours (default outbound allow). When an emergency is declared, the vault door slams shut, blocking all exits. Only one specific security officer carrying an authorized badge (the approved exam browser) is allowed to step through a reinforced access hatch to reach the bank headquarters.

### Layer 2: System View
Located in [`Spemcs.Agent.Core.Network`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/WindowsFirewallAdapter.cs). It uses Windows COM Interop to communicate directly with `HNetCfg.FwPolicy2` inside the Windows operating system kernel.

```
[ EnforcementStateMachine ]
          │
          ▼
┌──────────────────────────────────────────────┐
│            WindowsFirewallAdapter            │
│   COM Interop (ProgID: HNetCfg.FwPolicy2)    │
└──────────────────────────────────────────────┘
          │
          ▼
[ Windows Filtering Platform (Kernel Driver) ]
  • Default Outbound: BLOCK (Profiles 1, 2, 4)
  • Rule: SPEMCS-{sessionId}-BrowserAllow (chrome.exe)
  • Rule: SPEMCS-{sessionId}-MgmtAllow (Server IP:8002)
```

### Layer 3: Code View
- **File**: [`Endpoint-agent/src/Spemcs.Agent.Core/Network/WindowsFirewallAdapter.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/WindowsFirewallAdapter.cs)
- **Class**: `public class WindowsFirewallAdapter : IFirewallAdapter`
- **Key Symbols**:
  - `public void SetDefaultOutboundAction(FirewallProfiles profiles, FirewallAction action)`
  - `public void AddRule(FirewallRuleDefinition rule)`
  - `public void RemoveRule(string ruleName)`
  - `public FirewallBaselineSnapshot CaptureBaseline()`
- **Enforcement Reality**:
  - Applies to all three profiles: `FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public` (`Profiles.All = 7`).
  - Strict executable scoping: sets `rule.ApplicationName = @"C:\Program Files\Google\Chrome\Application\chrome.exe"`.
  - Naming standard: `SPEMCS-{sessionId:N}-{ruleSuffix}`.
- **What Happens When It Fails?**:
  - Catches `COMException`. Reverts any partially installed rules for the current session and throws `FirewallAdapterException` so the caller can trigger rollback.
- **Evidence**:
  ```text
  Evidence: Endpoint-agent/src/Spemcs.Agent.Core/Network/WindowsFirewallAdapter.cs
  Symbol: WindowsFirewallAdapter.SetDefaultOutboundAction
  Confidence: ✅ VERIFIED in WindowsFirewallAdapterIntegrationTests.cs
  ```

---

## 3. SqliteRollbackJournal

### Layer 1: Beginner View (Real-World Analogy)
Think of `SqliteRollbackJournal` like the "Black Box" flight data recorder combined with an automated undo ledger. Before any carpenter alters a wall in a historic building, they photograph and record every original nail, brick, and wire in an immutable notebook. If the renovation goes wrong or a sudden hurricane hits, the notebook contains the exact steps to rebuild the wall back to its original state.

### Layer 2: System View
Located in [`Spemcs.Agent.Core.Network`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/SqliteRollbackJournal.cs). Persists directly to the local filesystem at `%ProgramData%\Spemcs\sqlite_rollback_journal.db`. Runs in Session 0 so unprivileged desktop users cannot touch it.

```
[ WindowsFirewallAdapter ] ──Before Mutating──► [ SqliteRollbackJournal ]
                                                        │
                                                        ▼
                                         [ sqlite_rollback_journal.db ]
                                           • session_id: UUID
                                           • rule_name: "SPEMCS-..."
                                           • original_state: "ALLOW"
                                           • status: "ACTIVE"
```

### Layer 3: Code View
- **File**: [`Endpoint-agent/src/Spemcs.Agent.Core/Network/SqliteRollbackJournal.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/SqliteRollbackJournal.cs)
- **Class**: `public class SqliteRollbackJournal : IRollbackJournal`
- **Key Symbols**:
  - `public async Task RecordBaselineAsync(Guid sessionId, FirewallBaselineSnapshot baseline)`
  - `public async Task RecordRuleAddedAsync(Guid sessionId, string ruleName)`
  - `public async Task<RollbackReport> RollbackSessionAsync(Guid sessionId)`
  - `public async Task ReconcileStartupStateAsync()`
- **Schema**:
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
- **What Happens When It Fails?**:
  - If SQLite write fails, the state machine aborts the lockdown before modifying the firewall. If a rollback fails to delete a specific rule, it sweeps remaining rules and records a failure flag for administrator inspection.
- **Evidence**:
  ```text
  Evidence: Endpoint-agent/src/Spemcs.Agent.Core/Network/SqliteRollbackJournal.cs
  Symbol: SqliteRollbackJournal.ReconcileStartupStateAsync
  Confidence: ✅ VERIFIED in RollbackScopeTests.cs
  ```

---

## 4. ControlPipeWorker & Named Pipe IPC

### Layer 1: Beginner View (Real-World Analogy)
Think of `ControlPipeWorker` like a bulletproof teller window with a secure document drawer at a bank. The bank officer is sitting inside a secure vault (Session 0 SYSTEM), and the customer is standing in the public lobby (Session 1 User Desktop). They cannot touch each other, but they can slide signed verification slips back and forth through a secure mechanical slot (Named Pipe) with an armed guard inspecting every document.

### Layer 2: System View
Located in [`Spemcs.Agent.Service`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Service/ControlPipeWorker.cs). It bridges the privileged Session 0 daemon with the unprivileged Session 1 candidate UI.

```
[ Spemcs.Agent.UI (Desktop) ]
          │
          ▼
   Named Pipe Client
          │
          ▼ IPC Stream: \\.\pipe\spemcs-control-v1
┌──────────────────────────────────────────────┐
│              ControlPipeWorker               │
│  Windows Security Descriptor DACL Validator  │
└──────────────────────────────────────────────┘
          │
          ▼ Dispatches to
[ AgentWorker / StateMachine ]
```

### Layer 3: Code View
- **File**: [`Endpoint-agent/src/Spemcs.Agent.Service/ControlPipeWorker.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Service/ControlPipeWorker.cs)
- **Class**: `public class ControlPipeWorker : BackgroundService`
- **Key Symbols**:
  - `protected override async Task ExecuteAsync(CancellationToken stoppingToken)`
  - `private NamedPipeServerStream CreateServerPipe()`
  - `private async Task HandleMessageAsync(PipeMessage message)`
- **Security Descriptor Configuration**:
  - Implements a custom `PipeSecurity` DACL: grants `GENERIC_READ | GENERIC_WRITE` only to the interactive console user token (`InteractiveSessionUserSid`) and `NT AUTHORITY\SYSTEM`. Rejects remote network callers.
- **What Happens When It Fails?**:
  - If the pipe client disconnects or crashes, `ControlPipeWorker` recycles the pipe server instance, enters a listening state, and awaits a new connection.
- **Evidence**:
  ```text
  Evidence: Endpoint-agent/src/Spemcs.Agent.Service/ControlPipeWorker.cs
  Symbol: ControlPipeWorker.CreateServerPipe
  Confidence: ✅ VERIFIED
  ```

---

## 5. InteractiveSessionUiLauncher

### Layer 1: Beginner View (Real-World Analogy)
Imagine a manager sitting in a windowless command bunker who needs to display a message on a television screen in the public cafeteria. The manager cannot physically walk into the cafeteria, so they use a remote projector control system to cast the exact image onto the cafeteria screen.

### Layer 2: System View
Located in [`Spemcs.Agent.Service`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Service/InteractiveSessionUiLauncher.cs). Solves the classic Windows service dilemma: services in Session 0 cannot display windows on user monitors.

```
┌──────────────────────────────────────────────┐
│        InteractiveSessionUiLauncher          │
│   WTSGetActiveConsoleSessionId()             │
│   WTSQueryUserToken() -> DuplicateTokenEx()  │
│   CreateProcessAsUserW()                     │
└──────────────────────────────────────────────┘
          │
          ▼ Spawns process across session boundary
[ Spemcs.Agent.UI.exe in Session 1+ Desktop ]
```

### Layer 3: Code View
- **File**: [`Endpoint-agent/src/Spemcs.Agent.Service/InteractiveSessionUiLauncher.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Service/InteractiveSessionUiLauncher.cs)
- **Class**: `public static class InteractiveSessionUiLauncher`
- **Key Symbol**: `public static bool LaunchUiInActiveSession(string uiPath, string arguments)`
- **Win32 P/Invoke APIs**:
  - `WTSGetActiveConsoleSessionId()`: Identifies the ID of the physical monitor session (usually Session 1).
  - `WTSQueryUserToken(sessionId, out hToken)`: Retrieves the access token of the logged-in student.
  - `DuplicateTokenEx(..., SecurityIdentification, TokenPrimary, ...)`: Duplicates primary token.
  - `CreateProcessAsUserW(hDuplicatedToken, uiPath, ...)`: Spawns the WPF application in the user session.
- **What Happens When It Fails?**:
  - Returns `false` and logs Win32 error code via `Marshal.GetLastWin32Error()`. Service retries every 5 seconds until a user logs in.
- **Evidence**:
  ```text
  Evidence: Endpoint-agent/src/Spemcs.Agent.Service/InteractiveSessionUiLauncher.cs
  Symbol: InteractiveSessionUiLauncher.LaunchUiInActiveSession
  Confidence: ✅ VERIFIED
  ```

---

## 6. ConfigurableProcessClassifier & Process Monitor

### Layer 1: Beginner View (Real-World Analogy)
Think of `ConfigurableProcessClassifier` as an automated security scanner at airport baggage control. Every bag (new process) passing through the scanner is instantly X-rayed in under a tenth of a second. If the scanner detects unauthorized items (e.g. AnyDesk, TeamViewer, CheatEngine), it immediately tags the passenger and radios the control room.

### Layer 2: System View
Located in [`Spemcs.Agent.Core`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/ProcessServices.cs). Subscribes to Windows kernel events via WMI and ETW.

```
[ Windows Kernel ] ──Win32_Process Event──► [ ConfigurableProcessClassifier ]
                                                      │
                                                      ▼ Matches prohibited signatures
                                            [ EventUploaderWorker ]
                                                      │
                                                      ▼ HTTPS POST /api/v1/events
                                            [ Backend EventService ]
```

### Layer 3: Code View
- **File**: [`Endpoint-agent/src/Spemcs.Agent.Core/ProcessServices.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/ProcessServices.cs)
- **Class**: `public class ConfigurableProcessClassifier`
- **Key Symbols**:
  - `public ProcessClassification Classify(ProcessInfo process)`
  - `public void UpdateRules(IEnumerable<ProcessRule> rules)`
  - `public event EventHandler<ProcessViolationEventArgs> OnViolationDetected`
- **Detection Mechanics**:
  - Subscribes to WMI query: `SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'`.
  - Evaluates `TargetInstance.Name`, `TargetInstance.ExecutablePath`, and `TargetInstance.CommandLine`.
  - Flags categories: `RemoteDesktop`, `VirtualMachine`, `Debugger`, `Communication`.
- **What Happens When It Fails?**:
  - Catches WMI handle exhaustion exceptions, recycles the management event watcher, and falls back to ETW / polling.
- **Evidence**:
  ```text
  Evidence: Endpoint-agent/src/Spemcs.Agent.Core/ProcessServices.cs
  Symbol: ConfigurableProcessClassifier.Classify
  Confidence: ✅ VERIFIED
  ```

---

## 7. PolicyCompiler

### Layer 1: Beginner View (Real-World Analogy)
Think of `PolicyCompiler` as an official legal translator and cartographer. When a university professor specifies: "This exam uses the Canvas platform and Microsoft Edge", `PolicyCompiler` takes that human requirement, looks up all authorized IP address ranges and CDN subnets for Canvas, validates that no invalid IPs are included, and formats it into a standardized security specification.

### Layer 2: System View
Located in [`backend/backend/services/policy_compiler.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/policy_compiler.py). Called when an administrator triggers policy compilation or schedules an exam with network enforcement.

```
[ Admin / Exam Shield ]
          │
          ▼
┌──────────────────────────────────────────────┐
│               PolicyCompiler                 │
│  Validates Vendor Profiles, Domains & CIDRs  │
└──────────────────────────────────────────────┘
          │
          ▼ Canonical JSON Policy DTO
[ PolicySigner (RSA-PSS) ]
```

### Layer 3: Code View
- **File**: [`backend/backend/services/policy_compiler.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/policy_compiler.py)
- **Class / Function**: `compile_exam_policy(exam_id: UUID, db: Session) -> NetworkPolicyPayload`
- **Key Operations**:
  - Fetches `Exam`, `VendorProfile`, and `Device` records.
  - Expands domain names into authorized IP address specifications.
  - Normalizes IPv4 and IPv6 CIDRs; validates against forbidden private ranges.
  - Serializes schema version `2.0`.
- **What Happens When It Fails?**:
  - Raises `PolicyCompilationError` if vendor profile is missing or CIDR format is invalid. Halts exam activation.
- **Evidence**:
  ```text
  Evidence: backend/backend/services/policy_compiler.py
  Symbol: compile_exam_policy
  Confidence: ✅ VERIFIED
  ```

---

## 8. PolicySigner & SigningKeyManager

### Layer 1: Beginner View (Real-World Analogy)
Think of `PolicySigner` as the royal notary public who applies an embossed wax seal with a unique ring to an official proclamation. Anyone who reads the proclamation can verify the seal with an official magnifying glass (public key). If a single letter on the paper is scratched out or altered, the seal immediately breaks.

### Layer 2: System View
Located in [`backend/backend/services/signing_key_manager.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/signing_key_manager.py) and [`policy_signer.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/policy_signer.py). Protects network policies from man-in-the-middle alteration between backend and agent.

```
[ PolicyCompiler ]
          │
          ▼
┌──────────────────────────────────────────────┐
│                 PolicySigner                 │
│  1. RFC 8785 Canonical JSON Serialization    │
│  2. RSA-2048 / RSA-PSS (SHA-256 / MGF1)      │
│  3. Injects key_id & signature base64        │
└──────────────────────────────────────────────┘
          │
          ▼ Stored in network_policies table
[ Agent PolicyReceiver ] (Verifies Signature)
```

### Layer 3: Code View
- **Files**:
  - [`backend/backend/services/signing_key_manager.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/signing_key_manager.py)
  - [`backend/backend/services/policy_signer.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/policy_signer.py)
- **Key Symbols**:
  - `SigningKeyManager.get_active_private_key()`
  - `SigningKeyManager.rotate_key(reason: str)`
  - `SigningKeyManager.revoke_key(key_id: str, reason: str)`
  - `sign_policy_payload(payload: dict, private_key) -> str`
- **Cryptographic Ground Truth**:
  - Algorithm: RSA-PSS (Probabilistic Signature Scheme).
  - Digest: SHA-256 | MGF: MGF1 | Salt: 32 bytes.
  - Serialization: RFC 8785 Canonical JSON (deterministic key sorting, whitespace removal).
  - Storage: `/backend/secrets/keyring.json` (encrypted with optional passphrase).
- **What Happens When It Fails?**:
  - In production (`SPEMCS_ENV=production`), missing key directory or invalid passphrase throws a startup error; ephemeral fallback is strictly blocked.
- **Evidence**:
  ```text
  Evidence: backend/tests/test_signing_key_lifecycle.py
  Test Count: 74 hermetic tests passing
  Confidence: ✅ VERIFIED
  ```

---

## 9. RealtimeManager & WebSocket Hubs

### Layer 1: Beginner View (Real-World Analogy)
Think of `RealtimeManager` as a radio broadcast dispatcher at central emergency services. Patrol cars (endpoints) stream reports into Channel 1 (`/ws/agent`), while dispatch monitors (proctor dashboards) listen on Channel 2 (`/ws/dashboard`). When an incident occurs, the dispatcher broadcasts the alert instantly across all screens.

### Layer 2: System View
Located in [`backend/backend/websocket/realtime.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/websocket/realtime.py). Multiplexes WebSocket connections.

```
[ Lab Workstation Agents ]             [ Proctor / Admin Browsers ]
          │                                         │
          ▼ WSS: /api/v1/ws/agent                   ▼ WSS: /api/v1/ws/dashboard
┌────────────────────────────────────────────────────────────────────────┐
│                            RealtimeManager                             │
│   • Heartbeat Monitoring (30s interval, 10s timeout)                   │
│   • First-Frame AUTHENTICATE Handshake Gate                            │
│   • Event Multiplexer: ALERT_CREATED, DEVICE_UPDATE, EXAM_STATE        │
└────────────────────────────────────────────────────────────────────────┘
```

### Layer 3: Code View
- **File**: [`backend/backend/websocket/realtime.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/websocket/realtime.py)
- **Class**: `public class RealtimeManager`
- **Key Symbols**:
  - `register_agent(device_id: UUID, websocket: WebSocket)`
  - `register_dashboard(user_id: UUID, websocket: WebSocket)`
  - `broadcast_dashboard_event(event_type: str, data: dict)`
  - `broadcast_agent_command(device_id: UUID, command: dict)`
- **Authentication Handshake**:
  - Dashboard WebSockets accept connection, then require `{ "type": "AUTHENTICATE", "token": "<jwt>" }` as the first message within 5 seconds. Closes with code `4401` on invalid token or `4403` on insufficient role.
- **What Happens When It Fails?**:
  - Dead connections are pruned during heartbeat sweeps. Broadcasts gracefully handle broken pipes without dropping server state.
- **Evidence**:
  ```text
  Evidence: backend/backend/websocket/realtime.py
  Symbol: RealtimeManager.broadcast_dashboard_event
  Confidence: ✅ VERIFIED in test_websocket_heartbeat.py
  ```

---

## 10. EventService & Alert Ingestion

### Layer 1: Beginner View (Real-World Analogy)
Think of `EventService` as an emergency triage nurse. Patients (raw telemetry events) arrive constantly. The triage nurse assesses the severity of each case: normal vitals are filed away into medical records, while serious symptoms (e.g. unauthorized process spawn) trigger an immediate red alert that summons the doctor.

### Layer 2: System View
Located in [`backend/backend/services/event_service.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/event_service.py). Processes incoming telemetry from endpoints.

```
[ POST /api/v1/events ] ──(Device Token)──► [ EventService.ingest_event ]
                                                   │
                         ┌─────────────────────────┴─────────────────────────┐
                         ▼                                                   ▼
                [ Insert into events ]                             [ Severity == HIGH? ]
                                                                             │
                                                                             ▼
                                                                   [ Insert into alerts ]
                                                                             │
                                                                             ▼
                                                                 [ RealtimeManager Broadcast ]
```

### Layer 3: Code View
- **File**: [`backend/backend/services/event_service.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/event_service.py)
- **Key Symbol**: `ingest_event(db: Session, event_in: EventCreate) -> Event`
- **Database Interaction**:
  - Writes to `events` table (14 columns).
  - Evaluates `event_in.classification`: if classified as prohibited, writes to `alerts` table (9 columns).
  - Handles `alerts.exam_id` as nullable so background lab violations outside exams are never lost.
- **What Happens When It Fails?**:
  - Database rollback isolates failed transactions; returns HTTP 500 while preserving connection pool health.
- **Evidence**:
  ```text
  Evidence: backend/backend/services/event_service.py
  Symbol: ingest_event
  Confidence: ✅ VERIFIED in test_alerts.py
  ```

---

## 11. AppShell & Global State Management

### Layer 1: Beginner View (Real-World Analogy)
Think of `AppShell` like the dashboard console and steering wheel of a modern car. No matter which road you drive on (which page you view), the speedometer, fuel gauge, alert lights, and navigation buttons stay anchored around you, displaying live telemetry from the engine.

### Layer 2: System View
Located in [`frontend/src/components/layout/AppShell.tsx`](file:///c:/Users/shrma/Desktop/spemcsnew/frontend/src/components/layout/AppShell.tsx) and [`frontend/src/context/AppContext.tsx`](file:///c:/Users/shrma/Desktop/spemcsnew/frontend/src/context/AppContext.tsx). Coordinates frontend routing, authentication guards, and real-time state.

```
[ Browser Navigation ]
          │
          ▼
┌──────────────────────────────────────────────┐
│                   AppShell                   │
│   • Sidebar navigation & active route link   │
│   • Top header: user avatar & logout         │
│   • ToastContainer: real-time alert popups   │
└──────────────────────────────────────────────┘
          │
          ▼ Wraps
[ Current Page: LiveMonitor / ExamShield / etc. ]
```

### Layer 3: Code View
- **Files**:
  - [`frontend/src/components/layout/AppShell.tsx`](file:///c:/Users/shrma/Desktop/spemcsnew/frontend/src/components/layout/AppShell.tsx)
  - [`frontend/src/context/AppContext.tsx`](file:///c:/Users/shrma/Desktop/spemcsnew/frontend/src/context/AppContext.tsx)
- **Key Symbols**:
  - `AppShell()`: Main layout component.
  - `AppProvider()`: React context provider wrapping the application.
  - `useApp()`: Hook exposing `user`, `isAuthenticated`, `alerts`, `wsConnected`.
- **WebSocket Reconnection**:
  - Automatically reconnects with exponential backoff if the server drops connection. Dispatches toast notifications on incoming alerts.
- **What Happens When It Fails?**:
  - If JWT expires, clears `localStorage` and redirects to `/login`.
- **Evidence**:
  ```text
  Evidence: frontend/src/context/AppContext.tsx
  Symbol: AppProvider
  Confidence: ✅ VERIFIED
  ```

---

## 12. ExamShieldPage & LiveMonitorPage

### Layer 1: Beginner View (Real-World Analogy)
`ExamShieldPage` is the pre-flight checklist and launchpad control for an exam. `LiveMonitorPage` is the mission control room with a grid of live video screens showing the telemetry status of every workstation in the fleet.

### Layer 2: System View
The primary operational user interfaces for administrators and proctors during active examination sessions.

```
[ Administrator ] ──Configures & Activates──► [ ExamShieldPage ]
                                                      │
                                                      ▼ Verifies readiness
                                            [ EnforcementReadiness ]
                                                      │
                                                      ▼ Exam is ACTIVE
[ Proctor ] ───────Monitors Live Fleet──────► [ LiveMonitorPage ]
                                                      ▲
                                                      │ WSS Stream
                                            [ RealtimeManager ]
```

### Layer 3: Code View
- **Files**:
  - [`frontend/src/pages/ExamShieldPage.tsx`](file:///c:/Users/shrma/Desktop/spemcsnew/frontend/src/pages/ExamShieldPage.tsx)
  - [`frontend/src/pages/LiveMonitorPage.tsx`](file:///c:/Users/shrma/Desktop/spemcsnew/frontend/src/pages/LiveMonitorPage.tsx)
- **Key Symbols**:
  - `ExamShieldPage()`: Handles exam policy compilation, vendor selection, and pre-flight readiness verification.
  - `LiveMonitorPage()`: Displays live workstation tiles; pulses red when violations occur.
- **What Happens When It Fails?**:
  - If activation returns 409 Conflict (unarmed devices), `ExamShieldPage` renders the specific failing devices rather than entering a broken state.
- **Evidence**:
  ```text
  Evidence: frontend/src/pages/ExamShieldPage.tsx & LiveMonitorPage.tsx
  Confidence: ✅ VERIFIED
  ```
