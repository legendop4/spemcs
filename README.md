# SPEMCS — Secure Proctoring & Endpoint Management Compliance System

## 1. Project Overview

SPEMCS (Secure Proctoring & Endpoint Management Compliance System) is an enterprise-grade proctoring, lockdown, and compliance platform. The system enforces strict security invariants on student/candidate endpoints during examinations.

A core pillar of SPEMCS is **Network Lockdown Enforcement**: restricting all outbound network traffic on the candidate's machine to only authorized exam destinations (e.g., examination web servers, LMS platforms, content delivery networks) while strictly maintaining connectivity to the SPEMCS management control plane and preventing all unauthorized external communication.

---

## 2. Architecture

Network enforcement follows a defense-in-depth, privilege-separated pipeline:

```
┌──────────────────────────────────────────────────────────┐
│                     Central Backend                      │
│        (FastAPI / PostgreSQL / RSA-PSS Signer)           │
│                  http://127.0.0.1:8002                   │
└────────────────────────────┬─────────────────────────────┘
                             │
                  Signed Network Policy
                 (RSA-PSS SHA-256 JSON)
                             │
                             ▼
┌──────────────────────────────────────────────────────────┐
│                   Endpoint UI Process                    │
│      (Spemcs.Agent.UI.exe — Interactive User Session)    │
│           Receives policy via WebSocket                  │
└────────────────────────────┬─────────────────────────────┘
                             │
                     Secure Named Pipe
                   ("spemcs-control-v1")
                             │
                             ▼
┌──────────────────────────────────────────────────────────┐
│                Windows Service (SYSTEM)                  │
│  (Spemcs.Agent.Service.exe — NT AUTHORITY\SYSTEM)        │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ PolicyReceiver                                     │  │
│  │  - RSA-PSS Signature Verification                  │  │
│  │  - Monotonic Version & Timestamp Validation        │  │
│  │  - JSON Schema Validation                          │  │
│  └─────────────────────────┬──────────────────────────┘  │
│                            │                             │
│                            ▼                             │
│  ┌────────────────────────────────────────────────────┐  │
│  │ EnforcementStateMachine                            │  │
│  │  - Pre-enforcement Management Connectivity Check   │  │
│  │  - Phase Transitions (Prepared -> Enforcing -> ...)│  │
│  │  - Post-enforcement Management Verification       │  │
│  │  - Automatic Emergency Rollback Orchestration      │  │
│  └─────────────────────────┬──────────────────────────┘  │
│                            │                             │
│                            ▼                             │
│  ┌────────────────────────────────────────────────────┐  │
│  │ NetworkEnforcer                                    │  │
│  │  - Captures Baseline Firewall Profile State        │  │
│  │  - Persists State in SqliteRollbackJournal         │  │
│  │  - Installs Product-Owned Rules                    │  │
│  │  - Reads Back & Verifies Rule Properties           │  │
│  │  - Enforces DefaultOutboundAction = Block          │  │
│  │  - Safely Restores Baseline on Teardown/Failure    │  │
│  └─────────────────────────┬──────────────────────────┘  │
│                            │                             │
│                            ▼                             │
│  ┌────────────────────────────────────────────────────┐  │
│  │ WindowsFirewallAdapter                             │  │
│  │  - COM Interface: INetFwPolicy2 / HNetCfg.FWRule   │  │
│  │  - Atomic Profile Outbound Default Mutations       │  │
│  │  - Rule Readback & Enumeration by Group            │  │
│  └─────────────────────────┬──────────────────────────┘  │
└────────────────────────────┼─────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────┐
│                 Windows Defender Firewall                │
│    (Domain, Private, Public Profiles — Kernel Filtering) │
└──────────────────────────────────────────────────────────┘
```

### Privilege Boundary Separation
- **Interactive UI (`Spemcs.Agent.UI.exe`)**: Runs within the logged-in candidate's interactive Windows session. It handles user interface rendering and WebSocket communication with the central server. The interactive user token does NOT possess administrative privileges to mutate Windows Defender Firewall policies.
- **Windows Service (`Spemcs.Agent.Service.exe`)**: Runs as a background Windows Service under `NT AUTHORITY\SYSTEM`. It alone owns the firewall COM adapter, policy verification engine, sqlite journal, and network enforcer.
- **IPC Mechanism**: Communication between UI and Service occurs over the secure Windows named pipe `\\.\pipe\spemcs-control-v1` using length-prefixed JSON protocol frames.

---

## 3. Endpoint Enforcement Flow

1. **Policy Receipt**: The UI receives a `SIGNED_NETWORK_POLICY` message from the backend over WebSocket.
2. **IPC Delegation**: The UI forwards the signed policy payload to the background service over named pipe `spemcs-control-v1` via an `ApplyNetworkPolicy` command.
3. **Public Key Resolution**: The Service ensures the active RSA signing public key is loaded (via cached store or `GET /api/policies/signing-key/public`).
4. **Signature & Schema Validation**: `PolicyReceiver` validates:
   - Cryptographic signature (RSA-PSS SHA-256).
   - Strict monotonic version check against the local SQLite store (`PolicyVersion > currentVersion`).
   - Time validity (`not_before <= now <= expires_at`).
   - Exam ID match.
5. **Pre-Enforcement Management Probe**: `ManagementConnectivityVerifier` confirms the management server is reachable at its configured endpoint (`/api/v1/management/health`) before any firewall changes occur.
6. **Rule Generation**: `EnforcementStateMachine.BuildSessionRules` constructs the rule set in strict order:
   - `SPEMCS-{sessionId:N}-Loopback-IPv4` (Outbound, Allow, Protocol Any, Local `127.0.0.1`, Remote `127.0.0.1`).
   - `SPEMCS-{sessionId:N}-Loopback-IPv6` (Outbound, Allow, Protocol Any, Local `::/127`, Remote `::/127`).
   - `SPEMCS-{sessionId:N}-Mgmt-{cleanIp}-{port}` (Outbound, Allow, Protocol TCP, Remote `cleanIp`, Port `port`).
   - Exam-specific allowed vendor destinations (TCP and UDP ranges).
   - All rules belong to group `SPEMCS_EXAM_LOCKDOWN`.
7. **Two-Phase Application**:
   - **Baseline Capture**: Captures `Domain`, `Private`, and `Public` default outbound actions and active runtime profile bitmask.
   - **Journal Record**: Persists `Prepared` state to `network_journal.db`.
   - **Install Allow Rules**: Adds all allow rules to Windows Defender Firewall.
   - **Readback & Verify**: Reads back all installed rules; verifies 13 distinct COM properties (`DisplayName`, `Group`, `Enabled`, `Direction`, `Action`, `Protocol`, `Profiles`, `LocalAddresses`, `RemoteAddresses`, `LocalPorts`, `RemotePorts`, `ApplicationName`, `ServiceName`).
   - **Enforce Default Block**: Switches `DefaultOutboundAction` to `Block` for target profiles.
   - **Readback After Block**: Verifies `DefaultOutboundAction == Block` and confirms all allow rules survive and remain enabled.
8. **Post-Enforcement Health Verification**: Performs an authenticated health probe to `GET /api/v1/management/health`.
   - **Success**: State machine transitions to `EnforcementState.Active`.
   - **Failure**: State machine immediately triggers emergency rollback.
9. **Teardown / Exam Stop**: When `StopExam` or `RemoveNetworkPolicy` is received, the enforcer:
   - Restores the baseline `DefaultOutboundAction` FIRST.
   - Deletes ONLY rules belonging to group `SPEMCS_EXAM_LOCKDOWN`.
   - Leaves all unrelated system and vendor firewall rules completely untouched.

---

## 4. Current Implemented Features
 
> [!CAUTION]
> **CRITICAL ARCHITECTURAL DISTINCTION: Automated Tests Passing != Live Windows E2E Proven**  
> While the test suite passes (170/170), **Live Windows E2E network enforcement is NOT YET PROVEN / OPEN ISSUE**.  
> Do not label the network enforcement subsystem "complete", "production-ready", "fully working", or "E2E verified" solely because automated tests pass.

- [x] **Cryptographically Signed Network Policies**: RSA-PSS SHA-256 canonical JSON signature verification.
- [x] **Monotonic Version & Replay Protection**: Strict version progression and validity window checks.
- [x] **Management Plane Pre-Check**: Probing `/api/v1/management/health` before policy activation.
- [x] **Service-Delegated Enforcement**: Privileged firewall mutation isolated to `NT AUTHORITY\SYSTEM`.
- [x] **Named Pipe IPC Protocol**: `spemcs-control-v1` for inter-process communication.
- [x] **Product-Owned Rule Grouping**: Rules tagged with `SPEMCS_EXAM_LOCKDOWN`.
- [x] **SQLite Rollback Journal**: Atomic persistence of baseline state and applied rule IDs in `network_journal.db`.
- [x] **Automatic Emergency Rollback**: Restores baseline on any exception, health probe failure, or cancellation.
- [x] **Firewall Property Readback**: Full 13-property verification before and immediately after block enforcement.
- [x] **Deterministic Rule Naming**: SHA-256 derived names preventing rule duplication.
- [x] **Loopback Infrastructure Rules**: Explicit IPv4 (`127.0.0.1`) and IPv6 (`::/127`) allow rules.
- [x] **External Conflict Detection**: Detects if an external admin or GPO changed firewall defaults while SPEMCS was active and yields safely.
- [x] **Stale Binary Protection**: `install_service.ps1` stops service, waits for process termination, rebuilds solution, reinstalls, and restarts service.
- [x] **Automated Test Suite**: 170 passing tests covering unit, mock integration, and live COM property tests.

---

## 5. Security Model

- **Privilege Separation**: The UI process cannot alter firewall rules; only the service running as SYSTEM executes firewall COM mutations.
- **Signed Intent**: The service never accepts arbitrary firewall rules over the pipe; it only accepts cryptographically signed policies validated against trusted public keys.
- **Fail-Closed Design**: When active, all outbound traffic not explicitly allowlisted is blocked at the Windows Filtering Platform (WFP) / Defender Firewall layer.
- **Safe Rollback**: Baseline outbound action is restored before rules are deleted, preventing windows of exposure or lockouts.
- **Non-Destructive Cleanup**: Rollback queries by rule group (`SPEMCS_EXAM_LOCKDOWN`) and session ID; unrelated host firewall rules (e.g. corporate VPNs, domain rules) are never modified or removed.

---

## 6. Test Status

> [!IMPORTANT]
> **Automated Tests Passing != Live Windows E2E Proven**  
> While all 170 unit and integration tests are green, **Live Windows E2E Network Enforcement remains NOT YET PROVEN / OPEN ISSUE**. Live E2E status cannot be inferred from automated or mocked tests alone.

### Final Test Suite Run
Command:
```powershell
dotnet test Endpoint-agent/tests/Spemcs.Agent.Tests/Spemcs.Agent.Tests.csproj
```
**Results:**
- **Total Tests**: 170
- **Passed**: 170
- **Failed**: 0
- **Skipped**: 0
- **Duration**: ~31s

### Solution Build Run
Command:
```powershell
dotnet build Endpoint-agent/Spemcs.Agent.sln -c Debug
```
**Results:**
- **Projects Built**: `Spemcs.Agent.Ipc`, `Spemcs.Agent.Core`, `Spemcs.Agent.TestHarness`, `Spemcs.Agent.Service`, `Spemcs.Agent.UI`, `Spemcs.Agent.Tests`
- **Warnings**: 0
- **Errors**: 0

### Test Level Categorization

| Test Category | Description | Status |
| :--- | :--- | :--- |
| **Unit Tests** | Schema validation, monotonic version enforcement, replay protection, journal transitions, rule generation, and property validation. | **100% PASSED** (In test suite) |
| **Mock Integration Tests** | Full state machine activation, dynamic policy updates, sequence verifiers, conflict detection, and simulated network traffic. | **100% PASSED** (In test suite) |
| **Elevated Windows COM Tests** | Live `HNetCfg.FwPolicy2` and `HNetCfg.FWRule` property validation, IPv4 (`127.0.0.1`), IPv6 (`::/127`), protocol `256`, profiles `7`. | **100% PASSED** (In test suite) |
| **Real Live Windows E2E** | Live exam launch on real machine with running backend, service, UI, and real network blocking. | **OPEN / UNRESOLVED** (See Section 8) |

---

## 7. Problems Encountered and Fixes Implemented

### 1. UI Firewall Privilege Problem
- **Problem**: Initial network enforcement was attempted inside `Spemcs.Agent.UI.exe`. Even though the UI process was run by an administrator, the Windows Defender Firewall COM interface (`INetFwRules::Add`) threw `0x80070005 (E_ACCESSDENIED)` because interactive tokens lack the required security descriptor rights for firewall mutation.
- **Fix**: Re-architected enforcement into the Windows background service (`Spemcs.Agent.Service.exe`) running under `NT AUTHORITY\SYSTEM`. Created the `spemcs-control-v1` named pipe to forward signed policies from UI to Service.

### 2. Management Verifier HTTPS/HTTP Problem
- **Problem**: The development backend runs on plain HTTP (`http://127.0.0.1:8002/`). `ManagementConnectivityVerifier` defaulted to `TransportSecurityMode.StrictHttps`, rejecting plain HTTP before making any network call. Additionally, replacing `127.0.0.1` with `localhost` caused Windows to resolve IPv6 `[::1]` first against an IPv4-only uvicorn listener, generating a ~2.7s delay that raced the 3-second timeout.
- **Fix**: Updated verifier configuration in `Program.cs` to select `AllowInsecureHttpForTesting` when the configured URL begins with `http://`. Prevented rewriting explicit `127.0.0.1` to `localhost`. Added custom header host preservation.

### 3. Stale Binary Problem
- **Problem**: When editing C# source code and rebuilding, running `Spemcs.Agent.Service.exe` was locking DLLs in `bin/Debug/net8.0-windows/`. `dotnet build` failed with file lock errors, or older running service binaries continued executing stale logic.
- **Fix**: Updated `Endpoint-agent/scripts/install_service.ps1` to stop the service, wait in a loop until the process completely terminates and unlocks file handles, delete the service registration, execute `dotnet build`, recreate the service with failure recovery actions, and start the fresh binary.

### 4. Firewall Rule / Management-Plane Block Problem
- **Problem**: In live E2E testing, pre-enforcement health check passed. Enforcement activated and installed firewall rules. However, immediately after `DefaultOutboundAction` became `Block`, the post-enforcement health probe to `http://127.0.0.1:8002/api/v1/management/health` timed out after 3 seconds, triggering emergency rollback.
- **Analysis**: The explicit management rule only allowed outbound TCP traffic with `RemotePort = 8002`. In a local environment where the backend runs on the same machine (`127.0.0.1`), the local server's return response packets from port 8002 to the client's ephemeral port (e.g. 52143) were treated by Windows Firewall as outbound packets with remote port 52143. Because `52143 != 8002` and `DefaultOutboundAction == Block`, the return packets were blocked.
- **Fix**: Added explicit product-owned loopback allow rules for both IPv4 and IPv6 before setting `DefaultOutboundAction = Block`.

### 5. COM IPv6 Loopback Representation Problem
- **Problem**: During rule installation, `WindowsFirewallAdapter.AddRule` threw `System.ArgumentException: Value does not fall within the expected range` on line 104 when assigning `RemoteAddresses = "::1"`.
- **Discovery**: Windows Defender Firewall COM (`HNetCfg.FWRule`) explicitly rejects single host `"::1"` and `"::1/128"` for `RemoteAddresses` and `LocalAddresses`. However, it accepts CIDR prefix subnet notation `"::/127"`. Direct inspection of existing host rules (`codex_sandbox_offline_block_loopback_tcp`) confirmed Windows uses `::/127` for IPv6 loopback.
- **Fix**: Updated `CreateLoopbackIPv6Allow` to use `LocalAddresses = "::/127"` and `RemoteAddresses = "::/127"`. Added explicit logging before every COM property assignment. Guarded `fwRule.ServiceName` to only be set if non-null, non-empty, and not a sentinel value (`none`, `*`).

### 6. Partial-Application Rollback False Conflict
- **Problem**: When rule 2 failed during initial rule creation, rollback reported `Rules removed: 1, Baseline restored: False, Conflict: True`.
- **Analysis**: `ApplyEnforcementAsync` caught the exception during `ApplyingRules` and called `PerformSafeRollbackInternal` with `EnforcementPhase.Failed`. `defaultBlockWasAttempted` evaluated to `true`, causing `RestoreBaselineSafely` to be called. Because SPEMCS had not yet applied `Block`, `current` was still `Allow` (matching baseline). `RestoreBaselineSafely` misinterpreted this as an external modification away from `Block` and recorded a false conflict.
- **Fix**: Updated `ApplyEnforcementAsync` to capture the actual failure phase (`ApplyingRules`) before transitioning to `Failed`. In `PerformSafeRollbackInternal`, `defaultBlockWasAttempted` is `false` when failure happens during rule application; baseline restoration is skipped (since `Block` was never set), preventing false conflicts, while installed rules are cleaned up and the session transitions to `RolledBack` with `Conflict = false`.

### 7. Intermittent Pre-Enforcement Management Probe Timeout
- **Problem**: In a subsequent run, an intermittent timeout occurred during the **pre-enforcement** check (`RulesInstalled = 0`), before any firewall rules were touched.
- **Investigation**: Independently from the machine, `curl.exe http://127.0.0.1:8002/api/v1/management/health` returned HTTP 200 instantaneously, and `Test-NetConnection 127.0.0.1 -Port 8002` succeeded. Yet the service's `ManagementConnectivityVerifier` timed out on that same endpoint.
- **Root Cause (found)**: The timeout was never on the agent/HttpClient/socket side. `backend/backend/routes/health.py`'s `management_health_check` was running `db.execute(text("SELECT 1"))` against `DATABASE_URL` on every call — and `DATABASE_URL` points at a **remote serverless Neon Postgres instance** (see `backend/README.md`), which auto-suspends its compute after a period of inactivity. The first query after the compute has gone to sleep pays a multi-second cold-start penalty, well past the agent's ~3s probe timeout, even though the backend process and the local network path to it were completely healthy. This is exactly why the symptom was intermittent (warm vs. suspended Neon compute) and why a manual `curl` right after a failed probe always "fixed" it — the `curl` request itself woke the DB back up for the *next* call.
- **Fix**: `management_health_check` no longer touches the database at all — it's a pure, fast, dependency-free liveness response, since its only job (per Section 3, step 5) is to prove the agent can still reach the control plane, not that every downstream dependency is healthy. General DB/API health for dashboards/ops monitoring is still available separately at `GET /api/health`, which isn't on this latency budget.
- **Status**: **Resolved.**

---

## 8. Current Open Issues / Not Yet Proven

> [!WARNING]
> **DO NOT CLAIM THE PROJECT IS FULLY E2E VERIFIED.**
> Real live Windows E2E network lockdown has NOT yet been conclusively proven end-to-end.

1. ~~**Pre-Enforcement Intermittent Timeout**~~ — **Resolved**, see Section 7, item 7: the management health endpoint was silently coupled to a remote Neon Postgres cold-start, not an agent/socket issue. Needs a live Windows re-run to confirm the fix removes the intermittency in practice.
2. **Post-Enforcement Under Real Block**: While loopback IPv4 (`127.0.0.1`) and IPv6 (`::/127`) rules have been implemented and pass all COM validation tests, live E2E confirmation that the service receives HTTP 200 *while* `DefaultOutboundAction = Block` is active has not yet completed without an intermittent pre-check interruption. This should now be re-tested with the Section 7 fix in place.
3. **What HAS Been Proven**:
   - Signature validation, replay protection, monotonic versions, and journal persistence are 100% verified.
   - IPC named pipe communication between UI and Service is 100% verified.
   - Windows Firewall COM rule creation with `127.0.0.1` and `::/127` is 100% verified.
   - Rollback cleanly removes product rules and restores baseline without false conflicts.
   - 170 unit and integration tests pass cleanly with 0 warnings.

---

## 9. Current Environment

```
Backend URL:       http://127.0.0.1:8002
Frontend URL:      http://127.0.0.1:5173
Named Pipe:        \\.\pipe\spemcs-control-v1
Service Name:      SPEMCS Endpoint Agent
Service Account:   NT AUTHORITY\SYSTEM
Service Binary:    Endpoint-agent\src\Spemcs.Agent.Service\bin\Debug\net8.0-windows\Spemcs.Agent.Service.exe
Service Logs:      C:\ProgramData\Spemcs\Logs\agent-service-*.log
Journal Database:  C:\ProgramData\Spemcs\network_journal.db
Rule Group:        SPEMCS_EXAM_LOCKDOWN
```

*Security Note: No production passwords, API tokens, certificates, or private keys are committed in this repository.*

---

## 10. How To Build & Test

### Build the Full Solution
```powershell
dotnet build Endpoint-agent/Spemcs.Agent.sln -c Debug
```

### Run the Test Suite
```powershell
dotnet test Endpoint-agent/tests/Spemcs.Agent.Tests/Spemcs.Agent.Tests.csproj
```

### Reinstall the Windows Service (Elevated)
Open an **Administrator: Windows PowerShell** prompt:
```powershell
powershell -ExecutionPolicy Bypass -File .\Endpoint-agent\scripts\install_service.ps1
```

### Launch the Endpoint Agent UI (Standard User)
In a standard user terminal:
```powershell
dotnet run --project .\Endpoint-agent\src\Spemcs.Agent.UI\Spemcs.Agent.UI.csproj
```

### Reproduce E2E Exam Test
1. Ensure backend is running: `curl http://127.0.0.1:8002/` -> 200 OK.
2. Ensure service is running: `sc.exe query "SPEMCS Endpoint Agent"` -> STATE: RUNNING.
3. Open browser at `http://localhost:5173/` and navigate to ExamShield.
4. Select or create an exam with **Network Lockdown: ON** and a Vendor Profile (e.g. TCS iON).
5. Click **[ Compile & Sign Policy ]**, then **[ Launch Exam ]**.
6. Monitor service logs: `Get-Content C:\ProgramData\Spemcs\Logs\agent-service-*.log -Wait -Tail 30`.

---

## 11. Safe Testing Rules

1. **NEVER manually disable Windows Defender Firewall.**
2. **NEVER alter or delete unrelated firewall rules.**
3. **NEVER weaken cryptographic signature verification or bypass monotonic version checks just to make tests pass.**
4. **NEVER claim E2E success based solely on unit tests or mock adapters.**
5. **ALWAYS verify that emergency rollback leaves the firewall in its exact original state.**
