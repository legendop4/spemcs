# SPEMCS Engineering Handoff Document

**Date:** 2026-09-04  
**Target Audience:** Incoming Systems / Endpoint Security Engineers  
**Status:** In-Progress Checkpoint (Not Yet Verified Live E2E)

---

## 1. Current Architecture

Privileged Windows Defender Firewall (WFP / COM) enforcement has been moved out of the interactive UI process and delegated to a local Windows Service running as `NT AUTHORITY\SYSTEM`.

```
Central Server (Backend)
       │  [HTTP / WebSocket]
       ▼
Spemcs.Agent.UI (Interactive User Process)
       │
       │  Named Pipe: "spemcs-control-v1"
       │  Security: Local admin / SYSTEM ACL + PID verification
       ▼
Spemcs.Agent.Service (Background Windows Service — NT AUTHORITY\SYSTEM)
       │
       ├─ PolicyReceiver (Signature verification, replay/version checking, JSON deserialization)
       │
       ├─ EnforcementStateMachine (IDLE -> VERIFYING -> ENFORCING -> ACTIVE / FAILED / ROLLEDBACK)
       │     │
       │     ├─ ManagementConnectivityVerifier (Pre- & Post-enforcement health probing)
       │     │
       │     └─ NetworkEnforcer (Orchestrates rule lifecycle & atomic state changes)
       │           │
       │           ├─ RollbackJournal (Tracks installed rule IDs, baseline snapshot, failure phase)
       │           │
       │           └─ WindowsFirewallAdapter (Direct COM interop with HNetCfg.FwPolicy2)
       ▼
Windows Defender Firewall (WFP)
  - DefaultOutboundAction: Block
  - Management Allow Rule: TCP out to Backend (127.0.0.1:8002)
  - Loopback IPv4 Rule: TCP/UDP out to 127.0.0.1 (Local: 127.0.0.1)
  - Loopback IPv6 Rule: TCP/UDP out to ::/127 (Local: ::/127)
  - Exam Whitelist Rules: DNS (53), WebRTC/STUN, Exam Server HTTPS (443)
```

---

## 2. Implemented Subsystems (Passing Automated Test Suite)

> [!CAUTION]
> **CRITICAL DISTINCTION: Automated Tests Passing != Live Windows E2E Proven**  
> All 170 automated unit and integration tests are passing. However, **Live Windows E2E Network Enforcement is NOT YET PROVEN / OPEN ISSUE**.  
> The network enforcement subsystem must NOT be described as "complete", "production-ready", "fully working", or "E2E verified".

1. **Service-Delegated Enforcement Architecture:**
   - Dedicated Windows Service (`Spemcs.Agent.Service`) registered and running as `NT AUTHORITY\SYSTEM`.
   - IPC over secure named pipe `spemcs-control-v1`.
   - UI forwards `SIGNED_NETWORK_POLICY` packets directly to the service over named pipe via [EnforcementServiceClient.cs](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.UI/Network/EnforcementServiceClient.cs).
2. **Cryptographic Security & Policy Validation:**
   - Ed25519 signature verification against public keys (`dev-key-1`).
   - Monotonic version replay protection (`EnforcementStateMachine` rejects older or equal version numbers).
   - Expiration and validity time window validation.
3. **Firewall Rule Engine & COM Adapter:**
   - `WindowsFirewallAdapter` communicates with `HNetCfg.FwPolicy2` COM object.
   - Guarded `ServiceName` assignments (only assigned when valid non-empty string, preventing COM errors).
   - IPv6 loopback formatted as subnet prefix `::/127` (COM rejects literal `::1` or `::1/128`).
   - Grouping: All created rules tagged with `SPEMCS_EXAM_LOCKDOWN`.
   - Readback verification: Rules verified immediately after insertion via `INetFwRules` collection enumeration.
4. **Baseline Capture & Rollback Journal:**
   - Captures pre-enforcement baseline (`DefaultOutboundAction`, `DefaultInboundAction`) across all active profiles (Domain, Private, Public).
   - Tracks rules in `RollbackJournal`.
   - `failurePhase` tracking prevents false conflict detection when failures occur during `ApplyingRules` prior to switching the profile outbound action to `Block`.
5. **Clean Automation & Reinstallation Scripts:**
   - [install_service.ps1](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/scripts/install_service.ps1) automates stopping the service, killing stale locks, building the solution, installing via `sc.exe`, and starting the service cleanly.
6. **Comprehensive Automated Test Suite:**
   - 170 unit and integration tests passing with 0 errors and 0 warnings.

---

## 3. What Is Broken / Current Open Issues

> [!WARNING]
> **Live Windows E2E network enforcement has not yet been conclusively proven end-to-end on a live running desktop.**
> Do NOT claim or describe this codebase as "production-ready" or "fully verified E2E".

### Known Open Failures:

1. **Post-Enforcement Management Probe Timeout (Earlier Failure):**
   - Under active lockdown (`DefaultOutboundAction = Block`), `ManagementConnectivityVerifier` timed out probing `http://127.0.0.1:8002/api/v1/management/health`.
   - NetworkEnforcer triggered automatic rollback, restoring baseline connectivity.
   - Loopback rules (IPv4 `127.0.0.1` and IPv6 `::/127`) were added to resolve loopback drops, but live post-block connectivity has not yet been verified without timeout.
2. **Intermittent Pre-Enforcement Probe Timeout (Latest Failure):**
   - During live runs, `ManagementConnectivityVerifier` occasionally times out on `http://127.0.0.1:8002/api/v1/management/health` **before** any firewall rules are applied (`RulesInstalled = 0`).
   - During this exact failure, manual verification from the console confirmed the backend was responding:
     - `curl.exe http://127.0.0.1:8002/api/v1/management/health` -> HTTP 200 OK
     - `Test-NetConnection 127.0.0.1 -Port 8002` -> `TcpTestSucceeded: True`
   - Possible causes: `HttpClient` connection pooling/DNS delays, socket exhaustion, process permission constraints under `NT AUTHORITY\SYSTEM`, or thread-pool starvation under the default 3000ms timeout window.

---

## 4. Last Known Successful Test Result

- **Test Command:**
  ```powershell
  dotnet test Endpoint-agent/tests/Spemcs.Agent.Tests/Spemcs.Agent.Tests.csproj
  ```
- **Result:**
  - **Passed:** 170
  - **Failed:** 0
  - **Skipped:** 0
  - **Total:** 170
  - **Duration:** ~10 seconds
- **Build Command:**
  ```powershell
  dotnet build Endpoint-agent/Spemcs.Agent.sln -c Debug
  ```
- **Result:** Build succeeded. 0 Warning(s), 0 Error(s).

---

## 5. Last Known Live Failures

| Timestamp / Sequence | Error / Symptom | Component | Root Cause / Status |
| :--- | :--- | :--- | :--- |
| Run A | `Access is denied. (0x80070005 E_ACCESSDENIED)` | `Spemcs.Agent.UI` calling `policy.Rules.Add()` | **Fixed**: UI process lacks Windows Firewall COM privileges; delegated to SYSTEM service via named pipe. |
| Run B | `ManagementUnreachable` (immediate) | `ManagementConnectivityVerifier` | **Fixed**: Lab URL is `http://127.0.0.1:8002`, but verifier defaulted to `StrictHttps`. Added `AllowInsecureHttpForTesting`. |
| Run C | `Management connectivity failed under enforced firewall rules. Rolling back.` | Post-enforcement health probe | **Under investigation**: DefaultOutboundAction=Block severed loopback connectivity. Added explicit IPv4/IPv6 loopback allow rules. |
| Run D | `System.ArgumentException: Value does not fall within the expected range` | `WindowsFirewallAdapter.AddRule` | **Fixed**: COM rejected `::1` and `::1/128` for IPv6 remote addresses (fixed to `::/127`) and rejected `ServiceName="none"` (fixed to guard `ServiceName`). |
| Run E | `Pre-enforcement check failed: management server at 8002 is unreachable` (`RulesInstalled = 0`) | `ManagementConnectivityVerifier` | **ACTIVE OPEN ISSUE**: Intermittent HttpClient timeout under SYSTEM before rule installation, despite backend responding to curl. |

---

## 6. Exact Files Involved

- **Service Entry Point & DI:** [Spemcs.Agent.Service/Program.cs](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Service/Program.cs)
- **Service IPC Listener:** [Spemcs.Agent.Service/Ipc/PolicyPipeServer.cs](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Service/Ipc/PolicyPipeServer.cs)
- **UI IPC Client:** [Spemcs.Agent.UI/Network/EnforcementServiceClient.cs](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.UI/Network/EnforcementServiceClient.cs)
- **Policy Ingestion & Verification:** [Spemcs.Agent.Core/Network/PolicyReceiver.cs](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/PolicyReceiver.cs)
- **State Machine:** [Spemcs.Agent.Core/Network/EnforcementStateMachine.cs](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/EnforcementStateMachine.cs)
- **Firewall Orchestrator & Rollback:** [Spemcs.Agent.Core/Network/NetworkEnforcer.cs](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/NetworkEnforcer.cs)
- **Data & Rule Models:** [Spemcs.Agent.Core/Network/EnforcementModels.cs](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/EnforcementModels.cs)
- **Windows Firewall COM Adapter:** [Spemcs.Agent.Core/Network/WindowsFirewallAdapter.cs](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/WindowsFirewallAdapter.cs)
- **Health Prober:** [Spemcs.Agent.Core/Network/ManagementConnectivityVerifier.cs](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/ManagementConnectivityVerifier.cs)
- **Service Deployment Script:** [Endpoint-agent/scripts/install_service.ps1](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/scripts/install_service.ps1)

---

## 7. Exact Commands to Build, Test, and Install

### Build Solution
```powershell
dotnet build Endpoint-agent/Spemcs.Agent.sln -c Debug
```

### Run All Tests
```powershell
dotnet test Endpoint-agent/tests/Spemcs.Agent.Tests/Spemcs.Agent.Tests.csproj
```

### Install / Reinstall Windows Service (Run as Administrator)
```powershell
powershell -ExecutionPolicy Bypass -File Endpoint-agent/scripts/install_service.ps1
```

### Check Service Status & Verify Process Elevation
```powershell
Get-Service -Name "Spemcs.Agent.Service"
Get-Process -Name "Spemcs.Agent.Service" | Select-Object Id, ProcessName, StartTime
```

### Check Service Logs
```powershell
# Service logs stdout/stderr or traces to application event log / debug console
Get-WinEvent -ProviderName "Spemcs.Agent.Service" -MaxEvents 50 -ErrorAction SilentlyContinue
```

### Launch Endpoint UI (Interactive User Session)
```powershell
& "Endpoint-agent\src\Spemcs.Agent.UI\bin\Debug\net8.0-windows\Spemcs.Agent.UI.exe"
```

---

## 8. Exact Next Recommended Investigation

The next engineer should focus on **Issue E**: The intermittent pre-enforcement timeout in `ManagementConnectivityVerifier.cs`:

1. **Instrument `ManagementConnectivityVerifier.cs`:**
   - Log exact timestamps of DNS resolution, socket connect, TLS/plaintext negotiation, and HTTP response receiving.
   - Check if `SocketsHttpHandler` or `HttpClient` is using IPv6 (`[::1]`) by default when connecting to `127.0.0.1` or `localhost`, causing a 2-3 second TCP connect retry delay that hits the 3000ms timeout threshold.
2. **Review HTTP Client Lifecycles under SYSTEM:**
   - Verify whether `HttpClient` instantiated under `NT AUTHORITY\SYSTEM` encounters proxy discovery delays (`WinInet` / `WPAD` autodetect). Setting `UseProxy = false` in `HttpClientHandler` / `SocketsHttpHandler` is strongly recommended for local probes.
3. **Verify Loopback Firewall Filtering Under Active Block:**
   - Once pre-enforcement probes succeed consistently, verify whether the newly added IPv4 (`127.0.0.1`) and IPv6 (`::/127`) loopback allow rules permit traffic while `DefaultOutboundAction = Block`.
   - Use `netsh wfp show state` or Windows Filtering Platform (WFP) packet drop auditing (`auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable`) to determine if WFP drops outbound or inbound loopback connections.

---

## 9. Important Constraints

1. **Zero Secret Leaks:** Do not hardcode or commit keys, certificates, or tokens.
2. **Preserve User Firewall Rules:** Never run `netsh advfirewall reset` or delete rules not belonging to group `SPEMCS_EXAM_LOCKDOWN`.
3. **Fail-Closed Security:** In production, any loss of management connectivity must trigger rollback or exam freeze. Never disable `ManagementConnectivityVerifier` to make a test pass.
4. **Elevation Boundaries:** The UI process must NEVER attempt direct COM firewall manipulation. All firewall rules must be managed by the `NT AUTHORITY\SYSTEM` service.

---

## 10. What NOT to Change Unnecessarily

- **Do NOT bypass signature or version replay checks:** `PolicyReceiver` security must remain strict.
- **Do NOT revert the Named Pipe architecture:** The UI must communicate with the service via `spemcs-control-v1`.
- **Do NOT change IPv6 loopback back to `::1` or `::1/128`:** The Windows Firewall COM library explicitly rejects these and will throw `ArgumentException`. Keep `::/127`.
- **Do NOT assign `ServiceName` to `"none"` or `"*"`:** Windows Firewall COM expects empty/null for generic services. Keep the guard in `WindowsFirewallAdapter.cs`.
- **Do NOT remove `failurePhase` tracking in `NetworkEnforcer`:** It is required to prevent false external conflict alarms during partial-rule application failures.
