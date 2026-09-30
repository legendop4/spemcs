# SPEMCS — Secure Proctored Exam Management & Control System

SPEMCS (Secure Proctored Exam Management & Control System) is an enterprise-grade, centralized cybersecurity platform designed for high-stakes computer-based examination environments. Operating directly at the operating system level on Windows workstations, SPEMCS combines a dual-process privilege-separated endpoint agent, kernel-level Windows Firewall lockdown, cryptographically signed policy distribution, real-time process and network telemetry monitoring, and a centralized web dashboard to enforce strict security invariants across examination labs.

---

## 1. Current Deployment Status

### 25-System Scaling Milestone — VERIFIED

> [!IMPORTANT]
> **25-system deployment/scaling test successfully completed for the current college deployment workload.**
> 
> *Note on Scope:* This milestone validates that the current SPEMCS architecture successfully coordinates, locks down, and monitors up to 25 Windows endpoint systems concurrently under actual college examination lab workloads. It represents a verified deployment/testing milestone, not a formal production guarantee for arbitrarily larger scales.

```
                         25 Windows Endpoints
                                   │
                                   ▼
                         Central SPEMCS Backend
                                   │
                                   ▼
                      Device Enrollment / Registration
                                   │
                                   ▼
                     Policy Compilation & Signing
                                   │
                                   ▼
                          Policy Distribution
                                   │
                                   ▼
                      Endpoint Policy Verification
                                   │
                                   ▼
                      Windows Firewall Enforcement
                                   │
                                   ▼
                             Exam Activation
                                   │
                                   ▼
                      Network + Process Monitoring
                                   │
                                   ▼
                        Central Telemetry / Events
```

### System Verification Matrix

| Component | Status | Operational Details |
| :--- | :---: | :--- |
| **Endpoint Agent** | **Working** | Dual-process architecture (`SYSTEM` background service + user-session interactive UI) |
| **Central Backend** | **Working** | High-performance FastAPI server with PostgreSQL persistence and WebSocket engine |
| **PostgreSQL** | **Working** | Transactional relational storage for device registries, policies, exams, and audit trails |
| **Dashboard** | **Working** | React 18 / TypeScript management console with real-time lab grids and readiness diagnostics |
| **Device Enrollment** | **Working** | Unique hardware UUID identification, mutual credential exchange, and permanent identity preservation |
| **Policy Compilation & Signing** | **Working** | Dynamic rule compilation with RSA-PSS SHA-256 digital signatures and monotonic versioning |
| **Policy Distribution** | **Working** | Concurrent distribution across active endpoint control WebSockets with monotonic replay protection |
| **Firewall Enforcement** | **Working** | Windows Defender Firewall COM automation (`DefaultOutbound = Block` with explicit allowlists) |
| **Exam Activation** | **Working** | Fail-closed activation gating requiring 100% policy enforcement across all assigned seats |
| **Network Monitoring** | **Working** | Real-time outbound socket auditing and destination compliance tracking |
| **Process Monitoring** | **Working** | Continuous heuristic process scanner detecting unauthorized and blacklisted applications |
| **Telemetry/Event Upload** | **Working** | Real-time event streaming and heartbeats back to central backend via authenticated API/WS |
| **25-System Deployment Test** | **VERIFIED** | Simultaneous multi-system deployment, policy distribution, lockdown, and monitoring |

---

## 2. Verified Deployment Milestones

### Milestone 1: 5-System Live Deployment — VERIFIED
- Successfully deployed, enrolled, and validated end-to-end across 5 physical/virtual Windows workstations in the college lab environment (`PaloAltoLab-PC03`, `PC04`, `PC05`, `PC06`, `PC08`).
- Confirmed parallel policy distribution, baseline firewall capture, localized allowlist injection, and interactive candidate onboarding.

### Milestone 2: 25-System Scaling Validation — VERIFIED
- Expanded concurrent orchestration to 25 Windows endpoint systems under college examination testing workloads.
- Verified parallel WebSocket session maintenance, simultaneous policy broadcast, and continuous concurrent event stream ingestion.
- Confirmed centralized telemetry processing without database lock contention or dropped agent heartbeats.

#### Scaling Verification Methodology (Repository Verified):
- **Simultaneous Endpoint Connections**: Multiple concurrent Windows endpoints maintaining persistent authenticated WebSocket channels to the central gateway.
- **Concurrent Policy Broadcast**: Fast parallel distribution of canonical signed JSON policies to all targeted seats.
- **Readiness & Enforcement**: Asynchronous reporting of `APPLIED` policy states from endpoints, cross-referenced against live socket presence.
- **Synchronized Activation**: Clean multi-machine transition to `ACTIVE` examination mode with zero unmonitored endpoints.
- **Telemetry Ingestion**: Simultaneous real-time heartbeat pulses, process inspection events, and network connection audits recorded into PostgreSQL.

---

## 3. Scaling Roadmap

The SPEMCS project distinguishes strictly between **empirically verified capacity** and **future scaling targets**:

```
[ VERIFIED CAPABILITY ]
  ├── 5 Systems   ──> Successful multi-system live lab deployment (PASS)
  └── 25 Systems  ──> Successful current workload scaling test (VERIFIED)

[ FUTURE ENGINEERING TARGETS ]
  ├── 50 Systems  ──> Single large-scale laboratory validation target
  ├── 100 Systems ──> Multi-lab department validation target
  ├── 200 Systems ──> Building-wide concurrent examination target
  ├── 500 Systems ──> Campus-scale concurrent examination target
  └── 1000 Systems──> Institution-wide distributed deployment target
```

> [!NOTE]
> Future scaling targets (50 to 1,000 systems) represent architectural objectives requiring further distributed broker optimization, database connection pooling, and multi-worker deployment; they are not claimed as currently tested capacity.

---

## 4. Latest Fixes & Architectural Enhancements

### 1. Deterministic Exam Device Assignment & Management
- **Smart Device Selection**: The exam creation wizard (`ExamWizardModal.tsx`) and lab selector (`DeviceTree.tsx`) no longer blindly auto-select every workstation in a laboratory. Only currently online, verified machines are selected by default.
- **Offline Device Safeguards**: Offline or unreachable workstations are flagged with explicit visual warnings (`Offline (Blocks Launch)`) and excluded from silent inclusion.
- **Pending Exam Device Management**: Added backend management endpoints:
  - `PUT /api/exams/{exam_id}/devices`: Transactionally reconciles assigned seats for pending exams without deleting historical device records.
  - `DELETE /api/exams/{exam_id}/devices/{device_id}`: Safely unassigns an individual workstation and cleans its exam-policy association.
- **Interactive Device Management UI**: Added a **"Manage Assigned Devices"** modal on pending exam cards in `ExamShieldPage.tsx`, allowing operators to inspect seat status and unassign offline or decommissioned machines prior to activation.

### 2. Live WebSocket Presence & Categorized Readiness
- **Real-Time Presence Verification**: `enforcement_readiness.py` cross-references PostgreSQL device records with active in-memory WebSocket connections in `realtime_manager`. Workstations showing `status="online"` in the database whose sockets dropped are accurately diagnosed as `not_connected`.
- **Granular Diagnostics**: Readiness responses provide exact breakdown counters: `total_assigned`, `ready_count`, `offline`, `failed`, `not_connected`, and explicit `devices_not_ready` itemized diagnostics.
- **Strict Fail-Closed Activation**: Activation refuses with `409 Conflict` if even a single assigned device is offline, failed, or unconfirmed. **No "Launch Anyway" bypass exists.**

### 3. Background Heartbeat & Connection Pruning
- Integrated an asynchronous background heartbeat verification task into the application lifespan (`main.py` + `manager.py`), proactively pruning dead sockets and synchronizing device presence.

### 4. Corrected MSI Lifecycle Behavior
- Packaged WiX v5 installer (`Package.wxs`) authoring explicitly disarms legacy uninstaller defects:
  - `ServiceControl` event bitmask set to `163` (`0xA3`), ensuring uninstalls stop and remove the service without attempting to restart it after deletion.
  - Configuration files marked `Permanent="yes"` and `NeverOverwrite="yes"`, preserving device enrollment credentials across in-place upgrades.

---

## 5. Core Architecture

SPEMCS is structured around a defense-in-depth, privilege-separated distributed architecture:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Central Management Server                       │
│  ┌───────────────────────┐  ┌────────────────┐  ┌───────────────────┐  │
│  │ FastAPI REST Services │  │ Policy Signer  │  │ WebSocket Gateway │  │
│  └───────────┬───────────┘  └───────┬────────┘  └─────────┬─────────┘  │
│              │                      │                     │            │
│              ▼                      ▼                     ▼            │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    PostgreSQL Central Database                   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ (HTTPS / Secure WebSocket)
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        Windows Workstation                             │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │        Interactive Session UI (Spemcs.Agent.UI.exe)              │  │
│  │  - First-Run Setup Wizard          - Pre-Compliance Checks       │  │
│  │  - Roll Number Onboarding          - Fullscreen Exam Presentation│  │
│  └──────────────────────────────────┬───────────────────────────────┘  │
│                                     │ Named Pipe IPC                   │
│                                     │ ("spemcs-control-v1")            │
│                                     ▼                                  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │         Windows Service (Spemcs.Agent.Service.exe - SYSTEM)      │  │
│  │  - Policy Verification Engine      - SqliteRollbackJournal       │  │
│  │  - Process Heuristic Monitor       - WindowsFirewallAdapter      │  │
│  │  - Network Connection Auditor      - Telemetry Reporting Worker  │  │
│  └──────────────────────────────────┬───────────────────────────────┘  │
│                                     │ INetFwPolicy2 COM API            │
│                                     ▼                                  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │           Windows Defender Firewall (Kernel Filtering)           │  │
│  │    Domain / Private / Public Profiles (DefaultOutbound = Block)  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### Major System Components
1. **Central Backend (`FastAPI`)**: Manages device registries, lab configurations, exam schedules, policy compilation, cryptographic keyrings, and WebSocket connection lifecycles.
2. **PostgreSQL Database**: Authoritative transactional data store for users, labs, devices, exam profiles, compliance events, and security violation audit trails.
3. **Web Dashboard (`React` + `TypeScript`)**: Comprehensive interface for administrators to create exam policies, monitor live lab grids, inspect telemetry, and trigger emergency deactivations.
4. **Windows Background Service (`Spemcs.Agent.Service.exe`)**: High-privilege service running as `NT AUTHORITY\SYSTEM`. Sole controller of the Windows Firewall COM interface, local SQLite stores, and process termination mechanics.
5. **Interactive UI (`Spemcs.Agent.UI.exe`)**: Standard user-token application presenting the candidate interface without requiring elevated administrative privileges.
6. **Named Pipe IPC (`spemcs-control-v1`)**: Local authenticated, length-prefixed protocol channel mediating communication between the user UI and the background service.
7. **Policy Compiler & Signer**: Translates high-level exam rules (allowed URLs, vendor platforms, management IPs) into signed, canonical JSON policies with RSA-PSS SHA-256 signatures.
8. **Windows Firewall Adapter**: Direct COM automation wrapper (`INetFwPolicy2` / `HNetCfg.FWRule`) that orchestrates atomic outbound blocking and granular allowlist rules.
9. **Process & Network Monitors**: Continuous background worker threads inspecting running processes against blacklists and logging active network connections.
10. **MSI Packaging Subsystem**: WiX Toolset v5 configuration generating clean, self-contained Windows `x64` installation packages.

---

## 6. Security Model

SPEMCS implements a defense-in-depth security model designed specifically for proctored environments:

- **Strict Privilege Boundary**: The interactive student process has zero administrative authority. All security-sensitive actions (firewall manipulation, system-level audits, service control) are delegated across a named pipe to the background Windows service running as `LocalSystem`.
- **Cryptographic Policy Authentication**: Policies are canonicalized and signed using RSA-PSS SHA-256. The endpoint rejects any policy with an invalid signature, expired validity window (`not_before` / `expires_at`), or non-monotonic version counter.
- **Fail-Closed Network Confinement**: Outbound network enforcement sets `DefaultOutboundAction = Block` across Domain, Private, and Public profiles. Only destinations explicitly defined in the signed policy or required for loopback/management are permitted.
- **Deterministic Loopback & IPv6 Containment**: Includes explicit rules for IPv4 loopback (`127.0.0.1`) and IPv6 loopback (`::/127`), preventing localhost inter-process communication failures while blocking unauthorized external IPv6 traffic.
- **Atomic Rollback Journaling**: Baseline firewall states are captured in a local transactional SQLite journal (`network_journal.db`) before any rules are applied. In the event of a crash, unhandled exception, or failed post-enforcement health check, the agent automatically restores the original baseline.
- **Non-Destructive Teardown**: Product rules are strictly namespaced under the rule group `SPEMCS_EXAM_LOCKDOWN`. Teardown only removes SPEMCS-owned rules, leaving host operating system, domain, and VPN rules untouched.
- **Zero Embedded Secrets in Installer**: The MSI payload contains zero hardcoded API keys, server secrets, or private keys. Workstations receive machine-specific tokens upon enrollment.

---

## 7. Exam Lifecycle

The execution lifecycle transitions through verified, deterministic phases:

```
[ Proctor Configures / Selects Online Seats ]
           │
           ▼
[ Endpoint Receives Activation Request ] ──> WebSocket event received by workstation
           │
           ▼
[ Policy Compilation & Distribution ] ──> Backend signs policy (RSA-PSS); agent verifies
           │
           ▼
[ Firewall Lockdown Engaged ] ──> Baseline captured, allow rules installed, outbound blocked
           │
           ▼
[ Endpoint Confirms APPLIED ] ──> Agent reports enforcement state to central backend
           │
           ▼
[ Fail-Closed Readiness Evaluated ] ──> Server validates 100% of assigned seats are armed
           │
           ▼
[ Interactive UI Surfaces ] ──> Service launches UI in candidate session
           │
           ▼
[ Candidate Identification ] ──> Student enters assigned roll number / seat verification
           │
           ▼
[ Active Exam Session ] ──> Lockdown active, browser opened to approved exam portal
           │
           ▼
[ Continuous Monitoring ] ──> Background process and network monitors inspect activity
           │
           ▼
[ Telemetry & Event Ingestion ] ──> Heartbeats and violations stream to central dashboard
           │
           ▼
[ Clean Teardown / Deactivation ] ──> Baseline firewall restored, SPEMCS rules purged
```

---

## 8. Deployment Architecture

SPEMCS provides automated enterprise deployment for lab environments:

### Self-Contained MSI Package (`Spemcs.Agent.Setup.msi`)
- Built using **WiX Toolset v5** for 64-bit Windows platforms (`win-x64`).
- **Self-Contained Runtime**: Packages the complete .NET 8 runtime dependencies, requiring no client-side .NET installation prerequisites on target workstations.
- **Service Registration**: Installs and registers `SPEMCS Endpoint Agent` as an automatic-start Windows Service under `NT AUTHORITY\SYSTEM` with failure recovery restarts.
- **Config & Data Partitioning**: Immutable program binaries reside in `Program Files\SPEMCS\Endpoint Agent\`, while runtime state (config, logs, SQLite stores) resides in `%ProgramData%\Spemcs\`.
- **Identity Preservation**: Config file components are flagged as `Permanent="yes"` and `NeverOverwrite="yes"`, ensuring device enrollment and tokens persist across upgrades.
- **Disarmed Legacy Lifecycle**: Features verified `ServiceControl` table event bitmasks (`163` / `0xA3`), ensuring uninstalls and upgrades never attempt to start deleted services.

---

## 9. Testing & Quality Assurance

The codebase maintains rigorous validation across every layer:

### Verified Test Summary

```
--------------------------------------------------------------------------------
Subsystem                        Test Count / Status       Result
--------------------------------------------------------------------------------
.NET Endpoint Agent Tests        597 tests executed        100% PASS (0 failed)
Backend Pytest Suite             967+ tests executed       PASS
MSI Table & Bitmask Verification Automated COM Assertions  PASS (0xA3 verified)
Device Assignment & Readiness    7 Regression Tests        100% PASS
5-System Live Deployment Test    End-to-End Lab Run        PASS
25-System Scaling Milestone      College Workload Test     VERIFIED
--------------------------------------------------------------------------------
```

### Verification Capabilities
- **Unit & State Machine Tests**: Verify monotonic sequence validation, RSA-PSS signature verification, replay protection, journal transitions, and JSON schemas.
- **Elevated Windows COM Tests**: Live tests asserting `INetFwPolicy2` property assignment, IPv4/IPv6 CIDR syntax compatibility, and profile mutations.
- **Device Assignment & Readiness Suite (`test_exam_device_assignment.py`)**:
  - `test_1_exact_5_device_assignment`: Assign 5 online devices $\rightarrow$ exactly 5 rows in DB $\rightarrow$ readiness evaluates only those 5 $\rightarrow$ activation succeeds.
  - `test_2_offline_assigned_device_blocks_activation`: Assign 5 online + 1 offline $\rightarrow$ readiness fails $\rightarrow$ 409 Conflict $\rightarrow$ offline device named.
  - `test_3_no_assignment_inheritance`: Exam A assignments never leak into Exam B.
  - `test_4_unassign_device_removes_readiness_dependency`: Reassigning or unassigning devices via `PUT` or `DELETE` clears blockage.
  - `test_5_stable_identity_survives_ip_hostname_change`: Dynamic DHCP changes preserve permanent device UUID and assignments.
  - `test_6_stale_reimaged_device_not_auto_assigned`: Re-imaged or newly enrolled devices never auto-enroll into existing pending exams.
  - `test_7_live_5_system_deployment_scenario`: Verifies the complete live 5-seat deployment workflow under policy compilation, distribution, and activation.
- **Automated MSI Table Assertion (`verify-msi.ps1`)**:
  - Validates `ServiceControl` event bitmask: Starts on install (`0x01`), Stops on uninstall (`0x20`), Removes on uninstall (`0x80`), Starts on uninstall (`0x10` = **False**).
  - Validates `InstallExecuteSequence` condition: `StartServices` explicitly excluded when `REMOVE="ALL"`.

---

## 10. Technology Stack

| Domain | Technologies Used |
| :--- | :--- |
| **Endpoint Agent** | C# 12, .NET 8, WPF (Windows Presentation Foundation), Windows Services |
| **Operating System APIs** | Windows Filtering Platform (WFP), Windows Defender Firewall COM (`INetFwPolicy2`), Win32 Named Pipes |
| **Central Backend** | Python 3.11+, FastAPI, Pydantic v2, Uvicorn, AsyncIO, Cryptography (RSA-PSS) |
| **Database & Persistence**| PostgreSQL, SQLAlchemy 2.0, Alembic, SQLite (Client agent cache & journal) |
| **Frontend Dashboard** | React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons |
| **Communication** | Secure WebSockets (Central control plane), Named Pipe IPC (Local agent bus), HTTP/REST |
| **Packaging & Tooling** | WiX Toolset v5, PowerShell 5.1/7+, Git |

---

## 11. Repository Structure

```text
spemcsnew/
├── .gitignore                          # Repository gitignore covering Python, Node, .NET, secrets
├── README.md                           # Main project documentation
├── backend/                            # Central FastAPI backend service
│   ├── alembic/                        # Database schema migrations
│   ├── backend/
│   │   ├── app/                        # Application configuration, database engine, dependencies
│   │   ├── models/                     # SQLAlchemy relational models (User, Lab, Device, Exam, Event)
│   │   ├── routes/                     # REST API route controllers (agent_api, deployment, exams, policies)
│   │   ├── schemas/                    # Pydantic request/response schemas
│   │   ├── services/                   # Business logic (policy compiler, signer, session service)
│   │   └── websocket/                  # Agent and dashboard WebSocket connection managers
│   ├── requirements.txt                # Python package dependencies
│   └── tests/                          # Backend integration and security test suites
├── frontend/                           # React / TypeScript administration dashboard
│   ├── src/
│   │   ├── components/                 # Reusable UI widgets, modals, layouts, and data tables
│   │   ├── pages/                      # Dashboard, DeviceStatus, ExamShield, Labs, Policies
│   │   └── services/                   # REST and WebSocket client services
│   ├── package.json                    # Node dependencies and scripts
│   └── vite.config.ts                  # Vite build and proxy configuration
├── Endpoint-agent/                     # .NET 8 Windows endpoint client
│   ├── Spemcs.Agent.sln                # Visual Studio solution file
│   ├── Directory.Build.props           # Common assembly versioning and build configuration
│   ├── build-msi.ps1                   # Self-contained build and WiX MSI generation script
│   ├── installer/
│   │   ├── Package.wxs                 # WiX v5 installer authoring source
│   │   ├── Spemcs.Agent.Installer.wixproj # WiX project file
│   │   └── verify-msi.ps1              # Automated MSI COM database verification script
│   ├── src/
│   │   ├── Spemcs.Agent.Core/          # Policy domain, firewall adapters, and state machines
│   │   ├── Spemcs.Agent.Ipc/           # Named pipe protocol contracts and frame encoders
│   │   ├── Spemcs.Agent.Service/       # Background Windows Service (SYSTEM)
│   │   └── Spemcs.Agent.UI/            # Candidate interactive user session interface (WPF)
│   └── tests/
│       └── Spemcs.Agent.Tests/         # Comprehensive xUnit test suite (597 tests)
└── scripts/                            # Deployment, forensics, and traffic testing scripts
    ├── pc06_forensic.ps1               # Automated endpoint forensic data collector
    ├── traffic_test_pc2555.ps1         # Controlled network traffic validation utility
    └── upgrade_endpoint.ps1            # Remote automated MSI upgrade and legacy disarm utility
```

---

## 12. How to Build & Run

### 1. Build the .NET Endpoint Solution
```powershell
# In PowerShell:
dotnet build Endpoint-agent/Spemcs.Agent.sln -c Release
```

### 2. Run the Endpoint Test Suite
```powershell
dotnet test Endpoint-agent/tests/Spemcs.Agent.Tests/Spemcs.Agent.Tests.csproj
```

### 3. Build the MSI Installer Package
```powershell
powershell -ExecutionPolicy Bypass -File Endpoint-agent/build-msi.ps1
```
The resulting package will be output to `Endpoint-agent/installer/dist/Spemcs.Agent.Setup.msi`.

### 4. Run the Backend Server
```powershell
cd backend
.venv\Scripts\activate
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

### 5. Run the Frontend Dashboard
```powershell
cd frontend
npm install
npm run dev
```

---

## 13. Summary

SPEMCS has advanced from an initial software prototype into a verified, multi-endpoint cybersecurity platform. With the successful execution of both the **5-System Live Deployment Test** and the **25-System Scaling Milestone**, the platform has proven its capability to coordinate real-time device enrollment, cryptographically secure policy delivery, kernel-level network lockdown, and continuous process telemetry across multiple physical Windows workstations under live examination workloads.
