# SPEMCS — Secure Proctored Exam Management & Control System

SPEMCS (Secure Proctored Exam Management & Control System) is an enterprise-grade, centralized cybersecurity platform designed for high-stakes computer-based examination environments. Operating directly at the operating system level on Windows workstations, SPEMCS combines a dual-process privilege-separated endpoint agent, kernel-level Windows Firewall lockdown, cryptographically signed policy distribution, real-time process and network telemetry monitoring, and a centralized web dashboard to enforce strict security invariants across examination labs.

---

## 1. Current Project Status

| Subsystem / Capability | Current Status | Description |
| :--- | :---: | :--- |
| **Core Platform** | **Working** | Centralized orchestration, policy compiler, session management, and telemetry ingestion |
| **Windows Endpoint Agent** | **Working** | Dual-process architecture (`SYSTEM` background service + user-session interactive UI) |
| **Central Backend** | **Working** | High-performance FastAPI server with PostgreSQL persistence and WebSocket engine |
| **Web Dashboard** | **Working** | React / TypeScript management console for proctors, lab managers, and administrators |
| **Policy Distribution** | **Working** | RSA-PSS signed canonical JSON policies with monotonic version and expiration validation |
| **Firewall Enforcement** | **Working** | WFP / Windows Defender Firewall COM automation (`Block` default with explicit allowlists) |
| **Process Monitoring** | **Working** | Continuous heuristic process scanner detecting unauthorized and blacklisted applications |
| **Network Monitoring** | **Working** | Active outbound connection auditing and destination compliance tracking |
| **Exam Activation Workflow**| **Working** | Automated lifecycle from proctor activation to endpoint lockdown and student onboarding |
| **5-System Live Deployment**| **PASS** | Successfully deployed, enrolled, and validated end-to-end across 5 Windows lab machines |

---

## 2. Verified Deployment Milestone

### 5-System Live Deployment — VERIFIED

SPEMCS has officially achieved and verified end-to-end multi-endpoint operation across **5 separate physical/virtual Windows workstations** operating simultaneously within the target network environment.

```
       Administrator / Proctor
                  │ (Web Dashboard)
                  ▼
       Central SPEMCS Backend
                  │
                  ▼
     Policy Compilation & Signing (RSA-PSS)
                  │
                  ▼
        Endpoint Distribution (WebSocket)
                  │
                  ▼
        Windows Endpoint Agent (Service)
                  │
                  ▼
     Firewall Enforcement (Kernel / COM)
                  │
                  ▼
     Exam UI / Student Session (Interactive)
                  │
                  ▼
     Network + Process Monitoring (Telemetry)
                  │
                  ▼
           Telemetry / Events (HTTP/WS)
                  │
                  ▼
        Central Dashboard (Real-Time View)
```

#### What Was Verified Across the 5 Systems:
- **Workstation Enrollment & Connectivity**: All 5 Windows systems successfully established authenticated WebSocket control sessions with the central backend.
- **Automated Policy Compilation & Distribution**: Proctors activated an examination; the backend compiled exam policies, signed them using RSA-PSS SHA-256 keys, and distributed them to all 5 endpoints in parallel.
- **Fail-Closed Firewall Enforcement**: Each endpoint service captured baseline profile states, recorded them in local SQLite journals, installed granular allow rules, and enforced `DefaultOutboundAction = Block`.
- **Interactive UI Launch**: The background service identified interactive user sessions and launched the exam interface displaying pre-compliance hardware, display, and network checks.
- **Roll Number Verification & Session Activation**: Students entered their assigned roll numbers, and active exam sessions were established.
- **Concurrent Monitoring**: Process and network monitoring engines ran concurrently, successfully inspecting running tasks and reporting telemetry.
- **Centralized Event Ingestion**: Live telemetry, heartbeat pulses, and security events from all 5 systems streamed back to the central server and updated the live proctor dashboard.

> [!NOTE]
> This milestone proves that SPEMCS has graduated beyond isolated single-machine development prototypes into a proven multi-endpoint security platform operating over a real physical network.

---

## 3. Core Architecture

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

## 4. Security Model

SPEMCS implements a defense-in-depth security model designed specifically for proctored environments:

- **Strict Privilege Boundary**: The interactive student process has zero administrative authority. All security-sensitive actions (firewall manipulation, system-level audits, service control) are delegated across a named pipe to the background Windows service running as `LocalSystem`.
- **Cryptographic Policy Authentication**: Policies are canonicalized and signed using RSA-PSS SHA-256. The endpoint rejects any policy with an invalid signature, expired validity window (`not_before` / `expires_at`), or non-monotonic version counter.
- **Fail-Closed Network Confinement**: Outbound network enforcement sets `DefaultOutboundAction = Block` across Domain, Private, and Public profiles. Only destinations explicitly defined in the signed policy or required for loopback/management are permitted.
- **Deterministic Loopback & IPv6 Containment**: Includes explicit rules for IPv4 loopback (`127.0.0.1`) and IPv6 loopback (`::/127`), preventing localhost inter-process communication failures while blocking unauthorized external IPv6 traffic.
- **Atomic Rollback Journaling**: Baseline firewall states are captured in a local transactional SQLite journal (`network_journal.db`) before any rules are applied. In the event of a crash, unhandled exception, or failed post-enforcement health check, the agent automatically restores the original baseline.
- **Non-Destructive Teardown**: Product rules are strictly namespaced under the rule group `SPEMCS_EXAM_LOCKDOWN`. Teardown only removes SPEMCS-owned rules, leaving host operating system, domain, and VPN rules untouched.
- **Zero Embedded Secrets in Installer**: The MSI payload contains zero hardcoded API keys, server secrets, or private keys. Workstations receive machine-specific tokens upon enrollment.

---

## 5. Exam Lifecycle

The execution lifecycle transitions through verified, deterministic phases:

```
[ Proctor Activates Exam ]
           │
           ▼
[ Endpoint Receives Activation ] ──> WebSocket event received by workstation
           │
           ▼
[ Policy Compilation & Distribution ] ──> Backend signs policy; agent verifies RSA signature
           │
           ▼
[ Firewall Lockdown Engaged ] ──> Baseline captured, allow rules installed, outbound blocked
           │
           ▼
[ Interactive UI Surfaces ] ──> Service launches UI in candidate session
           │
           ▼
[ Pre-Compliance Readiness ] ──> Workstation passes display, network, and process checks
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

## 6. Deployment Architecture

SPEMCS provides automated enterprise deployment for lab environments:

### Self-Contained MSI Package (`Spemcs.Agent.Setup.msi`)
- Built using **WiX Toolset v5** for 64-bit Windows platforms (`win-x64`).
- **Self-Contained Runtime**: Packages the complete .NET 8 runtime dependencies, requiring no client-side .NET installation prerequisites on target workstations.
- **Service Registration**: Installs and registers `SPEMCS Endpoint Agent` as an automatic-start Windows Service under `NT AUTHORITY\SYSTEM` with failure recovery restarts.
- **Config & Data Partitioning**: Immutable program binaries reside in `Program Files\SPEMCS\Endpoint Agent\`, while runtime state (config, logs, SQLite stores) resides in `%ProgramData%\Spemcs\`.
- **Identity Preservation**: Config file components are flagged as `Permanent="yes"` and `NeverOverwrite="yes"`, ensuring device enrollment and tokens persist across upgrades.
- **Disarmed Legacy Lifecycle**: Features verified `ServiceControl` table event bitmasks (`163` / `0xA3`), ensuring uninstalls and upgrades never attempt to start deleted services.

---

## 7. Testing & Quality Assurance

The codebase maintains rigorous validation across every layer:

### Verified Test Summary

```
--------------------------------------------------------------------------------
Subsystem                        Test Count / Status       Result
--------------------------------------------------------------------------------
.NET Endpoint Agent Tests        597 tests executed        100% PASS (0 failed)
Backend Pytest Suite             960+ tests executed       PASS
MSI Table & Bitmask Verification Automated COM Assertions  PASS (0xA3 verified)
5-System Live Deployment Test    End-to-End Lab Run        PASS
--------------------------------------------------------------------------------
```

### Verification Capabilities
- **Unit & State Machine Tests**: Verify monotonic sequence validation, RSA-PSS signature verification, replay protection, journal transitions, and JSON schemas.
- **Elevated Windows COM Tests**: Live tests asserting `INetFwPolicy2` property assignment, IPv4/IPv6 CIDR syntax compatibility, and profile mutations.
- **Automated MSI Table Assertion (`verify-msi.ps1`)**:
  - Validates `ServiceControl` event bitmask: Starts on install (`0x01`), Stops on uninstall (`0x20`), Removes on uninstall (`0x80`), Starts on uninstall (`0x10` = **False**).
  - Validates `InstallExecuteSequence` condition: `StartServices` explicitly excluded when `REMOVE="ALL"`.
  - Verifies presence of all 530+ packaged self-contained runtime binaries and native platform libraries.

---

## 8. Project Milestones

### Completed Milestones
- [x] **M0–M2**: Core project setup, database schema design, and baseline API definitions.
- [x] **M3–M4**: Authentication, role-based access control, and lab workstation registry.
- [x] **M5–M6**: Real-time WebSocket connection manager and agent telemetry ingestion pipeline.
- [x] **M7–M8**: Process classification engine, heuristics monitor, and candidate onboarding UI.
- [x] **M9**: Adversarial red-team hardening, replay attack mitigation, and token security.
- [x] **Network Lockdown Subsystem**: COM-based Windows Defender Firewall integration, RSA-PSS signed policy distribution, and atomic rollback journals.
- [x] **Self-Contained MSI Packaging**: WiX v5 packaging, automated payload assertions, and permanent configuration preservation.
- [x] **5-System Live Deployment Test**: Successful simultaneous deployment, policy distribution, lockdown, and monitoring across 5 Windows workstations (**PASS**).

### Planned Future Scaling Targets
> [!NOTE]
> The following represent planned capacity scaling milestones and engineering targets. They are distinct from the verified 5-system deployment milestone:
- **Phase 1 Target**: 30 concurrent systems (Single laboratory validation)
- **Phase 2 Target**: 100 concurrent systems (Multi-lab department validation)
- **Phase 3 Target**: 200 concurrent systems (Building-wide concurrent examination)
- **Phase 4 Target**: 500 concurrent systems (Campus-scale concurrent examination)
- **Phase 5 Target**: 1,000 concurrent systems (Institution-wide distributed deployment)

---

## 9. Technology Stack

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

## 10. Repository Structure

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

## 11. How to Build & Run

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

## 12. Current Limitations & Next Steps

- **Enterprise Scaling**: Concurrency validation has been verified across 5 live systems; testing across 30+ simultaneous lab workstations constitutes the immediate next testing phase.
- **Automated Workstation Provisioning**: Remote mass-deployment currently leverages PowerShell orchestration; integrating with Active Directory Group Policy (GPO) or Microsoft Intune remains a roadmap enhancement.
- **Platform Scope**: Current endpoint lockdown specifically targets Windows 10 and Windows 11 64-bit platforms utilizing Windows Defender Firewall. Cross-platform Linux/macOS proctoring is out of scope for the current architecture.

---

## 13. Summary

SPEMCS has advanced from an initial software prototype into an operational, multi-endpoint cybersecurity platform. With the successful execution of the **5-System Live Deployment Test**, the platform has proven its capability to coordinate real-time device enrollment, cryptographically secure policy delivery, kernel-level network lockdown, and continuous process telemetry across multiple physical Windows workstations in an active examination environment.
