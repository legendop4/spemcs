# 01. Project Overview & Institutional Threat Model

---

## What Am I Looking At?

This document defines the real-world operational context, architectural mission, and institutional threat model that SPEMCS is built to solve. It details the vulnerabilities of higher-education computer examination environments, the limitations of commercial proctoring solutions, and the technical constraints under which SPEMCS operates.

---

## Why Does It Exist?

### The Institutional Exam Problem
University computer labs represent a uniquely hostile computing environment for examination integrity:
1. **Shared Physical Workstations**: A lab workstation is used by hundreds of students across diverse courses. It frequently contains pre-installed software, developer tools, compilers, virtualization platforms (VirtualBox, VMware), and network utilities.
2. **The "Ghost Solver" Threat**: Rather than bringing notes on paper, dishonest candidates leverage remote control daemons (AnyDesk, TeamViewer, Chrome Remote Desktop, UltraViewer) to allow offsite subject experts to view exam questions and solve them in real time.
3. **Encrypted DNS & Tunneling Bypasses**: Institutional firewalls that inspect hostnames fail completely against modern browsers that use **DNS over HTTPS (DoH)** or encapsulated tunnels (**6in4 / Protocol 41**), allowing candidates to communicate with private servers undetected.
4. **Flaws in Commercial Remote Proctoring**: Commercial proctoring tools (e.g., Proctorio, Honorlock) rely heavily on webcam analysis and periodic process polling. In a physical classroom or lab setting, webcam analysis creates immense false-positive noise, while 15-second polling intervals leave critical blind spots where ephemeral scripts can exfiltrate exam content.
5. **The Post-Exam Lab Outage**: When aggressive network tools crash or lose power, they frequently leave the operating system's firewall in a broken state. In a university with back-to-back classes, a single corrupted machine locks out the next class of students.

### SPEMCS High-Level Objectives
- **Zero Client-Side Privilege Leaks**: Run all security-critical operations in Windows **Session 0** under `NT AUTHORITY\SYSTEM` so that candidates cannot terminate the agent via Task Manager, debuggers, or standard scripts.
- **Fail-Closed Network Lockdown**: Enforce **Default Outbound BLOCK** across all firewall profiles; allow outbound connections *only* to the approved exam portal for the designated browser binary.
- **Sub-50ms Kernel Interception**: Use Windows Management Instrumentation (WMI) and Event Tracing for Windows (ETW) to intercept prohibited process creation instantly.
- **Guaranteed Idempotent Teardown**: Maintain a local SQLite rollback journal so that any restart, crash, or manual termination unconditionally returns the workstation to its exact pre-exam baseline.

---

## What Happens Internally?

### The SPEMCS Operational Paradigm
SPEMCS replaces reactive cheat detection with **deterministic environment confinement**:

```
[ Normal State ]
Workstation boots -> Services start -> Standard Windows networking -> All traffic allowed

         │  Admin triggers Exam Activation in Web Dashboard
         ▼
[ Hardening & Pre-Arming Phase ]
1. Backend compiles exam network policy (vendor IPs, domains, approved browser).
2. Backend signs policy with RSA-2048 / RSA-PSS (SHA-256).
3. Workstation fetches signed policy and verifies cryptographic signature.
4. Workstation records existing baseline firewall state in sqlite_rollback_journal.db.
5. Workstation registers HKLM registry policies to disable browser DoH.

         │  Candidate verifies student identity in WPF UI
         ▼
[ Lockdown & Enforcement Phase ]
1. Windows Firewall flips default outbound to BLOCK across Domain, Private, and Public.
2. Windows Firewall adds dynamic allow rules strictly scoped to approved browser path.
3. WMI / ETW listeners actively hook Win32_Process creation across all desktop sessions.
4. NetworkCollector polls socket table to cross-reference established TCP/UDP flows.
5. Violations trigger immediate telemetry push to backend via WebSocket / REST.

         │  Exam completes or Admin stops exam
         ▼
[ Teardown & Rollback Phase ]
1. Service reads sqlite_rollback_journal.db and purges all session-created rules.
2. Windows Firewall flips default outbound back to ALLOW.
3. Registry DoH policies are purged.
4. Post-exam audit report is generated and archived in PostgreSQL.
```

---

## Which Code Implements It?

### Technology Stack Matrix

| Layer / Role | Technology Selected | Version / Standard | Implementation Rationale | Source Code Location |
| :--- | :--- | :--- | :--- | :--- |
| **Endpoint Service** | .NET / C# | .NET 8 LTS | Native Windows Service host, COM Interop, WMI integration, low memory footprint. | [`Spemcs.Agent.Service`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Service/Program.cs) |
| **Firewall Engine** | Windows Firewall COM | `HNetCfg.FwPolicy2` | Direct operating system kernel firewall manipulation without third-party drivers. | [`WindowsFirewallAdapter.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/WindowsFirewallAdapter.cs) |
| **Rollback Storage** | SQLite | 3.x (Microsoft.Data.Sqlite) | Zero-configuration ACID-compliant local persistence for crash recovery. | [`SqliteRollbackJournal.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/SqliteRollbackJournal.cs) |
| **Interactive UI** | .NET WPF | .NET 8 WindowsDesktop | Rich native desktop interface for student verification and lock overlays. | [`Spemcs.Agent.UI`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.UI/App.xaml.cs) |
| **Backend Framework** | FastAPI (Python) | Python 3.11+ / FastAPI 0.110+ | High-performance asynchronous API, OpenAPI schema generation, strict Pydantic typing. | [`backend/backend/app/main.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/app/main.py) |
| **Policy Cryptography** | `cryptography` | RSA-2048, RSA-PSS | Deterministic cryptographic policy authenticity; eliminates MITM policy alteration. | [`signing_key_manager.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/signing_key_manager.py) |
| **Serialization** | Canonical JSON | RFC 8785 | Guarantees byte-identical JSON representation across Python and C# runtimes. | [`policy_signer.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/policy_signer.py) |
| **Database ORM** | SQLAlchemy / PostgreSQL | SQLAlchemy 2.0+ / PG 15+ | Reliable enterprise relational database with connection pooling and migrations. | [`database.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/app/database.py) |
| **Schema Migrations** | Alembic | 1.13+ | Version-controlled database schema evolution (`0001_baseline`, `0002_add_network_enforcement`). | [`backend/backend/migrations/`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/migrations/) |
| **Frontend Framework** | React / TypeScript | React 18 / Vite 5 / TS 5.5 | Modern typed single-page application with responsive TailwindCSS layout. | [`frontend/src/`](file:///c:/Users/shrma/Desktop/spemcsnew/frontend/src/) |
| **Realtime Channel** | WebSockets | RFC 6455 | Low-latency duplex communication for agent sync and dashboard live alerts. | [`realtime.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/websocket/realtime.py) |

---

## What Happens When It Fails?

### Core Fail-Safe Principles

1. **Failure during Policy Verification**:
   - If a delivered policy fails RSA-PSS signature verification or carries an unknown `key_id`, the agent **refuses to apply the policy** and never touches the firewall.
   - Evidence: [`PolicyReceiver.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/PolicyReceiver.cs#L140-L165).
   - Status: ✅ VERIFIED in [`PolicyDistributionTests.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/tests/Spemcs.Agent.Tests/PolicyDistributionTests.cs).
2. **Failure during Sudden Machine Reboot**:
   - If power is cut mid-exam, the Windows Service boots up on next power-on (Session 0) before any student logs in.
   - It reads `sqlite_rollback_journal.db`. If the server indicates the exam ended, it immediately deletes all rules with the `SPEMCS-` prefix and restores default outbound allow.
   - Evidence: [`SqliteRollbackJournal.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/SqliteRollbackJournal.cs#L85-L120).
   - Status: ✅ VERIFIED in [`RollbackScopeTests.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/tests/Spemcs.Agent.Tests/RollbackScopeTests.cs).
3. **Failure of Backend Connectivity**:
   - If the backend management server becomes unreachable mid-exam, active firewall lockdown **remains active locally** to prevent candidates from exploiting server downtime to access cheat materials. Telemetry events buffer in local memory.
   - Evidence: [`EventUploaderWorker.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/EventUploaderWorker.cs).
   - Status: ✅ VERIFIED in hermetic mock tests.
