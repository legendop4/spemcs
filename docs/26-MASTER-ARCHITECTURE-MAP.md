# 26. Master Architecture Map & Unified System Legend

---

## What Am I Looking At?

![Master System Overview](diagrams/01-system-overview.svg)

This document presents the **unified, panoramic architecture map** of the entire SPEMCS platform. It brings together every tier, process boundary, network socket, database table, cryptographic key, and IPC pipe into a single, cohesive visual representation.

---

## Why Does It Exist?

Individual subsystem diagrams show specific components in isolation. This master map allows an architect, developer, or security auditor to trace how a change in one tier (e.g. modifying an Alembic migration in PostgreSQL) ripples through the FastAPI dependency layer, out over WebSockets, across Windows Session boundaries, and into the Windows kernel packet filter.

---

## Unified System Architecture Map

```mermaid
graph TB
    %% TIERS DEFINITION
    subgraph TIER1 ["TIER 1: CANDIDATE LAB WORKSTATION (Windows 10/11 x64)"]
        subgraph S1 ["Interactive User Session (Session 1+)"]
            UI["Spemcs.Agent.UI (WPF .NET 8)<br/>App.xaml.cs | MainWindow.xaml<br/>Displays PIN & Status Overlay"]
            BROWSER["Approved Exam Browser<br/>chrome.exe / msedge.exe<br/>Restricted Path-Scoped Context"]
            CHEATER["Prohibited Process Attempts<br/>AnyDesk / Discord / VMs<br/>Neutralized by WMI & Firewall"]
        end

        subgraph S0 ["Privileged Service Enclave (Session 0: NT AUTHORITY\\SYSTEM)"]
            SVC["Spemcs.Agent.Service.exe<br/>Program.cs | AgentWorker.cs"]
            PIPE_SRV["ControlPipeWorker.cs<br/>Named Pipe Server (DACL)"]
            LAUNCHER["InteractiveSessionUiLauncher.cs<br/>CreateProcessAsUserW()"]
            WMI_MON["ConfigurableProcessClassifier.cs<br/>WMI / ETW Kernel Event Sinks"]
            POLICY_RCV["PolicyReceiver.cs<br/>RSA-PSS Signature Verifier"]
            STATE_MACH["EnforcementStateMachine.cs<br/>UNARMED -> ARMED -> ENFORCED"]
            FW_COM["WindowsFirewallAdapter.cs<br/>HNetCfg.FwPolicy2 COM Interop"]
            SQLITE_JRNL["SqliteRollbackJournal.cs<br/>%ProgramData%\\sqlite_rollback_journal.db"]
            CRED_STORE["DeviceCredentialStore.cs<br/>DPAPI Encrypted Store"]
        end

        UI <-->|IPC: \\\\.\\pipe\\spemcs-control-v1| PIPE_SRV
        LAUNCHER -.->|Cross-Session Spawn| UI
        WMI_MON -.->|Sub-50ms Detection| CHEATER
        SVC --> STATE_MACH
        STATE_MACH --> FW_COM
        STATE_MACH --> SQLITE_JRNL
        POLICY_RCV --> STATE_MACH
    end

    subgraph TIER2 ["TIER 2: MANAGEMENT CONTROL PLANE (FastAPI Python 3.11+)"]
        subgraph ROUTING ["API Gateway & Routers (86 Endpoints)"]
            R_AUTH["routes/auth.py (/api/auth)"]
            R_EXAMS["routes/exams.py (/api/exams)"]
            R_AGENT["routes/agent_api.py (/api/v1/*)"]
            R_POLICIES["routes/policies.py (/api/policies)"]
            R_ALERTS["routes/alerts.py (/api/alerts)"]
            R_EVENTS["routes/events.py (/api/events)"]
            R_REPORTS["routes/reports.py (/api/reports)"]
        end

        subgraph GATES ["Authentication & Authorization Gates (4 Trust Domains)"]
            G_STAFF["require_staff / require_admin<br/>Bearer JWT (HS256: SECRET_KEY)"]
            G_DEV["require_device / assert_device_owns<br/>HMAC Token (DEVICE_TOKEN_SECRET)"]
            G_BOOT["require_enrollment_key<br/>hmac.compare_digest(ENROLLMENT_BOOTSTRAP_KEY)"]
        end

        subgraph SERVICES ["Core Business Services"]
            S_READY["enforcement_readiness.py<br/>Fleet Pre-Arming Gate"]
            S_COMPILER["policy_compiler.py<br/>Vendor Domain Resolver"]
            S_SIGNER["policy_signer.py<br/>RSA-PSS Signer (RFC 8785)"]
            S_KEYMGR["signing_key_manager.py<br/>RSA-2048 Keyring Rotation"]
            S_EVENT["event_service.py<br/>Alert Ingestion & Triage"]
            S_REALTIME["realtime.py<br/>RealtimeManager WebSocket Hub"]
        end

        subgraph DB_TIER ["Persistence Tier (PostgreSQL 15+)"]
            PG_DB[("PostgreSQL Database<br/>14 Verified Relational Tables<br/>Alembic Migrations: 0001, 0002")]
        end

        R_AUTH --> G_STAFF
        R_EXAMS --> G_STAFF
        R_AGENT --> G_BOOT
        R_AGENT --> G_DEV
        R_EVENTS --> G_DEV
        
        R_EXAMS --> S_READY
        R_POLICIES --> S_COMPILER
        S_COMPILER --> S_SIGNER
        S_SIGNER --> S_KEYMGR
        R_EVENTS --> S_EVENT
        S_EVENT --> S_REALTIME
        
        SERVICES --> PG_DB
    end

    subgraph TIER3 ["TIER 3: OPERATOR COMMAND DASHBOARD (React 18 / Vite SPA)"]
        SPA_SHELL["AppShell.tsx (Layout & Navigation)"]
        SPA_CTX["AppContext.tsx (Global State Store)"]
        P_LOGIN["LoginPage.tsx (/login)"]
        P_SHIELD["ExamShieldPage.tsx (/exam-shield)"]
        P_MONITOR["LiveMonitorPage.tsx (/exam-shield/monitor/:id)"]
        P_ALERTS["AlertsPage.tsx (/alerts)"]
        P_REPORTS["ReportsPage.tsx (/reports)"]
        P_DEVICES["DeviceStatusPage.tsx (/devices)"]

        SPA_SHELL --> P_SHIELD
        SPA_SHELL --> P_MONITOR
        SPA_SHELL --> P_ALERTS
        SPA_SHELL --> P_REPORTS
        SPA_SHELL --> P_DEVICES
        SPA_CTX --> SPA_SHELL
    end

    %% INTER-TIER DATA CONNECTIONS
    CRED_STORE -->|X-Device-Token (HTTPS)| R_AGENT
    POLICY_RCV <--|GET /api/policies/distribute| R_POLICIES
    SVC <-->|WSS /api/v1/ws/agent| S_REALTIME
    FW_COM -->|Enforces Outbound Deny| BROWSER
    
    SPA_CTX -->|Bearer JWT (HTTPS)| ROUTING
    SPA_CTX <-->|WSS /api/v1/ws/dashboard| S_REALTIME
```

---

## Inter-Tier Link & Socket Dictionary

| Connection Link | Protocol & Transport | Source Endpoint | Destination Endpoint | Security Controls | Transmitted Payloads |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Candidate IPC** | Windows Named Pipe | `Spemcs.Agent.UI` (Session 1+) | `ControlPipeWorker` (Session 0) | Windows Pipe DACL (`InteractiveSessionUserSid`) | Student verification JSON, lock screen state. |
| **Agent Management**| HTTPS (Port 8002 / 443) | `Spemcs.Agent.Service` | Backend `/api/v1/*` | `X-Device-Token` (HMAC-SHA256) | Heartbeats, event telemetry, policy distribution. |
| **Agent Realtime** | WSS (WebSocket) | `Spemcs.Agent.Service` | Backend `/api/v1/ws/agent` | Device Token Handshake | Heartbeat pings, live command frames. |
| **Operator Admin** | HTTPS (Port 8002 / 443) | Operator Browser SPA | Backend `/api/*` | `Authorization: Bearer <jwt>` (HS256) | CRUD mutations, exam activation, alert triage. |
| **Dashboard Stream**| WSS (WebSocket) | Operator Browser SPA | Backend `/api/v1/ws/dashboard`| First-Frame `AUTHENTICATE` Handshake | Real-time `ALERT_CREATED` and `DEVICE_UPDATE` frames. |
| **Database Pool** | PostgreSQL TCP 5432 | FastAPI Backend | PostgreSQL Host | TLS Encryption (`sslmode=require`) | SQLAlchemy ORM queries, Alembic migrations. |
| **Firewall Control**| Native COM Interop | `WindowsFirewallAdapter` | Windows Kernel (WFP) | `NT AUTHORITY\SYSTEM` Token | `NET_FW_ACTION_BLOCK`, browser-scoped allow rules. |
