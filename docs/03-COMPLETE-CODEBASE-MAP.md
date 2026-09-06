# 03. Complete Codebase Map & Source Catalog

---

## What Am I Looking At?

This document is the **definitive file-by-file encyclopedia** of the entire SPEMCS repository. Every directory, entry point, service class, router module, database model, and test suite is cataloged with its exact file path, primary exported symbols, dependency relationships, and architectural purpose.

---

## Why Does It Exist?

Navigating a polyglot multi-tier repository (.NET 8 C#, FastAPI Python, React 18 TypeScript, COM Interop, SQLite, PostgreSQL) is challenging without an authoritative map. This catalog eliminates ambiguity by answering:
- Where is a feature implemented?
- Which module calls it?
- What database tables or OS APIs does it touch?
- What are its failure modes?

---

## Complete Repository Directory Tree

```
spemcs/
├── Endpoint-agent/                      # C# .NET 8 Endpoint Agent Solution
│   ├── deployment/                      # Service installation scripts
│   ├── installer/                       # WiX installer project files
│   ├── scripts/                         # PowerShell administration & service tools
│   │   ├── install_service.ps1          # Registers Windows Service (sc.exe)
│   │   ├── uninstall_service.ps1        # Purges service & wipes local rules
│   │   └── verify_firewall.ps1          # Diagnostic script testing COM adapter
│   ├── src/
│   │   ├── Spemcs.Agent.Core/           # Platform-independent core business logic
│   │   │   ├── Network/                 # Firewall adapter, rollback journal, policy receiver
│   │   │   │   ├── BrowserExecutableResolver.cs # Resolves chrome.exe / msedge.exe paths
│   │   │   │   ├── CommandReplayFilter.cs       # Replay attack protection filter
│   │   │   │   ├── EnforcementModels.cs         # Data models for network lockdown
│   │   │   │   ├── EnforcementStateMachine.cs   # State machine (UNARMED -> ARMED -> ENFORCED)
│   │   │   │   ├── FirewallAddressSpec.cs       # IPv4 / IPv6 subnet & range parser
│   │   │   │   ├── IFirewallAdapter.cs          # Abstraction for Windows Firewall COM
│   │   │   │   ├── IManagementConnectivityVerifier.cs # Health-check probe contract
│   │   │   │   ├── INetworkEnforcer.cs          # Contract for policy enforcement
│   │   │   │   ├── IRollbackJournal.cs          # Contract for rollback persistence
│   │   │   │   ├── ITrustedKeyStore.cs          # RSA public keyring cache contract
│   │   │   │   ├── NetworkEnforcer.cs           # Coordinates firewall rules & state
│   │   │   │   ├── PolicyDestinationValidator.cs # Validates allowed CIDRs & IPs
│   │   │   │   ├── PolicyDistributionModels.cs  # DTOs for policy distribution
│   │   │   │   ├── PolicyReceiver.cs            # Verifies RSA-PSS policy signatures
│   │   │   │   ├── SqliteRollbackJournal.cs     # ACID rollback journal in SQLite
│   │   │   │   └── WindowsFirewallAdapter.cs    # Native COM adapter (HNetCfg.FwPolicy2)
│   │   │   ├── ApprovedBrowserContext.cs        # Process tracking for approved browsers
│   │   │   ├── DnsCorrelationTracker.cs         # Correlates DNS requests with IP sockets
│   │   │   ├── Domain.cs                        # Core domain models (Device, Exam, Session)
│   │   │   ├── EtwDnsListener.cs                # Event Tracing for Windows DNS listener
│   │   │   ├── EventUploaderWorker.cs           # Asynchronous queue for HTTP telemetry
│   │   │   ├── Monitoring.cs                    # Metrics & system performance counters
│   │   │   ├── NetworkCollector.cs              # Polls active TCP/UDP socket table
│   │   │   ├── NetworkPolicyEvaluator.cs        # Evaluates process vs policy rules
│   │   │   ├── ProcessServices.cs               # WMI __InstanceCreationEvent watcher
│   │   │   └── SqliteAgentStore.cs              # General agent local database storage
│   │   ├── Spemcs.Agent.Ipc/            # Named Pipe IPC library
│   │   │   ├── NamedPipeClient.cs       # Interactive UI pipe client
│   │   │   ├── NamedPipeServer.cs       # Privileged Session 0 pipe server
│   │   │   └── PipeMessages.cs          # Serialization contracts for IPC messages
│   │   ├── Spemcs.Agent.Service/        # Privileged Windows Background Service
│   │   │   ├── AgentWorker.cs           # Primary background orchestration loop
│   │   │   ├── BackendAdapters.cs       # HTTP client connecting to FastAPI backend
│   │   │   ├── ControlPipeWorker.cs     # Handles IPC messages from user UI
│   │   │   ├── DeviceCredentialStore.cs # Secure storage for HMAC device tokens
│   │   │   ├── FileLogging.cs           # Rolling file logging to %ProgramData%\Spemcs
│   │   │   ├── InteractiveSessionUiLauncher.cs # Spawns UI into active desktop (Session 1+)
│   │   │   ├── NamedPipeUiGateway.cs    # Gateway routing IPC events
│   │   │   ├── ProcessAuditLogger.cs    # Local audit event logger
│   │   │   └── Program.cs               # Windows Service entry point (Host.CreateDefaultBuilder)
│   │   └── Spemcs.Agent.UI/             # Interactive Candidate Desktop Application
│   │       ├── App.xaml / App.xaml.cs   # WPF Application entry point
│   │       ├── MainWindow.xaml / .cs    # Verification dialog, status indicators, lock UI
│   │       └── ViewModels/              # MVVM presentation logic
│   └── tests/
│       ├── Spemcs.Agent.Tests/          # 289 verified unit & integration test methods
│       └── parity/                      # Cross-language Python <-> C# differential suite
├── backend/                             # Python 3.11+ FastAPI Management Server
│   ├── alembic.ini                      # Alembic migration configuration
│   ├── requirements.txt                 # Pinned Python package dependencies
│   ├── start-dev.ps1                    # Local development runner script
│   └── backend/
│       ├── app/                         # Core framework infrastructure
│       │   ├── config.py                # Pydantic Settings & production secret validator
│       │   ├── database.py              # SQLAlchemy engine & session factory
│       │   ├── dependencies.py          # 4 trust domain authentication gates
│       │   ├── identifiers.py           # Hardware UUID & ID generators
│       │   ├── main.py                  # FastAPI lifespan setup & router registration
│       │   ├── schema_check.py          # Startup DB schema verification
│       │   └── sqlite_compat.py         # SQLite test compatibility layer
│       ├── migrations/                  # Alembic database migration scripts
│       │   └── versions/
│       │       ├── 0001_baseline.py     # Initial database schema
│       │       └── 0002_add_network_enforcement.py # Network policy & readiness tables
│       ├── models/                      # SQLAlchemy ORM models (14 Tables)
│       │   ├── base.py                  # DeclarativeBase definition
│       │   ├── alert.py                 # Alert model (alerts.exam_id is nullable)
│       │   ├── audit_log.py             # Audit log model
│       │   ├── device.py                # Device model (hardware_uuid bound)
│       │   ├── device_policy_state.py   # Per-device policy installation state
│       │   ├── event.py                 # Process & network telemetry events
│       │   ├── exam.py                  # Exam entity & status enum
│       │   ├── exam_device.py           # Exam to device mapping
│       │   ├── exam_session.py          # Student roll number exam sessions
│       │   ├── lab.py                   # Computer labs
│       │   ├── lab_device.py            # Lab to device mapping
│       │   ├── network_policy.py        # Compiled & RSA-signed policies
│       │   ├── report.py                # Post-exam audit reports
│       │   ├── user.py                  # Operator users (admin, proctor)
│       │   └── vendor_profile.py        # Exam vendor domains & CIDRs
│       ├── routes/                      # API Route Handlers (84 HTTP + 2 WS)
│       │   ├── agent_api.py             # /api/v1/devices/register, /events, /sessions
│       │   ├── alerts.py                # /api/alerts (list, triage, resolve)
│       │   ├── audit_logs.py            # /api/audit-logs
│       │   ├── auth.py                  # /api/auth (operator login & token issue)
│       │   ├── dashboard.py             # /api/dashboard (aggregated statistics)
│       │   ├── deployment.py            # /deployment/push
│       │   ├── devices.py               # /api/devices (CRUD & heartbeats)
│       │   ├── events.py                # /api/events
│       │   ├── exam_devices.py          # /api/exam-devices
│       │   ├── exams.py                 # /api/exams (CRUD, activate, deactivate)
│       │   ├── health.py                # /health, /api/health
│       │   ├── labs.py                  # /api/labs
│       │   ├── policies.py              # /api/policies (compile, distribute, rotate)
│       │   ├── reports.py               # /api/reports (generate, CSV export)
│       │   └── sessions.py              # /api/sessions
│       ├── schemas/                     # Pydantic request/response schemas
│       ├── services/                    # Core business logic services
│       │   ├── auth_service.py          # JWT & HMAC token creation/verification
│       │   ├── enforcement_readiness.py # Pre-activation policy & device arming gate
│       │   ├── event_service.py         # Event ingestion & alert generation
│       │   ├── exam_service.py          # Exam state management & lifecycle
│       │   ├── policy_compiler.py       # Compiles vendor rules into policy JSON
│       │   ├── policy_signer.py         # Signs canonical JSON via RSA-PSS
│       │   └── signing_key_manager.py   # Manages RSA keyring, rotation & revocation
│       ├── tests/                       # 903 collected hermetic tests
│       └── websocket/                   # Real-time communications
│           └── realtime.py              # RealtimeManager (/ws/agent, /ws/dashboard)
└── frontend/                            # React 18 / Vite / TypeScript Dashboard SPA
    ├── src/
    │   ├── components/
    │   │   ├── layout/                  # AppShell.tsx, Sidebar.tsx, Header.tsx
    │   │   └── ui/                      # Modal, Badge, Button, ToastContainer
    │   ├── context/
    │   │   └── AppContext.tsx           # Global state, auth state, WS lifecycle
    │   ├── pages/                       # 9 Primary UI Views
    │   │   ├── LoginPage.tsx            # Operator login screen
    │   │   ├── DashboardPage.tsx        # Central management overview
    │   │   ├── ExamShieldPage.tsx       # Exam lockdown controls & readiness
    │   │   ├── LiveMonitorPage.tsx      # Real-time workstation grid & alert pulse
    │   │   ├── DeviceStatusPage.tsx     # Device fleet health & lab layout
    │   │   ├── AlertsPage.tsx           # Alert triage & proctor resolution
    │   │   ├── ReportsPage.tsx          # Exam integrity report generation
    │   │   ├── AuditLogsPage.tsx        # Immutable administrative audit log
    │   │   └── SettingsPage.tsx         # Keyring status & system configuration
    │   ├── services/                    # Frontend HTTP API client modules
    │   ├── App.tsx                      # React Router route definitions
    │   └── main.tsx                     # React DOM entry point
    └── vite.config.ts                   # Vite build & proxy configuration
```

---

## Detailed Catalog of Critical Subsystem Modules

### 1. Endpoint Agent Service Layer
- [`Spemcs.Agent.Service/Program.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Service/Program.cs):
  - **Purpose**: Service entry point; configures Microsoft.Extensions.Hosting dependency injection container.
  - **Key Symbol**: `Main(string[] args)`.
  - **Dependencies**: `AgentWorker`, `ControlPipeWorker`, `WindowsFirewallAdapter`, `SqliteRollbackJournal`.
  - **Failure Handling**: Catches startup exceptions and writes fatal logs to `%ProgramData%\Spemcs\Logs`.
- [`WindowsFirewallAdapter.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/WindowsFirewallAdapter.cs):
  - **Purpose**: Native Windows Firewall engine manipulation via COM Interop.
  - **Key Symbols**: `ApplyDefaultOutboundAction(NET_FW_ACTION_BLOCK)`, `CreateBrowserAllowRule()`, `RemoveRule()`.
  - **Evidence**: Interacts with COM ProgID `HNetCfg.FwPolicy2` across profiles 1, 2, and 4 (`All = 7`).
  - **Failure Handling**: Translates `COMException` into domain-specific `FirewallAdapterException`.
- [`SqliteRollbackJournal.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/SqliteRollbackJournal.cs):
  - **Purpose**: Transactional persistence for all applied firewall rules.
  - **Key Symbols**: `RecordRuleAddition()`, `ReconcileStartupState()`, `RollbackSession()`.
  - **Evidence**: Connects to `Data Source=C:\ProgramData\Spemcs\sqlite_rollback_journal.db`.
  - **Failure Handling**: Retries SQLite locked exceptions with WAL mode concurrency.

### 2. Backend Management Layer
- [`backend/app/main.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/app/main.py):
  - **Purpose**: FastAPI application factory and lifespan manager.
  - **Key Symbol**: `lifespan(app: FastAPI)`.
  - **Execution Path**: `validate_production_secrets()` $\rightarrow$ `verify_schema_revision()` $\rightarrow$ `ensure_demo_admin()` $\rightarrow$ warm up signing keyring.
  - **Failure Handling**: Halts application boot with `RuntimeError` if production secrets are invalid or database schema is outdated.
- [`backend/app/dependencies.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/app/dependencies.py):
  - **Purpose**: Implements the 4 distinct cryptographic trust domains.
  - **Key Symbols**: `require_authenticated`, `require_staff`, `require_admin`, `require_device`, `require_enrollment_key`, `assert_device_owns`.
  - **Evidence**: Uses `hmac.compare_digest` for timing attack resistance on bootstrap keys.
  - **Failure Handling**: Raises standard HTTP 401 Unauthorized or HTTP 403 Forbidden.
- [`backend/services/policy_signer.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/policy_signer.py):
  - **Purpose**: Compiles policies into canonical JSON (RFC 8785) and applies RSA-PSS signatures.
  - **Key Symbol**: `sign_policy_payload(raw_json: bytes, private_key)`.
  - **Evidence**: SHA-256 digest, MGF1 padding, salt length 32.
  - **Failure Handling**: Raises `CryptographicException` if key ID or private key is missing.

### 3. Frontend Dashboard Layer
- [`frontend/src/App.tsx`](file:///c:/Users/shrma/Desktop/spemcsnew/frontend/src/App.tsx):
  - **Purpose**: Route navigation and authentication protection.
  - **Key Symbols**: `AppRoutes()`, `ProtectedRoute()`, `PublicRoute()`.
  - **Evidence**: Maps the 9 verified views (`/login`, `/dashboard`, `/exam-shield`, `/exam-shield/monitor/:id`, `/devices`, `/alerts`, `/reports`, `/audit-logs`, `/settings`).
- [`frontend/src/context/AppContext.tsx`](file:///c:/Users/shrma/Desktop/spemcsnew/frontend/src/context/AppContext.tsx):
  - **Purpose**: Global application context managing operator authentication and real-time WebSockets.
  - **Key Symbols**: `login()`, `logout()`, `connectWebSocket()`, `useApp()`.
  - **Evidence**: Manages JWT token storage in `localStorage`, automated reconnect backoff on WS disconnect, and first-frame `AUTHENTICATE` message dispatch.
