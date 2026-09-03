# SPEMCS — Secure Proctoring & Endpoint Monitoring Control System

---

## Table of Contents

1. [What is SPEMCS?](#1-what-is-spemcs)
2. [System Components](#2-system-components)
3. [Overall Workflow](#3-overall-workflow)
4. [Component: Backend (FastAPI)](#4-component-backend-fastapi)
5. [Component: Frontend (React)](#5-component-frontend-react)
6. [Component: Endpoint Agent (.NET)](#6-component-endpoint-agent-net)
7. [Component: Database (PostgreSQL)](#7-component-database-postgresql)
8. [Testing](#8-testing)
9. [Deployment](#9-deployment)

---

## 1. What is SPEMCS?

**SPEMCS** (Secure Proctoring & Endpoint Monitoring Control System) — branded **CampusShield** — is a campus-wide exam proctoring and endpoint security system built for educational institutions.

### The Problem

During proctored online exams conducted on campus lab PCs, students may attempt to:
- Open unauthorized applications (Discord, TeamViewer, AnyDesk)
- Switch away from the exam browser
- Use screen-sharing tools to leak questions
- Use secondary browsers to search for answers

Traditional browser-based proctoring tools only monitor *inside* the browser. They cannot see what other processes are running on the operating system.

### The Solution

SPEMCS operates at the **operating system level**. A lightweight agent runs as a Windows Service on each lab PC. During an exam, it:
1. Scans all running processes
2. Classifies each as **Allowed** or **Suspicious** using a configurable rule engine
3. Blocks or flags unauthorized applications in real-time
4. Reports violations to a central backend via HTTP APIs
5. Administrators see live alerts on a real-time dashboard via WebSocket

### Objective

Build a centralized control system where:
- **Admins** create exams, assign lab PCs, activate monitoring, and observe live violations from a single dashboard.
- **Agents** (on each PC) enforce exam policies, detect violations, and report them instantly.
- **The Backend** orchestrates the lifecycle — device registration, exam activation, event ingestion, alerting, and reporting.

---

## 2. System Components

SPEMCS consists of **four** components that work together:

```
┌─────────────────────────────────────────────────────────────┐
│                      ADMIN / PROCTOR                        │
│              (Browser — React Frontend)                     │
│          Dashboard · Exam Shield · Live Monitor             │
└────────────────────┬────────────────────────────────────────┘
                     │  REST API + WebSocket
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                    BACKEND SERVER                           │
│              (Python — FastAPI + SQLAlchemy)                 │
│     Routes · Services · WebSocket Manager · Auth            │
└────────┬──────────────────────────────────┬─────────────────┘
         │  SQL                             │  HTTP API
         ▼                                  ▼
┌─────────────────┐           ┌───────────────────────────────┐
│    DATABASE      │           │     ENDPOINT AGENT (×N)       │
│  (PostgreSQL     │           │    (C# .NET 8 — Windows Svc)  │
│   hosted on Neon │           │  Process Monitor · Classifier │
│   or local)      │           │  Pre-Compliance · UI Gateway  │
└─────────────────┘           └───────────────────────────────┘
                              Runs on EACH exam lab PC
```

| Component | Technology | Location in Repo |
|-----------|-----------|-----------------|
| **Backend** | Python 3.11+, FastAPI, SQLAlchemy, Uvicorn | `backend/` |
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS | `frontend/` |
| **Endpoint Agent** | C# .NET 8, Windows Service, WPF UI | `Endpoint-agent/` |
| **Database** | PostgreSQL (Neon cloud or local) | `database/` (seed scripts) |

---

## 3. Overall Workflow

Here is the end-to-end flow of a proctored exam:

### Phase 1: Setup (Before Exam Day)
1. Admin logs into the **Frontend** dashboard.
2. Admin navigates to **Exam Shield** → **New Exam**.
3. Admin enters the exam name, exam URL, approved browser, and selects devices from the device tree (Building → Lab → PC).
4. The backend creates the exam record and links the selected devices via `exam_devices`.
5. Meanwhile, the **Endpoint Agent** has already been installed on each lab PC as a Windows Service. On first boot, it calls `POST /api/v1/devices/register` to register itself with the backend. The backend creates a `Device` record and returns a `device_id`.

### Phase 2: Activation (Exam Starts)
6. Admin clicks **Activate** on the exam.
7. The backend sets the exam status to `active`, timestamps `started_at`, and broadcasts `EXAM_STATUS_CHANGE` over WebSocket to all connected dashboards.
8. The agent on each assigned PC receives a `START_EXAM` command (via the named-pipe control channel from the TestHarness or the UI).
9. The agent transitions: `Idle → PreCompliance → StudentVerification → Monitoring`.
   - **PreCompliance**: Scans for suspicious processes. If any are found, the student must close them before proceeding.
   - **StudentVerification**: Student enters their roll number. The agent calls `POST /api/v1/sessions/verify-student`.
   - **Monitoring**: Active monitoring begins. The `ProcessMonitor` scans every 5 seconds.

### Phase 3: Monitoring (During Exam)
10. The agent's `ProcessMonitor` scans all running processes.
11. Each process is classified by `ConfigurableProcessClassifier`:
    - **Allowed**: Approved browser (Chrome), SPEMCS agent itself, essential Windows processes (csrss.exe, explorer.exe, etc.)
    - **Suspicious**: Everything else — unapproved browsers, Discord, TeamViewer, OBS, etc.
12. When a suspicious process is detected, the agent:
    - Creates a `ViolationEvent` record locally (SQLite).
    - Calls `POST /api/v1/events` to report it to the backend.
13. The backend's `event_service`:
    - Persists the event to PostgreSQL.
    - Creates an `Alert` record.
    - Broadcasts `VIOLATION_ALERT` over WebSocket to all dashboards subscribed to this exam.
14. The admin sees the alert **instantly** on the **Live Monitor** page — the device tile turns red, showing the violation details.

### Phase 4: Deactivation (Exam Ends)
15. Admin clicks **Stop** on the exam.
16. The backend sets status to `stopped`, timestamps `ended_at`, ends all active sessions, broadcasts `EXAM_STATUS_CHANGE`.
17. Agents receive `STOP_EXAM` and transition back to `Idle`.

### Phase 5: Reporting (Post-Exam)
18. Admin navigates to **Reports** → clicks **Generate** for the exam.
19. The backend compiles all sessions, events, and alerts into a structured report.
20. Admin can view the timeline and export to CSV.

---

## 4. Component: Backend (FastAPI)

### Role
The backend is the **central nervous system**. It handles:
- Device registration and presence tracking
- Exam lifecycle management (create, activate, deactivate)
- Event ingestion from agents
- Alert generation and management
- Real-time WebSocket broadcasting to dashboards
- Report generation and export
- JWT authentication

### Directory Structure

```
backend/
├── app/
│   ├── config.py          # Pydantic BaseSettings (loads .env)
│   ├── database.py        # SQLAlchemy engine + session factory
│   └── main.py            # FastAPI app, lifespan, CORS, router registration
├── models/
│   ├── base.py            # SQLAlchemy declarative Base
│   ├── device.py          # Device model (hardware_uuid, building, lab, status)
│   ├── exam.py            # Exam model (lifecycle, approved_browser)
│   ├── exam_device.py     # Many-to-many: Exam ↔ Device
│   ├── session.py         # ExamSession (student_roll_number, timestamps)
│   ├── event.py           # Violation events from agents
│   ├── alert.py           # Alerts (one per unauthorized event)
│   ├── report.py          # Generated exam reports
│   ├── lab.py             # Lab model
│   ├── lab_device.py      # Lab ↔ Device mapping
│   ├── user.py            # Auth user (username, hashed password, role)
│   ├── audit_log.py       # Administrative action log
│   └── __init__.py
├── schemas/               # Pydantic request/response models
│   ├── device.py, exam.py, alert.py, user.py, audit_log.py
│   └── __init__.py
├── services/              # Business logic (no HTTP concerns)
│   ├── device_service.py  # Registration, presence, hierarchy
│   ├── exam_service.py    # Create, activate, deactivate
│   ├── session_service.py # Start/end sessions, student verification
│   ├── event_service.py   # Event ingestion, dedup, alert creation
│   ├── alert_service.py   # Query/update alerts
│   ├── report_service.py  # Generate comprehensive exam reports
│   ├── realtime_service.py# WebSocket orchestration
│   ├── auth_service.py    # JWT, password hashing, token validation
│   └── __init__.py
├── routes/                # HTTP endpoint handlers
│   ├── agent_api.py       # /api/v1/* — Agent registration, events, sessions
│   ├── devices.py         # /api/devices/* — CRUD, tree, online
│   ├── exams.py           # /api/exams/* — CRUD, activate, deactivate
│   ├── sessions.py        # /api/sessions/*
│   ├── events.py          # /api/events/*
│   ├── alerts.py          # /api/alerts/*
│   ├── reports.py         # /api/reports/* — generate, export CSV
│   ├── dashboard.py       # /api/dashboard/summary
│   ├── labs.py            # /api/labs/*
│   ├── health.py          # /api/health
│   └── auth.py            # /api/auth/* — login, register, me
├── websocket/
│   ├── manager.py         # RealtimeManager singleton
│   ├── agent_ws.py        # WS endpoint: /api/v1/ws/agent
│   ├── dashboard_ws.py    # WS endpoint: /api/v1/ws/dashboard
│   └── __init__.py
├── logs/                  # Runtime log files (auto-created)
├── clear_db.py            # Utility to drop/recreate tables
└── seed/                  # Seed data scripts
```

### Key API Endpoints

| Method | Endpoint | Purpose |
|--------|---------|---------|
| `POST` | `/api/v1/devices/register` | Agent self-registration |
| `POST` | `/api/v1/events` | Agent reports a violation event |
| `POST` | `/api/v1/sessions/start` | Agent starts an exam session |
| `POST` | `/api/v1/sessions/verify-student` | Agent verifies a student's roll number |
| `GET` | `/api/devices` | List all devices |
| `GET` | `/api/devices/tree` | Hierarchical device tree (Building → Lab → PC) |
| `GET` | `/api/devices/online` | List online devices only |
| `POST` | `/api/exams` | Create a new exam |
| `POST` | `/api/exams/{id}/activate` | Activate exam monitoring |
| `POST` | `/api/exams/{id}/deactivate` | Stop exam monitoring |
| `GET` | `/api/exams/{id}/devices` | Devices assigned to an exam |
| `GET` | `/api/exams/{id}/alerts` | Alerts for an exam |
| `GET` | `/api/exams/{id}/sessions` | Sessions for an exam |
| `POST` | `/api/reports/generate/{exam_id}` | Generate an exam report |
| `GET` | `/api/reports/{id}/export/csv` | Export report as CSV |
| `GET` | `/api/dashboard/summary` | Dashboard stats (devices, exams, alerts, sessions) |
| `POST` | `/api/auth/login` | JWT login |
| `POST` | `/api/auth/register` | Create a new admin user |
| `GET` | `/api/auth/me` | Get current authenticated user |
| `GET` | `/api/health` | Health check |

### WebSocket Endpoints

| Endpoint | Used By | Purpose |
|----------|---------|---------|
| `/api/v1/ws/agent` | Endpoint Agent | Device heartbeat, status sync |
| `/api/v1/ws/dashboard` | Frontend | Real-time alerts, device status, exam events |

### WebSocket Message Types (Dashboard)

| Type | Direction | Payload |
|------|-----------|---------|
| `INITIAL_STATE` | Server → Client | `{online_devices, connected_dashboards}` |
| `DEVICE_STATUS_CHANGE` | Server → Client | `{hardware_uuid, device_name, status}` |
| `VIOLATION_ALERT` | Server → Client | `{alert_id, device_name, severity, message, ...}` |
| `SESSION_STARTED` | Server → Client | `{session_id, student_roll_number, ...}` |
| `EXAM_STATUS_CHANGE` | Server → Client | `{exam_id, status, exam_name}` |
| `SUBSCRIBE_EXAM` | Client → Server | `{exam_id}` — subscribe to exam room |
| `UNSUBSCRIBE_EXAM` | Client → Server | `{exam_id}` — leave exam room |
| `HEARTBEAT_PING` | Server → Client | Keep-alive ping |
| `HEARTBEAT_PONG` | Client → Server | Keep-alive response |

### Configuration

The backend reads configuration from the `.env` file at the project root:

```env
DATABASE_URL="postgresql+psycopg2://user:password@host/dbname?sslmode=require"
SECRET_KEY="your-production-secret-key"
```

`backend/app/config.py` auto-discovers the `.env` file by walking up from its own directory.

### Setup Instructions

**Prerequisites:** Python 3.11 or higher, pip.

Open a **regular terminal** (no admin needed). Run from the **project root** (`d:\PROJECTS\spemcs`):

```powershell
# Step 1: Create a Python virtual environment
python -m venv .venv

# Step 2: Activate the virtual environment
.\.venv\Scripts\Activate.ps1

# Step 3: Install dependencies
pip install -r requirements.txt

# Step 4: Verify .env exists and DATABASE_URL is set
cat .env
# Should show: DATABASE_URL="postgresql+psycopg2://..."

# Step 5: Start both development servers using the root .env configuration
.\start-dev.ps1
```

`start-dev.ps1` starts FastAPI using `BACKEND_HOST` and `BACKEND_PORT` from the project-root `.env`, then starts Vite. The browser uses relative `/api` requests, so Vite may use any available development port.

**To register your first admin user** (while the server is running), open a second terminal:

```powershell
curl -X POST http://127.0.0.1:8000/api/auth/register `
  -H "Content-Type: application/json" `
  -d '{"username": "admin", "email": "admin@campusshield.edu", "password": "Admin@0123", "role": "admin"}'
```

---

## 5. Component: Frontend (React)

### Role
The frontend is the **Admin Portal** — a single-page web application where proctors and administrators:
- View the real-time dashboard (online devices, active exams, alerts)
- Create exams and assign devices
- Activate/deactivate exam monitoring
- Watch the Live Monitor page with per-device status tiles
- View and manage security alerts
- Generate and export exam reports

### Directory Structure

```
frontend/src/
├── App.tsx                    # Root component, routing
├── main.tsx                   # Vite entry point
├── index.css                  # Global styles (glassmorphism theme)
├── context/
│   └── AppContext.tsx          # Global state: API data, WebSocket, auth
├── services/
│   ├── api.ts                 # REST API client (all endpoints)
│   └── websocket.ts           # WebSocket client (auto-reconnect, typed events)
├── types/
│   └── index.ts               # TypeScript interfaces (Device, Exam, Alert, etc.)
├── components/
│   ├── layout/
│   │   ├── AppShell.tsx        # Main layout with sidebar
│   │   └── Sidebar.tsx         # Navigation sidebar
│   └── ui/
│       ├── GlassCard.tsx       # Glassmorphism card container
│       ├── Button.tsx          # Styled button
│       ├── Badge.tsx           # Status badges (green/red/amber/gray)
│       ├── Modal.tsx           # Dialog modal
│       ├── PageHeader.tsx      # Page title + actions
│       ├── SearchBar.tsx       # Search input
│       ├── StatCard.tsx        # Metric cards
│       ├── Skeleton.tsx        # Loading skeletons
│       ├── EmptyState.tsx      # Empty data placeholders
│       ├── Toast.tsx           # Notification toasts
│       ├── DeviceTree.tsx      # Hierarchical device selector (Building → Lab → PC)
│       ├── DeviceTile.tsx      # Live device status tile
│       └── Timeline.tsx        # Event timeline
├── pages/
│   ├── LoginPage.tsx           # JWT login page
│   ├── DashboardPage.tsx       # Command center (stats, active exams, alerts)
│   ├── ExamShieldPage.tsx      # Exam CRUD + activate/deactivate
│   ├── LiveMonitorPage.tsx     # Real-time device grid for active exam
│   ├── DeviceStatusPage.tsx    # Device presence monitoring
│   ├── AlertsPage.tsx          # Alert management
│   ├── ReportsPage.tsx         # Report generation + CSV export
│   ├── AuditLogsPage.tsx       # Audit log viewer
│   └── SettingsPage.tsx        # Account + system status
```

### Pages & Routes

| Route | Page | Description |
|-------|------|-------------|
| `/login` | LoginPage | JWT authentication |
| `/dashboard` | DashboardPage | Real-time command center |
| `/exam-shield` | ExamShieldPage | Create, activate, manage exams |
| `/exam-shield/monitor/:id` | LiveMonitorPage | Live device tile grid for an active exam |
| `/devices` | DeviceStatusPage | Device presence (online/offline, grouped by building) |
| `/alerts` | AlertsPage | View, acknowledge, resolve alerts |
| `/reports` | ReportsPage | Generate and export exam reports |
| `/audit-logs` | AuditLogsPage | Admin action history |
| `/settings` | SettingsPage | Account info, system status |

### Design System

- **Theme**: Premium dark glassmorphism with mocha background (`#1A0D06`)
- **Accent**: Amber/gold (`#D89400` / `#FFC21A`)
- **CSS**: Tailwind CSS utilities + custom classes in `index.css` (`glass-card`, `bg-blob`, etc.)
- **Icons**: `lucide-react`
- **Path Alias**: `@` maps to `src/` (configured in `vite.config.ts`)

### Setup Instructions

**Prerequisites:** Node.js 18+ and npm.

Open a **regular terminal**. Run from the **frontend directory** (`d:\PROJECTS\spemcs\frontend`):

```powershell
# Step 1: Install dependencies
npm install

# Step 2: Start the development server
npm run dev
```

The frontend has no environment file of its own. Vite reads the project-root `.env` and proxies `/api` requests to `BACKEND_HOST` and `BACKEND_PORT`; Vite may select any available frontend port.

**Important:** The backend must be running first. The frontend will not function without it.

---

## 6. Component: Endpoint Agent (.NET)

### Role
The Endpoint Agent is the **eyes and hands** on each exam PC. It runs as a **Windows Service** (background, no user interaction needed) and:
- Registers itself with the backend on first boot
- Scans running processes every 5 seconds during monitoring
- Classifies each process as Allowed or Suspicious
- Reports violations to the backend via HTTP
- Communicates with a WPF UI (student-facing) via named pipes
- Persists state locally in SQLite (survives reboots)

### Architecture

```
Spemcs.Agent.sln
├── Spemcs.Agent.Core         # Domain models, state machine, classifier, monitor
├── Spemcs.Agent.Ipc          # Named-pipe protocol (Service ↔ UI)
├── Spemcs.Agent.Service      # Windows Service host, backend HTTP adapters
├── Spemcs.Agent.UI           # WPF student-facing window
├── Spemcs.Agent.TestHarness  # Interactive console for testing
└── Spemcs.Agent.Tests        # xUnit test suite
```

### Sub-Components

| Sub-Component | File | Purpose |
|--------------|------|---------|
| **AgentStateMachine** | `Core/Domain.cs` | State transitions: `Idle → PreCompliance → StudentVerification → Monitoring` |
| **ConfigurableProcessClassifier** | `Core/Domain.cs` | Rules engine: classifies each process as Allowed or Suspicious |
| **ProcessMonitor** | `Core/Monitoring.cs` | Scans processes every 5 seconds, detects new launches and terminations |
| **PreComplianceEngine** | `Core/Domain.cs` | Pre-exam scan — ensures no suspicious processes are running before exam starts |
| **ExamPipeline** | `Core/Domain.cs` | Orchestrates the full exam lifecycle on the agent side |
| **AgentWorker** | `Service/AgentWorker.cs` | `BackgroundService` — the main loop that runs as a Windows Service |
| **BackendAdapters** | `Service/BackendAdapters.cs` | HTTP clients for registration, session, and event APIs |
| **ControlPipeWorker** | `Service/ControlPipeWorker.cs` | Named-pipe server — receives `START_EXAM` / `STOP_EXAM` from TestHarness or UI |
| **SqliteAgentStore** | `Core/SqliteAgentStore.cs` | Local SQLite persistence for device registration, events, state |
| **NamedPipeUiGateway** | `Service/NamedPipeUiGateway.cs` | Sends commands to the WPF UI process |

### Agent State Machine

```
     ┌──────┐  START_EXAM  ┌───────────────┐  COMPLIANCE_OK  ┌─────────────────────┐  VERIFY_STUDENT  ┌────────────┐
     │ Idle │ ────────────►│ PreCompliance  │ ───────────────►│ StudentVerification  │ ───────────────►│ Monitoring │
     └──────┘              └───────────────┘                 └─────────────────────┘                 └────────────┘
        ▲                                                                                                   │
        │                                    STOP_EXAM                                                      │
        └───────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Classification Rules (V1)

| Category | Examples | Classification |
|----------|---------|----------------|
| **Approved Browser** | chrome.exe (only) | ✅ Allowed |
| **SPEMCS Agent** | Spemcs.Agent.*.exe | ✅ Allowed |
| **Essential Windows** | csrss.exe, explorer.exe, winlogon.exe, svchost.exe | ✅ Allowed |
| **Everything Else** | discord.exe, teamviewer.exe, firefox.exe, anydesk.exe, obs64.exe | 🚫 Suspicious |

### Backend API Calls Made by Agent

| When | HTTP Call | Purpose |
|------|-----------|---------|
| First boot | `POST /api/v1/devices/register` | Register device with backend |
| Exam start | `POST /api/v1/sessions/start` | Create exam session |
| Student login | `POST /api/v1/sessions/verify-student` | Attach roll number to session |
| Violation detected | `POST /api/v1/events` | Report violation event |

### Configuration

The backend URL is configured in `Endpoint-agent/src/Spemcs.Agent.Service/appsettings.json`:

```json
{
  "BackendApiUrl": "http://127.0.0.1:8000/"
}
```

**For deployment to lab PCs**, change this to the server's IP:
```json
{
  "BackendApiUrl": "http://192.168.1.100:8000/"
}
```

### Setup Instructions

**Prerequisites:** .NET 8 SDK (`winget install Microsoft.DotNet.SDK.8`).

Open a **regular terminal** (admin is only needed for the Windows Service install step). Run from the **Endpoint-agent directory** (`d:\PROJECTS\spemcs\Endpoint-agent`):

```powershell
# Step 1: Restore NuGet packages
dotnet restore

# Step 2: Build the entire solution
dotnet build --configuration Release

# Step 3: Run the unit tests
dotnet test --configuration Release

# Step 4: Publish the Service for deployment
dotnet publish src/Spemcs.Agent.Service -c Release -o ./publish/service

# Step 5: Publish the UI (student-facing WPF window)
dotnet publish src/Spemcs.Agent.UI -c Release -o ./publish/ui
```

**To install as a Windows Service** (requires **Administrator PowerShell**):

```powershell
# Open PowerShell as Administrator, navigate to the Endpoint-agent directory

# Step 6: Install the Windows Service
.\deployment\Install-SpemcsAgent.ps1 -ServiceExecutable ".\publish\service\Spemcs.Agent.Service.exe"

# Step 7: Set the UI path (so the Service knows where to launch the student UI)
[System.Environment]::SetEnvironmentVariable("SPEMCS_AGENT_UI_PATH", (Resolve-Path ".\publish\ui\Spemcs.Agent.UI.exe").Path, "Machine")

# Step 8: Start the service
Start-Service SpemcsAgent

# Step 9: Verify it is running
Get-Service SpemcsAgent
```

**To view real-time agent logs:**

```powershell
# From the Endpoint-agent directory (regular terminal)
.\watch-logs.ps1
```

Logs are stored at: `C:\ProgramData\Spemcs\Logs\agent-YYYYMMDD.log`

---

## 7. Component: Database (PostgreSQL)

### Role
PostgreSQL is the **persistent data store** for all backend data — devices, exams, sessions, events, alerts, reports, users.

### Schema Overview

The database schema is defined by SQLAlchemy models in `backend/models/`. Tables are **auto-created** on backend startup via `Base.metadata.create_all()`. No manual SQL migration is needed for initial setup.

```
devices          ← Registered lab PCs (hardware_uuid, building, lab, status)
exams            ← Exam definitions (name, link, approved_browser, lifecycle)
exam_devices     ← Many-to-many: which devices are assigned to which exam
exam_sessions    ← Student sessions (roll_number, timestamps)
events           ← Violation events from agents (process_name, classification)
alerts           ← One alert per unauthorized event (severity, status)
reports          ← Generated exam reports (summary JSON, timeline)
labs             ← Lab definitions
lab_devices      ← Lab ↔ Device mapping
users            ← Admin users (username, hashed_password, role)
audit_logs       ← Admin action log
```

### Current Setup: Neon (Cloud PostgreSQL)

The project currently uses **Neon** — a serverless PostgreSQL provider. The connection string is in `.env`:

```env
DATABASE_URL="postgresql+psycopg2://neondb_owner:password@ep-xxx.neon.tech/neondb?sslmode=require&channel_binding=require"
```

> **Note:** Neon has a free tier sufficient for development and small deployments.

### Local PostgreSQL (Alternative)

If you want to run PostgreSQL locally instead of Neon:

```powershell
# Install PostgreSQL (if not already installed)
winget install PostgreSQL.PostgreSQL.16

# Create the database (in PostgreSQL shell)
createdb spemcs

# Update .env to use local connection
# DATABASE_URL="postgresql+psycopg2://postgres:yourpassword@localhost:5432/spemcs"
```

### Seeding Test Data

To populate the database with synthetic test data for development:

```powershell
# From the project root, with virtual environment activated
python database/spemcs_database/seed_synthetic_data.py
```

This creates 20 devices, 3 exams, sessions, events, and alerts with realistic fake data.

### Clearing the Database

To drop and recreate all tables (destructive):

```powershell
# From the project root, with virtual environment activated
python backend/clear_db.py
```

---

## 8. Testing

### 8.1 Backend Testing

**Terminal:** Regular terminal, virtual environment activated.
**Directory:** Project root (`d:\PROJECTS\spemcs`).

```powershell
# Start the backend
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

**Verify it's running:**
```powershell
# In a second terminal
curl http://127.0.0.1:8000/api/health
# Expected: {"status": "healthy", ...}
```

**Stop the backend:** Press `Ctrl+C` in the terminal running uvicorn.

**After making backend changes:**
```powershell
# If using --reload, changes are auto-detected. Just save the file.
# If not using --reload, stop with Ctrl+C and restart:
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

**To start fresh (reset database + restart):**
```powershell
# Stop uvicorn (Ctrl+C), then:
python backend/clear_db.py
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
# Re-register your admin user (see Backend Setup section)
```

---

### 8.2 Frontend Testing

**Terminal:** Regular terminal.
**Directory:** `d:\PROJECTS\spemcs\frontend`.

```powershell
# Start the dev server
npm run dev
```

**Verify it's running:** Open `http://localhost:5173` in a browser.

**Stop the frontend:** Press `Ctrl+C` in the terminal.

**Type-check after changes:**
```powershell
npm run typecheck
```

**Production build test:**
```powershell
npm run build
```

**After making frontend changes:**
```powershell
# Vite dev server has hot-reload. Just save the file — the browser updates automatically.
# For a full rebuild from scratch:
npm run build
npm run preview    # Serves the production build locally at http://localhost:4173
```

**To start fresh:**
```powershell
# Stop dev server (Ctrl+C), then:
Remove-Item -Recurse -Force node_modules, dist
npm install
npm run dev
```

---

### 8.3 Endpoint Agent Testing

**Terminal:** Regular terminal for build, **Administrator PowerShell** for service operations.
**Directory:** `d:\PROJECTS\spemcs\Endpoint-agent`.

#### Running Unit Tests
```powershell
# Regular terminal — no admin needed
dotnet test --configuration Release --verbosity normal
```

#### Interactive Testing with TestHarness (No Service Install Needed)
```powershell
# Regular terminal
dotnet run --project src/Spemcs.Agent.TestHarness

# This starts a local harness. You can type:
#   start         → Transition to PreCompliance
#   verify 22ABC  → Simulate student verification
#   events        → View local events
#   stop          → End exam
#   quit          → Exit
```

#### Testing Against Running Service
```powershell
# Regular terminal
dotnet run --project src/Spemcs.Agent.TestHarness -- --service

# This connects to the installed Windows Service via named pipe.
# Type: start, stop, quit
```

**Stop the service:**
```powershell
# Administrator PowerShell
Stop-Service SpemcsAgent
```

#### After Making Agent Changes — Full Clean Rebuild & Re-test

When you modify agent code and want to ensure a completely clean slate:

```powershell
# --- Step 1: Stop and uninstall the old service (Administrator PowerShell) ---
Stop-Service SpemcsAgent -ErrorAction SilentlyContinue
.\deployment\Uninstall-SpemcsAgent.ps1

# --- Step 2: Clean build artifacts (Regular terminal, from Endpoint-agent/) ---
dotnet clean --configuration Release
Remove-Item -Recurse -Force ./publish -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force ./src/*/bin, ./src/*/obj -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force ./tests/*/bin, ./tests/*/obj -ErrorAction SilentlyContinue

# --- Step 3: Clear local agent data (Regular terminal) ---
Remove-Item -Recurse -Force "C:\ProgramData\Spemcs" -ErrorAction SilentlyContinue

# --- Step 4: Restore, build, test (Regular terminal) ---
dotnet restore
dotnet build --configuration Release
dotnet test --configuration Release

# --- Step 5: Re-publish (Regular terminal) ---
dotnet publish src/Spemcs.Agent.Service -c Release -o ./publish/service
dotnet publish src/Spemcs.Agent.UI -c Release -o ./publish/ui

# --- Step 6: Re-install and start (Administrator PowerShell) ---
.\deployment\Install-SpemcsAgent.ps1 -ServiceExecutable ".\publish\service\Spemcs.Agent.Service.exe"
Start-Service SpemcsAgent
Get-Service SpemcsAgent
```

#### Quick Re-test (No Uninstall Needed)

If changes are minor and you just want to update the running service:

```powershell
# Administrator PowerShell, from Endpoint-agent/
Stop-Service SpemcsAgent
dotnet publish src/Spemcs.Agent.Service -c Release -o ./publish/service
Start-Service SpemcsAgent
```

---

### 8.4 End-to-End Test Sequence

To test the full system working together:

1. **Start the backend** (Terminal 1, project root):
   ```powershell
   .\.venv\Scripts\Activate.ps1
   uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
   ```

2. **Start the frontend** (Terminal 2, frontend/):
   ```powershell
   npm run dev
   ```

3. **Run the agent TestHarness** (Terminal 3, Endpoint-agent/):
   ```powershell
   dotnet run --project src/Spemcs.Agent.TestHarness
   ```
   Type `start` → `verify 22BCS12345` → observe the dashboard updating in real-time.

4. **Open the browser** at `http://localhost:5173`:
   - Log in with your admin credentials
   - Go to **Exam Shield** → Create an exam → Activate it
   - Go to **Live Monitor** → Watch for violations
   - Go to **Devices** → See registered devices

---

## 9. Deployment

### 9.1 Deploying the Endpoint Agent to Lab PCs

The agent needs to be installed on **every PC** that will be used for proctored exams. Here are the recommended approaches, from simplest to most scalable:

#### Option A: USB Drive / Shared Network Folder (Simplest)

1. On your development machine, publish the agent:
   ```powershell
   # From Endpoint-agent/
   dotnet publish src/Spemcs.Agent.Service -c Release -o ./publish/service --self-contained -r win-x64
   dotnet publish src/Spemcs.Agent.UI -c Release -o ./publish/ui --self-contained -r win-x64
   ```
   The `--self-contained` flag bundles the .NET runtime, so target PCs don't need .NET installed.

2. **Before publishing**, update `appsettings.json` to point to the server:
   ```json
   {
     "BackendApiUrl": "http://<SERVER-IP>:8000/"
   }
   ```

3. Copy the `publish/` folder and `deployment/` folder to a USB drive or shared network folder.

4. On **each lab PC**, open **Administrator PowerShell** and run:
   ```powershell
   # Navigate to the copied folder
   cd D:\SpemcsAgent   # or wherever you copied it

   # Install
   .\deployment\Install-SpemcsAgent.ps1 -ServiceExecutable ".\service\Spemcs.Agent.Service.exe"

   # Set the UI path
   [System.Environment]::SetEnvironmentVariable("SPEMCS_AGENT_UI_PATH", (Resolve-Path ".\ui\Spemcs.Agent.UI.exe").Path, "Machine")

   # Start
   Start-Service SpemcsAgent
   ```

#### Option B: Group Policy / SCCM (Scalable, for IT Departments)

If your college IT department manages PCs via Active Directory:

1. Publish the agent as above (self-contained).
2. Place the published files on a network share accessible to all lab PCs.
3. Create a **Group Policy Startup Script** that runs the install PowerShell script.
4. The agent installs automatically on next PC restart.

#### Option C: PowerShell Remoting (Medium Scale)

If you have admin access to all lab PCs over the network:

```powershell
# From your admin machine, run on each target PC:
$pcs = @("LAB-PC-01", "LAB-PC-02", "LAB-PC-03")  # list of PC names
$source = "\\server\share\SpemcsAgent"              # network share with published agent

foreach ($pc in $pcs) {
    Invoke-Command -ComputerName $pc -ScriptBlock {
        param($src)
        Copy-Item -Path $src -Destination "C:\SpemcsAgent" -Recurse -Force
        cd C:\SpemcsAgent
        .\deployment\Install-SpemcsAgent.ps1 -ServiceExecutable ".\service\Spemcs.Agent.Service.exe"
        [System.Environment]::SetEnvironmentVariable("SPEMCS_AGENT_UI_PATH", "C:\SpemcsAgent\ui\Spemcs.Agent.UI.exe", "Machine")
        Start-Service SpemcsAgent
    } -ArgumentList $source
}
```

---

### 9.2 Deploying Backend + Frontend + Database on the College Server PC

Your college has a dedicated PC to use as a server. Here is the step-by-step guide to deploy everything on it.

#### Prerequisites for the Server PC

| Requirement | How to Install |
|-------------|---------------|
| Windows 10/11 Pro or Server | Already installed |
| Python 3.11+ | `winget install Python.Python.3.11` |
| Node.js 18+ | `winget install OpenJS.NodeJS.LTS` |
| Git | `winget install Git.Git` |
| PostgreSQL 16 | `winget install PostgreSQL.PostgreSQL.16` (optional, if not using Neon) |

#### Step 1: Clone the Repository

Open **regular PowerShell** on the server:

```powershell
cd C:\
git clone <your-repo-url> SPEMCS
cd C:\SPEMCS
```

#### Step 2: Set Up the Database

**Option A: Keep using Neon (recommended for simplicity)**

No changes needed. The `.env` already points to Neon. Skip to Step 3.

**Option B: Use local PostgreSQL on the server**

```powershell
# After installing PostgreSQL, open pgAdmin or psql:
psql -U postgres
```

```sql
CREATE DATABASE spemcs;
CREATE USER spemcs_user WITH PASSWORD 'your-strong-password';
GRANT ALL PRIVILEGES ON DATABASE spemcs TO spemcs_user;
\q
```

Then update `.env`:
```env
DATABASE_URL="postgresql+psycopg2://spemcs_user:your-strong-password@localhost:5432/spemcs"
SECRET_KEY="generate-a-random-64-char-string-here"
```

#### Step 3: Set Up the Backend

```powershell
cd C:\SPEMCS

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Verify database connectivity
python -c "from backend.app.database import engine; from sqlalchemy import text; print(engine.connect().execute(text('SELECT 1')).fetchone())"

# Seed initial data (optional)
python database/spemcs_database/seed_synthetic_data.py
```

#### Step 4: Set Up the Frontend for Production

```powershell
cd C:\SPEMCS\frontend

# Install dependencies
npm install

# Set the API URL to the server's own address
echo "VITE_API_URL=http://<SERVER-IP>:8000" > .env

# Build for production
npm run build
```

This creates a `dist/` folder with static files.

#### Step 5: Serve Everything

**Option A: Uvicorn serves both API and frontend (simplest)**

Install an additional package and serve the frontend static files from FastAPI:

```powershell
cd C:\SPEMCS
.\.venv\Scripts\Activate.ps1
pip install aiofiles
```

Add static file serving to `backend/app/main.py` (at the very end, after all router registrations):

```python
from fastapi.staticfiles import StaticFiles
import os

frontend_dist = os.path.join(os.path.dirname(__file__), '..', '..', 'frontend', 'dist')
if os.path.isdir(frontend_dist):
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")
```

Then start the server:

```powershell
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

Now the server serves both the API (`/api/*`) and the frontend (`/`) on port 8000.

**Option B: Nginx reverse proxy (production-grade)**

Install Nginx on Windows, then configure:

```nginx
server {
    listen 80;
    server_name campusshield.college.edu;

    # Frontend
    location / {
        root C:/SPEMCS/frontend/dist;
        try_files $uri $uri/ /index.html;
    }

    # Backend API
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # WebSocket
    location /api/v1/ws/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

#### Step 6: Run the Backend as a Windows Service (Auto-Start)

So the backend starts automatically when the server boots:

```powershell
# Install NSSM (Non-Sucking Service Manager)
winget install nssm

# Create the service (Administrator PowerShell)
nssm install SpemcsBackend "C:\SPEMCS\.venv\Scripts\python.exe" "-m" "uvicorn" "backend.app.main:app" "--host" "0.0.0.0" "--port" "8000"
nssm set SpemcsBackend AppDirectory "C:\SPEMCS"
nssm set SpemcsBackend DisplayName "SPEMCS Backend API"
nssm set SpemcsBackend Start SERVICE_AUTO_START

# Start it
nssm start SpemcsBackend
```

#### Step 7: Configure Firewall

Allow other PCs on the network to reach the server:

```powershell
# Administrator PowerShell
New-NetFirewallRule -DisplayName "SPEMCS Backend" -Direction Inbound -Port 8000 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "SPEMCS Frontend" -Direction Inbound -Port 80 -Protocol TCP -Action Allow
```

#### Step 8: Configure Agent PCs

On each lab PC's `appsettings.json`, set the `BackendApiUrl` to the server's IP:

```json
{
  "BackendApiUrl": "http://<SERVER-IP>:8000/"
}
```

#### Step 9: Verify Deployment

From any PC on the campus network:

| Check | Command / URL | Expected |
|-------|--------------|----------|
| Backend health | `curl http://<SERVER-IP>:8000/api/health` | `{"status": "healthy"}` |
| Frontend loads | Open `http://<SERVER-IP>:8000` in browser | Login page appears |
| Agent registers | Check backend logs or dashboard | Device appears in device list |
| WebSocket works | Open dashboard, check "Live" indicator | Green "Live" badge in sidebar |

---

### Network Architecture (Deployed)

```
                    Campus Network (e.g., 192.168.1.0/24)
                    ─────────────────────────────────────
                              │
                    ┌─────────┴──────────┐
                    │   SERVER PC         │
                    │   192.168.1.100     │
                    │                     │
                    │  ┌───────────────┐  │
                    │  │ FastAPI :8000  │  │
                    │  │ (Backend API)  │  │
                    │  └───────┬───────┘  │
                    │          │          │
                    │  ┌───────┴───────┐  │
                    │  │  PostgreSQL   │  │
                    │  │  (or Neon)    │  │
                    │  └───────────────┘  │
                    │                     │
                    │  ┌───────────────┐  │
                    │  │ Frontend      │  │
                    │  │ (static HTML) │  │
                    │  └───────────────┘  │
                    └─────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
   ┌──────┴──────┐     ┌─────┴───────┐    ┌─────┴───────┐
   │ Lab PC #1   │     │ Lab PC #2   │    │ Lab PC #N   │
   │ Agent Svc   │     │ Agent Svc   │    │ Agent Svc   │
   │ Student UI  │     │ Student UI  │    │ Student UI  │
   └─────────────┘     └─────────────┘    └─────────────┘
```

---

## Quick Reference Card

| Action | Command | Directory | Terminal |
|--------|---------|-----------|----------|
| Start backend | `uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000` | Project root | Regular (venv active) |
| Stop backend | `Ctrl+C` | — | — |
| Start frontend | `npm run dev` | `frontend/` | Regular |
| Stop frontend | `Ctrl+C` | — | — |
| Type-check frontend | `npm run typecheck` | `frontend/` | Regular |
| Build frontend | `npm run build` | `frontend/` | Regular |
| Build agent | `dotnet build --configuration Release` | `Endpoint-agent/` | Regular |
| Test agent | `dotnet test --configuration Release` | `Endpoint-agent/` | Regular |
| Install agent service | `.\deployment\Install-SpemcsAgent.ps1 -ServiceExecutable "..."` | `Endpoint-agent/` | **Admin** |
| Uninstall agent service | `.\deployment\Uninstall-SpemcsAgent.ps1` | `Endpoint-agent/` | **Admin** |
| Start agent service | `Start-Service SpemcsAgent` | Any | **Admin** |
| Stop agent service | `Stop-Service SpemcsAgent` | Any | **Admin** |
| View agent logs | `.\watch-logs.ps1` | `Endpoint-agent/` | Regular |
| Seed test data | `python database/spemcs_database/seed_synthetic_data.py` | Project root | Regular (venv active) |
| Clear database | `python backend/clear_db.py` | Project root | Regular (venv active) |
| Register admin user | `curl -X POST http://...:8000/api/auth/register -H "..." -d "..."` | Any | Regular |

---

*SPEMCS — CampusShield v2.0*
