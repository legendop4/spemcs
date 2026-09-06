# 17. Local Developer Setup & Onboarding Guide

---

## What Am I Looking At?

This document is the **complete onboarding guide** for software developers working on SPEMCS. It explains how to set up, configure, build, and run the backend, frontend, and endpoint agent on a local development workstation.

---

## Why Does It Exist?

SPEMCS spans multiple programming languages and environments (.NET 8 C# on Windows, Python 3.11 FastAPI, React 18 TypeScript). This guide ensures that a new engineer can bootstrap the entire local environment in under 10 minutes without hitting cryptic configuration or file-permission hurdles.

---

## Prerequisites & Tooling

Install the following tools before proceeding:
1. **Python**: Version 3.11 or 3.12 (64-bit)
2. **Node.js**: Version 18 LTS or 20 LTS (with npm)
3. **.NET SDK**: Version 8.0 LTS (x64 SDK)
4. **Git**: With CRLF / LF line ending support configured
5. **Operating System**: Windows 10/11 x64 is required for the agent; backend and frontend run on Windows, macOS, or Linux.

---

## Step-by-Step Local Setup

### 1. Repository Clone
```powershell
git clone https://github.com/legendop4/spemcs.git
cd spemcs
```

---

### 2. Backend Management Server Setup

```powershell
cd backend

# Create and activate Python virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Configure local development environment
# Setting SPEMCS_ENV=development relaxes secret entropy checks to warnings
$env:SPEMCS_ENV = "development"
$env:DATABASE_URL = "sqlite:///./dev_local.db"
$env:SECRET_KEY = "dev-secret-change-in-production-local-key"
$env:DEVICE_TOKEN_SECRET = "dev-device-token-secret-change-in-production"
$env:ENROLLMENT_BOOTSTRAP_KEY = "spemcs-enrollment-bootstrap-key-default"
$env:PYTHONPATH = "."

# Run database migrations
alembic upgrade head

# Seed demo users and labs
python -m backend.seed.seed_initial_data

# Start development server with auto-reload
python -m uvicorn backend.app.main:app --reload --port 8002
```

The backend is now live at `http://127.0.0.1:8002`.
- Swagger UI Documentation: `http://127.0.0.1:8002/docs`
- Health Check: `http://127.0.0.1:8002/health`

---

### 3. Frontend Web Dashboard Setup

Open a new terminal window:

```powershell
cd frontend

# Install Node dependencies
npm install

# Start Vite development server
npm run dev
```

The frontend dashboard is now live at `http://localhost:5173`.
Vite is pre-configured with a reverse proxy in [`vite.config.ts`](file:///c:/Users/shrma/Desktop/spemcsnew/frontend/vite.config.ts) forwarding all `/api` and `/api/v1/ws` requests directly to `http://127.0.0.1:8002`.

---

### 4. Endpoint Agent Build & Testing

Open a third terminal window:

```powershell
cd Endpoint-agent

# Restore and build the complete .NET 8 solution
dotnet build Spemcs.Agent.sln

# Run unit tests (using MockFirewallAdapter without touching host firewall)
dotnet test tests\Spemcs.Agent.Tests\Spemcs.Agent.Tests.csproj --no-build
```

---

## Seed Accounts & Default Credentials

When [`seed_initial_data.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/seed/seed_initial_data.py) runs, it provisions the following default test accounts:

| Role | Username | Default Password | Granted Permissions |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `admin123` | Full access: manage exams, rotate keys, trigger lockdown. |
| **Proctor** | `proctor` | `proctor123` | Read-only monitoring: live seat grid, triage & resolve alerts. |

---

## Common Development Pitfalls & Solutions

### 1. Port 8002 Already in Use
- **Symptom**: `ERROR: [Errno 10048] error while attempting to bind on address ('127.0.0.1', 8002)`.
- **Solution**: Find and terminate the dangling python process:
  ```powershell
  Get-NetTCPConnection -LocalPort 8002 | Select-Object OwningProcess
  Stop-Process -Id <PID> -Force
  ```

### 2. Frontend Typecheck Warning
- **Symptom**: Running `tsc` flags pre-existing types in `tsconfig.json`.
- **Solution**: The frontend uses `tsconfig.app.json` for application compilation. Use:
  ```powershell
  npm run typecheck
  ```

### 3. Running Agent without Elevating
- **Symptom**: Running the live agent throws `Access is denied` on `HNetCfg.FwPolicy2`.
- **Solution**: During local development, run unit and integration tests using `MockFirewallAdapter`. Real firewall manipulation requires an Elevated (Run as Administrator) terminal.
