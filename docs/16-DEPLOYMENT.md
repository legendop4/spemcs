# 16. Production Deployment & Infrastructure Runbook

---

## What Am I Looking At?

![Deployment Topology](diagrams/12-deployment-topology.svg)

This document is the **production deployment runbook** for SPEMCS. It contains step-by-step instructions for deploying:
1. **The Linux Management Server**: Nginx, Uvicorn, Systemd, PostgreSQL, and cryptographic keyring configuration.
2. **The Windows Lab Endpoint Workstations**: WiX MSI packaging, Windows Service installation, and interactive UI setup.

---

## Why Does It Exist?

An examination security system deployed in an enterprise university environment must be reproducible, resilient to power cuts, and automated across hundreds of physical machines without requiring manual intervention on each PC before every exam.

---

## Part 1: Linux Management Server Deployment

### System Requirements
- **OS**: Ubuntu 22.04 LTS or Debian 12 (x86_64)
- **CPU / RAM**: 4 vCPUs, 8 GB RAM minimum (scales to 500 concurrent workstations)
- **Software**: Python 3.11+, PostgreSQL 15+, Nginx, Git, OpenSSL

---

### Step 1: System User & Directories Setup
```bash
sudo useradd -r -s /bin/false -d /var/lib/spemcs spemcs
sudo mkdir -p /etc/spemcs /var/lib/spemcs/secrets /var/log/spemcs
sudo chown -R spemcs:spemcs /var/lib/spemcs /var/log/spemcs
sudo chmod 700 /var/lib/spemcs/secrets
```

---

### Step 2: Environment Configuration (`/etc/spemcs/backend.env`)
Create `/etc/spemcs/backend.env` with strict `0600` permissions:
```ini
DATABASE_URL=postgresql://spemcs_app:<DB_PASSWORD>@127.0.0.1:5432/spemcs_prod?sslmode=require
SPEMCS_ENV=production
SECRET_KEY=<GENERATE_64_CHAR_HEX_SECRET>
DEVICE_TOKEN_SECRET=<GENERATE_64_CHAR_HEX_SECRET>
ENROLLMENT_BOOTSTRAP_KEY=<SECURE_INSTALLATION_BOOTSTRAP_KEY>
SIGNING_KEY_DIR=/var/lib/spemcs/secrets
SIGNING_KEY_PASSPHRASE=<OPTIONAL_KEY_ENCRYPTION_PASSPHRASE>
SIGNING_KEY_ALLOW_EPHEMERAL=false
ACCESS_TOKEN_EXPIRE_MINUTES=480
CORS_ORIGINS=["https://spemcs.univ.edu"]
WS_HEARTBEAT_INTERVAL=30
WS_HEARTBEAT_TIMEOUT=10
PORT=8002
```
```bash
sudo chmod 600 /etc/spemcs/backend.env
sudo chown spemcs:spemcs /etc/spemcs/backend.env
```

---

### Step 3: Database Migrations & Seed
```bash
cd /opt/spemcs/backend
source .venv/bin/activate
export PYTHONPATH=.
alembic upgrade head
python -m backend.seed.seed_initial_data
```

---

### Step 4: Systemd Service (`/etc/systemd/system/spemcs-backend.service`)
```ini
[Unit]
Description=SPEMCS FastAPI Backend Management Server
After=network.target postgresql.service

[Service]
Type=simple
User=spemcs
Group=spemcs
WorkingDirectory=/opt/spemcs/backend
EnvironmentFile=/etc/spemcs/backend.env
ExecStart=/opt/spemcs/backend/.venv/bin/uvicorn backend.app.main:app --host 127.0.0.1 --port 8002 --workers 4 --proxy-headers
Restart=always
RestartSec=5s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now spemcs-backend
```

---

### Step 5: Nginx Reverse Proxy with WebSocket Upgrades
```nginx
server {
    listen 443 ssl http2;
    server_name spemcs.univ.edu;

    ssl_certificate /etc/letsencrypt/live/spemcs.univ.edu/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/spemcs.univ.edu/privkey.pem;

    # Static Frontend SPA
    root /opt/spemcs/frontend/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # REST API Gateway
    location /api/ {
        proxy_pass http://127.0.0.1:8002/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Real-Time WebSocket Hubs
    location /api/v1/ws/ {
        proxy_pass http://127.0.0.1:8002/api/v1/ws/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # Health Check
    location /health {
        proxy_pass http://127.0.0.1:8002/health;
    }
}
```

---

## Part 2: Windows Lab Endpoint Workstation Deployment

### System Requirements
- **OS**: Windows 10 or 11 Pro / Enterprise (x64)
- **Runtime**: Microsoft .NET 8 Runtime (Windows Desktop & Console)
- **Privilege**: Local Administrator during installation; runs as `NT AUTHORITY\SYSTEM` post-install

---

### Automated Deployment via PowerShell Script
Run in an Elevated PowerShell Window on each lab PC:

```powershell
# Endpoint-agent/scripts/install_service.ps1
param(
    [string]$BackendUrl = "https://spemcs.univ.edu",
    [string]$BootstrapKey = "<SECURE_INSTALLATION_BOOTSTRAP_KEY>"
)

$InstallDir = "C:\Program Files\Spemcs\Endpoint Agent"
$DataDir = "C:\ProgramData\Spemcs"

# 1. Create Directories
New-Item -ItemType Directory -Force -Path $InstallDir
New-Item -ItemType Directory -Force -Path "$DataDir\Logs"

# 2. Copy Binaries
Copy-Item -Path ".\publish\*" -Destination $InstallDir -Recurse -Force

# 3. Write Config
$Config = @{
    Spemcs = @{
        BackendUrl = $BackendUrl
        EnrollmentBootstrapKey = $BootstrapKey
        HeartbeatIntervalSeconds = 30
    }
} | ConvertTo-Json -Depth 5
Set-Content -Path "$InstallDir\appsettings.json" -Value $Config

# 4. Register Windows Service in Session 0
$BinaryPath = "$InstallDir\Spemcs.Agent.Service.exe"
sc.exe create Spemcs.Agent.Service binPath= "$BinaryPath" start= auto DisplayName= "SPEMCS Endpoint Agent"

# 5. Configure SCM Auto-Restart Failure Actions
sc.exe failure Spemcs.Agent.Service reset= 86400 actions= restart/5000/restart/10000/restart/60000

# 6. Start the Service
Start-Service -Name Spemcs.Agent.Service
```

---

### Interactive Desktop UI Autorun Configuration
The service uses [`InteractiveSessionUiLauncher.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Service/InteractiveSessionUiLauncher.cs) to spawn `Spemcs.Agent.UI.exe` dynamically across the session boundary whenever an active console session is detected. No manual user startup shortcut is required.

---

## System Health & Readiness Verification

After deployment, verify the installation using these commands:

```bash
# 1. Backend Health Check
curl -i https://spemcs.univ.edu/health
# Response: HTTP/2 200 OK {"status":"healthy"}

# 2. Keyring Public Key Verification
curl -i https://spemcs.univ.edu/api/policies/signing-key/public
# Response: HTTP/2 200 OK {"key_id":"...","algorithm":"RSA-PSS"}

# 3. Windows Service Status
Get-Service Spemcs.Agent.Service | Select-Object Name, Status, StartType
# Status: Running | StartType: Automatic

# 4. Inspect Local SQLite Rollback Journal
sqlite3.exe "C:\ProgramData\Spemcs\sqlite_rollback_journal.db" ".schema"
```
