# SPEMCS Endpoint Agent

The SPEMCS Endpoint Agent runs on campus lab workstations to provide automated pre-compliance scanning, candidate verification, and real-time process monitoring during exams.

## Quick Start (Development / Testing)

### 1. First-Time Setup Wizard
To manually configure Central Server URL, Lab selection, and PC Number:
```powershell
dotnet run --project src/Spemcs.Agent.UI -- --setup
```

### 2. Normal Startup (Silent Background Mode)
```powershell
dotnet run --project src/Spemcs.Agent.UI
```
The agent connects silently to the Central Server WebSocket (`ws://<serverUrl>/api/v1/ws/agent`) and automatically surfaces fullscreen when an exam is activated on the proctoring dashboard.

## Building the MSI Installer

To compile the self-contained Windows `x64` MSI installer (`Spemcs.Agent.Setup.msi`):

```powershell
powershell -ExecutionPolicy Bypass -File ./build-msi.ps1
```

The installer will be generated at:
```text
installer/dist/Spemcs.Agent.Setup.msi
```
