# SPEMCS Visual Architecture Diagrams Directory

This directory contains standalone, high-resolution vector SVG diagrams illustrating every major subsystem, trust boundary, security model, and data flow in SPEMCS (**Secure Proctoring & Endpoint Monitoring Control System**).

Every diagram in this directory is grounded in **verified source code** from the active repository.

---

## Diagram Index & Reference Guide

| File | Title | Primary Architecture Focus | Verified Code Symbols |
| :--- | :--- | :--- | :--- |
| [`01-system-overview.svg`](file:///c:/Users/shrma/Desktop/spemcsnew/docs/diagrams/01-system-overview.svg) | **Master System Overview** | 3-Tier topology: Windows Lab Client, FastAPI Backend, React 18 SPA | `Spemcs.Agent.Service`, `backend.app.main`, `AppShell.tsx` |
| [`02-session0-vs-session1.svg`](file:///c:/Users/shrma/Desktop/spemcsnew/docs/diagrams/02-session0-vs-session1.svg) | **Session 0 vs Session 1+ Runtime** | Windows Session 0 SYSTEM Service vs Session 1+ Interactive User Desktop | `InteractiveSessionUiLauncher.cs`, `ControlPipeWorker.cs`, `HNetCfg.FwPolicy2` |
| [`03-database-erd.svg`](file:///c:/Users/shrma/Desktop/spemcsnew/docs/diagrams/03-database-erd.svg) | **Complete Entity-Relationship Diagram** | 14 PostgreSQL tables + SQLite rollback journal | `backend.models.*`, `alerts.exam_id` (NULLABLE), `sqlite_rollback_journal.db` |
| [`04-trust-boundaries.svg`](file:///c:/Users/shrma/Desktop/spemcsnew/docs/diagrams/04-trust-boundaries.svg) | **Trust Boundaries & Credential Matrix** | 4 Cryptographic Trust Domains (Operator JWT, Device HMAC, Bootstrap Key, RSA-PSS) | `dependencies.py`, `auth_service.py`, `signing_key_manager.py` |
| [`05-how-spemcs-works-story.svg`](file:///c:/Users/shrma/Desktop/spemcsnew/docs/diagrams/05-how-spemcs-works-story.svg) | **How SPEMCS Works Storyboard** | 15 verified sequential lifecycle stages from PC boot to final audit report | `Program.cs`, `PolicyCompiler`, `PolicyReceiver.cs`, `WindowsFirewallAdapter.cs` |
| [`06-before-after-network-lockdown.svg`](file:///c:/Users/shrma/Desktop/spemcsnew/docs/diagrams/06-before-after-network-lockdown.svg) | **Network Lockdown Architecture** | Comparative analysis: Normal open networking vs hardened exam enclave | `WindowsFirewallAdapter.cs`, `FirewallProfiles.All = 7`, `BrowserExecutableResolver.cs` |
| [`07-before-after-process-detection.svg`](file:///c:/Users/shrma/Desktop/spemcsnew/docs/diagrams/07-before-after-process-detection.svg) | **Process Monitoring & Detection** | Unmonitored execution vs sub-50ms kernel WMI/ETW interception | `ConfigurableProcessClassifier.cs`, `EtwDnsListener.cs`, `EventUploaderWorker.cs` |
| [`08-failure-recovery-map.svg`](file:///c:/Users/shrma/Desktop/spemcsnew/docs/diagrams/08-failure-recovery-map.svg) | **Failure & Recovery Architecture Map** | 9 Failure modes, detection triggers, implementation recovery, and test status | `SqliteRollbackJournal.cs`, `realtime.py`, `enforcement_readiness.py` |
| [`09-packet-event-flow.svg`](file:///c:/Users/shrma/Desktop/spemcsnew/docs/diagrams/09-packet-event-flow.svg) | **Follow the Packet & Event** | 3-Level data pipeline: Conceptual → Subsystem → Implementation | `EventService.py`, `realtime.py`, `AppContext.tsx` |
| [`10-button-click-execution-trace.svg`](file:///c:/Users/shrma/Desktop/spemcsnew/docs/diagrams/10-button-click-execution-trace.svg) | **Follow the Button Click** | 10-stage execution trace from UI action to database commit & WS broadcast | `examService.ts`, `exams.py`, `require_admin`, `enforcement_readiness.py` |
| [`11-network-topology.svg`](file:///c:/Users/shrma/Desktop/spemcsnew/docs/diagrams/11-network-topology.svg) | **Network Topology & Port Matrix** | Campus VLANs, DMZ, transport socket definitions, and DNS handling | Ports 8002, 5432, Named Pipes `spemcs-control-v1`, Protocol 41 |
| [`12-deployment-topology.svg`](file:///c:/Users/shrma/Desktop/spemcsnew/docs/diagrams/12-deployment-topology.svg) | **Production Deployment Topology** | Linux server infrastructure (Nginx/Uvicorn/Postgres) + Windows client MSI | `install_service.ps1`, `build-msi.ps1`, systemd unit, SCM auto-restart |

---

## Rendering and Usage Guidelines

1. **Standard Markdown Embedding**:
   All diagrams are standard SVG XML files and render natively in any modern browser, GitHub, GitLab, VS Code Markdown Preview, and Obsidian:
   ```markdown
   ![Master System Overview](diagrams/01-system-overview.svg)
   ```
2. **Coexistence with Mermaid**:
   Every markdown chapter in `docs/` presents both the rendered SVG visual artifact for immediate visual understanding and the editable Mermaid block for version control diffing and modifications.
3. **No Fabrication Guarantee**:
   All arrows, data flows, port numbers, file names, and state machines depicted in these SVGs match verified code in this repository.
