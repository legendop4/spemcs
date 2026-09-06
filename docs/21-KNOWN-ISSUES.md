# 21. Known Issues, Technical Debt & Verification Gaps

---

## What Am I Looking At?

This document is the **unvarnished register of known limitations, technical debt, and pending verification milestones** in the current SPEMCS repository. It explicitly separates what is mathematically and hermetically verified from operational assumptions that remain to be tested on physical hardware.

---

## Why Does It Exist?

High-integrity software engineering requires absolute transparency. Presenting an untested operational feature as "production-verified" is dangerous. This register provides developers, evaluators, and future maintainers with an honest appraisal of the codebase today.

---

## 1. Confirmed Issues & Operational Limitations

### A. Live Bare-Metal Windows Multi-Profile E2E Validation Gap
- **Status**: 🟠 PROBABLE / OPERATIONAL GAP
- **Description**: The .NET agent test suite contains 289 unit and integration tests that pass hermetically using `MockFirewallAdapter`. While `WindowsFirewallAdapterIntegrationTests.cs` exercises live COM calls on developer workstations, **full multi-workstation bare-metal end-to-end testing across physical domain-joined lab networks under power cuts remains an operational milestone**.
- **Risk**: In university labs with aggressive Active Directory Group Policy Objects (GPOs), network admins might inadvertently configure domain firewalls that override local COM rule insertion unless local rule merging is permitted.
- **Remediation**: Before deploying to a new lab, run [`Endpoint-agent/scripts/verify_firewall.ps1`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/scripts/verify_firewall.ps1) with administrative privileges to confirm COM rule precedence.

---

### B. WMI Event Watcher Quota Exhaustion Under Synthetic Stress
- **Status**: 🔴 CONFIRMED (Mitigated)
- **Description**: When a synthetic load generator spawns $>500\text{ processes/second}$, the underlying Windows WMI COM subsystem (`System.Management.ManagementEventWatcher`) can throw a quota violation `InvalidOperationException`.
- **Mitigation in Code**: The agent implements an automatic watcher recycle loop and registers a secondary kernel ETW provider (`EtwDnsListener.cs`) to ensure uninterrupted telemetry.

---

## 2. Technical Debt & Codebase Nuances

### A. Frontend TypeScript Configuration Churn
- **Status**: 🟡 TECHNICAL DEBT
- **Description**: Running `tsc --noEmit` from the root of `frontend/` reads `tsconfig.json` rather than `tsconfig.app.json`, causing TypeScript to inspect build configuration files and raise pre-existing type warnings.
- **Workaround**: Use the dedicated npm script:
  ```powershell
  npm run typecheck
  # Executes: tsc --noEmit -p tsconfig.app.json
  ```

### B. Legacy Plaintext `password` Column in `users` Table
- **Status**: 🟡 TECHNICAL DEBT
- **Description**: The `users` SQLAlchemy model in [`backend/backend/models/user.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/models/user.py) retains a legacy `password` column alongside `password_hash`.
- **Security Reality**: Authentication exclusively validates against `password_hash` using PBKDF2/Bcrypt in [`auth_service.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/auth_service.py). However, a future migration should formally drop the unused plaintext column to reduce database surface area.

### C. Git Working Tree CRLF Line-Ending Warnings
- **Status**: 🟡 MINOR HYGIENE
- **Description**: On Windows development machines, Git frequently warns about `CRLF will be replaced by LF` when staging files across the repository.
- **Remediation**: Standardize `.gitattributes` to enforce `* text=auto eol=lf` across all text files.

---

## 3. Reconciliation: Historical Documentation vs Codebase Ground Truth

Earlier repository documentation and handoff notes contained outdated metrics that have been updated by this master documentation:

| Documented Item | Previous Documentation Claim | Current Repository Ground Truth | Reconciliation Methodology |
| :--- | :--- | :--- | :--- |
| **Backend Test Suite** | "469 tests" | **903 tests collected** (902 passing, 1 skipped) | Recalculated via `pytest --collect-only`. Growth reflects extensive cryptographic keyring, secret config, and enforcement readiness tests added in recent milestones. |
| **Endpoint Agent Tests**| "146 tests" | **289 test methods** + 4,534 parity vectors | Recalculated via `dotnet test --list-tests`. Expanded coverage includes command replay, rollback isolation, and address validators. |
| **Backend Endpoints** | "81 routes" | **84 HTTP endpoints + 2 WebSockets** = 86 total | Recalculated via FastAPI OpenAPI and Starlette route table introspection. |
| **Database Tables** | "11 or 12 tables" | **14 PostgreSQL tables + 1 SQLite table** | Recalculated via SQLAlchemy `Base.metadata.tables` enumeration. |
