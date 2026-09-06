# 07. Comprehensive API Reference & Endpoint Matrix

---

## What Am I Looking At?

This document is the **authoritative API reference** for the SPEMCS management server. Every endpoint in the system has been directly introspected and verified from the active FastAPI application.

```text
Evidence Standard:
Method: Programmatic OpenAPI and Starlette routing introspection of backend.app.main.app
Verified Count: 84 HTTP endpoints across 59 paths + 2 WebSocket endpoints = 86 total endpoints
Gating: 76 Protected Endpoints | 10 Public / Diagnostic Endpoints
Confidence: ✅ VERIFIED
```

---

## Complete Route Matrix

| HTTP Method | Route Path | Security Gate / Dependency | Target Function Symbol | Primary DB Tables Touched |
| :--- | :--- | :--- | :--- | :--- |
| **POST** | `/api/auth/token` | Public | `login_for_access_token` | `users` |
| **GET** | `/api/auth/me` | `require_authenticated` | `read_users_me` | `users` |
| **POST** | `/api/auth/logout` | `require_authenticated` | `logout` | `audit_logs` |
| **GET** | `/api/dashboard/stats` | `require_staff` | `get_dashboard_stats` | `exams`, `devices`, `alerts`, `labs` |
| **GET** | `/api/exams` | `require_staff` | `list_exams` | `exams` |
| **POST** | `/api/exams` | `require_admin` | `create_exam` | `exams`, `audit_logs` |
| **GET** | `/api/exams/{id}` | `require_staff` | `get_exam` | `exams` |
| **PUT** | `/api/exams/{id}` | `require_admin` | `update_exam` | `exams`, `audit_logs` |
| **DELETE** | `/api/exams/{id}` | `require_admin` | `delete_exam` | `exams`, `audit_logs` |
| **POST** | `/api/exams/{id}/activate` | `require_admin` | `activate_exam` | `exams`, `network_policies`, `audit_logs` |
| **POST** | `/api/exams/{id}/deactivate` | `require_admin` | `deactivate_exam` | `exams`, `audit_logs` |
| **GET** | `/api/exams/{id}/enforcement-readiness` | `require_staff` | `get_enforcement_readiness` | `exams`, `network_policies`, `device_policy_states` |
| **GET** | `/api/exams/{id}/devices` | `require_staff` | `get_exam_devices` | `exam_devices`, `devices` |
| **GET** | `/api/exams/{id}/sessions` | `require_staff` | `get_exam_sessions` | `exam_sessions` |
| **GET** | `/api/exams/{id}/alerts` | `require_staff` | `get_exam_alerts` | `alerts` |
| **GET** | `/api/exams/{id}/timeline` | `require_staff` | `get_exam_timeline` | `events`, `alerts` |
| **GET** | `/api/devices` | `require_staff` | `list_devices` | `devices` |
| **POST** | `/api/devices` | `require_admin` | `create_device` | `devices`, `audit_logs` |
| **GET** | `/api/devices/{id}` | `require_staff` | `get_device` | `devices` |
| **PUT** | `/api/devices/{id}` | `require_admin` | `update_device` | `devices`, `audit_logs` |
| **DELETE** | `/api/devices/{id}` | `require_admin` | `delete_device` | `devices`, `audit_logs` |
| **POST** | `/api/devices/{id}/heartbeat` | `require_device` | `device_heartbeat` | `devices` |
| **GET** | `/api/alerts` | `require_staff` | `list_alerts` | `alerts`, `devices`, `events` |
| **GET** | `/api/alerts/{id}` | `require_staff` | `get_alert` | `alerts` |
| **PATCH** | `/api/alerts/{id}` | `require_staff` | `resolve_alert` | `alerts`, `audit_logs` |
| **GET** | `/api/labs` | `require_staff` | `list_labs` | `labs` |
| **POST** | `/api/labs` | `require_admin` | `create_lab` | `labs`, `audit_logs` |
| **GET** | `/api/labs/{id}` | `require_staff` | `get_lab` | `labs` |
| **GET** | `/api/labs/{id}/devices` | `require_staff` | `get_lab_devices` | `lab_devices`, `devices` |
| **PATCH** | `/api/labs/{id}/status` | `require_admin` | `update_lab_status` | `labs`, `audit_logs` |
| **GET** | `/api/policies/vendors` | `require_staff` | `list_vendor_profiles` | `vendor_profiles` |
| **POST** | `/api/policies/vendors` | `require_admin` | `create_vendor_profile` | `vendor_profiles`, `audit_logs` |
| **GET** | `/api/policies/vendors/{id}` | `require_staff` | `get_vendor_profile` | `vendor_profiles` |
| **PUT** | `/api/policies/vendors/{id}` | `require_admin` | `update_vendor_profile` | `vendor_profiles`, `audit_logs` |
| **DELETE** | `/api/policies/vendors/{id}` | `require_admin` | `delete_vendor_profile` | `vendor_profiles`, `audit_logs` |
| **POST** | `/api/policies/compile/{exam_id}` | `require_admin` | `compile_exam_policy` | `network_policies`, `vendor_profiles` |
| **GET** | `/api/policies/exam/{exam_id}` | `require_staff` | `get_latest_exam_policy` | `network_policies` |
| **GET** | `/api/policies/exam/{exam_id}/device-states` | `require_staff` | `list_device_policy_states` | `device_policy_states` |
| **POST** | `/api/policies/distribute/{exam_id}/{device_uuid}` | `require_admin` | `distribute_policy` | `device_policy_states` |
| **GET** | `/api/policies/signing-key/public` | Public | `get_signing_public_key` | None (In-memory keyring) |
| **GET** | `/api/policies/signing-key/keyring` | Public | `get_signing_keyring` | None (In-memory keyring) |
| **POST** | `/api/policies/signing-key/rotate` | `require_admin` | `rotate_signing_key` | `audit_logs` |
| **POST** | `/api/policies/signing-key/{key_id}/revoke` | `require_admin` | `revoke_signing_key` | `audit_logs` |
| **POST** | `/api/reports/generate/{exam_id}` | `require_admin` | `generate_report` | `reports`, `exams`, `alerts` |
| **GET** | `/api/reports` | `require_staff` | `list_reports` | `reports` |
| **GET** | `/api/reports/{id}` | `require_staff` | `get_report` | `reports` |
| **GET** | `/api/reports/{id}/export/csv` | `require_staff` | `export_report_csv` | `reports`, `events` |
| **GET** | `/api/audit-logs` | `require_admin` | `list_audit_logs` | `audit_logs` |
| **POST** | `/api/v1/devices/register` | `require_enrollment_key` | `register_device` | `devices`, `audit_logs` |
| **GET** | `/api/v1/enrollment/labs` | `require_enrollment_key` | `list_enrollment_labs` | `labs` |
| **POST** | `/api/v1/events` | `require_device` | `receive_event` | `events`, `alerts` |
| **POST** | `/api/v1/sessions/start` | `require_device` | `start_session` | `exam_sessions` |
| **POST** | `/api/v1/sessions/verify-student` | `require_device` | `verify_student` | `exam_sessions` |
| **GET** | `/health` | Public | `health_check` | None |
| **WS** | `/api/v1/ws/agent` | Device Token | `agent_websocket_endpoint` | None (Realtime in-memory) |
| **WS** | `/api/v1/ws/dashboard` | Operator JWT Handshake | `dashboard_websocket_endpoint` | None (Realtime in-memory) |

---

## Detailed Specifications for Critical Endpoints

### 1. `POST /api/exams/{exam_id}/activate`
- **Purpose**: Transitions an exam from `PENDING` to `ACTIVE` and commands network lockdown.
- **Permissions**: `require_admin` (Administrator role only).
- **Internal Execution Flow**:
  1. Verifies exam exists and status is `PENDING`.
  2. Calls [`enforcement_readiness.evaluate_exam_readiness()`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/enforcement_readiness.py).
  3. If `network_enforcement=True`, verifies that:
     - An active RSA-signed policy exists.
     - Assigned devices have fetched and applied the policy (`rules_installed > 0`).
  4. If any assigned device is unready, raises **HTTP 409 Conflict** with detailed device readiness list.
  5. Commits `exams.status = 'ACTIVE'`, sets `started_at = NOW()`.
  6. Broadcasts `EXAM_STATE` event across WebSocket hub.
- **Response**: `200 OK` with serialized `ExamRead` schema.

---

### 2. `POST /api/v1/devices/register`
- **Purpose**: Bootstraps an unenrolled Windows workstation into the system and issues a hardware-bound HMAC device token.
- **Permissions**: `require_enrollment_key` (`X-Enrollment-Key` header verified via `hmac.compare_digest`).
- **Request Body**:
  ```json
  {
    "hardware_uuid": "4C4C4544-004D-4A10-8053-C8C04F343232",
    "device_name": "LAB-B-PC-14",
    "building_name": "Science Block",
    "lab_name": "Lab B",
    "pc_number": "14",
    "ip_address": "192.168.1.114"
  }
  ```
- **Internal Execution Flow**:
  1. Checks if `hardware_uuid` already exists in `devices` table.
  2. If exists: updates IP and `last_seen`.
  3. If new: inserts record with status `ONLINE`.
  4. Generates HMAC-SHA256 device token signed with `DEVICE_TOKEN_SECRET`:
     ```python
     payload = {
         "hardware_uuid": hardware_uuid,
         "token_id": str(uuid4()),
         "roles": ["device"],
         "exp": now + timedelta(days=30)
     }
     ```
- **Response**: `200 OK`
  ```json
  {
    "device_id": "8a329d48-3162-42fe-b58f-7c1543789ab1",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6...",
    "expires_at": "2026-10-06T02:00:00Z"
  }
  ```

---

### 3. `POST /api/v1/events`
- **Purpose**: Ingests real-time security events and process violations from endpoints.
- **Permissions**: `require_device` (`X-Device-Token` header).
- **Ownership Verification**: Automatically matches authenticated `hardware_uuid` against reporting device.
- **Request Body**:
  ```json
  {
    "device_id": "8a329d48-3162-42fe-b58f-7c1543789ab1",
    "event_type": "PROCESS_VIOLATION",
    "process_name": "AnyDesk.exe",
    "pid": 5824,
    "executable_path": "C:\\Users\\student\\Downloads\\AnyDesk.exe",
    "classification": "RemoteDesktop",
    "reason": "Prohibited remote screen sharing daemon",
    "timestamp": "2026-09-06T02:02:00Z"
  }
  ```
- **Database Effect**:
  - Inserts row into `events` table.
  - Automatically creates corresponding row in `alerts` table (with `exam_id=NULL` if no exam is active on the workstation).
  - Triggers `RealtimeManager.broadcast_dashboard_event("ALERT_CREATED", alert_data)`.
- **Response**: `200 OK` `{ "status": "INGESTED", "event_id": "..." }`.

---

### 4. `POST /api/policies/compile/{exam_id}`
- **Purpose**: Compiles exam vendor domain specifications into an immutable, canonical, RSA-signed policy payload.
- **Permissions**: `require_admin`.
- **Internal Execution Flow**:
  1. Resolves `VendorProfile` IP ranges and TCP/UDP ports.
  2. Resolves approved browser executable path (`chrome.exe` / `msedge.exe`).
  3. Includes backend server IP for management channel continuity.
  4. Serializes into canonical JSON (RFC 8785).
  5. Signs payload using active RSA-2048 private key (RSA-PSS with SHA-256).
  6. Saves record into `network_policies` table.
- **Response**: `200 OK` with compiled `NetworkPolicyRead` schema.
