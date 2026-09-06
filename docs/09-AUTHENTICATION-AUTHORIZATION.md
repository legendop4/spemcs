# 09. Authentication, Authorization & Cryptographic Trust Domains

---

## What Am I Looking At?

![Trust Boundaries & Credential Matrix](diagrams/04-trust-boundaries.svg)

This document is the authoritative cryptographic reference for SPEMCS authentication and authorization. Rather than using a single shared secret or generic JWT across the system, SPEMCS implements **Four Strictly Separated Trust Domains**:

1. **Operator Identity**: Human staff carrying a Bearer JWT signed by `SECRET_KEY`.
2. **Device Identity**: Enrolled lab machines carrying an HMAC token signed by `DEVICE_TOKEN_SECRET`.
3. **Enrollment Bootstrap**: Installation secret compared in constant-time via `ENROLLMENT_BOOTSTRAP_KEY`.
4. **Policy Integrity**: Cryptographic keyring using RSA-2048 with RSA-PSS (SHA-256) signatures.

```text
Evidence Standard:
File: backend/app/dependencies.py & backend/services/auth_service.py
Evidence: Explicit separation of operator gates vs require_device vs require_enrollment_key
Verification: 469 hermetic security tests passing in test_auth_security.py
Confidence: ✅ VERIFIED
```

---

## Why Does It Exist?

In multi-tier systems, credential confusion is a leading cause of severe security vulnerabilities:
- **Token Confusion Attack**: If a machine token can be used on an administrative endpoint, an attacker who extracts a device token from a lab PC can elevate privileges to administrator and alter exam grades.
- **Workstation Impersonation**: If authentication only verifies "is this a valid machine token" without asserting "does this token belong to PC #14", Workstation A can submit fake violation events attributed to Workstation B.
- **Timing Attacks on Static Secrets**: Using standard string comparison (`==`) on bootstrap keys leaks secret length and byte values through microsecond response timing differences.

---

## The 4 Distinct Trust Domains

| Trust Domain | Subject | Secret Configuration | Cryptographic Algorithm | Token Lifetime | Scope & Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Operator JWT** | Human (`admin`, `proctor`) | `SECRET_KEY` | HS256 (HMAC-SHA256) | 480 minutes (8 hours) | Management CRUD, activating exams, resolving alerts. |
| **2. Device Token** | Machine (Hardware UUID) | `DEVICE_TOKEN_SECRET` | HMAC-SHA256 over Canonical JSON | 30 days | Heartbeats, process telemetry, policy fetching. |
| **3. Bootstrap Key** | Unenrolled Workstation | `ENROLLMENT_BOOTSTRAP_KEY` | Timing-Safe String (`hmac.compare_digest`) | Static pre-shared key | Initial machine registration (`POST /api/v1/devices/register`). |
| **4. Policy Keyring** | Network Policy Document | `SIGNING_KEY_DIR` | RSA-2048, RSA-PSS (SHA-256, MGF1) | Policy validity window | Immutable firewall lockdown distribution. |

---

## What Happens Internally?

### 1. Operator Login & Session Lifecycle

```mermaid
sequenceDiagram
    autonumber
    participant Browser as Operator Browser SPA
    participant AuthRouter as backend/routes/auth.py
    participant AuthService as backend/services/auth_service.py
    participant DB as PostgreSQL (users table)
    participant Dep as backend/app/dependencies.py

    Browser->>AuthRouter: POST /api/auth/token (username, password)
    AuthRouter->>AuthService: authenticate_user(db, username, password)
    AuthService->>DB: SELECT * FROM users WHERE username = ...
    DB-->>AuthService: User record (with password_hash)
    AuthService->>AuthService: verify_password(password, user.password_hash)
    AuthService->>AuthService: create_access_token(data={"sub": user.user_id, "role": user.role})
    AuthService-->>Browser: JSON: { access_token: "<jwt>", token_type: "bearer" }
    
    Note over Browser: Stores token in localStorage<br/>Attaches Authorization: Bearer <jwt>

    Browser->>AuthRouter: POST /api/exams/activate
    AuthRouter->>Dep: require_admin(token)
    Dep->>Dep: Decodes JWT with SECRET_KEY
    Dep->>Dep: Asserts role == "admin" (403 if false)
    Dep-->>AuthRouter: Yields authenticated Admin User
```

---

### 2. Workstation Bootstrap Enrollment & Device Token Issuance

```mermaid
sequenceDiagram
    autonumber
    participant Workstation as Windows Service (Session 0)
    participant AgentRouter as backend/routes/agent_api.py
    participant Dep as backend/app/dependencies.py
    participant AuthService as backend/services/auth_service.py
    participant DB as PostgreSQL (devices table)

    Note over Workstation: Workstation powers up.<br/>Holds ENROLLMENT_BOOTSTRAP_KEY in config.
    Workstation->>AgentRouter: POST /api/v1/devices/register<br/>Header: X-Enrollment-Key: <key><br/>Body: { hardware_uuid, device_name, ip }
    AgentRouter->>Dep: require_enrollment_key(x_enrollment_key)
    Dep->>Dep: hmac.compare_digest(x_enrollment_key, settings.ENROLLMENT_BOOTSTRAP_KEY)
    Note over Dep: Timing-safe comparison prevents side-channel probing
    AgentRouter->>DB: Find or create device by hardware_uuid
    AgentRouter->>AuthService: generate_device_token(hardware_uuid, roles=["device"])
    AuthService->>AuthService: Signs claims with DEVICE_TOKEN_SECRET (HMAC-SHA256)
    AgentRouter-->>Workstation: 200 OK: { device_id, token, expires_at }
    Note over Workstation: Stores token in C:\ProgramData\Spemcs\credential_store
```

---

### 3. Device Ownership Verification (`assert_device_owns`)

```mermaid
sequenceDiagram
    autonumber
    participant Workstation as Lab Workstation A (UUID: 4C4C4544...)
    participant EventsRouter as backend/routes/events.py
    participant Dep as backend/app/dependencies.py

    Note over Workstation: Workstation A submits an event
    Workstation->>EventsRouter: POST /api/v1/events<br/>Header: X-Device-Token: <token_A><br/>Body: { device_id: "B-UUID", event: "..." }
    EventsRouter->>Dep: require_device() -> yields DeviceIdentity(UUID_A)
    EventsRouter->>Dep: assert_device_owns(DeviceIdentity, claimed_uuid="B-UUID")
    Note over Dep: Compares DeviceIdentity.hardware_uuid == claimed_uuid
    Dep-->>Workstation: HTTP 403 Forbidden: "Device token is not authorized for this device"
```

---

### 4. First-Frame WebSocket Handshake (`/api/v1/ws/dashboard`)

```mermaid
sequenceDiagram
    autonumber
    participant Browser as Proctor Browser (AppContext)
    participant Hub as backend/websocket/realtime.py
    participant AuthService as backend/services/auth_service.py

    Browser->>Hub: WebSocket Connect (/api/v1/ws/dashboard)
    Hub-->>Browser: Connection Accepted (Pending Auth)
    Note over Hub: Starts 5-second disconnect timer
    Browser->>Hub: Frame: { "type": "AUTHENTICATE", "token": "<operator_jwt>" }
    Hub->>AuthService: decode_token(token, SECRET_KEY)
    alt Token Valid & Role in ["admin", "proctor"]
        Hub-->>Browser: Frame: { "type": "AUTHENTICATED", "user_id": "..." }
        Note over Hub: Added to active dashboard broadcast pool
    else Token Expired or Invalid
        Hub-->>Browser: WS Close Frame: Code 4401 (Unauthorized)
    else Insufficient Role (e.g. device token presented)
        Hub-->>Browser: WS Close Frame: Code 4403 (Forbidden)
    end
```

---

## Which Code Implements It?

### 1. `backend/backend/app/dependencies.py`
- [`require_authenticated`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/app/dependencies.py#L53): General operator gate.
- [`require_staff`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/app/dependencies.py#L56): `admin` and `proctor` roles.
- [`require_admin`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/app/dependencies.py#L59): `admin` role only.
- [`require_device`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/app/dependencies.py#L82): Enrolled machine gate.
- [`assert_device_owns`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/app/dependencies.py#L129): Workstation ownership check.
- [`require_enrollment_key`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/app/dependencies.py#L168): Timing-safe bootstrap gate.

### 2. `backend/backend/services/auth_service.py`
- `verify_password(plain, hashed)`: Secure password check.
- `create_access_token(data, expires_delta)`: Issues operator JWTs.
- `verify_device_token(token)`: Validates machine HMAC tokens.

### 3. `backend/backend/services/signing_key_manager.py`
- `SigningKeyManager.sign_policy(payload)`: Applies RSA-PSS SHA-256 signatures.
- `SigningKeyManager.verify_policy(payload, signature)`: Validates policy integrity.

---

## What Happens When It Fails?

| Violation Condition | Gate Encountered | HTTP / WS Code | Internal Error Detail |
| :--- | :--- | :--- | :--- |
| Missing Authorization header | `require_authenticated` | `401 Unauthorized` | `"Not authenticated"` |
| Expired operator JWT | `require_authenticated` | `401 Unauthorized` | `"Could not validate credentials"` |
| Proctor calls `/api/exams/activate` | `require_admin` | `403 Forbidden` | `"Operation requires administrator privileges"` |
| Device token used on management route | `require_staff` | `401 Unauthorized` | Rejects non-JWT format |
| Malformed or forged device token | `require_device` | `401 Unauthorized` | Uniform message: `"Invalid or expired device token"` |
| Device A submits event for Device B | `assert_device_owns` | `403 Forbidden` | `"Device token is not authorized for this event"` |
| Wrong bootstrap key on enrollment | `require_enrollment_key` | `401 Unauthorized` | `"Invalid or missing enrollment bootstrap key"` |
| Dashboard WS timeout (>5s without auth) | `dashboard_websocket` | Close `4401` | Disconnects pending socket |
