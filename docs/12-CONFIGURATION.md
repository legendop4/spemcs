# 12. Configuration Reference & Secret Rotation Runbook

---

## What Am I Looking At?

This document provides the exhaustive configuration specification for all SPEMCS components. It documents every environment variable used by the backend server, the configuration schemas used by the endpoint agent, and provides an actionable runbook for zero-downtime cryptographic secret rotation.

---

## Why Does It Exist?

Misconfiguration in security software causes catastrophic operational failures:
- If a server silently boots using default development credentials, the entire exam enclave is vulnerable to token forgery.
- If an environment variable is renamed or omitted without strict validation, the failure may surface mid-exam rather than during server startup.
- SPEMCS enforces **strict startup-time validation** via Pydantic: missing or placeholder secrets abort process launch before any network traffic is accepted.

---

## Complete Backend Environment Variables Matrix

Loaded centrally by [`backend/backend/app/config.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/app/config.py) from environment variables or `/etc/spemcs/backend.env`.

| Variable Name | Type | Default Value | Required in Production? | Description & Security Impact |
| :--- | :--- | :--- | :--- | :--- |
| `DATABASE_URL` | `str` | *None* | **YES** | PostgreSQL connection URI (`postgresql://user:pass@host:5432/dbname`). Must use TLS (`sslmode=require`). |
| `SPEMCS_ENV` | `str` | `"production"` | **YES** | Deployment environment. Defaults to `"production"` on purpose: setting `"development"` downgrades secret checks to warnings. |
| `SECRET_KEY` | `str` | `"dev-secret-change..."` | **YES** | Master HMAC secret for signing operator JWTs (HS256). Must be $\ge$ 32 characters of high-entropy random bytes. |
| `DEVICE_TOKEN_SECRET` | `str` | `"dev-device-token..."` | **YES** | HMAC key used to issue and verify hardware-bound machine tokens. Must be $\ge$ 32 characters. |
| `ENROLLMENT_BOOTSTRAP_KEY` | `str` | `"spemcs-enrollment..."`| **YES** | Pre-shared bootstrap key presented by workstations during initial enrollment. Timing-safe compared. |
| `SIGNING_KEY_DIR` | `str` | `""` (Default path) | NO | Absolute path to directory storing the RSA policy-signing keyring (`keyring.json`). Must be owned by service UID. |
| `SIGNING_KEY_PASSPHRASE` | `str` | `""` | NO | Passphrase used to encrypt the stored RSA private key (PKCS#8). If empty, relies on filesystem ACLs. |
| `SIGNING_KEY_ALLOW_EPHEMERAL`| `bool`| `False` | NO | Allows falling back to in-memory RSA key. Strictly **REFUSED** when `SPEMCS_ENV=production`. |
| `ACCESS_TOKEN_EXPIRE_MINUTES`| `int` | `480` (8 hours) | NO | Operator JWT expiration window in minutes. |
| `CORS_ORIGINS` | `List[str]` | `[]` | NO | Allowed CORS origins for operator browser access. Example: `["https://spemcs.univ.edu"]`. |
| `WS_HEARTBEAT_INTERVAL` | `int` | `30` | NO | Interval in seconds between WebSocket ping frames. |
| `WS_HEARTBEAT_TIMEOUT` | `int` | `10` | NO | Seconds to wait for a heartbeat pong before terminating a dead socket. |

---

## Endpoint Agent Configuration

Located in [`appsettings.json`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Service/appsettings.json) and `%ProgramData%\Spemcs\config.json`.

```json
{
  "Spemcs": {
    "BackendUrl": "https://spemcs.univ.edu:8002",
    "EnrollmentBootstrapKey": "<PRE_SHARED_BOOTSTRAP_KEY>",
    "HeartbeatIntervalSeconds": 30,
    "TelemetryFlushIntervalSeconds": 5,
    "LogDirectory": "C:\\ProgramData\\Spemcs\\Logs",
    "JournalDatabasePath": "C:\\ProgramData\\Spemcs\\sqlite_rollback_journal.db",
    "PipeName": "spemcs-control-v1",
    "ApprovedBrowsers": [
      {
        "Name": "chrome",
        "Executable": "chrome.exe",
        "Path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
      },
      {
        "Name": "edge",
        "Executable": "msedge.exe",
        "Path": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
      }
    ]
  }
}
```

---

## Production Secret Validation: `validate_production_secrets()`

Located in [`backend/backend/app/config.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/app/config.py#L180):
- Executes during FastAPI startup lifespan before connecting to the database.
- Inspects `SECRET_KEY`, `DEVICE_TOKEN_SECRET`, and `ENROLLMENT_BOOTSTRAP_KEY`.
- In `SPEMCS_ENV=production`:
  - Rejects any key containing `"dev-"`, `"change-in-production"`, or `"default"`.
  - Rejects any key with length $< 32$ characters.
  - Rejects `SIGNING_KEY_ALLOW_EPHEMERAL=True`.
- **Security Guarantee**: A problem description never contains the offending secret value or reveals secret lengths in logs.

---

## Secret Rotation Runbook

Follow this operational runbook to rotate secrets without causing exam disruption:

### 1. Rotating Operator `SECRET_KEY`
- **Blast Radius**: Invalidates all active operator browser sessions. Forces proctors to re-authenticate.
- **Downtime**: Zero downtime. Active exams and endpoint agents are completely unaffected.
- **Procedure**:
  1. Generate a fresh 64-character secret: `openssl rand -hex 32`.
  2. Update `SECRET_KEY` in `/etc/spemcs/backend.env`.
  3. Reload systemd service: `systemctl reload spemcs-backend`.
  4. Active proctors will receive a 401 response and re-login via `/login`.

### 2. Rotating `DEVICE_TOKEN_SECRET`
- **Blast Radius**: Invalidates current workstation machine tokens.
- **Prerequisite**: Must be performed **between examination sessions** when no exam is active.
- **Procedure**:
  1. Generate new secret: `openssl rand -hex 32`.
  2. Update `DEVICE_TOKEN_SECRET` in `/etc/spemcs/backend.env`.
  3. Restart backend service: `systemctl restart spemcs-backend`.
  4. Endpoint agents receive 401 on next heartbeat and automatically re-authenticate via their persistent bootstrap key against `/api/v1/devices/register`.

### 3. Rotating the RSA Policy-Signing Key
- **Blast Radius**: None. Existing active policies continue to verify against their original `key_id`.
- **Procedure**:
  1. Operator clicks "Rotate Key" in web dashboard (`POST /api/policies/signing-key/rotate`).
  2. Backend generates a new RSA-2048 keypair, appends it to `/backend/secrets/keyring.json`, marks it `active`, and sets the old key to `retired`.
  3. New exams are signed with the fresh key; existing exams finish cleanly under their original key.
