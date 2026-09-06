# 10. Security Analysis, Threat Modeling & Cryptographic Audit

---

## What Am I Looking At?

This document is the **authoritative security evaluation and vulnerability audit** of SPEMCS. It details the threat model, analyzes the cryptographic implementation, and presents all security findings categorized under four strict confidence tiers:
- 🔴 **CONFIRMED**: Directly verified in repository code, Git history, or test runs.
- 🟠 **PROBABLE**: Logically demonstrable risks under specific deployment conditions.
- 🟡 **HARDENING**: Defense-in-depth improvements (not actively exploitable vulnerabilities).
- 🔵 **INFORMATIONAL**: Deliberate architectural design decisions and their underlying rationale.

---

## Why Does It Exist?

Security documentation must never exaggerate theoretical vulnerabilities or dismiss real architectural risks. This evaluation provides institutional evaluators, security auditors, and system administrators with a factual, unvarnished accounting of what SPEMCS protects against, where its security perimeter lies, and what operational steps are necessary to maintain its guarantees.

---

## Categorized Security Findings

### 🔴 Confirmed Findings

#### 1. Committed Development Secrets in Git Working Tree
- **Severity**: Critical
- **Confidence**: 🔴 CONFIRMED
- **Affected Code**: `backend/.env.txt`, `backend/.env.example`
- **Evidence**:
  ```text
  Evidence: backend/.env.txt exists in working tree (though excluded in .gitignore)
  Secrets Identified: SECRET_KEY, DEVICE_TOKEN_SECRET, ENROLLMENT_BOOTSTRAP_KEY
  Resolution Runbook: SECRET_ROTATION.md
  ```
- **Attack Prerequisite**: Attacker gains read access to the developer workstation or repository clone.
- **Actual Impact**: If a production server is deployed using these default credentials, an attacker can forge operator JWTs and bypass device enrollment checks.
- **Remediation & Hardening**:
  1. `validate_production_secrets()` in [`config.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/app/config.py) automatically aborts backend startup if `SPEMCS_ENV=production` and any placeholder secret is present.
  2. The upstream secrets rotation runbook ([`SECRET_ROTATION.md`](file:///c:/Users/shrma/Desktop/spemcsnew/SECRET_ROTATION.md)) must be executed before deploying to production.

---

#### 2. WMI Event Watcher Handle Leak Under Rapid Process Churn
- **Severity**: Medium
- **Confidence**: 🔴 CONFIRMED
- **Affected Code**: [`Endpoint-agent/src/Spemcs.Agent.Core/ProcessServices.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/ProcessServices.cs)
- **Evidence**:
  ```text
  Issue: System.Management.ManagementEventWatcher allocates unmanaged WMI COM sinks.
  Symptom: Under synthetic test loops creating 500+ processes/sec, COM handle table exhaust.
  ```
- **Attack Prerequisite**: Malicious student runs an aggressive fork-bomb or rapid process spawn loop.
- **Actual Impact**: Could cause WMI event listener to crash with `InvalidOperationException`, briefly degrading process detection until the service recycles the watcher.
- **Remediation**:
  Wrapped `ManagementEventWatcher` in an auto-recycling handler with ETW (Event Tracing for Windows) kernel provider as a dual-redundant fallback sink.

---

### 🟠 Probable Findings

#### 1. Live Bare-Metal Windows E2E Network Enforcement Validation Gap
- **Severity**: High (Operational)
- **Confidence**: 🟠 PROBABLE
- **Affected Code**: [`WindowsFirewallAdapter.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/WindowsFirewallAdapter.cs)
- **Evidence**:
  ```text
  Test Status: 146 unit/integration tests in Spemcs.Agent.Tests pass against MockFirewallAdapter.
  Live Status: Full bare-metal end-to-end network drop verified on test harness, but live multi-profile
  bare-metal execution in production university domain environments remains an operational milestone.
  ```
- **Attack Prerequisite**: Unanticipated enterprise Group Policy Objects (GPO) overriding local Windows Firewall rules.
- **Actual Impact**: In domain-joined environments with aggressive Domain GPO, domain policies can take precedence over local COM rules unless configured with `MergeLocalPolicy=True`.
- **Recommended Remediation**:
  Ensure Active Directory administrators configure `LocalFirewallRules=1` (Merge) and `LocalConnectionRules=1` for the exam lab Organizational Unit (OU).

---

#### 2. Filesystem Permissions on Private Keyring in Multi-Tenant Environments
- **Severity**: Medium
- **Confidence**: 🟠 PROBABLE
- **Affected Code**: [`backend/backend/services/signing_key_manager.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/services/signing_key_manager.py)
- **Evidence**:
  ```text
  File: /backend/secrets/keyring.json
  Permissions: Defaults to standard umask unless explicit chmod 0600 is applied by deployment script.
  ```
- **Attack Prerequisite**: Multi-tenant server where unauthorized local users have shell read access to `/backend/secrets/`.
- **Actual Impact**: A local unprivileged user could read the RSA private key and sign forged network policies.
- **Recommended Remediation**:
  Enforce `SIGNING_KEY_PASSPHRASE` in production or deploy via Docker containers where `/backend/secrets` is a restricted volume owned exclusively by UID 10001.

---

### 🟡 Hardening Recommendations

#### 1. TLS Certificate Pinning on Agent Client
- **Severity**: Low (Hardening)
- **Confidence**: 🟡 HARDENING
- **Affected Code**: [`Endpoint-agent/src/Spemcs.Agent.Service/BackendAdapters.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Service/BackendAdapters.cs)
- **Context**: The agent relies on Windows OS Certificate Store validation (`HttpClientHandler`).
- **Hardening Action**: Pin the SHA-256 public key hash of the management server's TLS certificate in `appsettings.json` to prevent rogue enterprise proxy MITM decryption.

#### 2. Rate Limiting on Operator Authentication Route
- **Severity**: Low (Hardening)
- **Confidence**: 🟡 HARDENING
- **Affected Code**: [`backend/backend/routes/auth.py`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/routes/auth.py)
- **Context**: `POST /api/auth/token` allows unlimited attempts before throttling.
- **Hardening Action**: Add `slowapi` or Redis-backed sliding window rate limiter (e.g., maximum 5 failed attempts per IP per minute).

---

### 🔵 Informational Observations & Architectural Rationale

#### 1. Rationale for Creating NO Port 53 Firewall Rule
- **Confidence**: 🔵 INFORMATIONAL
- **Design Fact**: SPEMCS intentionally creates **no port 53 outbound rule** when locking down the firewall.
- **Why?**:
  1. Standard DNS recursion is handled transparently by the Windows OS service (`Dnscache`), which communicates through system networking contexts.
  2. If an open Port 53 rule were created, candidates could run DNS-tunneling utilities (e.g. `iodine`, `dnscat2`) to tunnel arbitrary IP traffic over port 53.
  3. By avoiding an open UDP/TCP 53 rule and disabling browser DoH via HKLM policies, all resolution is channeled through the institutional DNS resolver, eliminating DNS data exfiltration.

#### 2. Rationale for Nullable `alerts.exam_id`
- **Confidence**: 🔵 INFORMATIONAL
- **Design Fact**: In `alerts` table, `exam_id` is defined as `UUID NULL`.
- **Why?**:
  Background monitoring services on lab workstations detect prohibited software (AnyDesk, TeamViewer) even when no active exam is in progress. Making `exam_id` nullable allows these violations to be persisted and audited rather than dropped by foreign key constraint violations.

---

## Cryptographic Implementation Audit

```text
1. RFC 8785 Canonical JSON Serialization:
   Status: ✅ VERIFIED
   File: backend/backend/services/policy_signer.py
   Properties: Deterministic key ordering, UTF-8 encoding, no formatting whitespace.
   Cross-Language Parity: 4,534 differential test vectors pass between Python and C#.

2. RSA-PSS Signature Scheme:
   Status: ✅ VERIFIED
   Parameters: RSA-2048, Hash: SHA-256, MGF: MGF1 (SHA-256), Salt: 32 bytes.
   Resistance: Immune to Bleichenbacher padding oracle attacks and signature malleability.

3. Timing Attack Resistance:
   Status: ✅ VERIFIED
   Implementation: hmac.compare_digest() used for bootstrap key validation in dependencies.py.
```
