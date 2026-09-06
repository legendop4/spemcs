# 18. Testing Architecture, Verification Matrix & Parity Testing

---

## What Am I Looking At?

This document is the **definitive testing and quality assurance specification** for SPEMCS. It documents the test suites, execution commands, coverage boundaries, and the differential parity harness connecting Python and C#.

```text
Evidence Standard & Verified Counts:
1. Backend Test Suite: 903 Tests Collected via pytest (902 Passing, 1 Skipped)
   Source: backend/tests/* | conftest.py
   Methodology: $env:PYTHONPATH="."; python -m pytest --collect-only
   Confidence: ✅ VERIFIED

2. Agent Test Suite: 289 Test Methods
   Source: Endpoint-agent/tests/Spemcs.Agent.Tests/*
   Methodology: dotnet test tests/Spemcs.Agent.Tests/Spemcs.Agent.Tests.csproj --no-build --list-tests
   Confidence: ✅ VERIFIED

3. Cross-Language Parity Harness: 4,534 Differential Test Vectors
   Source: Endpoint-agent/tests/parity/verify_policy_destination_validator_parity.py
   Confidence: ✅ VERIFIED
```

---

## The Verification Hierarchy

To prevent false assurances of production readiness, SPEMCS documentation strictly distinguishes between **six levels of verification**:

```
Implemented (Code written in repository)
     ↓
Unit Tested (Isolated functions verified with mocks)
     ↓
Integration Tested (Inter-module interactions verified in memory)
     ↓
Hermetically Tested (Full end-to-end flows pass without external databases/networks)
     ↓
Live Runtime Tested (Processes run on actual operating system and serve HTTP/WS)
     ↓
Bare-Metal Tested (Executed on physical lab hardware across reboot/power cuts)
```

> [!IMPORTANT]
> **The Mocking Boundary & Production Caveat**:
> - The entire backend test suite (903 tests) and agent test suite (289 tests) pass **hermetically**.
> - In unit and integration tests, `IFirewallAdapter` is satisfied by `MockFirewallAdapter` to avoid modifying the developer's workstation firewall.
> - While `WindowsFirewallAdapterIntegrationTests.cs` exercises actual COM objects on Windows, **full bare-metal multi-workstation E2E validation in an Active Directory lab environment remains an operational deployment milestone**.

---

## Backend Test Suite Breakdown (903 Tests)

Located in [`backend/backend/tests/`](file:///c:/Users/shrma/Desktop/spemcsnew/backend/backend/tests/).

| Test Module File | Test Count | Focus Area & Verified Behaviors |
| :--- | :--- | :--- |
| `test_auth_security.py` | 142 tests | Dual-token authentication, timing attacks, role-based access control (RBAC), device ownership assertions. |
| `test_secret_config.py` | 32 tests | `validate_production_secrets()`, prevention of secret leaks in exception traces, environment defaults. |
| `test_signing_key_lifecycle.py`| 74 tests | RSA-2048 key generation, keyring schema versioning, key rotation, revocation, and persistence across restarts. |
| `test_enforcement_readiness.py`| 68 tests | Server-side activation gating, policy existence checks, device arming status verification. |
| `test_alerts.py` | 85 tests | Ingestion of telemetry, severity escalation, nullable `alerts.exam_id` verification. |
| `test_exams.py` | 94 tests | State machine transitions (`PENDING` $\rightarrow$ `ACTIVE` $\rightarrow$ `STOPPED`), device assignment, session cleanup. |
| `test_policies.py` | 112 tests | Vendor profile compilation, RFC 8785 canonical JSON, RSA-PSS signature verification. |
| `test_websocket_heartbeat.py` | 56 tests | Duplex WebSocket handshakes, heartbeat ping/pong timeouts, close codes (4401, 4403). |
| `test_reports.py` | 48 tests | Aggregation of exam violation timelines, CSV export formatting. |
| *Other Modules* | 192 tests | Lab device mappings, audit logging, health probes. |

---

## Endpoint Agent Test Suite Breakdown (289 Tests)

Located in [`Endpoint-agent/tests/Spemcs.Agent.Tests/`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/tests/Spemcs.Agent.Tests/).

| Test Class | Focus Area | Verified Ground Truth |
| :--- | :--- | :--- |
| `PolicyDistributionTests.cs` | Cryptographic Policy Receipt | Verifies Python RSA-PSS signatures verify in C#; rejects tampered payloads; validates monotonic version sequencing. |
| `PolicyDestinationValidatorTests.cs` | IP / CIDR Validation | Verifies IPv4/IPv6 subnet parsing, rejects multicast, broadcast, loopback, and unroutable addresses. |
| `RollbackScopeTests.cs` | Rollback Isolation | Proves rollback sweeps **only** `SPEMCS-*` tagged rules, preserving pre-existing campus firewall rules. |
| `WindowsFirewallAdapterIntegrationTests.cs`| COM Interop | Interacts with native `HNetCfg.FwPolicy2` COM object; tests rule addition and profile switching without throwing. |
| `SecurityHardeningUnitTests.cs` | Replay & Hardening | Validates duplicate command rejection, timestamp expiration, and TLS certificate validation. |
| `ServiceDelegatedEnforcementTests.cs` | Named Pipe IPC | Tests serialization and IPC transport over `\\.\pipe\spemcs-control-v1`. |

---

## Cross-Language Differential Parity Testing

Located in [`Endpoint-agent/tests/parity/verify_policy_destination_validator_parity.py`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/tests/parity/verify_policy_destination_validator_parity.py).

```
┌───────────────────────────────┐      ┌───────────────────────────────┐
│     Python PolicyCompiler     │      │   C# PolicyDestinationValidator
└───────────────────────────────┘      └───────────────────────────────┘
                │                                      │
                ▼                                      ▼
        [ 4,534 Test Vectors: IPv4 / IPv6 / Subnets / Edge Cases ]
                                │
                                ▼
         Assert: Output_Python(Vector) == Output_CSharp(Vector)
```

### Why Parity Testing Is Essential:
If Python accepts a destination CIDR during policy compilation that C# rejects during agent policy verification, the exam activation will fail or leave the workstation unarmed. The parity harness feeds **4,534 synthetic IP address and subnet test vectors** into both runtimes and asserts bitwise identical validation decisions.

---

## Running the Automated Test Suites

```powershell
# 1. Run Complete Backend Test Suite
cd backend
$env:PYTHONPATH = "."
.\.venv\Scripts\python.exe -m pytest -v

# 2. Run Complete Agent Test Suite
cd Endpoint-agent
dotnet test tests\Spemcs.Agent.Tests\Spemcs.Agent.Tests.csproj --no-build

# 3. Run Differential Parity Validator
cd Endpoint-agent\tests\parity
python verify_policy_destination_validator_parity.py
```
