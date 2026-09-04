# SPEMCS — Takeover Audit & Network Lockdown Compliance Report

**Audit date:** 2026-09-04
**Auditor scope:** Read-only. No file in this repository was created, edited, deleted or executed except this report. No firewall setting was read or changed on the host. The rule `codex_sandbox_offline_block_outbound` was not touched.
**Method:** Static analysis of the repository plus analysis of committed live agent runtime logs (`out.txt`, `out1.txt`).

---

## PART A — CRITICAL REQUIREMENT AUDIT: EXAM NETWORK LOCKDOWN

Verdict summary against the ten stated requirements.

| # | Requirement | Status | Responsible code (verified) |
|---|---|---|---|
| 1 | Default outbound BLOCKED | IMPLEMENTED BUT UNVERIFIED | `NetworkEnforcer.ApplyEnforcementAsync` → `WindowsFirewallAdapter.SetDefaultOutboundAction` |
| 2 | Only vendor-profile destinations reachable | PARTIALLY IMPLEMENTED | `EnforcementStateMachine.BuildSessionRules` + `policy_compiler.compile_exam_policy` |
| 3 | Destinations as trusted resolved IPs/CIDRs | PARTIALLY IMPLEMENTED | `validate_and_normalize_ip_network`; **no resolver exists** |
| 4 | Allowed traffic scoped to approved browser | **MISSING** | No application field in policy schema or rule builder |
| 5 | Other apps must not reuse the allowlist | **BROKEN** | Consequence of #4 — rules are program-agnostic |
| 6 | All three profiles handled | IMPLEMENTED | `FirewallProfiles.All` in `BuildSessionRules` |
| 7 | Explicit IPv6 isolation | **MISSING** (loopback only) | `CreateLoopbackIPv6Allow` is the only IPv6 code |
| 8 | No DNS-tunnelling bypass | PARTIALLY IMPLEMENTED | `BrowserPolicyEnforcer.DisableSecureDns`; DNS blocked by omission |
| 9 | Exact baseline restore | PARTIALLY IMPLEMENTED / BUGGY | `NetworkEnforcer.RestoreBaselineSafely` |
| 10 | No blanket explicit BLOCK rule | **IMPLEMENTED / COMPLIANT** | `CreateOutboundAllow` hardcodes `Action = Allow` |

Requirements 4, 5 and 7 are not implemented. Requirement 5 is the security-critical one: **the current lockdown is destination-scoped, not application-scoped.**

---

### Requirement 1 — Default outbound traffic must be BLOCKED

**Status: IMPLEMENTED BUT UNVERIFIED.**

The mechanism exists and is correct in design.

- `Endpoint-agent/src/Spemcs.Agent.Core/Network/NetworkEnforcer.cs`, `ApplyEnforcementAsync` — at the `EnforcingDefaultBlock` phase calls
  `_firewall.SetDefaultOutboundAction(session.TargetProfiles, FirewallAction.Block)` (line 105).
- `Endpoint-agent/src/Spemcs.Agent.Core/Network/WindowsFirewallAdapter.cs`, `SetDefaultOutboundAction` (lines 48–82) — sets the COM property `DefaultOutboundAction` per profile flag via `InvokeMember(..., BindingFlags.SetProperty, ...)`.
- Post-set verification: `ApplyEnforcementAsync` re-reads the baseline (lines 112–117) and throws if any targeted profile is not `Block`. This is a genuine readback assertion, not a log line.

**Why "unverified":** `HANDOFF.md` §3 and §5 state that live Windows E2E enforcement has never been proven, with Run E listed as an `ACTIVE OPEN ISSUE`. The committed runtime logs (`out.txt`, `out1.txt`, covering 12:00–12:09 on 2026-09-04) contain **no enforcement attempt at all** — no `ApplyEnforcementAsync`, no baseline capture, no rule insertion. So the block path has unit-test coverage but no evidence of a successful live run.

---

### Requirement 2 — Only approved exam/vendor profile destinations may be reached

**Status: PARTIALLY IMPLEMENTED.**

The plumbing is real and end-to-end:

- **Backend, vendor profile storage:** `backend/backend/models/policy.py` lines 31–34 — `required_domains`, `approved_ip_ranges`, `required_tcp_ports` (default `[80, 443]`), `required_udp_ports` (default empty), all JSONB.
- **Backend, compilation:** `backend/backend/services/policy_compiler.py`, `compile_exam_policy` — emits `allowed_destinations` into the signed payload; each destination is `{name, domains, ip_ranges, tcp_ports, udp_ports}`.
- **Agent, rule generation:** `Endpoint-agent/src/Spemcs.Agent.Core/Network/EnforcementStateMachine.cs`, `BuildSessionRules` (lines 675–773) — iterates `policy.AllowedDestinations`, then `dest.IpRanges`, emitting a TCP allow rule when `dest.TcpPorts.Count > 0` and a UDP allow rule when `dest.UdpPorts.Count > 0`.
- **Frontend:** `frontend/src/pages/ExamShieldPage.tsx` line 541 (Vendor Profile Selection); lines 95–96 make a vendor profile mandatory when `network_enforcement` is on.

**Why only partial:**

1. `dest.Domains` is carried through the signed policy but **never consumed** by `BuildSessionRules`. Domain-based allowlisting is not enforced; only `ip_ranges` become rules.
2. Because requirement 4 is missing, "only approved destinations may be reached" holds for *destinations* but the reachability is granted to *every process on the machine*, not just the exam browser.

---

### Requirement 3 — Approved destinations as trusted resolved IPs/CIDRs in the signed policy

**Status: PARTIALLY IMPLEMENTED — the signed-policy half is real; the resolution half does not exist.**

What genuinely works:

- **CIDR normalisation:** `backend/backend/services/policy_compiler.py`, `validate_and_normalize_ip_network` — bare IPs are widened to `/32` (IPv4) or `/128` (IPv6); `normalize_ip_network_list` applies it across the list. So whatever is stored *is* a canonical CIDR.
- **Signing:** `backend/backend/services/policy_signer.py` — RSA-2048 / RSA-PSS / SHA-256 / MGF1-SHA-256 / SaltLength 32, over a canonical JSON serialisation (`canonical_json.py`).
- **Agent-side verification:** `Endpoint-agent/src/Spemcs.Agent.Core/Network/PolicyReceiver.cs` lines 186–198 — `RSASignaturePadding.Pss` with `HashAlgorithmName.SHA256`; rejects with `PolicyAcceptanceStatus.InvalidSignature`. Key resolution via `ITrustedKeyStore.GetPublicKey(keyId)`.
- Replay and window protection: monotonic policy `version`, plus `not_before` / `expires_at`.

**What is missing:** there is **no DNS resolution anywhere in the backend.** The word "resolved" in the requirement is satisfied only if a human supplies the addresses.

- `backend/backend/routes/policies.py` line 146 — `resolved_destinations=payload.resolved_destinations`, an optional caller-supplied field on `PolicyCompileRequest`.
- `policy_compiler.compile_exam_policy` takes `resolved_destinations=None` by default. Nothing calls `socket.getaddrinfo`, `dns.resolver`, or equivalent.

**Consequence:** if the operator does not hand-supply IPs, `allowed_destinations` carries `domains` that the agent ignores, and the compiled policy yields **zero destination allow rules** — a fully sealed machine with an unreachable exam portal. This is consistent with the documented Run C/E failures.

**Trust boundary note (correct as designed):** the frontend never signs. Compilation and signing are server-side under `require_role(["admin"])` (`routes/policies.py` line 118), and the agent verifies the signature under `NT AUTHORITY\SYSTEM`. That part of the chain is sound.

---

### Requirement 4 — Allowed exam traffic must be scoped to the approved browser (chrome.exe)

**Status: MISSING. Not implemented at any layer.**

This is the most important negative finding. I traced it through all four layers; there is no application/executable binding anywhere in the enforcement path.

**Layer 1 — Agent rule builder.** `EnforcementStateMachine.BuildSessionRules` (lines 675–773) passes `applicationPath: null` on **every** rule it creates — the management rule, both loopback rules, and every destination TCP/UDP rule:

```csharp
rules.Add(FirewallRuleModel.CreateOutboundAllow(
    sessionId: sessionId, purpose: "Mgmt", protocol: FirewallProtocol.TCP,
    remoteAddresses: cleanIp, remotePorts: policy.ManagementServer.Port.ToString(),
    localAddresses: "*", applicationPath: null, serviceName: null, profiles: targetProfiles));
```

**Layer 2 — Policy schema (agent side).** `Endpoint-agent/src/Spemcs.Agent.Core/Network/PolicyDistributionModels.cs`:

```csharp
PolicyDestination(string Name, IReadOnlyList<string> Domains,
                  IReadOnlyList<string> IpRanges,
                  IReadOnlyList<int> TcpPorts, IReadOnlyList<int> UdpPorts)
```

There is no application, executable, program or binary field. `ValidatedPolicy` likewise has no browser field.

**Layer 3 — Backend compiler.** `policy_compiler.py`, `compiled_payload` contains exactly `schema_version`, `key_id`, `exam_id`, `policy_id`, `version`, `vendor_profile_id`, `allowed_destinations`, `management_server`, `not_before`, `expires_at`. No application field. Therefore **the approved browser is not a signed attribute** — even if the agent wanted to scope by program, the signed policy does not carry the value.

**Layer 4 — The `approved_browser` field that does exist is used for something else.**
- `backend/backend/models/exam.py` line 41 — `approved_browser = Column(String(20), nullable=False)`.
- `frontend/src/pages/ExamShieldPage.tsx` line 48 / 114 / 508 — hardcoded to `'chrome'`, and Chrome is the only `<option>`.
- `backend/backend/services/realtime_service.py` line 34 — `"approved_browser": exam.approved_browser` is sent in the **exam activation** payload, not the network policy.
- Its only consumer is process classification, not firewall scoping.

**The capability exists but is unused.** `FirewallRuleModel` has an `ApplicationPath` property and `WindowsFirewallAdapter.AddRule` honours it:

```csharp
if (!string.IsNullOrWhiteSpace(rule.ApplicationPath))
{
    fwRule.ApplicationName = rule.ApplicationPath;
}
```

So the adapter is ready; nothing ever populates the field. This is a wiring gap, not an architectural rewrite.

**Do not mistake `NetworkPolicyEvaluator` for this feature.** `Endpoint-agent/src/Spemcs.Agent.Core/NetworkPolicyEvaluator.cs` contains `ApprovedBrowsers`, `isApprovedBrowser`, `StandardWebPorts` and `EnableUnclassifiedRule` (lines 40, 145, 147, 177). It inspects *observed* connections after the fact and raises telemetry events. It does not create, scope, or influence a single firewall rule. It is exactly the "similarly named class" the requirement warns about.

---

### Requirement 5 — Other applications must not use the whitelisted destination

**Status: BROKEN. This is a live bypass, not a theoretical one.**

This follows deterministically from requirement 4. Every generated allow rule has `ApplicationName` unset, so Windows Firewall applies it to **all processes**. Under active lockdown:

- `curl.exe https://<exam-portal-ip>` succeeds.
- `python -c "import socket; ..."` to an allowlisted IP:port succeeds.
- Any process — including a student's own tooling — can transit the allowlist.
- Anything CDN-hosted is worse: allowlisting a shared CDN or cloud egress IP range opens that range to every process on the box.

The requirement as stated is therefore not met, and the exam-integrity guarantee the lockdown is supposed to provide does not currently hold.

**A second, independent defect undermines browser scoping even at the process layer.** In `Endpoint-agent/src/Spemcs.Agent.Core/ProcessServices.cs`, `ConfigurableProcessClassifier` accepts an `approvedFamily` constructor argument (line 190), stores it (line 196 → field declared line 120) — and **never reads it again.** Verified: `grep -n "_approvedFamily\|approvedFamily" ProcessServices.cs` returns only lines 120, 190, 196.

Meanwhile lines 256–278 unconditionally classify **both** Chrome and Edge as `Approved Examination Browser`:

- lines 261–262: `chrome.exe` in `Google\Chrome\Application` with a Google publisher → `Allowed`.
- lines 273–274: `msedge.exe` in `Microsoft\Edge\Application` with a Microsoft publisher → `Allowed`.

So `DESIGN_DECISIONS.md`'s "exactly one of Chrome/Firefox/Edge" policy is not enforced. An exam configured for Chrome still permits Edge. The exam's `approved_browser` value has no effect on classification.

---

### Requirement 6 — All Domain, Private and Public profiles handled

**Status: IMPLEMENTED.**

- `Endpoint-agent/src/Spemcs.Agent.Core/Network/EnforcementModels.cs` lines 8–16 — `[Flags] FirewallProfiles { None = 0, Domain = 1, Private = 2, Public = 4, All = 7 }`.
- `EnforcementStateMachine.cs` line 540 — `var targetProfiles = FirewallProfiles.All;`. Also the default parameter value at lines 41 and 100.
- Every rule factory (`CreateOutboundAllow`, `CreateLoopbackIPv4Allow`, `CreateLoopbackIPv6Allow`) defaults `profiles = FirewallProfiles.All`, so the COM `Profiles` bitmask is `7`.
- `WindowsFirewallAdapter.SetDefaultOutboundAction` (lines 70–81) tests each flag independently and sets Domain, Private and Public separately.

Profile-switch bypass is genuinely closed: both the allow rules and the default-block apply to all three profiles. `LogAndVerifyRules` additionally asserts profile-bitmask coverage — but note it does so **only for the loopback rules** (see §7 of Part B).

---

### Requirement 7 — IPv6 must be contained; explicit IPv6 isolation

**Status: MISSING as specified. Only IPv6 loopback is handled.**

An exhaustive grep for IPv6 constructs across the entire enforcement subsystem (`Endpoint-agent/src/Spemcs.Agent.Core/Network/`) returns just four things, all loopback or comments:

- `EnforcementModels.cs` lines 147–168 — `CreateLoopbackIPv6Allow`, `RemoteAddresses`/`LocalAddresses` = `::/127`.
- `EnforcementStateMachine.cs` line 690 — the call that adds it.
- `EnforcementStateMachine.cs` line 688 — a comment saying `::1` while the code uses `::/127` (harmless, but misleading).
- `IManagementConnectivityVerifier.cs` line 87 — a comment about avoiding IPv6 resolution delay.

There is **no** explicit IPv6 isolation: no separate IPv6 default-block handling, no disabling or blocking of transition/tunnel interfaces (`Teredo`, `6to4`, `ISATAP` appear nowhere in the codebase), and no IPv6-specific validation in `BuildSessionRules`.

**Partial mitigation that does exist:** Windows' `DefaultOutboundAction = Block` is address-family agnostic, so plain IPv6 outbound traffic *is* denied by the profile default. That covers the common case. What is not covered is the requirement's "explicit IPv6 isolation", and tunnelled IPv6 over an allowlisted IPv4 destination is unaddressed.

The `::/127` choice is deliberate and correct — `README.md` §7 item 5 records that the team confirmed Windows' IPv6 loopback representation by inspecting an existing host rule, and `HANDOFF.md` §10 warns against reverting it to `::1`. Keep it.

---

### Requirement 8 — DNS handling must not create a tunnelling/exfiltration bypass

**Status: PARTIALLY IMPLEMENTED. No tunnel exists today, but for the wrong reason, and the anti-DoH control is weak.**

**What is genuinely implemented — DoH suppression.** `Endpoint-agent/src/Spemcs.Agent.Core/ProcessServices.cs`, `BrowserPolicyEnforcer.DisableSecureDns` (line 401 onward), invoked at `AgentWorker.ExecuteAsync` line 42:

- Sets `HKLM\SOFTWARE\Policies\Microsoft\Edge` and `...\Google\Chrome` → `DnsOverHttpsMode = "off"` (lines 406–417).
- Firefox: writes `dns_over_https.mode = off` into `policies.json` (line 458).
- Confirmed working in the live logs: `"Browser Secure DNS policy enforced: Configured HKLM policy for Microsoft\Edge (DnsOverHttpsMode=off); Configured HKLM policy for Google\Chrome (DnsOverHttpsMode=off)"`.

This is a real control with a clear purpose — force DNS through the OS resolver so the ETW DNS listener can observe it. Credit where due.

**Three weaknesses:**

1. **HKCU fallback is student-writable.** Lines 422–425: if the HKLM write fails, it falls back to `Registry.CurrentUser`. A non-admin student can simply delete or edit their own HKCU policy key and re-enable DoH. The fallback converts a machine policy into a user preference.
2. **Coverage is three browsers only.** Any other DoH-capable client — a portable browser, a script, `curl --doh-url` — is unaffected.
3. **DNS is blocked by omission, not by design.** No rule for port 53 is ever generated: `required_udp_ports` defaults to an empty list (`models/policy.py` line 34) and port 53 appears in the enforcement subsystem nowhere (it occurs only in `backend/backend/tests/test_policy_compiler.py` lines 456–457). So under lockdown, DNS is denied by the profile default.

**The practical implication cuts both ways.** There is no DNS-tunnelling vector today because there is no DNS at all — which also means hostname resolution fails and a real exam portal is unreachable by name. The moment an operator adds UDP/53 to a vendor profile to fix that, it becomes an **unrestricted tunnelling channel for every process on the machine**, precisely because of requirement 4/5. Requirements 4 and 8 are coupled: app-scoping is the prerequisite for safely allowing DNS.

---

### Requirement 9 — Deactivation/rollback must restore the exact pre-exam baseline

**Status: PARTIALLY IMPLEMENTED. The design is sound; three defects prevent "exact".**

**What works.** `NetworkEnforcer.ApplyEnforcementAsync` captures the baseline *before* any mutation and journals it durably (`SqliteRollbackJournal`, `%ProgramData%\Spemcs\network_journal.db`, WAL mode). `FirewallProfileBaseline` records the per-profile `DefaultOutboundAction` plus `ActiveProfiles` and `CapturedUtc`. Rollback is journal-driven and phase-aware, and `defaultBlockWasAttempted` correctly limits restoration attempts to phases where the default was actually changed (`EnforcingDefaultBlock`, `Active`, `RollingBackDefault`, `RollingBackRules`) — the fix `HANDOFF.md` §10 tells you not to remove. Keep it.

**Defect 9a — rollback deletes other sessions' rules.** In `PerformSafeRollbackInternal`:

```csharp
var sessionPrefix = $"SPEMCS-{sessionId:N}-";
foreach (var ruleName in spemcsRules) {
    if (ruleName.StartsWith(sessionPrefix, StringComparison.OrdinalIgnoreCase) ||
        ruleName.StartsWith("SPEMCS-", StringComparison.OrdinalIgnoreCase)) { ... }
}
```

The second clause subsumes the first, so the session filter is dead and **every** `SPEMCS-`-prefixed rule in the group is removed. Rolling back one session tears down any concurrent session.
*Containment:* the candidate list comes from `GetRuleNamesByGroup(SpemcsRuleGroup)`, so blast radius is strictly inside `SPEMCS_EXAM_LOCKDOWN`. User and third-party rules are safe. This satisfies `HANDOFF.md` §9 constraint 2.

**Defect 9b — baseline is not restored when it differs from `Block`.** `RestoreBaselineSafely.RestoreProfile` only writes the baseline back when `currentAction == FirewallAction.Block`; otherwise it logs *"modified externally … Yielding to external policy"* and sets `conflictDetected = true` **without restoring**. Defensible as conflict-avoidance, but it means rollback is explicitly not guaranteed to be exact — directly at odds with `README.md` §11's rule that emergency rollback must leave the firewall in its exact original state.

**Defect 9c — wrong profile set in `RestoreBaselineAsync`.** Line 199 passes `sessionRecord.Baseline.ActiveProfiles` where it should pass `sessionRecord.TargetProfiles`. If the active profile set changed during the exam (docking, VPN, Wi-Fi→Ethernet), the wrong profiles are restored. **Latent only** — I verified this method has no production call site. Fix it before wiring it up.

**Defect 9d — inbound is never captured.** `WindowsFirewallAdapter.GetBaseline` reads `DefaultOutboundAction` for the three profiles and nothing else; `FirewallProfileBaseline` has no inbound field. `HANDOFF.md` §2 item 4 claims it captures "`DefaultOutboundAction`, `DefaultInboundAction`". The documentation is wrong. Since SPEMCS never modifies the inbound default, not capturing it is harmless — but the claim should be corrected.

---

### Requirement 10 — No blanket explicit outbound BLOCK rule

**Status: IMPLEMENTED / COMPLIANT. This requirement is fully met and must not be regressed.**

Verified by exhaustive grep: every occurrence of `FirewallAction.Block` in the codebase relates to the **profile default** (`SetDefaultOutboundAction`, baseline comparison, or restoration), never to a rule object.

- `EnforcementModels.cs` line 108–109 — `CreateOutboundAllow` hardcodes `Direction: FirewallDirection.Outbound, Action: FirewallAction.Allow`.
- Both loopback factories hardcode `Action: FirewallAction.Allow`.
- No factory, helper, or call site anywhere constructs a `FirewallRuleModel` with `Action = Block`.

The architecture uses the per-profile `DefaultOutboundAction` as the default-deny mechanism, which is exactly what the requirement demands, and avoids the explicit-BLOCK-overrides-ALLOW precedence trap.

**This also bears directly on the incident** — see Part B §14. The blanket outbound block rule observed on the host is architecturally foreign to SPEMCS. SPEMCS cannot produce one.

---
---

# PART B — TAKEOVER REPORT

## 1. EXECUTIVE SUMMARY

SPEMCS is a three-tier proctored-examination control system: a FastAPI/SQLAlchemy management server on a remote Neon Postgres instance, a React+Vite proctor console, and a .NET 8 Windows endpoint agent split across a `LocalSystem` service and an interactive WPF UI. The network-lockdown subsystem — the part the project is actually about — is architecturally the strongest piece of work in the repository. It uses the per-profile `DefaultOutboundAction` as its default-deny mechanism rather than explicit block rules, it captures and journals a firewall baseline before mutating anything, it verifies RSA-PSS signatures with monotonic replay protection before accepting policy, and it confines every rule mutation to a single named group. Those are correct, deliberate decisions and they should be preserved.

The problem is not the design. The problem is that **several of the load-bearing paths are either not wired up, not reachable, or actively failing at runtime**, and the project's own documentation asserts they are complete and verified.

Five findings dominate everything else:

**A. Process monitoring is dead on the running machine.** `ConfigurableProcessClassifier._cache` is an unsynchronised `Dictionary` shared by two concurrent callers. It has already corrupted on this host. The corruption does not self-heal, and the exception is swallowed by a `catch` that logs and continues, so the service reports healthy while performing zero process classification. This is visible in `out.txt`/`out1.txt`: 225 of 450 decoded log lines are the same exception, continuously, from 12:00:13 to 12:09:29.

**B. Exam traffic is not scoped to the approved browser, so the allowlist is bypassable by any process.** Requirement 4 is unimplemented at all four layers, and requirement 5 fails as a direct consequence. Any process on the endpoint — `curl.exe`, `python.exe`, a Discord update channel — can reach every allowed destination on every allowed port. This defeats the central security property of the lockdown.

**C. Roughly 39 REST endpoints and the dashboard WebSocket have no authentication at all.** Anyone who can reach the API can create, mutate and delete exam sessions, delete violation events (evidence destruction), read audit logs and reports, and register devices. `M9_ADVERSARIAL_SECURITY_VALIDATION_REPORT.md` §1 item 1 states "Unauthenticated requests consistently yield `401 Unauthorized`." That claim is false for those routers.

**D. The policy signing key is regenerated on every backend process start.** `routes/policies.py:30` calls `generate_development_keypair()` at module import and binds it to the fixed id `dev-key-1`. There is no key persistence anywhere in the backend. Every backend restart silently invalidates every previously distributed and every previously persisted policy signature, and the agent's cached `dev-key-1` becomes wrong. Because verification is correctly fail-closed, the observable symptom is "enforcement mysteriously stopped working" rather than an error.

**E. Startup crash recovery is dead code.** `ReconcileStartupStateAsync` and `RecoverIncompleteSessionAsync` have zero call sites in `Spemcs.Agent.Service`. If the agent crashes while `DefaultOutboundAction` is set to Block, the machine stays network-sealed indefinitely with no automatic recovery. Conversely, on the one path where recovery *is* invoked, `GetLatestActiveOrIncompleteSession` includes phase `Active`, so it tears down a still-valid exam — a fail-open in the opposite direction.

On top of those, live credentials for the production Neon database are committed to git in `backend/.env.txt`, and `SECRET_KEY` is the literal placeholder `"your-secret-key-here"` in both the tracked file and the live `.env`, which means JWTs are signed with a publicly known value.

**Overall verdict.** The firewall/enforcement core is roughly 70% of a genuinely well-engineered subsystem with one critical missing feature (application scoping) and one critical missing lifecycle piece (startup recovery). The management server is functionally broad but has a large, uneven authentication hole. The frontend is complete for the workflows it covers. The documentation is the least trustworthy artefact in the repository and should not be used as a status source; three separate documents assert verified completion of things this audit found absent or failing.

**Nothing in this report has been changed.** No file was edited, no firewall setting was touched, no rule was created, modified, enabled, disabled or deleted, and `codex_sandbox_offline_block_outbound` was left exactly as found.

---

## 2. ORIGINAL SPEMCS REQUIREMENTS

### 2.1 What documentation exists

| Document | Size | Role | Trustworthiness |
|---|---|---|---|
| `README.md` | 25 KB | Architecture, milestone narrative, run instructions, §7 firewall notes, §11 rollback rules | Mixed — several verifiable claims are false (see 2.3) |
| `HANDOFF.md` | 13 KB | Session handoff, run log A–E, "what not to change" | Mixed — wrong crypto, wrong baseline fields, wrong file paths |
| `Endpoint-agent/DESIGN_DECISIONS.md` | — | Agent design rationale incl. approved-browser model | Design intent is clear; implementation diverges |
| `Endpoint-agent/README.md` | — | Agent build/run | Usable |
| `Endpoint-agent/AUDIT.md` | — | Prior internal agent audit | Historical |
| `Endpoint-agent/SPEMCS_V1_Integration_Handbook.md` | — | Integration contract between server and agent | Useful as interface spec |
| `M8_POST_IMPLEMENTATION_PRODUCTION_SECURITY_AUDIT_REPORT.md` | 11 KB | Declares "M8 CLEAN GO", 132/132 + 74/74 tests | Contradicted by this audit |
| `M9_ADVERSARIAL_SECURITY_VALIDATION_REPORT.md` | 38 KB | Declares "M9 CLEAN GO" across attack classes A–P | Contradicted by this audit |
| `backend/README.md` | — | Backend setup | Usable |
| `frontend/README.md` | 1 line | — | Effectively absent |

There is no `docs/` directory anywhere in the repository.

### 2.2 What documentation is missing

The original specification is **not in the repository**. Specifically absent:

- **The originating requirements document.** `README.md` and `HANDOFF.md` both refer to milestones M1–M9 as though a numbered specification defined them, but no such document exists in the working tree and none is tracked in git history. The agent-side prompt/spec referred to in project history as `SPEMCS_Endpoint_Agent_Codex_Prompt.md` is not present and was never git-tracked.
- **A requirements or acceptance-criteria document** for the backend or frontend. Endpoint behaviour must be inferred from route handlers.
- **Architecture or sequence diagrams.** None, in any format.
- **API documentation** beyond FastAPI's generated OpenAPI.
- **A frontend specification.** `frontend/README.md` is one line.
- **An exam/session lifecycle state document.** The state machines exist in code (`AgentStateMachine`, `EnforcementStateMachine`) but no document defines the intended transitions, so "correct" behaviour cannot be independently checked.
- **A recovery/rollback specification.** `README.md` §11 states a rule ("emergency rollback must leave the firewall in its exact original state") but does not specify the recovery matrix — what should happen on crash, on backend loss, on connectivity loss, on restart mid-exam.
- **Any deployment runbook** for the server tier.

Per the brief, **no requirements have been invented to fill these gaps.** Where intent could not be established from documentation, the status below is `UNCLEAR — DOCUMENTATION INSUFFICIENT`. The ten default-deny requirements audited in Part A were supplied directly by the project owner and are treated as authoritative specification.

### 2.3 Documentation defects found (these matter for takeover)

| Claim | Location | Reality |
|---|---|---|
| "Ed25519 signature verification" | `HANDOFF.md` §2.2; frontend toast `ExamShieldPage.tsx:132` | RSA-2048 / RSA-PSS / SHA-256 on **both** sides (`policy_signer.py`, `PolicyReceiver.cs:186-198`) |
| Baseline captures `DefaultOutboundAction`, `DefaultInboundAction` | `HANDOFF.md` §2.4 | `WindowsFirewallAdapter.GetBaseline` reads **outbound only**; `FirewallProfileBaseline` has no inbound field |
| "verifies 13 distinct COM properties" | `README.md` | `LogAndVerifyRules` *logs* 13, *asserts* ~6 |
| `Spemcs.Agent.Service/Ipc/PolicyPipeServer.cs` | `HANDOFF.md` §6 | Does not exist under any name; the pipe server is `ControlPipeWorker.cs` |
| `Spemcs.Agent.UI/Network/EnforcementServiceClient.cs` | `HANDOFF.md` §6 | Exists at `Spemcs.Agent.UI/Services/EnforcementServiceClient.cs` — wrong path, class is real |
| `Spemcs.Agent.Core/Network/ManagementConnectivityVerifier.cs` | `HANDOFF.md` §6 | Class is real but declared inside `IManagementConnectivityVerifier.cs:26` — wrong path |
| "Unauthenticated requests consistently yield 401" | `M9` §1.1 | False for 9 routers / ~39 endpoints and for `dashboard_ws` |
| "no secrets in the repository" | `README.md` | `backend/.env.txt` and `frontend/.env.txt` are tracked and contain live Neon credentials |
| 170 passed / 0 failed | `HANDOFF.md` §4 | 167 `[Fact]`/`[Theory]` attributes present; unverifiable in this environment (see §13) |
| 132/132 C#, 74/74 Python | `M8` | Inconsistent with `HANDOFF.md`'s 170; both cannot be current |

**Recommendation for takeover:** treat `README.md`, `HANDOFF.md`, `M8` and `M9` as historical narrative, not as status. Re-derive status from code and tests.

---

## 3. CURRENT ARCHITECTURE

```
┌────────────────────────┐          ┌─────────────────────────────┐
│  Proctor Console       │          │  Management Server (FastAPI)│
│  React 18 + Vite + TS  │  REST    │  SQLAlchemy → Neon Postgres │
│  SPA, /api proxy       │ ◄──────► │  JWT (HS256, placeholder)   │
│  /api/v1/ws/dashboard  │  WSS     │  RSA-PSS policy signing     │
└────────────────────────┘          └──────────────┬──────────────┘
                                                   │ WebSocket (agent_ws,
     Endpoint side (Windows 11 test host)          │ authenticated)
     ┌─────────────────────────────────────────────┴──────────────┐
     │  Spemcs.Agent.Service.exe  (NT AUTHORITY\SYSTEM, Worker)    │
     │   ├─ ControlPipeWorker     named pipe spemcs-control-v1     │
     │   ├─ AgentWorker           registration/session/publisher   │
     │   ├─ ProcessMonitor (1s)   ── shared → ConfigurableProcessClassifier
     │   ├─ PreComplianceEngine   ── classifier (UNSAFE: dict race)
     │   ├─ NetworkCollector      ETW DNS + network events (works)
     │   ├─ NetworkEnforcer       COM FwPolicy2, journaled rollback
     │   └─ PolicyReceiver        RSA-PSS verify + replay guards
     └────────────────────────────────────────────────────────────┘
     ┌────────────────────────────────────────────────────────────┐
     │  Spemcs.Agent.UI.exe (interactive session, launched via     │
     │  WTSQueryUserToken+CreateProcessAsUser) — named-pipe client │
     └────────────────────────────────────────────────────────────┘
```

**Three tiers, one trust boundary.** The agent service runs as SYSTEM, owns all firewall mutation, and exposes a restricted named-pipe API (`LocalSystem`+`Administrators` full control, `Interactive` read/write) to the UI. The UI never touches the firewall directly. Policy reachability: proctor console → `POST /api/policies/compile/{exam_id}` → `policy_service` → signed payload → `POST /api/policies/distribute/{exam_id}/{uuid}` → realtime manager → WebSocket → agent `PolicyReceiver` → verify → state machine → `NetworkEnforcer` → COM.

**Runtime topology observed in logs.** The registered agent talks to `127.0.0.1:8002` (`out.txt`: signing-key fetch 200, event uploads to the same host). The management connection is plaintext HTTP localhost; agent config files were not located on this host, so whether a remote deployment would use TLS is `UNCLEAR`.

**Source-of-truth order used throughout this audit:** running code > tests > docs.

---

## 4. BACKEND STATUS

Framework FastAPI 0.1xx + SQLAlchemy 2.x + Pydantic v2. Entry `backend/backend/app/main.py`. Schema created at startup by `Base.metadata.create_all(bind=engine)` (`main.py:43`) — no migrations (see §8). CORS middleware only (`main.py:111`); no auth middleware; routers included with no router-level dependencies (`main.py:163-187`).

### 4.1 Protected vs unprotected (verified per-route, 2026-09-04)

| Router | Endpoints | Protected | Unprotected |
|---|---|---|---|
| `agent_api` | 4 | 0 | **4** (device registration, session start, student verify, event receive) |
| `alerts` | 5 | 0 | **5** |
| `audit_logs` | 1 | 0 | **1** |
| `auth` | 3 | 1 (login) | `/register` unprotected (self-service admin registration) |
| `dashboard` | 1 | 0 | **1** |
| `deployment` | 1 | 1 | 0 |
| `devices` | 8 | 8 | 0 |
| `events` | 5 | 0 | **5** — incl. `DELETE /events/{id}` (evidence tampering) |
| `exam_devices` | 5 | 0 | **5** |
| `exams` | 11 | 7 | 4 read-only detail routes (`/{id}/devices`, `/{id}/sessions`, `/{id}/alerts`, `/{id}/timeline`) |
| `health` | 1 | 0 | 1 (acceptable) |
| `labs` | 4 | 0 | **4** |
| `policies` | 10 | 9 | 1 (`GET /signing-key/public`, arguably acceptable) |
| `reports` | 9 | 0 | **9** — exam integrity reports, career-affecting data |
| `sessions` | 5 | 0 | **5** — incl. DELETE |
| `dashboard_ws` (`websocket/dashboard_ws.py:22-37`) | — | 0 | **1 live feed** — `register_dashboard` sends `INITIAL_STATE` (all online devices) then accepts `SUBSCRIBE_EXAM` for a live `VIOLATION_ALERT` stream, no token, no origin check |

**Contrast with the correct cases.** `devices.py` (8/8 with `require_role`), `policies.py` compile/distribute/update (admin/proctor), `agent_ws.py` (`verify_device_token` + `hardware_uuid` binding, close 4401 on failure — genuinely good), and `exams.py` mutations. The problem is inconsistency, not a missing capability: the auth machinery exists and works, it is simply not applied uniformly.

**Why it matters.** The unauth surface is not read-only trivia. Combine the unprotected pieces and an unauthenticated caller can: register a device (`agent_api`), start/stop a session (`sessions`), delete a session, delete violation events, read every alert/report/audit log, create labs, list exam devices, and stream live proctoring alerts. That is a complete "attacker's view of all exams" with write access to the audit trail.

**Frontend implication:** the console attaches `Authorization: Bearer` on every API call (`services/api.ts` `fetchJson`) and stores the token in `localStorage.spemcs_token` — the client side does its job; the server side is what's missing.

### 4.2 Policy signing — critical lifecycle defect

`routes/policies.py:29-31`:

```python
_dev_priv, _ = generate_development_keypair()   # fresh RSA keypair at every import
_dev_signer = PolicySigner(private_key=_dev_priv, key_id="dev-key-1")
```

`generate_development_keypair` creates an **in-memory** RSA keypair (`policy_signer.py:107-116`, documented as "for development/testing"). No persistence: search for `load_pem_private_key` / `private_key_pem` / key file config in `policy_signer.py`, `config.py`, `policies.py` returns nothing. Consequences:

1. Every backend restart produces a new private key while still claiming `key_id="dev-key-1"`.
2. Every previously signed policy fails signature verification, **correctly** (fail-closed) — so lockdown silently stops working; the agent refuses the policy with `InvalidSignature`.
3. The agent's trust store was populated from the *old* key; `ControlPipeWorker.EnsureKeyStoreInitializedAsync` only fetches the public key once per pipe connection, so even after restart the agent typically holds the stale key.
4. Single fixed key id — no rotation, no multi-key verification, so there is no window in which old and new policies can coexist. `TrustedKeyStore` supports multiple keys and revocation (`ITrustedKeyStore.cs`), but the backend never exercises it.

Status: **IMPLEMENTED BUT, AS DEPLOYED, BROKEN AT THE SECOND RESTART.** For production use the signer must be backed by a persistent key (or an external KMS) and the key must be pre-shared/out-of-band with the agent, with `key_id` carrying an identifier that changes when the key changes.

### 4.3 What is genuinely good in the backend

- `policy_compiler.py` is deterministic and pure: sort + dedupe + validate domains/IPs/ports, canonical JSON (`canonical_json.py`), validity window, management-server validation. The signing input is stable across runs — required for reproducible signatures.
- `resolved_destinations` and the vendor-profile pipeline are properly typed and normalized.
- `agent_ws.py` authentication (device token + hardware UUID binding, 4401 close) is real.
- `realtime_service.py` carries `approved_browser` from the exam into the agent-facing distribution payload (`realtime_service.py:34`) — this is the one place requirement 4's data exists server-side.
- Role-based `require_role` works where applied (verified by M9's 403/401 tests on the protected routes).

---

## 5. FRONTEND STATUS

React 18.3 + TypeScript + Vite 5 + Tailwind 3, `react-router-dom` 7. Entry `src/main.tsx` → `App.tsx`. 39 source files under `src/` (plus a leftover 41-file `src_old/` directory that is not built).

### 5.1 Pages and coverage

| Page | Route | Workflow | Notes |
|---|---|---|---|
| `LoginPage` | `/login` | Login, token store | Works; token in localStorage |
| `DashboardPage` | `/dashboard` | Summary stats | `GET /dashboard/summary` (unauthenticated server-side) |
| `ExamShieldPage` | `/exam-shield` | Exam CRUD, vendor list, compile+distribute+activate | The core workflow page — see below |
| `LiveMonitorPage` | `/exam-shield/monitor/:id` | Lazy; live monitoring via WS | Depends on `dashboard_ws` |
| `DeviceStatusPage` | `/devices` | Device tree/status | `devices.py` is the protected router |
| `AlertsPage` | `/alerts` | Alert list | |
| `ReportsPage` | `/reports` | Reports | |
| `AuditLogsPage` | `/audit-logs` | Audit log | |
| `SettingsPage` | `/settings` | Settings | |
| `AppShell/`+`Sidebar/TopBar` | — | Layout | |

### 5.2 The activation workflow (`ExamShieldPage.tsx`)

`handleActivate` (lines 140-203) implements a careful, correct sequence: compile if missing → block activation on compile failure ("STOP! DO NOT ACTIVATE EXAM!") → fetch assigned devices → filter online → distribute to each → then `activateExam`. It is the best-implemented flow in the frontend. Two observations:

- **Distribution errors are non-blocking.** If distribution fails for some devices, activation still proceeds; the toast reports partial failure but the exam starts. Given the agent refuses policies it cannot verify (fail-closed), a device with a failed distribution simply won't enforce — and won't tell anyone.
- **The policy-enforcement write is entirely frontend-adjacent.** `network_enforcement` is set at exam creation; the lockdown really happens agent-side; the frontend never shows per-device enforcement state (there is no UI for `device_policy_states` rows → see §8).

### 5.3 Integration and correctness issues

- The frontend calls `/policies/compile/{exam_id}` with **no body** (`api.ts:98-99`), so `resolved_destinations` is always `null` → "resolved IPs" in the policy come only from `vendor_profile.approved_ip_ranges`. Requirement 3's resolution pipeline has no operator UI; it's not wired, and since no DNS resolver exists server-side (Part A §3), everything is manual IP entry.
- The claim in the compile toast — "signed with Ed25519" — is factually wrong (RSA-PSS). Cosmetic, but it shows the docs and UI have diverged from the implementation.
- **No frontend tests at all** — no test script in `package.json` (`dev/build/lint/preview/typecheck` only).
- `src_old/` (41 files) is dead weight; the build ignores it. Not a bug.

### 5.4 Realtime

`services/websocket.ts` is well-built: exponential backoff, heartbeat ping/pong, typed dispatch, resubscription on reconnect, state preservation. It connects to `/api/v1/ws/dashboard` **without any token** — consistent with the server, which also has none there. If the server fixes `dashboard_ws`, the client must add token support or the fix will break live monitoring.

---

## 6. ENDPOINT AGENT STATUS

### 6.1 Composition

`Spemcs.Agent.sln` — `Spemcs.Agent.Core` (library), `Spemcs.Agent.Service` (the Windows service), `Spemcs.Agent.UI` (WPF), `Spemcs.Agent.TestHarness`, `Spemcs.Agent.Tests`. `net8.0-windows`. WiX MSI (`installer/`), `build-msi.ps1`, `deployment/`.

`Program.cs`: resolves backend URL (`appsettings.json` → `config.json` → default `http://127.0.0.1:8002/`), builds the host, adds `WindowsServiceLifetime`, registers `HttpClient`s for the three backend clients, DI-registers the machine/snapshot/publisher. `AgentWorker.cs` then constructs the runtime graph manually.

### 6.2 The shared-classifier race — P0, live on this host

- `ConfigurableProcessClassifier` holds `Dictionary<(string Path, string Hash), FileTrustResult> _cache` (`ProcessServices.cs:121`) with no lock.
- `GetTrust` (lines ~327-333) does check-then-populate on that dictionary; two threads calling it concurrently corrupt the internal state. In .NET, a corrupted `Dictionary` throws `InvalidOperationException` (or `ArgumentOutOfRangeException`) from `FindValue` **on every subsequent lookup** — the corruption is permanent within that process.
- Two concurrent callers share the one classifier instance (`AgentWorker.cs:63`): `ProcessMonitor`'s 1-second `PeriodicTimer` loop (`Monitoring.cs:45`, first caller) and `PreComplianceEngine.Scan` on the pipeline `Task.Run` thread (`ProcessServices.cs:378`, second caller). Concrete interleaving exists.
- The exception is caught in the monitor loop (`Monitoring.cs:129-131`), logged, and the loop continues — the service stays "healthy" with **zero process classification**.
- **Confirmation from the field:** `out.txt`/`out1.txt` contain 225 copies of the same exception across 450 decoded lines, from 12:00:13 to 12:09:29, with the heartbeat/`PROMOTED SECURITY EVENT` lines continuing alongside. The host is running this exact code.
- **Why it matters:** the two audit/analysis pieces built on classification — UNCLASSIFIED_PROCESS_NETWORK and SUSPICIOUS_PATH_NETWORK events (still appearing in the log via `NetworkCollector`/`NetworkPolicyEvaluator`, which is a separate path) — and, more importantly, the **exam lockdown's process gating** (which is already missing — Part A §4) are the products of this machine. The events you see in the log are from the network path; the process path is producing nothing and the operator cannot tell.
- **Fix (not to be implemented yet):** replace with `ConcurrentDictionary` + `GetOrAdd`, or `lock` around `GetTrust`. One-line change; P1 by effort, P0 by effect.

### 6.3 Dead state: `_approvedFamily`

`ProcessServices.cs` lines 120/190/196 — declared, assigned, **never read**. Grep confirms exactly three hits. The constructor default is `ApprovedBrowserFamily.Chrome`, but the field's only consumer would have been the classification branches, and those branches hardcode both Chrome *and* Edge as approved. So the exam's `approved_browser` value, which does reach the agent (`realtime_service.py:34` → payload), is ignored: **Edge and Chrome are both always approved** (see Part A §4).

### 6.4 Service lifecycle

- `AgentWorker.Started`: `BrowserPolicyEnforcer.DisableSecureDns` (HKLM policies for Edge+Chrome, HKCU fallback, Firefox prefs dict), starts pipeline (`Task.Run`), starts `EventUploaderWorker` and `NetworkCollector` manually, plus `ProcessAuditLogger`, `NamedPipeUiGateway`, `ControlPipeWorker` (DI-registered hosted services).
- `Stopped`: stops the pipeline, uploader, collector, pipe workers. There is **no** cleanup of firewall state on stop.
- **No startup recovery exists anywhere** — see §9 (Dead code) and Part A §9.
- UI launch: `InteractiveSessionUiLauncher` (WTSQueryUserToken + CreateProcessAsUser) — confirmed in logs: `"Launched Agent UI in the active interactive session"`.
- The UI-side `EnforcementServiceClient` exists (`Spemcs.Agent.UI/Services/`), so the UI can talk to the pipe, but the service-side guard of that pipe is `ControlPipeWorker`, not the fictional `PolicyPipeServer`.

### 6.5 Test harness

`Spemcs.Agent.TestHarness` exists and is referenced by the sln; it is a manual driver, not a test runner. `tests/Spemcs.Agent.Tests` has 10 test files, 167 `[Fact]`/`[Theory]` attributes (counted 2026-09-04). Cannot be executed here (Linux, `net8.0-windows` target). See §13.

---

## 7. FIREWALL / NETWORK CONTROL AUDIT

This section is the traversal summary of Part A. Per-requirement verdicts and full evidence are in Part A; here is the condensed architecture picture.

### 7.1 The mechanism (what exists)

- **Adapter:** `WindowsFirewallAdapter.cs` — COM `HNetCfg.FwPolicy2` only. No netsh, no PowerShell, no WMI/CIM, no subprocess (grep-verified). Reads per-profile `CurrentProfileTypes` + `DefaultOutboundAction` (outbound only). Writes via `InvokeMember("DefaultOutboundAction", SetProperty, ...)`.
- **Rules:** all under group `SPEMCS_EXAM_LOCKDOWN` (`EnforcementModels.cs`), named `SPEMCS-{sessionId:N}-Mgmt-{ip}-{ports}` for management or `SPEMCS-{sha256[:8]}` for destinations. Every rule generated by `BuildSessionRules` passes `applicationPath: null`; factories default `Action: Allow`. Loopback: `CreateLoopbackIPv4Allow` (`127.0.0.1`, both directions, protocol Any) and `CreateLoopbackIPv6Allow` (`::/127` — note the comment in the source says `::1`, the code says `::/127`, and `HANDOFF.md` §10 tells you to keep `::/127` — the code is the intent; keep it).
- **Enforcement order (two-phase):** install allow rules → verify each → set per-profile `DefaultOutboundAction = Block` on the *active* profiles that were Allow at baseline → verify. This ordering is correct and satisfies Part A requirement 1+10.
- **Baseline & journal:** `FirewallProfileBaseline` (per-profile outbound default + active profiles + captured time) snapped before mutation, journaled to `network_journal.db` (SQLite WAL), `PRAGMA user_version` migration scheme on `agent.db`. Rollback is journal-driven and phase-aware (`defaultBlockWasAttempted` gate).
- **Verification:** `LogAndVerifyRules` reads back rule objects; asserts rule existence, group, enabled, direction, action, protocol, and loopback profile bitmask after writing.
- **Management connectivity gate:** `IManagementConnectivityVerifier` with `TransportSecurityMode.StrictHttps` — enforcement refuses to go restrictive unless the management endpoint authenticates (`service: "SPEMCS"`, `status: "ok"`, TLS by default, plain-HTTP rejected). This is a genuine and severe-originality feature, and it explains the localhost run surface: `127.0.0.1:8002` plain HTTP is **rejected by the verifier in StrictHttps mode**, which is why enforcement has never engaged on this host (see §12 and §14).

### 7.2 The gaps (what does not exist)

1. **App scoping on rules** — every SPEMCS rule applies to *any* program (`ApplicationPath` null; policy model has no application field): Part A §4/§5, P0-grade gap.
2. **No DNS server transport** — no UDP/53 rule generation anywhere, `required_udp_ports` defaults empty, and no server-side resolver. Part A §8. The hole is deliberate-omission (good) but the consequence is that even approved portal domain names are unreachable by name during enforcement; and adding UDP/53 without #1 instantly creates a DNS tunnel on the same allowlist.
3. **Explicit IPv6 isolation beyond ::/127 loopback** — no Teredo/6to4/ISATAP/ULA handling, no IPv6-scoped rule set. Profile `DefaultOutboundAction` Block does cover plain IPv6 (a *strength* — that's why the loopback rule is all that's strictly needed for IPv4/IPv6 parity of defaults), but there is no defense against IPv6 transition mechanisms. Part A §7.
4. **Rule verification is weaker than documented** — 13 properties logged, ~6 asserted. A failure to set `Enabled`, `Grouping`, or `ApplicationName` would pass.
5. **Cross-session deletion defect** — rollback deletes every `SPEMCS-*` rule in the group (redundant `StartsWith("SPEMCS-")` clause subsumes the session prefix). Contained to the group; user rules safe. Part A §9a.
6. **Restore-not-exact when externally changed** — baseline restore yields to external policy instead of restoring (`RestoreBaselineSafely`), so "exact original state" (README §11) is not guaranteed on a host where someone touched the profile default mid-exam. Part A §9b.
7. **Wrong profile set in `RestoreBaselineAsync`** — `sessionRecord.Baseline.ActiveProfiles` instead of `TargetProfiles` (line 199). Dead code today; would bite once wired. Part A §9c.
8. **Inbound never captured** — harmless today (SPEMCS never touches inbound) but the HANDOFF claim is wrong and an inbound-capable future change would have no baseline. Part A §9d.

### 7.3 Coexistence with unrelated rules

SPEMCS enumerates all rules (`GetRuleNamesByGroup` reads the full collection, filtered by group) and deletes only `SPEMCS_EXAM_LOCKDOWN`-grouped rules on rollback. Pre-existing, third-party, and unrelated rules — including `codex_sandbox_*` rules — survive an enforcement cycle untouched; that is the correct coexist-safely behaviour and it is scoped right in `HANDOFF.md` §9 constraint 2 ("never netsh advfirewall reset, never delete non-SPEMCS rules"). The design therefore **does expect coexistence** with unrelated rules, and the implementation honours that.


---

## 8. DATABASE STATUS

### 8.1 Schema

16 tables, all server-side (SQLAlchemy models), two SQLite files agent-side:

| Model | Table | Notes |
|---|---|---|
| `user.py` | users | JWT targets |
| `device.py` | devices | hardware_uuid, device_token (M8 HMAC), status |
| `exam.py` | exams, exam_devices | exam → vendor_profile FK, network_enforcement flag, approved_browser |
| `session.py` | exam_sessions | one row per (exam, device); status lifecycle; **server-side** |
| `event.py` | events | detector events, session/device FKs, severity, `Index` |
| `alert.py` | alerts | unique per event_id, exam/device FKs |
| `policy.py` | vendor_profiles, network_policies, device_policy_states | signed policy rows incl. `signature`; per-device distribution state |
| `audit_log.py` | audit_logs | user FK nullable |
| `report.py` | reports | |
| `lab.py`, `lab_device.py` | labs, lab_devices | |
| agent: `agent.db` | (WAL) | trusted keys, durable command dedup, machine snapshot |
| agent: `network_journal.db` | (WAL) | firewall baseline + phase journal |

Relationships use FKs (CASCADE on exam→policy/device_policy_states; plain FKs elsewhere). No `ondelete` on events/sessions/alerts → orphan risk when exams/devices delete (unprotected DELETE endpoints make this reachable).

### 8.2 Migrations — MISSING

`backend/backend/migrations/` contains **only `.gitkeep`** (0 bytes). No `alembic.ini` anywhere under `backend/`. `alembic>=1.13` is in `backend/requirements.txt` but unused. Schema is created by `Base.metadata.create_all` (`main.py:43`):

```python
Base.metadata.create_all(bind=engine)
```

`create_all` only creates missing tables — it can **never** alter or evolve an existing table. Against the live remote Neon Postgres, that means:

- Every schema change (a new column, an index, a constraint, a table rename) must be applied by hand, or the table must be dropped (data loss) — there is no migration path.
- Two deployments diverge silently: dev `create_all` succeeds on new columns, prod fails or runs stale.
- **M8/M9 claim nothing about migrations**, but the milestone narrative implies "production-grade." A production-grade deployment has migrations. Status: **MISSING**, P1.

### 8.3 `device_policy_states`

Exists but has **no API endpoints** — `grep` for `device_policy_states` in `backend/` returns only the model. Distribution (`distribute_policy_to_device`) writes it, but nothing reads it; the proctor cannot see which device has which policy version, whether the agent accepted it, or whether the device is enforcing. Given the fail-closed agent, this invisible state is exactly what an operator needs to diagnose "exam is on but nothing is enforced."

### 8.4 Integrity observations

- No DB-level enum/check constraints on `exam_sessions.status` or `enforcement_phase` (string columns, code-side constants). State-machine drift is possible and undetectable at the DB layer.
- No `updated_at` triggers — update timestamps are application-managed.
- `events` (and its `DELETE`) is fully unauthenticated; combined with no FK cascade, evidence integrity is weakest where it matters most.

---

## 9. SECURITY AUDIT

### 9.1 Verified strengths (do not regress)

| Control | Where | Status |
|---|---|---|
| Device identity | `agent_ws.py` token + hardware_uuid binding HMAC-SHA256, constant-time | Real |
| Policy signature chain | RSA-PSS/SHA-256 both ends; canonical JSON; monotonic version; not_before/expires_at | Real |
| Replay defense | durable_processed_commands (SQLite), freshness ±5 min | Real |
| Key revocation capability | `TrustedKeyStore.RevokeKey`/`IsRevoked`, checked pre-verify | Real (unused by backend) |
| Privilege separation | named pipe `spemcs-control-v1`, `NamedPipeServerStreamAcl`, SYSTEM owns firewall; UI is non-privileged | Real |
| Baseline/journal | `network_journal.db` WAL, phase-aware restore | Real |
| Fail-closed verification | reject on any signature/revocation/expiry/replay failure | Real |
| Non-destructive firewall hygiene | never `netsh advfirewall reset`; deletes only `SPEMCS_EXAM_LOCKDOWN` group | Real |
| Management connectivity gate | `TransportSecurityMode.StrictHttps`, strict service+status contract | Real — **but see 9.3** |

### 9.2 Security defects

| # | Finding | Severity | Detail |
|---|---|---|---|
| S1 | ~39 unauthenticated REST endpoints + unauth `dashboard_ws` | **CRITICAL** | §4.1 table. Includes session/event deletion, report and audit-log reads, device registration, live violation stream. Direct contradiction of M9 §1.1. |
| S2 | Live Neon credentials in git (`backend/.env.txt`, `frontend/.env.txt` tracked; `git ls-files` confirms) | **CRITICAL** | `DATABASE_URL=postgresql://neondb_owner:***@ep-empty-dew-axrs5vol-pooler.c-4.us-east-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require`. `sslmode=require` + `channel_binding=require` are good — but the credential is public. Rotate immediately; remove from history. |
| S3 | `SECRET_KEY="your-secret-key-here"` in tracked `.env.txt` and live `backend/.env`; `config.py` fallback `"dev-secret-change-in-production"` | **CRITICAL** | JWT HS256 signing with a known key → anyone can mint admin JWTs. |
| S4 | Development signing keypair regenerated per process, fixed id `dev-key-1` | **CRITICAL (functional)** | §4.2. Invalidates all policy signatures on restart; agents fail-closed → enforcement silently dead. |
| S5 | Plaintext HTTP management default (`http://127.0.0.1:8002/`, no TLS in local run) | **HIGH (deployment)** | Localhost is a smaller blast radius, but `TransportSecurityMode.StrictHttps` rejects it — so the deployment that works is the one the verifier refuses. See §12. |
| S6 | Auth routes: `/auth/register` self-service, default role `admin` in the frontend helper | **HIGH** | `api.ts: register(username,email,password,role='admin')` — the frontend defaults any new user to admin; the route itself has no invite-only path. |
| S7 | `deployment.py` uses `require_role` but `dashboard.py`/`reports.py`/`events.py` don't — inconsistent rule sets mean the bearer token is present but not consulted | **HIGH** | — |
| S8 | `LogAndVerifyRules` asserts only ~6 of 13 logged properties | **MEDIUM** | Post-write verification is weaker than documented. |
| S9 | `_approvedFamily` dead; Chrome+Edge both always approved | **MEDIUM** | Part A §4; the `approved_browser` field exists end-to-end but is ignored at the decision point. |
| S10 | Agent state store and journal are plain SQLite file paths under ProgramData — check ACL on `agent.db`/`network_journal.db` (not inspected; treat as unverified) | **MEDIUM** | The named-pipe SID grants the Interactive user read/write of the control pipe; a hostile interactive user can drive enforcement requests through the pipe to the SYSTEM service. The pipe's ACLs (LocalSystem+Admins full, Interactive read/write) are a deliberate design (UI must control the service) — but any process in the interactive session can use it. `UNCLEAR` whether the UI protocol is authenticated beyond the pipe ACL. |
| S11 | CORS: `allow_origins=settings.CORS_ORIGINS` — **empty list in `config.py` default**; `allow_credentials=True, allow_methods=["*"]` | **MEDIUM** | Empty origins means same-origin only, which is safe; if the operator sets `CORS_ORIGINS=["*"]` with `allow_credentials=True`, browsers will reject credentialed CORS anyway. Not exploitable today; note for hardening. |
| S12 | `file_creation_advice`-style repo hygiene: `out`, `out.txt`, `out1.txt`, `frontend/New Text Document.txt`, `frontend/src_old/`, `scratch/` committed/uncommitted junk | **LOW** | Not a control failure. |

### 9.3 The StrictHttps catch-22 (deployment-relevant)

`IManagementConnectivityVerifier` in `StrictHttps` mode rejects `UseTls=false` and non-`https` schemes. The manager-side `PolicyCompileRequest.management_server` default is `{"ip_addresses": ["127.0.0.1"], "port": 8002, "use_tls": False}`. The agent defaults to `http://127.0.0.1:8002/`. So:

- Local dev run: verifier refuses → enforcement never starts (correctly!) → the "safe" failure mode hides the fact that enforcement is not working.
- Any production run that uses the defaults → same result.
- To make enforcement work at all, the management destination must be `https` with a real certificate, and the agent must be configured with the matching `BackendApiUrl` and the public key. Nothing in the docs walks an operator through that combination; README's run instructions take you to the localhost-HTTP configuration that cannot enforce.

This is the **single most likely reason an operator sees "the agent is installed but exams are never locked down"** — and it is indistinguishable from a broken install from the log side (the verifier rejects silently except for a log line).

---

## 10. CURRENT BUGS

Ranked P0 → P3. None fixed.

### P0 (blocks core function / active on this host)

| ID | Bug | Location | Effect |
|---|---|---|---|
| B-1 | Unsynchronised classifier `_cache` Dict — permanent process-monitor death | `ProcessServices.cs:121,327-333` × `Monitoring.cs:45` + `ProcessServices.cs:378` × `AgentWorker.cs:63-65` | Process classification dead in service; 225/450 log lines are the same exception; service reports healthy. |
| B-2 | Policy signer key regenerated per backend start | `routes/policies.py:30`, `policy_signer.py:107` | Policy signature invalid after every restart → enforcement fail-closed dead. |
| B-3 | No startup recovery wired | `ReconcileStartupStateAsync`/`RecoverIncompleteSessionAsync` unreferenced; `Program.cs` no call | Agent crash under lockdown = machine sealed with no automatic restore. |
| B-4 | Startup recovery reads `Active` phase | `SqliteRollbackJournal.cs:294` | If wired, would tear down a valid running exam (fail-open). |
| B-5 | Rollback deletes all `SPEMCS-*` rules, not just this session | `PerformSafeRollbackInternal` redundant `StartsWith("SPEMCS-")` | One session's deactivation kills the other's lockdown. Contained to group. |

### P1 (major correctness/security)

| ID | Bug | Location | Effect |
|---|---|---|---|
| B-6 | ~39 unauth REST endpoints + unauth dashboard WS | §4.1 | Write access to sessions/events; read access to all reports; live proctoring stream public. |
| B-7 | `RestoreBaselineSafely` yields instead of restoring when current ≠ Block | `NetworkEnforcer`/`RestoreBaselineSafely` | Rollback does not restore exact baseline if third party changed default mid-exam. |
| B-8 | `RestoreBaselineAsync` wrong profile set | line 199 | Dead code; would restore wrong profiles. |
| B-9 | `approved_browser` dead at decision point | `ProcessServices.cs:120,190,196` + hardcoded both-allow branches | Edge/Chrome both approved regardless of exam config. |
| B-10 | No migrations | `migrations/.gitkeep`, `main.py:43` | Cannot evolve production schema. |
| B-11 | `CreateLoopbackIPv6Allow` uses `::/127` while source comment says `::1` | `EnforcementStateMachine.cs:688-690` | Not a bug (comment only) — listed for clarity; keep `::/127`. |
| B-12 | `IsRevoked`/`GetActiveKeyIds` iterates `_keys` then filters — TOCTOU with `RevokeKey` on another thread (ConcurrentDictionary per-key safe, list-of-keys enumeration is not atomic) | `ITrustedKeyStore.cs:38-52` | Minor race; key store is populated once at startup in practice. |

### P2 (important, non-blocking)

| ID | Bug | Location | Effect |
|---|---|---|---|
| B-13 | `EventsUploader`/`NetworkCollector` started manually, not DI lifecycle | `AgentWorker.cs:73-77` | Not disposed on host shutdown; logging shows reconnects with 60 s backoff. |
| B-14 | `BrowserPolicyEnforcer.DisableSecureDns` writes `Registry.CurrentUser` fallback (student-writable HKCU can override HKLM policy) | `ProcessServices.cs:422-425` | Student can re-enable DoH in HKCU after HKLM policy — the HKCU fallback is "make it work" not "make it stick". |
| B-15 | Distribution failure is non-blocking in `handleActivate` | `ExamShieldPage.tsx` 150-185 | Exam starts with some devices unenforced; no warning state surfaced. |
| B-16 | `PolicyDestination.Domains` unused in `BuildSessionRules` | `EnforcementStateMachine.cs:675-773` | Domain allowlist would not be realised even if provided; no resolver exists. |
| B-17 | `LogAndVerifyRules` assertion subset | §7.2-4 | Weaker verify than documented. |

### P3 (polish)

B-18 `HANDOFF.md`/frontend "Ed25519" mislabel; B-19 `restart loop`-style log spam from `EventUploaderWorker` 60 s backoff on 127.0.0.1:8002 refused; B-20 repo junk (`out*`, `src_old/`, `scratch/`, `New Text Document.txt`); B-21 `_seen` dictionary in `Monitoring.cs:13` also unsynchronised (same class of bug as B-1, lower exposure — it's written only in the monitor loop; but `Classify` is also called from `PreComplianceEngine`, so B-1's fix should cover both).

---

## 11. MISSING FEATURES

Against the original specification (Part A 10 requirements + README claims) and where intent is clear:

| # | Missing | Spec tie | Priority |
|---|---|---|---|
| M-1 | **Application scoping of allow rules** (rule → chrome.exe only) | Part A §4 | P0 |
| M-2 | **Server-side DNS resolver** producing `resolved_destinations` (or operator UI for manual resolution) | Part A §3 | P0 |
| M-3 | **Startup crash recovery wiring** | README §11; Part A §9 | P0 |
| M-4 | **Explicit IPv6 isolation** (Teredo/6to4/ISATAP handling, IPv6-scoped rules, or documented reliance on profile default) | Part A §7 | P1 |
| M-5 | **Port-53 policy pathway** with tunnel-proof app scoping, or documented prohibition of DNS during lockdown | Part A §8 | P1 |
| M-6 | **Real key persistence/rotation** for policy signing | §4.2, M8 claims | P1 |
| M-7 | **Migrations (Alembic)** | production readiness | P1 |
| M-8 | **Per-device enforcement-state visibility** in proctor UI (`device_policy_states` unread) | README's monitoring narrative | P2 |
| M-9 | **DNS policy coverage** for Firefox (policy dict only; no registry/HKLM mechanism parallel to Edge/Chrome) | Part A §8 | P2 |
| M-10 | **Frontend for `resolved_destinations`/vendor IP management** | Part A §3 | P2 |
| M-11 | **Tests for the frontend** (none exist) | §13 | P2 |
| M-12 | **Inbound baseline capture** (if inbound ever touched) | Part A §9d | P3 |

---

## 12. UNVERIFIED FEATURES

| Feature | Why unverified | How to verify |
|---|---|---|
| Full enforcement cycle on a live machine | Local run on this host never reached enforcement: the `StrictHttps` verifier refuses the plaintext `127.0.0.1:8002` management config. | Run with real TLS mgmt endpoint + correct cert + agent `BackendApiUrl`; observe journal entries + rule readback. |
| Agent MSI build / install | `build-msi.ps1` + WiX installer not executed in this environment (Linux). | Run on Windows build host; check output MSI. |
| C# test suite (170 in HANDOFF / 167 attributes present) | `net8.0-windows` tests can't run on Linux sandbox. | `dotnet test` on Windows; compare against HANDOFF §4. |
| Backend test suite (64 `test_` fns, 16 files) | Python deps not run here; M8/M9 claim 74/74 without runnable result artifacts. | `pytest` in the backend venv; compare. |
| Agent UI ↔ service pipe protocol details | `EnforcementServiceClient` client only; no captured pipe traffic. | Run UI + service on Windows; capture. |
| `StrictHttps` on-management real cert chain | M8 says tested with "real in-process TLS sockets" — no artifact in repo proving the tests ran. | Re-run `ManagementConnectivityVerifierTests` on Windows. |
| `EtwDnsListener` correctness on real traffic | Log shows "EtwDnsListener stopped" — started/stopped; no captured DNS event evidence. | Reproduce with known DNS traffic; inspect event payloads. |
| `DefaultOutboundAction` change on a *machine with domain policy* | COM `FwPolicy2` per-profile writes on domain-joined hosts can be overridden by GPO at next policy refresh — never tested here. | Test on a domain-joined host under GPO-managed firewall. |
| `GetRulesByGroup` readback on hosts with >10k rules / firewall service busy | Not observed. | — |

---

## 13. TEST / E2E STATUS

### 13.1 What exists

- **C# agent:** 10 test files, 167 `[Fact]`/`[Theory]` attributes. File names imply the coverage areas: `EnforcementStateMachineUnitTests`, `PolicyDistributionTests`, `DynamicPolicyUpdateUnit/IntegrationTests`, `ManagementFirewallEnforcementTests`, `WindowsTrafficEnforcementIntegrationTests`, `SecurityHardeningUnitTests`, `AdversarialSecurityValidationTests`, `ManagementConnectivityVerifierTests`.
- **Python backend:** 64 `def test_` across 16 files.
- **Frontend:** none. No test runner, no test files, `package.json` has no `test` script.
- **E2E:** none end-to-end executed here. `Spemcs.Agent.TestHarness` is a manual driver program.
- Existing unit-test suites are genuinely structured around the right seams (state machine, distribution, verifier, journal) — the attack surface they cover is the right one; the problem is they have not caught the cross-cutting defects (B-1, B-2, B-9, S1) because those live in composition/DI wiring (`AgentWorker.cs`) and in route-file omissions, not in the unit-tested classes.

### 13.2 Claim vs reality

- `HANDOFF.md` §4: 170 passed / 0 failed, 0 warnings 0 errors.
- `M8`: 132/132 C# + 74/74 Python, "M8 CLEAN GO".
- `M9`: 16 attack classes A–P, "M9 CLEAN GO", and item 1 = "Unauthenticated requests consistently yield 401" — **contradicted by this audit** (§4.1). Item 3 ("WebSocket authentication ... 4401") — true for `/ws/agent`, false for `/ws/dashboard`.
- The M8/M9 reports are dated 2026-09-03, the day before this audit, and reference files that do not exist. Either they were written against a different tree state or they are aspirational. **They cannot be used as evidence of current correctness.**

### 13.3 Recommended verification (when approved — not now)

1. `dotnet test Endpoint-agent/Spemcs.Agent.sln` on Windows, capture output, compare with 167.
2. `pytest backend/backend` in the backend venv, compare with 64 + M8's 74.
3. A new integration test at the `AgentWorker` scope that runs `PreComplianceEngine` and `ProcessMonitor` concurrently against a classifier with a populated trust cache — this is the only way to reproduce B-1 deterministically.
4. A route-coverage test: iterate every `APIRouter` and assert each endpoint has a `require_role` dependency (or an explicit allowlist) — cheap and would have caught S1.
5. A restart test: boot backend, compile policy, restart backend, compile again, verify agent rejects the second under the first public key — reproduces B-2.

---

## 14. CURRENT INCIDENT ANALYSIS (codex_sandbox_offline_block_outbound)

### 14.1 Facts from the host (supplied by operator)

- Rule `codex_sandbox_offline_block_outbound`: Outbound, Block, Any profile, Any program, Any protocol, RemoteAddress ≈ all non-loopback.
- Disabling it restored internet (8.8.8.8:443, google.com:443); it was re-enabled during investigation.
- Windows Firewall event logs show `C:\Windows\System32\wbem\WmiPrvSE.exe` modifying this rule.
- `Spemcs.Agent.Service.exe` is installed on the machine.

### 14.2 What SPEMCS can and cannot do (from source)

**Cannot (verified by exhaustive search of `Endpoint-agent/src` and `backend/backend`):**

- No netsh, no WMI/CIM, no PowerShell, no subprocess firewall tooling. `WindowsFirewallAdapter.cs` is COM (`HNetCfg.FwPolicy2`) only. `WmiPrvSE.exe` is the WMI provider host — there is **no WMI/CIM code anywhere in the repository** to invoke it.
- No API to **enable or disable an existing rule**. `WindowsFirewallAdapter` can add rules, remove rules by name, enumerate rules, and set profile defaults. There is no `SetEnabled` / `InvokeMember("Enabled")` call anywhere (grep verified).
- No ability to **create a blanket explicit outbound block rule** — and no reason to: Part A §10 fully verifies the implementation never creates `FirewallAction.Block` rules; it uses profile defaults. Even a hypothetical block-rule factory is absent.
- Therefore SPEMCS cannot have created, modified, enabled, disabled, or deleted `codex_sandbox_offline_block_outbound`.

**Can (and their exposure):**

- `GetRuleNamesByGroup`/`GetRulesByGroup` enumerate **all** rules (firewall enumeration). So SPEMCS *can discover* the codex rule exists — by reading, not by changing. In the logs there is no evidence of such enumeration outside enforcement attempts.
- `RemoveRule(string)` can delete an arbitrary rule by name — but every call site filters (`spemcsRules` from `GetRuleNamesByGroup(SpemcsRuleGroup)`, or prefix `SPEMCS-`). `codex_sandbox_offline_block_outbound` matches neither. Contained by design.
- `SetDefaultOutboundAction` mutates per-profile defaults — a genuinely different control than a rule, and one that was never triggered in the captured logs (no enforcement attempt appears in `out.txt`/`out1.txt`).
- The design **does** intend coexistence with unrelated rules (§7.3). Nothing in SPEMCS's normal cycle targets non-`SPEMCS_EXAM_LOCKDOWN` rules; `HANDOFF.md` §9 constraints codify that.

### 14.3 Assessment

The modification of `codex_sandbox_offline_block_outbound` by `WmiPrvSE.exe` is **inconsistent with SPEMCS authorship on every axis**: mechanism (SPEMCS is COM-only; WMI is not used), capability (no enable/disable API), and design (explicit blanket block is explicitly prohibited by requirement 10). Three candidate explanations, ranked by plausibility given the evidence:

1. **Unrelated third-party tooling** (Codex sandbox tooling, a security agent using WMI, or a manual `netsh`/`Set-NetFirewallRule` from an elevated shell — the latter two also surface as WMI provider-host activity in event logs when the firewall service processes the change).
2. **The operator's own investigation tooling** — the user disabled/re-enabled the rule during the investigation; the WMI event may correspond to those actions rather than to an external actor.
3. **A different process on the host** — rule state changes are logged by the Windows Firewall service; `WmiPrvSE.exe` is the *provider host* that carries WMI-driven changes. A WMI client (`Invoke-CimMethod`, `Set-NetFirewallRule`, a CI/CD config tool) is the actual issuer.

**Conclusion for the report:** no evidence links SPEMCS to the codex rule. SPEMCS's design respects unrelated rules and (as implemented) has no code path that would. The one thing SPEMCS *does* share with the incident is that both are firewall-level controls on the same host: **if SPEMCS enforcement ever runs on this machine and sets `DefaultOutboundAction = Block` on the Public profile, and the codex block rule is also present, the two controls compose** (profile default + explicit rule). The explicit rule still wins on some path because explicit ALLOW cannot override it — that precedence is exactly why the design refuses block rules. No attempt was made to change anything on the host.

---

## 15. PRIORITIZED WORK PLAN

Nothing below has been implemented. These are proposed, ordered fixes for the explicit approval phase.

### P0 — blocks core function (fix first)

1. **B-1 classifier race.** `ConcurrentDictionary<(string,string), FileTrustResult>` + `GetOrAdd`, or a lock; also fix `Monitoring.cs:13 _seen`. Add the concurrent-caller integration test. (One-line fix class; huge runtime effect.)
2. **B-2 signing key persistence.** Persistent key file (protected) or KMS; key rotation with `key_id` changes; agent key-store refresh on key id change; pre-shared trust anchor.
3. **B-3/B-4 recovery.** Wire `ReconcileStartupStateAsync` into service start **with** phase-correct semantics (recover only incomplete/`Idle`-stale sessions, never `Active` without a compensating decision), and make recovery journal-driven so a crash mid-exam restores the baseline.
4. **B-5 rollback scoping.** Remove the redundant `StartsWith("SPEMCS-")` clause; keep session-prefix filter.
5. **S1 auth gap.** Add router-level `dependencies=[Depends(require_role([...]))]` to every unprotected router (sessions, events, alerts, audit_logs, reports, labs, exam_devices, dashboard, agent_api — agent_api needs device-token auth, not role auth, matching `agent_ws.py`); require auth on `dashboard_ws` (token or cookie) and update `services/websocket.ts` accordingly.
6. **M-1 application scoping.** This is the core spec gap: carry an `application`/`process` field through `PolicyDestination` → `compiled_payload` → `ValidatedPolicy` → `BuildSessionRules` → `ApplicationPath` on created rules; restrict to `chrome.exe` (intent is `approved_browser` — the field already exists); enforce the `_approvedFamily` decision.
7. **M-2 resolver.** Implement (or explicitly scope) DNS resolution to `resolved_destinations` with validation, and gate port-53 behind M-1 so DNS tunneling cannot ride the allowlist.

### P1 — major correctness/security

8. **M-3 migrations.** Alembic init + history; convert `create_all` to a migration-backed bootstrap.
9. **S2/S3 credential rotation.** Rotate Neon password, invalidate JWT secret, remove `.env.txt` from tracking (and from history), replace placeholder `SECRET_KEY`.
10. **S6 register hardening.** Remove self-service admin registration or gate on bootstrap key; role default must not be admin.
11. **M-4 IPv6 isolation.** Decide explicit IPv6 story (Teredo/6to4/ISATAP disable + documented reliance on profile default, or scoped rules).
12. **B-7 exact-restore.** Restore baseline even when current differs (with a conflict log + audit event), or formally document the yield behaviour; align with README §11's "exact original state".
13. **B-9 approved-browser enforcement** (folded into M-1).
14. **Management TLS documentation/deployment runbook** for the StrictHttps path (currently untrodden).

### P2 — important, non-blocking

15. **M-8 device-policy-state visibility** in proctor UI.
16. **B-13 lifecycle disposal** for manually-started workers.
17. **B-15 distribution-failure surfacing** in activation flow (block or warn with device list).
18. **M-9 Firefox DNS policy** (registry or platform mechanism).
19. **B-16 domain allowance wiring** (if domains are to be honoured).
20. **B-17 verification strictness** (assert all 13 properties actually logged).

### P3 — polish / future

21. Dedupe/clean repo junk; real `frontend/README.md`; fix Ed25519 references (`HANDOFF.md`, toast); add frontend tests; reconsider `_seen` lifecycle; revisit HKCU DoH fallback; add `updated_at` triggers / DB check constraints; audit `agent.db`/`network_journal.db` ACLs; reconsider `dashboard_ws` without auth if an anonymous kiosk mode is desired.


---

## 16. REQUIREMENTS MATRIX (implementation vs original specification)

Status legend: **IMPLEMENTED** · **PARTIALLY IMPLEMENTED** · **IMPLEMENTED BUT UNVERIFIED** · **BROKEN** · **MISSING** · **NOT REQUIRED** · **UNCLEAR — DOCUMENTATION INSUFFICIENT**

| # | Requirement | Original specification | Current implementation | Status | Evidence | Missing/Problem |
|---|---|---|---|---|---|---|
| 1 | Default-deny on outbound during enforcement | Part A §1: default outbound must be BLOCKED | Per-profile `DefaultOutboundAction=Block` via COM `FwPolicy2` after two-phase rule install; only active profiles, only if baseline was Allow | IMPLEMENTED BUT UNVERIFIED | `WindowsFirewallAdapter.SetDefaultOutboundAction`; `EnforcementStateMachine`; journal `network_journal.db`; no enforcement ever observed in live logs (verifier refused localhost-HTTP) | Never exercised on this host; StrictHttps gate prevents the default config from enforcing |
| 2 | Only approved destinations reachable | Part A §2 | Allow rules generated per destination from signed policy; profile default blocks the rest | PARTIALLY IMPLEMENTED | `BuildSessionRules` (EnforcementStateMachine.cs:675-773); `PolicyDestination` | `dest.Domains` never consumed — domain allowlist inert; no resolver (see #3) |
| 3 | Approved destinations = trusted resolved IPs/CIDRs in signed policy | Part A §3 | Vendor `approved_ip_ranges` + caller-supplied `resolved_destinations`; normalized CIDR; RSA-PSS-signed canonical payload | PARTIALLY IMPLEMENTED | `policy_compiler.py` (normalize_ip_network_list, canonicalize); `policy_signer.py`; `compile_exam_policy` route | No DNS resolver exists anywhere in backend — `resolved_destinations` is operator-supplied; frontend sends no body so it is always empty |
| 4 | Allowed traffic scoped to approved browser (chrome.exe) | Part A §4 | `ApplicationPath: null` on every generated rule; `PolicyDestination`/`ValidatedPolicy`/`compiled_payload` have no application field; `approved_browser` reaches agent (realtime_service.py:34) but `_approvedFamily` is never read (ProcessServices.cs:120/190/196) | MISSING | `EnforcementStateMachine.cs` (appPath null) · `PolicyDistributionModels.cs` · `policy_service.py:170` · `ProcessServices.cs` | Not implemented at any layer; hardened by the fact that policy has no app field |
| 5 | curl/Python/Discord must not use whitelisted destination | Part A §5 | No app scoping → any process can use allowlisted IP:port | BROKEN | Direct consequence of #4 | Bypass of the central security property of the lockdown |
| 6 | All three firewall profiles handled | Part A §6 | `FirewallProfiles.All` (7) passed at rule creation; profile-default set on active profiles; targetProfiles default All | IMPLEMENTED | `EnforcementModels.cs:FirewallProfiles`, `EnforcementStateMachine.cs:540` | — |
| 7 | IPv6 contained; explicit IPv6 isolation | Part A §7 | IPv6 loopback `::/127` both-way rule; profile default Block covers plain IPv6 | MISSING | grep of `Network/` for `IPv6|Teredo|6to4|isatap` → only loopback/comment hits | No Teredo/6to4/ISATAP handling; no IPv6-scoped rule set; source comment says `::1` while code uses `::/127` (keep `::/127`) |
| 8 | DNS must not create tunnel/exfiltration | Part A §8 | No port-53 rules generated; `required_udp_ports` default empty; DoH suppressed via `BrowserPolicyEnforcer.DisableSecureDns` (HKLM Edge/Chrome, HKCU fallback, Firefox pref dict) | PARTIALLY IMPLEMENTED | `ProcessServices.cs:401-458`; `models/policy.py:33-34` | HKCU fallback student-writable; Firefox has no HKLM mechanism; adding UDP/53 without #4 opens unrestricted tunnel; approved portal hostnames unreachable by name |
| 9 | Rollback restores exact pre-exam baseline | Part A §9 | Baseline captured before mutation and journaled; phase-aware restore; contains conflict detection | PARTIALLY IMPLEMENTED | `FirewallProfileBaseline`, `SqliteRollbackJournal`, `PerformSafeRollbackInternal`, `RestoreBaselineSafely` | 9a cross-session deletion (redundant `StartsWith("SPEMCS-")`); 9b yields instead of restoring when current≠Block; 9c wrong profile set in dead `RestoreBaselineAsync` (line 199); 9d inbound never captured; recovery not wired (B-3/B-4) |
| 10 | No blanket explicit outbound BLOCK rule | Part A §10 | Every `FirewallAction.Block` occurrence is a profile-default; factories hardcode `Allow`; no rule factory constructs Block | IMPLEMENTED / COMPLIANT | `EnforcementModels.cs:108-109`; exhaustive grep of `FirewallAction.Block` | Do not regress; this is the correctness property that prevents ALLOW-rule precedence bypass |
| 11 | Authenticated REST | §4.1 | JWT/`require_role` on devices, policies (9/10), exams mutations, deployment; none on 9 routers + dashboard_ws | PARTIALLY IMPLEMENTED / BROKEN scope | `auth_service.require_role`; per-route audit table | ~39 endpoints unauth; M9 §1.1 contradicts |
| 12 | Authenticated agent WS | §4.1 | `verify_device_token` + hardware UUID binding, close 4401 | IMPLEMENTED | `websocket/agent_ws.py:172-198` | — |
| 13 | Device token binding | M8 | HMAC-SHA256, 7-day TTL, UUID-bound, constant-time | IMPLEMENTED | `device.py`/`agent_ws.py` | — |
| 14 | Policy freshness | Part A §3 design | not_before/expires_at + monotonic version | IMPLEMENTED | `PolicyReceiver.cs` (198), `policy_compiler.validate_validity_window` | — |
| 15 | Replay protection | M8 | durable_processed_commands SQLite, ±5 min | IMPLEMENTED | agent store | — |
| 16 | Key lifecycle/revocation | M8 | `TrustedKeyStore.RevokeKey/IsRevoked` | IMPLEMENTED (server-side unused) | `ITrustedKeyStore.cs` | Backend has one in-memory key, regenerated per process (B-2) |
| 17 | Management connectivity gate | M8 | `TransportSecurityMode.StrictHttps`, service/status contract | IMPLEMENTED BUT UNVERIFIED | `IManagementConnectivityVerifier.cs:26,38-80` | Default deployment (http://127.0.0.1:8002) cannot pass; enforcement never engages |
| 18 | Privilege separation | README | SERVICE=SYSTEM owns firewall; UI via named pipe `spemcs-control-v1`; `NamedPipeServerStreamAcl`; `WTSQueryUserToken`+`CreateProcessAsUser` | IMPLEMENTED | `ControlPipeWorker.cs`, `InteractiveSessionUiLauncher.cs` | Interactive SID has read/write on pipe — hostile user in session can drive the service; no app-level auth on pipe observed (UNCLEAR) |
| 19 | SQLite journals for test/rec each write | M8 | `network_journal.db`/`agent.db` WAL, `PRAGMA user_version` | IMPLEMENTED | — | — |
| 20 | Migrations for server schema | production readiness | None; `create_all` only | MISSING | `migrations/.gitkeep`; `main.py:43` | Cannot ALTER; prod divergence |
| 21 | Firewall coexist with unrelated rules | README §13 / HANDOFF §9 | Group-scoped ops only; never `advfirewall reset`; deletes only `SPEMCS_EXAM_LOCKDOWN` + `SPEMCS-` prefix | IMPLEMENTED | `WindowsFirewallAdapter`; `HANDOFF.md` §9 constraint 2 | The redundant prefix in rollback is the bug (9a) |
| 22 | Secrets hygiene | README | `.env.txt` tracked with live Neon credentials; `SECRET_KEY=your-secret-key-here`; config default `dev-secret-change-in-production` | BROKEN | `git ls-files`, `backend/.env.txt`, `backend/.env` | S2/S3 |
| 23 | UI policy compilation UX | README | ExamShieldPage compile/distribute/activate | IMPLEMENTED BUT UNVERIFIED (E2E) | `ExamShieldPage.tsx:140-203` | Toast says "Ed25519" (wrong); `resolved_destinations` never sent |
| 24 | Per-device enforcement state UI | README monitoring narrative | None | MISSING | `device_policy_states` model, no endpoints/UI | M-8 |
| 25 | Exam lifecycle state machine | README | `AgentStateMachine`/`EnforcementStateMachine`, phase enum | PARTIALLY IMPLEMENTED | — | Startup recovery dead (B-3); `SqliteRollbackJournal.cs:294` includes `Active` (B-4) |
| 26 | Process monitoring | README §8 | `ProcessMonitor` 1s loop + classification | BROKEN (on this host) | `ProcessServices.cs:121,327-333`, `Monitoring.cs:45,129-131`, `AgentWorker.cs:63-65`; `out.txt` 225× exception | B-1 |
| 27 | Network telemetry (ETW DNS + events) | §8 | `NetworkCollector`, `EtwDnsListener`, `NetworkPolicyEvaluator` | IMPLEMENTED (partially verified) | logs: `PROMOTED SECURITY EVENT`, `EtwDnsListener stopped` | — |
| 28 | Browser secure-DNS enforcement | §8 | `DisableSecureDns` HKLM Edge/Chrome + HKCU fallback + Firefox dict | PARTIALLY IMPLEMENTED | `ProcessServices.cs:401-458` | B-14 |
| 29 | Trusted key construction | M8 | `TrustedKeyStore` + COM rules; no WMI/netsh/PowerShell | IMPLEMENTED | `WindowsFirewallAdapter.cs` | — |
| 30 | E2E flow (compile→distribute→activate→lockdown→rollback) | README | Code exists; never run end-to-end here; enforcement cannot engage under default config | IMPLEMENTED BUT UNVERIFIED | Part A; §12 | StrictHttps catch-22 |

---

## 17. CLOSING SUMMARY

### A. What SPEMCS is supposed to do

A proctored exam runs on an endpoint under a default-deny network lockdown: only the exam vendor's approved destinations, scoped to the approved browser, reachable only via trusted resolved IPs in a signed policy; all profiles contained; IPv6 isolated; DNS tunnel-proof; rollback restoring the exact baseline; no blanket explicit block rule. Around that core: an agent service (SYSTEM) that enforces and journals, a UI for the proctor, a management server with role-based auth, device identity enrolled via bootstrap key, signed/versioned policy distribution, and an audit trail of violations.

### B. What SPEMCS currently does

The agent service runs, registers devices, receives signed policies over an authenticated WebSocket, verifies RSA-PSS signatures + freshness + monotonic version, and — when a management endpoint passes the StrictHttps gate — installs a group-scoped allowlist and flips per-profile `DefaultOutboundAction` to Block, journaled for rollback. On this host it additionally suppresses browser DoH, collects ETW DNS/network telemetry, and publishes violation events to the central server. The frontend creates exams, compiles/distributes/activates policies, and streams live monitoring. The backend stores exams/devices/sessions/events/policies and serves a proctor console — but only ~half of it with authentication.

### C. What is currently broken

1. Process classification is dead at runtime (B-1) — 225/450 live log lines are that one exception.
2. Any process can use the allowlist (Part A §4/§5) — the spec's core guarantee doesn't hold.
3. Policy signatures invalidate on every backend restart (B-2).
4. Agent crash mid-lockdown leaves the machine sealed with no automatic recovery (B-3/B-4); and the one recovery path would tear down a valid exam (B-4).
5. Rollback of one session tears down all sessions' rules (B-5); restore can silently yield to external changes (B-7); the backup restore path is broken-by-construction (B-8).
6. ~39 endpoints + dashboard WS unauthenticated (S1); `/auth/register` self-service admin (S6).
7. Live Neon credentials and a placeholder JWT secret committed (S2/S3).
8. No migrations (B-10).
9. `approved_browser` ignored; Edge AND Chrome always approved (B-9).
10. Default deployment config cannot pass the management verifier, so the advertised run path never enforces (S5/catch-22) — the most likely "it's installed but nothing locks down" cause.

### D. What is missing

Application scoping of rules (M-1); server-side destination resolution (M-2); wired startup recovery (M-3); explicit IPv6 isolation (M-4); DNS pathway or prohibition (M-5); persistent signing key/rotation (M-6); Alembic migrations (M-7); per-device enforcement-state visibility (M-8); Firefox DNS policy (M-9); frontend for resolved destinations (M-10); frontend tests (M-11); inbound baseline (M-12). Plus, from the top: the original requirements/spec document set itself (`SPEMCS_Endpoint_Agent_Codex_Prompt.md` and companions) — absent from repo and git history.

### E. What should be fixed first

P0 in this order: (1) classifier race + its integration test; (2) signing key persistence/rotation; (3) startup recovery with phase-correct semantics; (4) rollback session-scoping; (5) closing the auth gap (REST routers + dashboard WS + register); (6) application scoping of allow rules the spec demands; (7) destination resolution. P1: migrations, credential rotation, IPv6, exact-restore semantics, and an operator runbook for the TLS management path. All gated on explicit approval.

### F. What must NOT be changed (already matches the specification)

- The per-profile `DefaultOutboundAction` default-deny mechanism, and the absence of explicit `FirewallAction.Block` rules (Part A §10). Never "fix" this into a blanket block rule.
- The `::/127` IPv6 loopback representation (comment/`::1` mismatch is cosmetic — the value in `HANDOFF.md` §10 is the one to keep).
- The `ServiceName` guard in `WindowsFirewallAdapter.AddRule` (null/empty/"none"/"*" skip) — it prevents wildcard service rules.
- The `failurePhase` tracking and `defaultBlockWasAttempted` gate in rollback/state-machine restore.
- The named-pipe + SYSTEM privilege split: service owns firewall, UI in interactive session never touches COM.
- RSA-PSS/SHA-256 signature verification with monotonic replay protection, expiry, revocation, and canonical-JSON signing — matching the implementation on both ends (while the docs/UI text that says "Ed25519" is the thing to correct).
- The `SPEMCS_EXAM_LOCKDOWN` group scoping of every create/delete/enumerate operation — and the never-reset / never-delete-user-rules hygienic constraints (§9).
- `FirewallProfiles.All` coverage at rule creation and the "only change active profiles' default" rule.
- The two-phase apply order (install allow rules → verify → default block → verify).
- Hardware-UUID-bound device tokens + 4401 close on the agent WS.
- The `TransportSecurityMode.StrictHttps` gate itself — the bug is the *deployment config*, not the gate.

---

*Audit method: read-only. No file, firewall setting, or rule was created, modified, enabled, disabled, or deleted. `codex_sandbox_offline_block_outbound` was not touched. All findings derive from source inspection, git inspection, and the agent's own runtime logs (`out.txt`/`out1.txt`), verified September 4, 2026. Claims sourced to files: `Endpoint-agent/src/Spemcs.Agent.Core/…`, `Endpoint-agent/src/Spemcs.Agent.Service/…`, `backend/backend/…`, `frontend/src/…`.*

---

## 18. FIREWALL / NETWORK-CONTROL CLAIM-BY-CLAIM CHECK (incident-focused)

| Question | Answer | Evidence |
|---|---|---|
| Can SPEMCS discover the codex rule? | Yes — by read-only enumeration (`GetRuleNamesByGroup`, `GetRulesByGroup` enumerate all rules), but no code path appears to invoke enumeration outside enforcement cycles. | `WindowsFirewallAdapter.cs` |
| Can SPEMCS enable/disable it? | **No.** No method sets `Enabled` on an existing rule anywhere in the repository. | exhaustive grep for `Enabled` setter on firewall rule models |
| Can SPEMCS modify it? | No. No update/`InvokeMember` on arbitrary rule properties exists. | `WindowsFirewallAdapter.cs` |
| Can SPEMCS delete/recreate it? | `RemoveRule(name)` can delete any named rule, but every call site is scoped to `SPEMCS_EXAM_LOCKDOWN` group or `SPEMCS-` prefix — the codex rule matches neither. No code recreates it. | `PerformSafeRollbackInternal`, `GetRuleNamesByGroup` |
| Can SPEMCS change profile defaults? | Yes — `SetDefaultOutboundAction` — a different control class than an explicit block rule. It was never invoked in the captured logs. | `WindowsFirewallAdapter.cs`, `out.txt` |
| Does SPEMCS use WMI/CIM/PowerShell/netsh? | **No.** COM only (`HNetCfg.FwPolicy2`, `HNetCfg.FWRule` via `dynamic`). No `Process.Start` on firewall tools, no `ManagementObject`, no `Invoke-CimMethod`. | `WindowsFirewallAdapter.cs`; grep across `Endpoint-agent/src` and `backend/backend` |
| Does the original design expect coexistence? | Yes. §9 of HANDOFF codifies "never `netsh advfirewall reset`, never delete non-`SPEMCS_EXAM_LOCKDOWN` rules", and the rollback paths honour it. | `HANDOFF.md` §9; implementation §7.3 |
| Could SPEMCS have created the codex rule? | **Almost certainly not.** The observed `WmiPrvSE.exe`-attributed modification is inconsistent with SPEMCS's COM-only, no-enable/disable, no-block-rule architecture. | §14.3 |
| Is there any SPEMCS code that could *in the future* interact with it? | Only via a future change to `RemoveRule`/enumeration or an explicit feature to manage non-SPEMCS rules. Today: none. | — |

---

## 19. VERIFICATION PASS (how each top-level finding was confirmed)

| Claim | Confirmation method |
|---|---|
| B-1 classifier race | Re-read `ProcessServices.cs` (121, 326-333), `Monitoring.cs` (13, 44-46, 129-131), `AgentWorker.cs` (63-65) after compaction; greped for `lock (` in `Spemcs.Agent.Core` — DnsCorrelationTracker/Domain/EtwDnsListener/EventUploaderWorker/NetworkEnforcer/SqliteRollbackJournal all lock, classifier and `_seen` don't |
| Auth gap | Per-route `grep -cE '^@router\.'` vs `require_role|get_current_user` counts; confirmed no router-level `dependencies`; re-read `main.py` include list; re-read `dashboard_ws.py:22-37` |
| Signing key | Re-read `routes/policies.py:29-38`, `policy_signer.py:107-125`; greped for persistent-key loading (`load_pem_private_key`, `private_key_pem`) → none |
| Migrations | `ls backend/backend/migrations` → `.gitkeep` only; no `alembic.ini`; `main.py:43` |
| Credentials | `git ls-files` → `.env.txt` tracked; `git show HEAD:backend/.env.txt` redacted + shown; live `.env` + placeholder `SECRET_KEY` present |
| Dead recovery code | `grep -rn "ReconcileStartupStateAsync\|RecoverIncompleteSessionAsync"` over `Spemcs.Agent.Service` → zero hits; `Program.cs` full read |
| Rollback scope defect | Re-read `PerformSafeRollbackInternal` from `NetworkEnforcer.cs` (or the journal-adjacent code) — the redundant `StartsWith("SPEMCS-")` clause confirmed present |
| `::/127` vs `::1` comment | Re-read `EnforcementStateMachine.cs:688-690` |
| `_approvedFamily` dead | grep → 3 hits (declaration, assignment, assignment); no reads |
| Requirement 10 compliance | grep `FirewallAction.Block` across `Endpoint-agent/src` → only profile-default references |
| Docs contradictions | Re-read `HANDOFF.md` §2.2/§2.4/§4/§6/§9/§10; `M8` header + §1.1; `M9` §1.1; `frontend/README.md` (1 line); `ExamShieldPage.tsx:132` toast |

---

## 20. WORD ABOUT MODE AND BOUNDARIES

Everything above is an audit. The deliverable file itself is the only change made to the repository (this document). No source file, configuration value, database row, firewall rule, or Windows setting was modified. If you approve a fix list, the natural first implementation tranche is the P0 set (section 15) — and specifically a decision on whether `applicationPath`-scoped rules are a Phase-1 change or a Phase-1.5 change, because that decision changes the policy schema and the agent-side rule builder together.

**Open questions for the operator (not blocking the audit):**

1. Was there ever a second exam platform profile (e.g., a legacy vendor) that the `approved_browser` field was meant to support? (Informs M-1's scope.)
2. Is the management server intended to run on the same machine as an agent (localhost) in production, or is that purely a dev configuration? (Determines how the StrictHttps catch-22 is resolved.)
3. Should the codex rule be treated as a permanent fixture of this test host's baseline (i.e., SPEMCS must be *tested against* it) or as a transient incident artifact?
