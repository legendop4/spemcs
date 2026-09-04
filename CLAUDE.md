# SPEMCS — working context

Read this before touching anything. It carries the project owner's constraints, the toolchain
facts that are easy to get wrong here, and what is already done so it does not get redone.

## Non-negotiable constraints from the project owner

These are standing instructions, not suggestions, and they matter more with a real shell on a real
Windows box than they did in a sandbox.

- **Do not change or delete the "Codex" Windows Firewall rule.** Do not enable it, do not disable
  it, do not modify it, do not remove it as part of SPEMCS rollback, and do not redesign SPEMCS
  around it. Do not assume SPEMCS created it.
- **Do not change live firewall settings on this machine.** No `netsh advfirewall reset`, no profile
  `DefaultOutboundAction` changes, no adding or deleting rules against the real host firewall.
  Firewall behaviour is tested through `MockFirewallAdapter`, not against the live stack.
- **Do not run destructive commands.** No mass deletes, no `git reset --hard`, no force pushes.
- **Never print, log, commit, or echo a credential value.** Real secrets are committed in this repo
  (see below); refer to them by file and field name only.
- **Do not rewrite git history** unless the owner explicitly asks for it.

## What the work is

Full takeover of SPEMCS: implement, fix, test, verify. The read-only audit phase is finished —
`SPEMCS_TAKEOVER_AUDIT.md` is its output. **Do not redo the audit.** The current phase is
implementation against ten acceptance requirements for exam-time network lockdown, the core of
which are: outbound deny-by-default via profile-level `DefaultOutboundAction`, never a blanket
explicit outbound BLOCK rule; every allow rule scoped to the approved examination browser
executable so `curl.exe`/`python.exe` cannot use the allowlist; destinations validated and
normalized in the signed policy rather than trusted from the client; all three firewall profiles
covered; IPv6 containment including 6to4/Teredo; DNS not usable as an exfiltration path; and
rollback that restores the exact pre-exam baseline without deleting another session's or another
product's rules.

## Toolchain facts

**Endpoint agent (C#).** Six projects, all `net8.0-windows`. Needs the **.NET 8 SDK** on Windows.
The WiX installer project is *not* referenced by `Spemcs.Agent.sln`, so building the solution does
not require WiX. `Spemcs.Agent.UI` and the test project use WPF.

- `Directory.Build.props`: `TreatWarningsAsErrors=true`, `Nullable=enable`, `AnalysisLevel=latest`.
  There is no `EnforceCodeStyleInBuild`, so IDE#### style rules are not build errors but CA####
  analyzer warnings are.
- Central package management via `Directory.Packages.props`, plus
  `RestorePackagesWithLockFile=true`. If restore fails claiming a lock file is out of date, use
  `dotnet restore --force-evaluate` rather than deleting lock files.
- **There is no `InternalsVisibleTo` anywhere in the solution.** Anything the test project must
  reach has to be `public`. This is why `PolicyDestinationValidator` is public.

**Backend (Python/FastAPI).** `pip install -r backend/requirements.txt`. Without it,
`test_policy_compiler.py` cannot even be collected (module-scope `fastapi` import) and
`test_policy_browser_scoping.py` reports 17 failures that are purely a missing `pydantic`.

## Start here

```
dotnet --list-sdks                                            # expect an 8.0.x
dotnet restore Endpoint-agent/Spemcs.Agent.sln --force-evaluate
dotnet build Endpoint-agent/Spemcs.Agent.sln --no-restore
dotnet test  Endpoint-agent/tests/Spemcs.Agent.Tests --no-build

pip install -r backend/requirements.txt
python -m pytest backend/backend/tests -q
python3 Endpoint-agent/tests/parity/verify_policy_destination_validator_parity.py
python3 Endpoint-agent/tests/parity/verify_policy_destination_validator_parity.py --self-check
```

`--force-evaluate` is required on the first restore: `Spemcs.Agent.Tests.csproj` gained a
`ProjectReference` to `Spemcs.Agent.Service` (so `AgentWorker` can be tested at all), and with
`RestorePackagesWithLockFile=true` a changed dependency graph makes the committed
`packages.lock.json` stale. Restore will fail with NU1004 otherwise. Do not delete lock files.

The solution now **builds clean: 0 warnings, 0 errors** (first real build, 2026-09-05, .NET SDK
8.0.424). Everything written during this takeover compiled and analysed clean; the only two
diagnostics in the whole solution were pre-existing xUnit2029/xUnit2030 in
`FirewallProfileCoverageTests.cs` and are fixed. Compiling is no longer the open question — running
is.

**Run `dotnet test` from a NON-elevated shell.** Two tests branch on
`WindowsPrincipal.IsInRole(Administrator)` and, when elevated, call
`SetDefaultOutboundAction(..., FirewallAction.Block)` against the *live* host firewall —
`WindowsFirewallAdapterIntegrationTests.cs:143` (all active profiles) and
`WindowsTrafficEnforcementIntegrationTests.cs:143` (Private). Both restore the baseline, but an
interrupted or crashed run leaves outbound traffic blocked on this machine. Unelevated, those same
paths assert `UnauthorizedAccessException` instead and touch nothing, so the suite is safe and still
meaningful. Nothing in the suite ever writes the registry, and every firewall cleanup path is scoped
by exact rule name or by `FirewallRuleModel.SpemcsRuleGroup`, so the Codex rule is never at risk.

## Status

Verified by actually running:

- Backend destination/DNS resolution pipeline — `test_destination_resolution.py`, 112 passed.
- Persistent signing key lifecycle — `test_signing_key_lifecycle.py`, 43 passed.
- C#/Python agreement on destination validation — the parity harness passes, and `--self-check`
  catches 27 of 27 mutations.

**The whole C# suite now executes green: 289 of 289 cases passed, 0 failed, 0 skipped** (2026-09-05,
non-elevated shell, SDK 8.0.424, VSTest 17.11.1, 7.1 s). That covers everything written during this
takeover: process-classifier concurrency (P0-A), startup recovery ordering in `AgentWorker` (P0-C),
browser-scoped firewall allow rules (P0-D), `approved_browser` gating approval (P0-E), all three
firewall profiles, and `PolicyDestinationValidator` + `PolicyReceiver` validation. Two caveats keep
this from being total coverage of the shipped behaviour, and both are structural rather than
oversights: there is no positive-path `AgentWorker` test (see below), and
`LiveBackend_VerifyConnectivityAsync_Succeeds` asserts the fail-closed half of its contract unless
uvicorn is running on port 8002.

Not started: IPv6/DoH hardening beyond destination refusal of 6to4/Teredo; the remaining rollback
semantics work (`RestoreBaselineSafely` result semantics, inbound baseline contract); backend auth
coverage on `agent_api.py` and the `/auth/register` self-service admin escalation; Alembic initial
migration; `device_policy_states` API; fail-closed activation; stale crypto claims in the docs.

`AgentWorkerStartupOrderTests.cs` now covers the P0-C ordering guarantee — startup recovery
completes before `_ready` lets `START_EXAM` or `STOP_EXAM` through — which was previously argued
only by a code comment. **Every test in that file keeps recovery blocked forever, on purpose.** The
statement immediately after `await RunStartupRecoveryAsync(...)` is
`BrowserPolicyEnforcer.DisableSecureDns(...)`, which opens `HKLM\SOFTWARE\Policies\Microsoft\Edge`
and `...\Google\Chrome` for write; letting `ExecuteAsync` past recovery inside a test would mutate
machine-wide browser policy on whatever box runs `dotnet test`, silently succeeding when the test
host is elevated. So there is deliberately no positive-path AgentWorker test, and the suite treats
any appearance of the Secure-DNS log line as a failure. Writing positive-path tests requires
extracting that registry write behind an injectable abstraction first — that belongs with the
DNS-hardening work item, not with P0-C.



## Traps specific to this repo

**`127.0.0.1` is a legal `management_server` address and an ILLEGAL `allowed_destinations` range.**
Both sides enforce this: `PolicyDestinationValidator.ForbiddenV4` lists `127.0.0.0/8` and
`policy_compiler.py::_ALWAYS_FORBIDDEN_V4` lists the same, while
`DescribeUnsafeManagementAddress` deliberately permits loopback because the dev/lab management
server really is on `127.0.0.1:8002`. The asymmetry is intentional — do not "unify" it. Three
integration tests predated that rule and put `"ip_ranges": ["127.0.0.1"]` in a vendor destination
purely so the harness could bind a real `TcpListener`, so they failed at their first
`Assert.True(result.Success)`. **Fixed 2026-09-05 on the test side only**: each now declares
`private const string VendorIp = "198.51.100.7"` (RFC 5737 TEST-NET-2) and uses it for the vendor
`ip_ranges` and every vendor traffic probe, while `management_server` and the management probes stay
on loopback — the shape of `PythonInteropFixtures.ValidRawJson`. A single host, not a CIDR, because
both files' `IsTrafficPermitted` matches `RemoteAddresses` by substring rather than by prefix
containment; a CIDR fixture with a host probe would silently invert the test. Loosening the
validator to make those tests green would delete requirement 3.

**`LiveBackend_VerifyConnectivityAsync_Succeeds` needs uvicorn on `http://127.0.0.1:8002`** to
exercise its success path. `ManagementConnectivityVerifier` probes
`GET /api/v1/management/health` and requires `service == "SPEMCS"` **and** `status == "ok"`
exactly — `degraded` is refused by the M8 security model. `backend/backend/routes/health.py`
returns a constant `ok`, so a running backend is the only precondition. No credentials involved.
There is no `Skip=` convention in this suite and no skippable-fact package, so the test branches at
run time instead (the idiom `ControlledTrafficEnforcement_Verification` already uses for elevation):
a 750 ms TCP probe decides which half of the contract to assert — backend up ⇒ verification must
succeed, nothing listening ⇒ it must fail closed. Both branches assert, so it can never pass
vacuously, and an optimistic verifier would be caught even with no backend running.

**`Endpoint-agent/tests/Spemcs.Agent.Tests/AddressValidationFixtures.cs` is generated.** Its
expected verdicts are the *backend's* behaviour, established by differential-testing a Python
transliteration of the validator against `backend/backend/services/policy_compiler.py` over 4534
inputs. If `PolicyDestinationValidatorTests` fails, the default assumption is that the agent has
drifted from the backend. Regenerate the fixture only after confirming the backend is the side that
changed, via `--emit-fixture`. Regenerating it to make a red test go green destroys the only proof
that the agent's check and the backend's check agree.

**Line endings.** 278 tracked files show as modified, but only 48 have real content changes — the
other 230 are a wholesale LF→CRLF flip in the working tree. Use
`git diff --numstat --ignore-all-space` to see the real ones. Do not let the EOL churn into a
commit; it would bury the actual work.

**Committed secrets.** `backend/.env.txt` and `frontend/.env.txt` are tracked and contain live
credentials, including a Neon database URL. Both need `git rm --cached` and every value in them
rotated. `.gitignore` has been updated to stop new copies, which does not untrack the existing
ones. Do not print the values. Do not rewrite history to purge them without explicit instruction.

**`out.txt` / `out1.txt`** at the repo root are captured agent logs kept as field evidence for
P0-A: 225 `InvalidOperationException`s out of `ConfigurableProcessClassifier.GetTrust` between
12:00 and 12:09 UTC on 2026-09-04. They are evidence, not deliverables.

**Private key file permissions** set by the agent are advisory on Windows, so the key directory
must be protected by NTFS ACLs. Any claim that file mode alone protects the signing key is wrong.

## Documents

`SPEMCS_TAKEOVER_AUDIT.md` is the requirements matrix and audit findings. `HANDOFF.md` describes
the service/UI split and the enforcement architecture. The M8 and M9 reports predate this phase and
contain crypto claims that are now stale — treat them as history, not as specification.
