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

**The MSI is built separately and has its own preconditions.** `wix` 7.0.0 is on PATH; the project
takes `WixToolset.Util.wixext` (pinned in `Directory.Packages.props` like every other package — a
`Version=` on the `PackageReference` is NU1008 under central package management).

```
dotnet build Endpoint-agent/installer/Spemcs.Agent.Installer.wixproj -c Release
powershell -ExecutionPolicy Bypass -File Endpoint-agent/installer/verify-msi.ps1
```

It harvests `Endpoint-agent/publish/stage/` — Service and UI published into **one** directory, so
the shared `Spemcs.Agent.Core`/`.Ipc` assemblies are carried once. That directory is `.gitignore`d
(`Endpoint-agent/.gitignore:16`), so it must exist before the installer will build; there is no
script that creates it.

Four things about this project are easy to get wrong:

- **`SuppressValidation=true` is in the `.wixproj` and is required on this box, not laziness.** ICE
  validation cannot run under this machine's system policy and wix reports that as
  `error WIX1105` — a hard failure *after* a correct MSI has been written. Compile/link checks are
  unaffected (they caught WIX0026/WIX1044/WIX8601 while this file was being written). Contents are
  verified instead by `verify-msi.ps1`, which reads the built package's own tables rather than
  trusting the `.wxs`. Drop the suppression on a CI/signing host where ICE can run.
- **`<Exclude>` must be a child element of `<Files>`.** A `!negated` glob inside `@Include` is read
  as part of the literal path and fails with `WIX8601`.
- **Do not hand-write `File/@ShortName`.** WiX generates 8.3 names itself; a literal `SERVICE~1.EXE`
  is `WIX0026` (not 8.3-compliant) and `UI~1.EXE` is `WIX1044` (ambiguous `~n`).
- **`*.pdb` and `packages.lock.json` are excluded, but `runtimes/**` is NOT.** An earlier build
  mistakenly excluded `runtimes/**` to shrink the MSI from 11 MB to 1.9 MB, but this broke
  the Windows Service at launch with .NET Runtime Event 1026 (`System.IO.FileNotFoundException:
  Could not load file or assembly System.ServiceProcess.ServiceController`), because the .NET
  runtime dependency resolution (`Spemcs.Agent.Service.deps.json`) resolves `System.ServiceProcess.ServiceController`
  and `System.Diagnostics.EventLog` via `runtimes/win/lib/net8.0/`. The MSI preserves the full
  publish runtime payload (~11 MB / 72 files).

`ServiceInstall` must name the service **`SPEMCS Endpoint Agent`**, byte-identical to
`Program.cs:11`'s `AddWindowsService`, or the registered service cannot attach to its host (error
1063). It installs as **LocalSystem, Start=auto**, with `util:ServiceConfig` restarting on the
first, second *and* subsequent failures and `ResetPeriodInDays=0` — an agent that stops restarting
after two crashes is an unenforced seat for the rest of the exam. `ServiceControl` is
`Start="install" Stop="uninstall"`, deliberately not `"both"`: a major upgrade already sequences
uninstall-then-install, and stopping on the install pass would bounce the agent mid-exam.

The first-run wizard is launched by `WixShellExec` with **`Impersonate="yes"`** so it runs as the
installing user, not as the elevated installer — a SYSTEM-owned window lands on the wrong desktop
and any `config.json` it wrote would be SYSTEM-owned. `Return="ignore"`: the agent is installed and
running by that point, so a cosmetic window failing to open must not roll back a working install.

**The installer touches the Windows Firewall in no way at all** — no rules, no default-action
changes, no rollback. Verified against the built package: it has no `WixFirewall*` table and no
`netsh` custom action. Enforcement is reached only through authenticated exam activation, so the
`Codex` rule and `TEMP SPEMCS TCP 8000` are never enumerated or modified by an install or uninstall.

Only `config.json` and `Logs\` are MSI-managed under `%ProgramData%\Spemcs`. **`agent.db` and
`network_journal.db` are deliberately not**: they are created by the service at run time, and an
uninstall that removed the rollback journal would destroy the firewall baseline a crashed session
still has to restore. (Earlier comments in `Package.wxs` named a `state.db`,
`rollback_journal.db` and a `DeviceCredentials\` directory — **none of those exist**; the real names
are `agent.db` and `network_journal.db`, both directly under the root, and there is no credential
directory.) The `"Spemcs"`/`"SPEMCS"` casing disagreement between `Program.cs:23` and
`AgentConfigService.cs:36` is harmless on NTFS — every call site resolves to the same live
directory — and is left alone rather than churned.

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
cd backend && python -m pytest backend/tests -q          # NOT from the repo root - see below
python Endpoint-agent/tests/parity/verify_policy_destination_validator_parity.py
python Endpoint-agent/tests/parity/verify_policy_destination_validator_parity.py --self-check
```

Use `python`, not `python3`, on this box: `python3` resolves to the Microsoft Store app-execution
alias and opens the Store instead of running anything.

The backend suite has to be run **from `backend/`**, not from the repo root. The test modules import
`backend.services.*`, which needs `<repo>/backend` on `sys.path`; `python -m pytest backend/backend/tests`
from the root puts `<repo>` there instead and every one of the nine test modules dies at collection
with `ModuleNotFoundError: No module named 'backend.services'`.

**If the build fails with MSB3027/MSB3021 file-lock errors, do not kill the process.** The SPEMCS
agent service and `Spemcs.Agent.UI` run on this machine and hold their `bin/Debug/...` DLLs open, so a
Debug build cannot copy `Spemcs.Agent.Core.dll` or `Spemcs.Agent.Ipc.dll` into the Service and UI
output directories. Build and test in **Release** instead — separate output directories, nothing
running is touched, same analyzers and same `TreatWarningsAsErrors`:

```
dotnet build Endpoint-agent/Spemcs.Agent.sln -c Release
dotnet test  Endpoint-agent/tests/Spemcs.Agent.Tests -c Release --no-build
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

- Backend destination/DNS resolution pipeline — `test_destination_resolution.py`, 134 passed.
- Persistent signing key lifecycle — `test_signing_key_lifecycle.py`, 43 passed.
- C#/Python agreement on destination validation — the parity harness passes, and `--self-check`
  catches 34 of 34 mutations, every one by a failed assertion rather than a crash. **The older
  "27 of 27" claim was void**, and the two reasons are worth knowing because both made the check
  report success while proving nothing: (1) each mutant was written to a temp directory and derived
  the repo root from its own `__file__`, so it died on `import backend` and was scored "caught" for a
  reason unrelated to the mutation — an *unmutated* copy run from a temp directory also exited 1;
  (2) every mutation's search string also appears verbatim in the `MUTATIONS` table earlier in the
  file, so `replace(old, new, 1)` rewrote the table entry and left the logic untouched. Fixed by
  passing the real root down in `SPEMCS_PARITY_REPO` and by mutating only the source below the
  `from backend.services.policy_compiler import` marker. If a future change makes the self-check
  report a suspiciously perfect score, suspect this class of bug first.

**The whole C# suite executes green: 393 of 393 cases passed, 0 failed, 0 skipped** (2026-09-05,
non-elevated shell, SDK 8.0.424, VSTest 17.11.1, Release). That covers everything written during this
takeover: process-classifier concurrency (P0-A), startup recovery ordering in `AgentWorker` (P0-C),
browser-scoped firewall allow rules (P0-D), `approved_browser` gating approval (P0-E), all three
firewall profiles, `PolicyDestinationValidator` + `PolicyReceiver` validation, the P1-H/I IPv6
transition-mechanism and DNS work, and the 72 rollback-correctness cases in `RollbackScopeTests`.
Two caveats keep
this from being total coverage of the shipped behaviour, and both are structural rather than
oversights: there is no positive-path `AgentWorker` test (see below), and
`LiveBackend_VerifyConnectivityAsync_Succeeds` asserts the fail-closed half of its contract unless
uvicorn is running on port 8002.

**Backend suite: 868 passed, 1 skipped, 0 failed** (2026-09-05, **15 s**). The previous figures —
773 passed / 10 failed / 1 skipped in 316 s — described a suite that ran against the **live remote
Neon database**. It no longer does; see P1-Q below. The 10 failures were all one cause (the live
`network_policies` table had no `approved_browser` column) and none was a validation defect: in the
five `malicious_ranges` cases the *security* assertion (`assert resp.status_code == 400` —
client-supplied addresses are still rejected) always passed, and the failing line was the follow-up
`GET /api/policies/exam/{id}` expecting 404.

Nothing is "not started" from the original P1 list any more. **Phase 20 (P1-Q/R/S/T) is done and
verified** — see the four sections below.

**A caveat about those four labels.** `P1-R`, `P1-S` and `P1-T` appear **nowhere** in this
repository, and `SPEMCS_TAKEOVER_AUDIT.md` carries no P-labels at all. The mapping used was
*derived* from the four-item sentence that used to sit here — "Alembic initial migration and
hermetic backend tests (P1-Q); `device_policy_states` API; fail-closed activation; stale crypto
claims in the M8/M9 docs" — one item per label, in order. If the owner meant something else by
R/S/T, that work is still outstanding under those names; the four items themselves are done.

**P1-Q (Alembic + hermetic backend tests) is done and verified.**

- `backend/alembic.ini` + `backend/backend/migrations/` with two revisions. **`0001_baseline`
  reproduces the schema `Base.metadata.create_all` had already built**, so the deployed database is
  brought under version control by `alembic stamp 0001` — running 0001 for real against it would
  fail on tables that already exist. `0002_network_policies_signed_columns` adds the three columns
  the deployed table was actually missing (`approved_browser`, `key_id`, `schema_version`).
- Two omissions from 0001 are load-bearing and must not be "completed": the three 0002 columns are
  absent (including them would make `stamp 0001` claim columns the database does not have, and 0002
  would then be skipped), and the nine undeclared `events` columns plus three undeclared tables that
  exist only on the deployed database are absent (this baseline describes the *models*).
  `migrations/env.py` filters those out of autogenerate so no future revision proposes dropping
  them, and `test_without_the_filters_those_drops_are_exactly_what_autogenerate_proposes` fails if
  the filter ever stops being the reason.
- **0002 backfills the empty string, deliberately.** All three columns are `nullable=False`, so
  `ADD COLUMN` on a non-empty table needs a value, and there is no correct one: those rows were
  signed before the columns existed, so any plausible value produces canonical bytes that differ
  from the bytes actually signed. `rebuild_signed_payload` already refuses a falsy `key_id` /
  `approved_browser` with "Recompile the policy for this exam", surfaced as a 409. Empty string is a
  tombstone routing legacy rows into a legible refusal instead of an opaque signature failure on the
  endpoint. No `server_default` is left behind — add nullable, backfill, then `SET NOT NULL`.
- **`alembic.ini` carries no `sqlalchemy.url`, on purpose.** It is a tracked file and the URL carries
  live credentials; `migrations/env.py` reads it from `backend.app.config.settings` at run time.
- `backend/backend/tests/conftest.py` makes the whole suite **hermetic**: a session-scoped autouse
  fixture builds a file-backed SQLite database in a `TemporaryDirectory`. The one non-obvious line is
  `db_module.SessionLocal.configure(bind=test_engine)` — mutating the `sessionmaker` **in place** is
  the only thing that redirects modules which did `from backend.app.database import SessionLocal` at
  import time (`dashboard_ws._authenticate` is one). `connect_args={"check_same_thread": False}`
  because `TestClient` serves on a worker thread, and a `PRAGMA foreign_keys=ON` `Engine.connect`
  listener guarded on the sqlite3 driver. `SPEMCS_TEST_DATABASE_URL` is the escape hatch back to real
  PostgreSQL.
- Effect: **316 s → 15 s**, 10 failures → 0, and no test touches the production database.
  `test_migrations.py` is 10 cases.

> **Applying the migration to the live Neon database is the owner's action, not something this
> phase did.** That database holds 24 real `network_policies` rows and ~3121 `events` rows. The two
> commands are `cd backend && python -m alembic stamp 0001` then `python -m alembic upgrade head`,
> in that order — the stamp first, or 0001 will try to create tables that already exist. Until then
> the deployed schema still lacks the three `network_policies` columns and policy compilation still
> fails against it with `UndefinedColumn`.

**P1-R (`device_policy_states` API) is done and verified.** The table existed since M1 and **nothing
had ever written a row to it**, which is what made P1-S impossible: there was no server-side record
of whether a seat had actually taken the policy.

- `services/device_policy_state_service.py` — `record_state` upserts on `(exam_id, device_id)`;
  `_NOT_ARMED = {PENDING, FAILED, ROLLED_BACK}` so `is_armed` is defined by naming the **unsafe**
  states, not the safe ones — a new status string added later reads as *not armed* until someone
  decides otherwise. `_MAX_ERROR_LENGTH = 255` truncates rather than raising on the `String(255)`
  column. `record_state_for_hardware_uuid` returns `None` for an unknown device instead of inventing
  a row.
- `routes/policies.py` writes APPLYING on a successful distribution and FAILED + `last_error`
  **before** the 503, so a failure is recorded, not just reported. `_record_distribution_state`
  swallows its own failures deliberately: no state row means not armed, which is the fail-closed
  direction.
- `websocket/agent_ws.py::_map_reported_status` maps an **unrecognised** reported status to
  `STATUS_FAILED` and puts the raw value in `last_error`. `_resolve_policy_identity` derives the exam
  from the policy row's FK and explicitly refuses a "device's current exam" fallback — a report
  naming nothing must not be attributed to whatever exam happens to be ACTIVE, which
  `test_a_report_naming_nothing_is_not_attributed_to_the_active_exam` pins.
- Reads: `GET /api/policies/exam/{exam_id}/device-states` and `.../device-states/{device_id}`.

**P1-S (fail-closed activation) is done and verified.** The entire "is this exam safe to start"
decision used to live in `frontend/src/pages/ExamShieldPage.tsx::handleActivate`; the server
activated unconditionally. A direct `POST /api/exams/{id}/activate` with any staff token therefore
produced an ACTIVE network-enforcement exam with no policy at all, and the front-end's own
distribution loop could fail on **every** device and still reach an endpoint that reported
"activated".

- `services/enforcement_readiness.py` — 12 problem codes plus an `EPHEMERAL_SIGNING_KEY` **warning**
  (warn, do not refuse: an ephemeral key still signs correctly, it just will not survive a restart).
  The armed set is `{state.device_id where is_armed(status)} & assigned_device_ids`.
- `POST /{exam_id}/activate` refuses with **409 + the full readiness dict + a prose `message`, and
  leaves the exam PENDING** — nothing is half-started. `GET /{exam_id}/enforcement-readiness` is the
  same evaluation as a read, so an operator sees the reason before pressing Launch.
- `exam_service.activate_exam` gained `armed_device_ids`. An un-armed seat is left **PENDING and not
  launched**, never `MONITORING`. Marking it MONITORING was a fail-open in both directions at once:
  the workstation enters exam mode with no lockdown, and the dashboard prints the word an invigilator
  reads as "this seat is controlled". `armed_device_ids=None` means no restriction, which is the
  pre-existing behaviour for exams that make no lockdown claim.
- Partial readiness activates: armed seats go MONITORING, un-armed seats stay PENDING and are
  **named** in `devices_not_enforcing` (named, not counted — an operator who launches 40 seats and
  gets 38 needs to know which two).

`backend/backend/tests/test_enforcement_activation.py` is 60 cases across both items. It passed
60/60 on its first run, which is exactly the shape of a file that proves nothing, so four
source mutations were applied and reverted to prove it is falsifiable:

| Mutation | Result |
|---|---|
| `exam_service`: neutralise the `armed_device_ids` filter | 1 failed, 59 passed |
| `routes/exams`: neutralise `if not readiness.ready` | 14 failed, 46 passed |
| `agent_ws._map_reported_status`: unknown status ⇒ APPLYING | 6 failed, 54 passed |
| `routes/policies._record_distribution_state`: return before writing | 4 failed, 56 passed |

**P1-T (stale crypto claims) is done.** Ground truth was re-established from source in every case,
not from the older documents:

- **Device-token TTL is 30 days** (`auth_service.py:174`, `ttl_seconds: int = 2592000`), not the
  "7-day" figure asserted in `M8:31` and `M9:20`. That was wrong when written — nothing ever issued
  a 7-day device token.
- **No Ed25519 code has ever existed in this repository.** `HANDOFF.md` §2.2 and the frontend compile
  toast both said the policy signature was Ed25519; both are corrected to RSA-2048 / RSA-PSS /
  SHA-256 / MGF1-SHA-256 / salt 32 over RFC 8785 canonical JSON. **The Ed25519 hits in
  `SPEMCS_TAKEOVER_AUDIT.md` (lines 321, 459, 668, 808, 841, 890) are the audit *recording* the
  mislabel as a finding and are correct as written — do not "fix" them.**
- `dev-key-1` is historical. Key ids are derived from the key material:
  `spemcs-<32 hex of SHA-256 over SPKI DER>`, or `ephemeral-<…>` (`signing_key_manager.compute_key_id`).
  Note the persistent prefix is **`spemcs-`**, not `persistent-`.
- The M9 firewall group string `SPEMCS-EXAM-ENFORCEMENT` is wrong; it is **`SPEMCS_EXAM_LOCKDOWN`**
  (`EnforcementModels.cs:180`).
- M9's A-07 row tests a **`student` role that does not exist** — `UserRole` is exactly
  `ADMIN`/`PROCTOR`, and since P1-N/O/P `role` is a closed enum so an out-of-enum value is a 422
  before the role comparison is ever reached.
- M8/M9's role-authorization claims ("proved", "consistently yield 401") were true of the routes they
  enumerate and false as universal statements: the Phase 19 inventory found **53 of 81 routes open**
  on the date of those reports.
- `HANDOFF.md` also claimed the baseline captures `DefaultInboundAction` (it never did — inbound is
  out of scope and `IFirewallAdapter` cannot mutate it) and listed a whitelist of
  `DNS (53), WebRTC/STUN, HTTPS (443)` (there is no SPEMCS DNS rule and ports come from the signed
  policy). Both corrected.

**M8 and M9 were annotated, not rewritten.** Each now opens with a "HISTORY, NOT SPECIFICATION"
corrections table, and each stale claim keeps its original wording plus an inline `[†C-n]` marker
pointing at the row. Editing the numbers in place would have destroyed the record of what was
actually asserted at the time, which is the only thing those documents are still good for.

**Two frontend defects in the blast radius of P1-S were fixed.** `api.ts::fetchJson` did
`throw new Error(error.detail || ...)`, and a FastAPI `detail` is not always a string — the new 409
refusal answers with an **object**, so `new Error(obj)` rendered the toast as `[object Object]` for
the one refusal an operator most needs to read. There is now an `ApiError` carrying `status` and the
structured `detail`, and `handleActivate` renders `problems` and the named un-armed seats.

**P1-H/I (IPv6 transition mechanisms + DNS) is done and verified.** What it changed:

- **ISATAP** is now refused on both sides. It could not be a row in the forbidden-CIDR table because
  RFC 5214 assigns it no prefix — it is identified by the modified-EUI-64 interface identifier
  (`0000:5EFE:w.x.y.z` or `0200:5EFE:w.x.y.z`) at address bytes 8–11, under whatever prefix the
  ISATAP router advertises. `_is_isatap_network` / `IsIsatapRange` therefore fire only when the
  prefix pins all 32 marker bits (**`prefixlen >= 96`**). **This exactness is load-bearing, not
  laziness:** an overlap test — the shape used for `2002::/16` and `2001::/32` — would refuse every
  IPv6 range of /95 or shorter, including `2001:db8::/48` and `2606:4700::/32`, because such a range
  always *contains* some address carrying the marker. A refused legitimate destination cancels an
  exam. `test_isatap_detection_has_no_false_positives` and
  `ClassQ_OrdinaryIPv6Destinations_AreNotMistakenForTransitionMechanisms` exist to stop anyone
  "fixing" this into an overlap test.
- The residual that exactness leaves — a `/95` straddling the marker, or a `/64` containing ISATAP
  addresses — is **contained at a different layer, and that layer is the real control**: all three
  mechanisms encapsulate IPv6 in IPv4 **protocol 41**, and `BuildSessionRules` emits nothing but
  `FirewallProtocol.TCP` and `.UDP` except the two loopback rules, which pin *both* ends to loopback.
  Under profile-level default-deny an unnamed protocol is a denied protocol. Asserted against real
  rule generation by `ClassQ_NoGeneratedRuleCanCarryAProtocol41Tunnel`. Read the validator as policy
  hygiene, not as the thing that stops the tunnel.
- The ISATAP check runs **after** the forbidden-range table on both sides, deliberately, so
  `fe80::5efe:w.x.y.z` keeps reporting the tighter `fe80::/10`. Two tests pin that message.
- The DNS model is now written down rather than implied — the required-versus-denied breakdown sits
  at the `DisableSecureDns` call site in `AgentWorker`, and the reason there is **no `:53` rule** sits
  in the `BuildSessionRules` remarks. Short version: recursive DNS is REQUIRED and is already carried
  by the Windows built-in "Core Networking - DNS (UDP-Out)" rule scoped to the Dnscache service, so
  SPEMCS creates no DNS rule and touches no built-in rule; a SPEMCS `:53` rule would at best duplicate
  a narrower scope and at worst hand every process a resolver. DNS tunnelling to the permitted
  resolver stays a **detected, not prevented** residual. Do not let any document claim otherwise.
- `BrowserDnsPolicy` (in `ProcessServices.cs`) replaced the inline registry writes with a pure
  descriptor plus a pure `Summarize`. It adds **`BuiltInDnsClientEnabled=0`**, which the old code
  omitted: that is the browser's own embedded *plain-DNS* stub resolver, so `DnsOverHttpsMode` does
  not cover it, it bypasses the DNS Client service and the ETW monitor, and it runs inside the
  approved-browser program scope every allow rule is pinned to.
- `DisableSecureDns` **no longer always returns true.** The old `bool success = true;` was never
  reassigned, so a total failure to disable DoH was logged as "policy enforced" and the `LogWarning`
  branch in `AgentWorker` was unreachable. It now returns true only when every required value landed
  in **HKLM**; an HKCU fallback returns false, because that hive covers one user and the candidate can
  rewrite it. Expect a warning on non-elevated dev runs — that is correct, and in production
  (LocalSystem) it should not appear.

`BrowserDnsPolicyTests.cs` **never touches the registry**, and that is the whole point of the
descriptor: `DisableSecureDns` opens `HKLM\SOFTWARE\Policies\...` for write, so calling it from a test
would mutate machine-wide browser policy on whatever box runs `dotnet test` and would silently
succeed when the host is elevated — the same hazard that keeps `AgentWorkerStartupOrderTests` from
ever letting startup recovery complete. The two things worth testing (which values are required, and
whether the outcomes amount to success) are now reachable as pure functions. **No `IRegistry` seam was
introduced** and none is needed; the part that still calls `Registry.LocalMachine` has no logic left
in it worth faking. The positive-path `AgentWorker` test remains impossible for the same reason as
before and is still deliberately absent.

`AgentWorkerStartupOrderTests.cs` now covers the P0-C ordering guarantee — startup recovery
completes before `_ready` lets `START_EXAM` or `STOP_EXAM` through — which was previously argued
only by a code comment. **Every test in that file keeps recovery blocked forever, on purpose.** The
statement immediately after `await RunStartupRecoveryAsync(...)` is
`BrowserPolicyEnforcer.DisableSecureDns(...)`, which opens `HKLM\SOFTWARE\Policies\Microsoft\Edge`
and `...\Google\Chrome` for write; letting `ExecuteAsync` past recovery inside a test would mutate
machine-wide browser policy on whatever box runs `dotnet test`, silently succeeding when the test
host is elevated. So there is deliberately no positive-path AgentWorker test, and the suite treats
any appearance of the Secure-DNS log line as a failure.

**Rollback correctness (P1-J) is done and verified.** Rollback is now *session-scoped teardown*, not
firewall cleanup. What changed, and why each change is load-bearing:

- **Ownership is by session, not by prefix.** `RemoveSessionOwnedRules` takes the union of the
  journal's `AppliedRuleNames` and a live group scan, then filters BOTH through
  `SPEMCS-{sessionId:N}-`. Names inside the group that parse to a different session, or that do not
  parse at all, are logged at Error and **never deleted** by a rollback. `"delete every SPEMCS-* rule"`
  survives in exactly one place — `RecoverIncompleteSessionAsync`'s orphan sweep, which is the only
  caller entitled to it, and which now excludes every session `LiveSessionIds()` reports as live.
- **`TryParseSessionId` refuses to guess.** Prefix + exactly 32 hex digits + `'-'` + at least one
  more character, then `Guid.TryParseExact(..., "N", ...)`. A name carrying 31 characters of a live
  GUID is an orphan, not that session's rule. Thirteen malformed inputs are pinned by `[Theory]`.
- **Restoration no longer depends on the current action.** The old `if (current != Block) return;`
  conflated "already at baseline" with "externally weakened", and `FirewallAction` has only the two
  values `Block`/`Allow`, so on a host that was *already* deny-by-default before the exam a mid-exam
  clearing to `Allow` would be left in place and the session reported as safely rolled back.
  `RestoreBaselineSafely` now writes the captured value whenever it differs, re-reads to confirm, and
  reports tamper detection (`ConflictDetected`) and convergence (`BaselineRestored`) as two separate
  answers. `RollbackResult.Success` is a claim about **convergence**, not about the absence of a
  conflict.
- **Restoration is keyed off `TargetProfiles`, not `Baseline.ActiveProfiles`.** Audit finding #3 was
  already stale — `RestoreBaselineAsync` passes `sessionRecord.TargetProfiles` — and this is correct
  rather than accidental: `ActiveProfiles` is an *observation* of which profiles were live at capture
  time, and a laptop that moves from Private to Public mid-exam would otherwise have its mutated
  profile left on `Block`. A profile outside the target set is never written at all, which
  `DefaultActionWrites` makes assertable (a final-state check cannot distinguish "left alone" from
  "written back to the same value").
- **`lockdownMayBeLive` is `EnforcingDefaultBlock or Active` only.** It used to include
  `RollingBackDefault` and `RollingBackRules`, which was a total-blackout bug: a crash between a
  rollback's first `SetDefaultOutboundAction` and its last rule removal left the profiles on `Block`,
  recovery declared that enforcement healthy and *preserved* it, while `LiveSessionIds()` — which
  counts only Prepared/ApplyingRules/EnforcingDefaultBlock/Active — classified the same session as
  dead and swept away its allow rules. Deny-by-default with nothing permitted through it, re-confirmed
  by every later restart. Both phases now fall through to the idempotent
  `PerformSafeRollbackInternal`, which finishes the interrupted job.
- The preserve branch adds its own session to the live set **explicitly** before sweeping, rather than
  trusting that its phase appears in `LiveSessionIds()`. The decision to preserve was just made a few
  lines above; if the two phase lists ever drift again, that sweep would delete the allow rules of the
  very lockdown it is preserving.

**Inbound is out of scope, on purpose, and that is a documented boundary rather than a gap.**
`IFirewallAdapter` has exactly seven members and not one of them can mutate inbound state;
`FirewallDirection.Inbound` appears nowhere in `src/` except its own enum member. So
`FirewallProfileBaseline` captures the three outbound defaults and nothing inbound, and three
reflection/direction tests in `RollbackScopeTests` fail if that ever stops being true. No fields were
added to widen the baseline to match the old documentation's broader claim — the documentation was
corrected instead.

`RollbackScopeTests.cs` (72 cases) is where these properties are *proven* rather than asserted about.
Two habits distinguish it from the rest of the suite and both are worth keeping: (1) **state, not
calls** — every restoration claim is checked by reading `MockFirewallAdapter` back and comparing
against a pre-exam `FirewallSnapshot`; (2) **preservation is falsifiable** —
`MockFirewallAdapter.RemoveRule` now deletes from `UnrelatedRuleNames` as well as `Rules`, because
until it did, every "unrelated rules preserved" assertion in the suite passed no matter what the
production code did. `Property_TheSnapshotComparisonCanActuallyFail` walks each snapshot field
proving it is genuinely sensitive, so the equality checks cannot decay into tautologies.
`MockFirewallAdapter.DefaultUnrelatedRuleNames` includes a rule named `"Codex"`, which turns the
project owner's standing instruction into something the suite checks on every run. It is a string in a
test double; nothing reachable from that file talks to the real Windows Firewall.

`SeedActiveLockdown` sets the live profiles to `Block` as part of seeding, and that is not decoration.
`Active` is the one phase in which read-back confirmed `Block`, so it is the one phase that licenses an
external-modification report. A fixture that seeds `Active` while leaving the defaults at their pre-exam
values is describing a machine somebody has **already tampered with**, and every test built on it
carries a conflict verdict it never meant to assert. Five tests were written that way first and had to
be rewritten.

**Backend auth, authorization and secrets (P1-N/O/P) is done and verified.** The route audit was
redone against current source rather than inherited: **81 routes → 71 gated, 10 open**, and every one
of the 10 is deliberate (`GET /`, `GET /health`, `GET /api/health`,
`GET /api/v1/management/health`, `POST /api/auth/login`, two public signing-key GETs,
`POST /api/v1/devices/register`, and the two WebSockets, which authenticate in-band). The old
audit's "~39 unauthenticated endpoints" figure was **low, not stale-high** — it counted only the
management-REST subset; the real open count was 53. What changed:

- **Gating is router-level `dependencies=[Depends(require_staff)]` plus per-endpoint
  `require_admin` on mutations.** Router level is the omission-proof floor: a new endpoint added to
  a gated router inherits the gate, whereas a per-endpoint convention fails silently the first time
  somebody forgets. FastAPI resolves dependencies **before** body validation, so a gated
  `POST`/`PUT`/`PATCH` answers 401/403 to `json={}` rather than 422 — that is what makes the
  inventory-driven tests able to probe mutations without constructing valid bodies.
- **`/auth/register` is admin-only and no longer self-service.** It previously let an anonymous
  caller pick its own `role`. `User.role`'s column default was `ADMIN` and the frontend helper's
  `role` parameter *defaulted* to `'admin'`, so the obvious call created an administrator. The
  column default is now `PROCTOR`, the schema default is the least-privileged role, the role field
  is a closed enum (an out-of-enum value is a 422, not a stored string), and the frontend
  `register()` requires `role` explicitly at the call site. `Column(default=...)` is a Python-side
  INSERT default, not `server_default`, so this needs no migration and rewrites no existing row.
- **`get_current_user` now refuses a disabled account.** It used to accept any structurally valid
  token for an existing user; tokens live 8 hours with no revocation list, so deactivating an
  operator did nothing for up to 8 hours. The REST and WebSocket paths disagreed on this, which is
  the more interesting half of the bug.
- **Ownership, not merely "has a valid token".** A device token authenticates *one* workstation, so
  the agent endpoints check that the session/device being acted on is the caller's. Ownership
  failures answer **403, not 404**, deliberately: 404 would turn the endpoint into an existence
  oracle for other candidates' session ids.
- **The dashboard WebSocket authenticates with a first-frame `AUTHENTICATE` handshake**, closing
  4401 (no/bad credentials) or 4403 (wrong role) — not with `?token=`, because query strings are
  written verbatim into proxy and access logs. Nothing is registered with `realtime_manager` until
  after the handshake succeeds, and the falsifier pair on `get_dashboard_count()` proves it.
- **Startup refuses to boot on a placeholder, missing or too-short shared secret** unless
  `SPEMCS_ENV` names a non-production environment. `validate_production_secrets()` is the *first*
  statement in the lifespan, before `engine.connect()`, and a test pins that ordering — a check that
  runs after the DB connect is a check that never runs on a box with a bad DATABASE_URL. Unset means
  production on purpose: the deployment this protects is the one where nobody set the variable.
  Diagnostics name the variable and how to generate a replacement, never the value, and never its
  length (a test requires byte-identical text for a 5-char and a 25-char secret).
- **Three trust domains stay separate and must not be conflated:** operator JWT (`SECRET_KEY`,
  HS256, 8 h), device HMAC (`DEVICE_TOKEN_SECRET`, HMAC-SHA256 over canonical JSON, 30 d), and the
  persistent RSA policy-signing keyring (`SIGNING_KEY_DIR`). Database credentials are a fourth,
  separate concern. The signing keyring was **not** touched and is explicitly excluded from
  rotation — see `SECRET_ROTATION.md` for why.
- `backend/.env.txt` and `frontend/.env.txt` are **untracked** now (`git rm --cached`, working
  copies kept). Git history was **not** rewritten. `SECRET_ROTATION.md` names the four credentials
  that must be rotated, in severity order, with blast radius and effect on live users, and no values.

`test_auth_security.py` (410 cases) and `test_secret_config.py` (59 cases) are **hermetic — proven,
not claimed**: both files pass with `DATABASE_URL` pointed at an unreachable host (469 passed in
7.9 s). Three facts make that work and all three are load-bearing:

1. `TestClient(app)` used **without** the context manager never runs the lifespan, and
   `create_engine` is lazy, so a 401/403 resolves before anything opens a socket.
2. `TestClient(app, raise_server_exceptions=False)` turns a route-body explosion into a 500, which
   is what lets a *positive* gate test assert `status_code not in (401, 403)` without a database.
3. `dashboard_ws._authenticate` builds its own session from
   `from backend.app.database import SessionLocal` **inside the function**, so a `get_db` override
   does not reach it. Both are needed:
   `monkeypatch.setattr("backend.app.database.SessionLocal", factory)` *and* the override.

The inventories are **data, not prose** — `STAFF_READ_ENDPOINTS`, `ADMIN_ONLY_ENDPOINTS`,
`STAFF_MUTATION_ENDPOINTS`, `DEVICE_ONLY_ENDPOINTS`, `INTENTIONALLY_PUBLIC` — and
`test_every_route_is_either_gated_or_on_the_public_list` walks `app.routes` so a new ungated route
fails the suite instead of being noticed later. Two vacuity traps were found and fixed rather than
tolerated: the live-route walk was confirmed to probe **71** routes (not zero), the leak-detector to
carry **4** needles (not an empty list), and four device-token tests were moved from
`/api/v1/events` to `/api/v1/sessions/start` **with a stubbed device row plus an explicit positive
control**, because on the old target a 401 also arrives from the device *lookup* failing — they
passed whether or not the signature was ever checked.

**`alerts.exam_id` is nullable, and the model was the side that was wrong** (found 2026-09-05 by
`alembic check` after the owner applied the migration to the live database; live DB **not**
modified). The check reported one drift and it is the only one — a scan of every declared column
against `information_schema` finds no other nullability disagreement. Two things about it are worth
carrying forward:

- **Read alembic's message carefully; it is easy to invert.** `compare.py` logs
  `"Detected %s on column '%s.%s'" % ("NULL" if metadata_col.nullable else "NOT NULL", ...)`, so
  *"Detected NOT NULL on column 'alerts.exam_id'"* means **the metadata wants NOT NULL and the
  database column is nullable** — alembic is proposing to *add* the constraint. It reads naturally
  as a statement about the database, which is exactly backwards.
- **The live column was right.** `event_service.ingest_event` writes
  `exam_id=exam.exam_id if exam else None`, and `exam` is None whenever the reporting device is not
  assigned to an exam with status ACTIVE — the ordinary state of a lab machine outside exam hours,
  and reachable even mid-exam because the function resolves the exam twice by independent
  mechanisms (the `realtime_manager` cache gates the function; a DB join through `ExamDevice`
  supplies `exam_id`) and those two can disagree. Every reader was already written for NULL:
  `_enrich_alert` guards on `if alert.exam_id`, `list_alerts` uses `outerjoin(Exam, ...)`,
  `agent_api.py:386` falls back to `""`, and `AlertCreate` declares `exam_id: Optional[UUID] = None`.
  Production holds one such row — a real `PROHIBITED_DOMAIN_ACCESS` / "Prohibited AI assistant"
  alert from 2026-09-02 — out of 900. Corrected in `models/alert.py` **and** in
  `0001_baseline.py`, which had faithfully mirrored the model's error.

  Under NOT NULL the consequence was worse than a dropped alert: `db.add(alert)` is followed
  immediately by `db.flush()` in the same transaction that just persisted the `Event`, so the
  IntegrityError would have taken the event down too. A device reporting AnyDesk outside an ACTIVE
  exam would have left no trace at all.

**Editing `0001_baseline.py` in place was correct here, and is not a general licence.** On the live
database that revision was `stamp`ed, never executed — its body only ever runs when a database is
built from scratch, so changing it altered no deployed schema (re-verified: live still
`0002 (head)`, 900 alert rows, the same single NULL). A new `0003` doing `DROP NOT NULL` would have
been a no-op against live and would have left the baseline describing a schema that never existed.

**`test_upgrade_head_produces_exactly_the_model_schema` could not have caught this**, and the
reason generalises: it compares migrations against models, and both were wrong in the same
direction. Model-vs-*reality* drift is only visible from `alembic check` against a real database,
or from a test that actually inserts a row. `backend/tests/test_alerts.py` was an **empty
placeholder** — nothing in ~870 tests had ever constructed an `Alert`, which is precisely why
`nullable=False` was never executed. It now holds three cases: the off-exam insert, a falsifier
proving the NOT NULL check is live in the SQLite dialect (so the first is not vacuous), and the
full `ingest_event` path with the cache primed and no `ExamDevice` row. All three were confirmed to
fail with `NOT NULL constraint failed: alerts.exam_id` when the column is flipped back.



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

**Committed secrets.** `backend/.env.txt` and `frontend/.env.txt` were tracked and carried live
credentials. Both are now **untracked** (`git rm --cached`, working copies kept on disk), and
`backend/.env.example` is the only tracked env file left. `.gitignore` covers `.env`, `.env.txt`,
`*.pem`, `*.key`, `secrets/` and `**/secrets/signing_keys/`. **Rotation is still outstanding and is
the owner's action** — see `SECRET_ROTATION.md` for the four credentials, in severity order. Git
history was not rewritten, so every value in it is still public; untracking stops new copies, it does
not un-publish an old one. Do not print the values. Correction to the earlier audit note:
`frontend/.env.txt` held only `BACKEND_HOST`/`BACKEND_PORT`, so no frontend credential was ever
exposed.

**The local `backend/.env` (untracked) needs `SPEMCS_ENV=development`** or the dev backend will not
boot: `DEVICE_TOKEN_SECRET` and `ENROLLMENT_BOOTSTRAP_KEY` are absent from it, so they fall back to
the committed placeholders in `backend/app/config.py`, and a production start refuses a placeholder.
That refusal is the feature working, not a regression. It is already appended locally.

**`frontend`'s `typecheck` script cannot type-check the app.** Two separate faults. `tsc -p
tsconfig.json` checks **nothing** — the root config is `"files": []` plus project references only, so
it exits 0 while reading no source; any "type-check passed" claim based on it is void. And
`package.json`'s `"typecheck": "tsc --noEmit -p tsconfig.app.json"`, which *would* check the app,
fails at config load with `TS5090` because `paths` is set without `baseUrl` (pre-existing). Workaround
without touching build config: `npx tsc --noEmit -p tsconfig.app.json --baseUrl .`. That reports **9
pre-existing errors** in `DeploymentModal.tsx`, `DeviceTile.tsx`, `AlertsPage.tsx`,
`ExamShieldPage.tsx` and `LiveMonitorPage.tsx`, none of them from this takeover. `"build": "vite
build"` runs no type-check at all, which is why the three dead references in `services/api.ts` — a
call through an `api` object that never existed in that module — survived to be found by hand.

**`TEMP SPEMCS TCP 8000` is a real, pre-existing, hand-made inbound firewall rule on this box.** It
matches a `SPEMCS`-substring search but not the `SPEMCS-{sessionId:N}-` naming convention, so
session-scoped rollback logs it at Error and never deletes it — exactly as designed. Like the
`Codex` rule: do not touch it, and do not assume SPEMCS created it.

**`out.txt` / `out1.txt`** at the repo root are captured agent logs kept as field evidence for
P0-A: 225 `InvalidOperationException`s out of `ConfigurableProcessClassifier.GetTrust` between
12:00 and 12:09 UTC on 2026-09-04. They are evidence, not deliverables.

**Private key file permissions** set by the agent are advisory on Windows, so the key directory
must be protected by NTFS ACLs. Any claim that file mode alone protects the signing key is wrong.

## Documents

`SPEMCS_TAKEOVER_AUDIT.md` is the requirements matrix and audit findings. `HANDOFF.md` describes
the service/UI split and the enforcement architecture. `SECRET_ROTATION.md` lists the credentials
that must be rotated at their source, with blast radius and no values. The M8 and M9 reports predate
this phase and contain crypto claims that are now stale — treat them as history, not as specification.
