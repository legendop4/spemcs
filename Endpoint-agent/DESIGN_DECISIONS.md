# SPEMCS Endpoint Agent design decisions

## Boundaries

The Service owns state, persistence, process enumeration/classification, monitoring, and future Backend transport. The WPF UI is a separate interactive process and communicates only through the versioned named-pipe contract. The TestHarness exercises the same state-machine path offline; no Backend, exam-platform, Admin Portal, or WebSocket implementation is included.

## Persistence

`Microsoft.Data.Sqlite` is used because the event queue needs transactions, durable writes, indexing, and future upload-status queries; flat JSON is insufficient for that queue. SQLite is placed under `%ProgramData%\\Spemcs\\agent.db` and uses WAL mode. Registration/session configuration is stored in the same database so state changes and event writes have one machine-wide persistence boundary. `PRAGMA user_version` is reserved for forward migrations. Pending events are retained until a future uploader marks them uploaded; a later retention job can safely remove only confirmed-uploaded records.

## Classification and safety

The classifier is shared by pre-compliance and monitoring and emits three explicit categories: `Allowed`, `EssentialProtected`, and `Unauthorized`. `Allowed` means SPEMCS components, the one browser family selected for the session (Chrome, Firefox, or Edge), or explicitly catalog-approved examination software. `EssentialProtected` means Windows/system infrastructure, Windows-managed components, or recognized security/system software that must not be terminated. EssentialProtected processes are not violations, are not shown in the student's close list, and never block compliance. `Unauthorized` is reserved for user applications outside the approved examination environment and is the only category eligible for enforcement.

Signing and location alone do not grant approval: a signed executable under Program Files is still Unauthorized unless it is explicitly catalog-approved or recognized as essential security/system software. Unresolved paths remain visible for audit safety but are never eligible for termination. `TerminationSafetyPolicy` independently enforces `Unauthorized && !NeverTerminate` and blocks SPEMCS, Windows-root, and other protected targets.

The approved examination browser is a session-level policy with exactly one configured family: Chrome, Firefox, or Edge. The V1 environment variable is only the local fallback; the Core session stores the choice so a future Backend can supply it. A valid browser match is `Allowed`, never terminated, and its recognized helper processes inherit that status. A different browser family is Unauthorized. Renaming an arbitrary executable does not satisfy the browser policy because a name alone is insufficient; the configured path and trusted publisher signal must also match.

Parent process IDs are collected from the Windows Toolhelp process snapshot and resolved recursively. An unauthorized parent makes a child suspicious; a protected approved-browser parent protects recognized browser children. This is a signal, not a cryptographic identity, so the classifier still records path, hash, publisher, and matched rule for audit.

Pre-compliance uses bounded scan/classify/close/re-scan passes. The student explicitly chooses `Skip` or `Close all applications`. Skip performs no termination, persists `PreComplianceSkipped` in the session, and records a state transition. Close-all requests graceful close first and force termination only for `Unauthorized && NeverTerminate == false`; essential/system/security/SPEMCS/browser processes are never attempted. Monitoring never closes or kills processes and creates durable `APPLICATION_OPENED` events silently; V1 does not emit monitoring application-closed events.

The UI uses a full-screen, borderless, modal WPF overlay with a dimmed background, disabled resize/task-switch affordances, and foreground activation during the pre-compliance choice/compliance interaction. This is a UAC-style interactive modal experience, not a Windows secure desktop: creating a separate secure desktop would prevent the Service/UI named-pipe workflow and requires a different credential-prompt architecture. The implementation deliberately avoids global keyboard hooks and keylogging.

## IPC security

The protocol uses newline-delimited JSON envelopes with type, version, correlation ID, UTC timestamp, and payload. The Service is the pipe server. Pipes use the supported .NET `NamedPipeServerStreamAcl`/`PipeSecurity` API: LocalSystem and Administrators have full control, while only the Windows `Interactive` SID receives read/write access for the logged-in local UI. This avoids the fragile post-creation native ACL mutation and excludes non-interactive service identities and remote/untrusted users. Malformed messages are rejected and UI requests use bounded retries/timeouts.

The Service launches the UI with `WTSQueryUserToken` + `CreateProcessAsUser` in the active console session, rather than calling `Process.Start` from the non-interactive service session. This requires the Service identity to have the Windows privileges needed for querying the active session token; deployments without an interactive console session fail clearly and leave the exam activation rejected. A production deployment should validate the service account and session behavior on its supported Windows images.

## Trust and classification

Classification uses SHA-256 plus Authenticode certificate-chain validation where available. The current chain validation uses the system trust store and disables online revocation lookup (`NoCheck`) to avoid blocking offline exams; this limitation is logged by the verifier design and should be addressed with an enterprise revocation policy before production. Approved manifest entries require exact normalized path, current-file hash, and publisher match, and the manifest itself is loaded only when its SHA-256 equals a deployment-pinned value. A pinned hash protects against accidental/local edits but is not a full key-signature update system; future centrally signed manifests should replace it.

Parent-process context is a suspicion signal: a process whose resolved parent is unauthorized is rejected even if its own path is configured. System-critical protection is centralized in `TerminationSafetyPolicy`, which blocks force termination for SPEMCS paths, Windows-root paths, and classifications marked system-critical.

## Event retention and delivery

Events progress `Pending -> Uploading -> Uploaded`, or `Uploading -> Failed -> Pending` after the retry time. Only `Uploaded` events are eligible for purge; unresolved pending/failed/uploading events are never removed. The store schema is migrated to version 2 with retry counters/timestamps. The current upload worker is transport-agnostic and local/offline by default; a deployment can run a future uploader behind `IEventUploader`.

## Dependencies

The implementation uses the BCL for processes, named pipes, hashing, and networking. `Microsoft.Data.Sqlite` provides the durable local queue; `Microsoft.Extensions.Hosting.WindowsServices` integrates the Worker Service with Windows Service control; xUnit/test SDK are test-only. Package versions are centrally pinned in `Directory.Packages.props`.
