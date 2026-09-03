# Endpoint Agent build-spec audit

Audit baseline: original `SPEMCS_Endpoint_Agent_Codex_Prompt.md` and the implementation in this directory.

## Implemented/integrated in this increment

- Solution/project structure and central package versions.
- Worker Service host and persisted Core state machine.
- SQLite registration/session/event storage.
- Service-owned activation control pipe (`START_EXAM` / `STOP_EXAM`).
- Service pipeline: activation -> Core state transition -> bounded pre-compliance -> UI gateway -> StudentVerification -> persisted roll number -> silent polling monitor -> STOP/IDLE.
- Separate WPF UI pipe client for compliance acknowledgement and roll-number collection.
- Shared classifier/pre-compliance logic and durable violation event generation.
- Core pipeline test covering the integrated sequence.

## Incomplete milestones and remaining gaps

| Milestone | Status | Remaining work |
|---|---|---|
| 1 Service skeleton | Partial | Worker Service and structured rolling JSON logs under `%ProgramData%\\Spemcs\\Logs` now exist; service installation/startup/manual Windows validation remains. |
| 2 Persistence | Partial | SQLite/WAL persistence, schema-v2 migration, upload statuses, retry timestamps, and uploaded-only purge now exist; crash injection and scheduled retention execution remain. |
| 3 Registration | Partial | Blocking registration mode, automatic IP display, `REGISTRATION_DATA`, persistence, pre-registration rejection, and restart/no-reprompt logic now exist; live interactive-session validation remains. |
| 4 Named Pipe IPC | Partial | Explicit local ACL, registration handling, bounded retries, malformed-message rejection, and session-aware UI launch now exist; complete live crash/restart round trips remain. |
| 5 State machine | Partial | Core transitions, restart persistence, invalid-transition rejection, and structured transition callbacks now exist; full service log reconstruction testing remains. |
| 6 Local harness/transport abstraction | Partial | Service control pipe, `--service` harness, formal `LocalTestActivationSource`, and interface test now exist; command-source wiring can be expanded. No Backend transport is implemented. |
| 7 Classification | Partial | Conservative protected-category classifier now covers SPEMCS, Windows paths, installed runtimes, endpoint security, configurable approved-browser family/children, SHA-256, Authenticode, publisher/path/hash, and parent context. Production signed-manifest/revocation policy and image-specific allow decisions remain. |
| 8 Pre-compliance | Partial | Explicit Skip/Close-all state-machine behavior, bounded enforcement, centralized safety policy, protected browser handling, dimmed modal UI, per-process audit sink, and failure reasons now exist; live Windows secure-desktop equivalence and full real-process acceptance coverage remain. |
| 9 StudentVerification | Integrated foundation | Service/UI exchange, validation, persistence, and session-start close signal exist; disconnect/cancel tests and registration-to-verification UI flow remain. |
| 10 Monitoring | Partial | Shared classifier, silent polling, baseline suppression, durable events, and STOP cleanup exist; event-driven detection, uploader scheduling, and full scenario coverage remain. |
| 11 Event store | Partial | Durable metadata-rich events, Pending/Uploading/Failed/Uploaded transitions, retry timestamps, uploaded-only retention, and harness inspection now exist; service scheduling/export polish remains. |
| 12 Full scenarios | Incomplete | Focused tests now cover registration, IPC, classification, safety, event state, activation abstraction, state rejection, and pipeline flow; full Windows/manual checklist and process-lifecycle scenarios remain. |

Backend APIs, WebSocket transport, Admin Portal, alerting, reporting, PostgreSQL, and external exam-platform integration remain intentionally out of scope.
